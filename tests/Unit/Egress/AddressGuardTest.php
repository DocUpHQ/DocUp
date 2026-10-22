<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Egress;

use App\Egress\AddressGuard;
use App\Egress\EgressRejection;
use App\Egress\IpAddressClassifier;
use PHPUnit\Framework\TestCase;
use Tests\Support\FakeDnsResolver;

/**
 * Resolve-then-pin, and the rebind control (§8.3.4, §8.3.9).
 */
final class AddressGuardTest extends TestCase
{
    private function guard(FakeDnsResolver $resolver): AddressGuard
    {
        return new AddressGuard($resolver, new IpAddressClassifier);
    }

    public function test_a_public_name_is_pinned_to_its_first_address(): void
    {
        $resolver = (new FakeDnsResolver)->stable('example.com', ['93.184.216.34', '93.184.216.35']);

        $inspection = $this->guard($resolver)->inspect('example.com');

        $this->assertFalse($inspection->isRefused());
        $this->assertSame('93.184.216.34', $inspection->pinnedAddress);
        $this->assertSame(['93.184.216.34', '93.184.216.35'], $inspection->addresses);
    }

    /**
     * 🛑 Every address in the answer is checked, not only the one we would
     * connect to.
     *
     * A name publishing a public address alongside loopback is refused
     * outright. The alternative — pin the public one and proceed — assumes
     * the pin can never fail open, and a control whose correctness depends on
     * another control never failing is one control, not two.
     */
    public function test_a_name_answering_with_any_private_address_is_refused(): void
    {
        $resolver = (new FakeDnsResolver)->stable('mixed.example.com', ['93.184.216.34', '127.0.0.1']);

        $inspection = $this->guard($resolver)->inspect('mixed.example.com');

        $this->assertSame(EgressRejection::LoopbackAddressDenied, $inspection->rejection);
        $this->assertSame('127.0.0.1', $inspection->offendingAddress);
    }

    public function test_the_metadata_address_is_refused_with_its_own_identifier(): void
    {
        $resolver = (new FakeDnsResolver)->stable('metadata.example.com', ['169.254.169.254']);

        $this->assertSame(
            EgressRejection::MetadataAddressDenied,
            $this->guard($resolver)->inspect('metadata.example.com')->rejection,
        );
    }

    /**
     * 🛑 The TTL-0 rebind case, and the reason it has an identifier of its own.
     *
     * The first answer is public and would have been accepted. The second
     * disagrees and is private. The request is pinned to the first address
     * regardless — so nothing would have reached 127.0.0.1 — but a name
     * behaving this way is refused rather than quietly served.
     */
    public function test_a_rebinding_name_is_refused_with_a_distinct_identifier(): void
    {
        $resolver = (new FakeDnsResolver)->rebinding('rebind.example.com', ['93.184.216.34'], ['127.0.0.1']);

        $inspection = $this->guard($resolver)->inspect('rebind.example.com');

        $this->assertSame(EgressRejection::DnsRebindDetected, $inspection->rejection);
        $this->assertSame('127.0.0.1', $inspection->offendingAddress);
        $this->assertSame(0, $inspection->ttl, 'the TTL is recorded for the operator, not used as the trigger');
    }

    /**
     * 🛑 Round-robin DNS must NOT be mistaken for rebinding.
     *
     * Large origins legitimately return different subsets of a public RRset
     * from one query to the next. A guard that refused on any difference would
     * refuse real providers intermittently — the kind of failure that gets a
     * security control switched off rather than fixed. The condition is a
     * second answer that is **not routable**, not a second answer that differs.
     */
    public function test_a_changing_public_answer_is_not_a_rebind(): void
    {
        $resolver = (new FakeDnsResolver)->rebinding(
            'roundrobin.example.com',
            ['93.184.216.34'],
            ['93.184.216.35', '93.184.216.36'],
        );

        $inspection = $this->guard($resolver)->inspect('roundrobin.example.com');

        $this->assertFalse($inspection->isRefused());
        $this->assertSame('93.184.216.34', $inspection->pinnedAddress, 'the first answer is what is pinned');
    }

    public function test_an_unresolvable_name_is_refused(): void
    {
        $resolver = (new FakeDnsResolver)->unresolvable('nowhere.example.com');

        $this->assertSame(
            EgressRejection::HostNotResolvable,
            $this->guard($resolver)->inspect('nowhere.example.com')->rejection,
        );
    }

    /**
     * A literal address has no name to rebind, so it is classified and pinned
     * without a lookup. Asserted on the resolver's call count: "we did not ask
     * DNS" is the claim, and counting is the only way to check it.
     */
    public function test_a_literal_address_is_not_resolved(): void
    {
        $resolver = new FakeDnsResolver;

        $inspection = $this->guard($resolver)->inspect('93.184.216.34');

        $this->assertSame('93.184.216.34', $inspection->pinnedAddress);
        $this->assertSame(0, $resolver->callsFor('93.184.216.34'));
    }

    public function test_a_bracketed_ipv6_literal_is_unwrapped_before_classification(): void
    {
        $inspection = $this->guard(new FakeDnsResolver)->inspect('[::1]');

        $this->assertSame(EgressRejection::LoopbackAddressDenied, $inspection->rejection);
    }

    /**
     * 🛑 The context that reaches a log carries addresses and classes and
     * nothing else. Phase 05's exit criterion is that no token appears in any
     * log; the cheapest way to honour it is for the structures that get logged
     * never to have had one.
     */
    public function test_the_logged_context_carries_no_url_or_credential(): void
    {
        $resolver = (new FakeDnsResolver)->stable('metadata.example.com', ['169.254.169.254']);

        $context = $this->guard($resolver)->inspect('metadata.example.com')->context();

        $this->assertSame([
            'rejection' => 'egress.metadata_address_denied',
            'addresses' => ['169.254.169.254'],
            'ttl' => 300,
            'offending_address' => '169.254.169.254',
            'offending_class' => 'metadata',
        ], $context);
    }
}
