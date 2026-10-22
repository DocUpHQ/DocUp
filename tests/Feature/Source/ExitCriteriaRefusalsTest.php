<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Source;

use App\Egress\AddressGuard;
use App\Egress\EgressOptions;
use App\Egress\EgressRefused;
use App\Egress\EgressRejection;
use App\Egress\HardenedEgressClient;
use App\Egress\IpAddressClassifier;
use App\Egress\PinnedCurlTransport;
use App\Source\GitUrlPolicy;
use App\Source\SourceRefused;
use App\Source\SourceRejection;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FakeDnsResolver;
use Tests\Support\LoopbackHttpServer;
use Tests\TestCase;

/**
 * 🛑 Phase 05's exit criteria, demonstrated.
 *
 * > "`ext::sh -c id`, `file:///etc/passwd`, a `169.254.169.254` host, a TTL-0
 * > DNS-rebind target and an HTTP redirect to a private address are each
 * > refused **with distinct errors**."
 *
 * The distinctness is the requirement. A single generic rejection would
 * satisfy a careless test and hide which control fired — and the day four of
 * the five regress, the fifth keeps the suite green. So the central test here
 * asserts that the five identifiers are **five**, not that each input was
 * refused.
 *
 * The vectors and their expected identifiers are `git_url-009` to `-013` in
 * the permanent abuse corpus, appended by this phase per §9.4. The corpus is
 * the commitment; this file is the measurement, and the last test checks the
 * two still agree.
 *
 * 🛑 The redirect case runs against a **real HTTP origin**, not a stubbed
 * transport. Phase 04's §18.18 finding was that a configuration asserted only
 * against a constant is a configuration nobody has run, and
 * `CURLOPT_FOLLOWLOCATION => false` is exactly that shape: asserting the
 * option proves the array, not libcurl's behaviour. Guzzle's equivalent
 * default is **on**, which is how this control gets lost in the first place.
 */
final class ExitCriteriaRefusalsTest extends TestCase
{
    private ?LoopbackHttpServer $server = null;

    protected function tearDown(): void
    {
        $this->server?->stop();
        $this->server = null;

        parent::tearDown();
    }

    /**
     * The four vectors that need no origin.
     *
     * @return \Generator<string, array{0: string, 1: SourceRejection}>
     */
    public static function staticVectors(): \Generator
    {
        yield 'git_url-009 ext::sh -c id' => ['ext::sh -c id', SourceRejection::RemoteHelperForbidden];
        yield 'git_url-010 file:///etc/passwd' => ['file:///etc/passwd', SourceRejection::LocalPathForbidden];
        yield 'git_url-011 metadata host' => [
            'https://169.254.169.254/latest/meta-data/repo.git',
            SourceRejection::MetadataAddressDenied,
        ];
        yield 'git_url-014 IPv4-mapped metadata' => [
            'https://[::ffff:169.254.169.254]/repo.git',
            SourceRejection::MetadataAddressDenied,
        ];
        yield 'git_url-015 NAT64 private' => [
            'https://[64:ff9b::a00:1]/repo.git',
            SourceRejection::PrivateAddressDenied,
        ];
        yield 'git_url-016 credential in the URL' => [
            'https://x-access-token:ghp_0123456789abcdefghijklmnopqrstuvwxyz@github.com/acme/docs.git',
            SourceRejection::CredentialsInUrl,
        ];
    }

    #[DataProvider('staticVectors')]
    public function test_it_refuses_a_hostile_repository_url(string $url, SourceRejection $expected): void
    {
        try {
            $this->policy()->inspect($url);
            $this->fail($url.' was accepted');
        } catch (SourceRefused $refused) {
            $this->assertSame($expected, $refused->rejection);
        }
    }

    /** 🛑 git_url-012: a TTL-0 name that answers publicly, then privately. */
    public function test_it_refuses_a_dns_rebind_target(): void
    {
        try {
            $this->policy()->inspect('https://rebind.example.com/acme/docs.git');
            $this->fail('the rebinding name was accepted');
        } catch (SourceRefused $refused) {
            $this->assertSame(SourceRejection::DnsRebindDetected, $refused->rejection);
        }
    }

    /**
     * 🛑 git_url-013: a **real** origin answering `302 Location: http://10.0.0.1/`.
     *
     * The refusal is on the 3xx itself, before the target is examined, which
     * is why the identifier is `redirect_refused` and not a private-address
     * one. Re-validating after following is the shape of every SSRF bypass:
     * the second request is made by a layer that has forgotten the first
     * one's constraints.
     */
    public function test_it_refuses_an_http_redirect_to_a_private_address(): void
    {
        $refused = $this->refusalFromRedirectingOrigin();

        $this->assertSame(EgressRejection::RedirectRefused, $refused->rejection);
        $this->assertSame('10.0.0.1', $refused->context['location_host'] ?? null);
        $this->assertSame(302, $refused->context['status'] ?? null);

        // The repository-facing vocabulary an author would be shown.
        $this->assertSame(
            SourceRejection::RedirectRefused,
            SourceRejection::fromEgress($refused->rejection),
        );
    }

    /**
     * 🛑 The exit criterion in one assertion: **five distinct errors**.
     *
     * Collected from live runs rather than restated, so this cannot pass
     * while one of the controls is failing.
     */
    public function test_the_five_vectors_produce_five_distinct_identifiers(): void
    {
        $policy = $this->policy();
        $identifiers = [];

        foreach ([
            'ext::sh -c id',
            'file:///etc/passwd',
            'https://169.254.169.254/latest/meta-data/repo.git',
            'https://rebind.example.com/acme/docs.git',
        ] as $url) {
            try {
                $policy->inspect($url);
                $this->fail($url.' was accepted');
            } catch (SourceRefused $refused) {
                $identifiers[] = $refused->identifier();
            }
        }

        $identifiers[] = SourceRejection::fromEgress($this->refusalFromRedirectingOrigin()->rejection)->value;

        $this->assertSame([
            'git_url.remote_helper_forbidden',
            'git_url.local_path_forbidden',
            'git_url.metadata_address_denied',
            'git_url.dns_rebind_detected',
            'git_url.redirect_refused',
        ], $identifiers);

        $this->assertCount(5, array_unique($identifiers), 'the five controls must be distinguishable');
    }

    /**
     * Every identifier these controls produce is the one the corpus named.
     *
     * The corpus committed to these strings before the code existed; this
     * asserts the code did not quietly choose different words. It fails
     * loudly when a case is missing, because a corpus case that stops running
     * while the suite reports green is the failure the corpus exists to
     * prevent.
     */
    public function test_the_corpus_names_the_identifier_each_control_produces(): void
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(base_path('tests/Fixtures/AbuseCorpus/corpus.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $expectations = [];

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) === 'git_url') {
                $expectations[(string) $case['id']] = (string) $case['expect'];
            }
        }

        foreach ([
            'git_url-009' => SourceRejection::RemoteHelperForbidden,
            'git_url-010' => SourceRejection::LocalPathForbidden,
            'git_url-011' => SourceRejection::MetadataAddressDenied,
            'git_url-012' => SourceRejection::DnsRebindDetected,
            'git_url-013' => SourceRejection::RedirectRefused,
            'git_url-014' => SourceRejection::MetadataAddressDenied,
            'git_url-015' => SourceRejection::PrivateAddressDenied,
            'git_url-016' => SourceRejection::CredentialsInUrl,
            'git_url-017' => SourceRejection::SubmoduleRecursionForbidden,
        ] as $id => $rejection) {
            $this->assertArrayHasKey($id, $expectations, "abuse corpus case {$id} is missing");
            $this->assertSame($rejection->value, $expectations[$id], "corpus case {$id} expects a different identifier");
        }
    }

    /**
     * The policy with a resolver that answers the names these tests use.
     *
     * `github.com` resolves publicly so that the credential-in-URL case is
     * refused for carrying a credential and not for some incidental DNS
     * failure; `rebind.example.com` answers publicly once and privately after.
     */
    private function policy(): GitUrlPolicy
    {
        $resolver = (new FakeDnsResolver)
            ->stable('github.com', ['140.82.121.4'])
            ->rebinding('rebind.example.com', ['93.184.216.34'], ['127.0.0.1']);

        return new GitUrlPolicy(new AddressGuard($resolver, new IpAddressClassifier));
    }

    /**
     * Drive the real client at a real origin that redirects into RFC1918.
     *
     * `http` is in the scheme list and the address policy is stood down,
     * because the suite cannot stand up a TLS origin with a chain cURL will
     * verify and the address policy correctly refuses loopback. The control
     * under test is the **redirect**, not the scheme or the address — both of
     * which have their own tests, and both of which are asserted for the
     * shipped configuration by `EgressConfigurationTest`.
     */
    private function refusalFromRedirectingOrigin(): EgressRefused
    {
        $this->server ??= (new LoopbackHttpServer(<<<'PHP'
            <?php
            header('Location: http://10.0.0.1/internal.git', true, 302);
            echo 'moved';
            PHP))->start();

        $port = $this->server->port();
        $resolver = (new FakeDnsResolver)->stable('redirect.test', ['127.0.0.1']);

        $client = new HardenedEgressClient(
            new AddressGuard($resolver, new IpAddressClassifier),
            new PinnedCurlTransport,
            new EgressOptions(
                allowedSchemes: ['http', 'https'],
                allowedPorts: [$port],
                enforceAddressPolicy: false,
            ),
        );

        try {
            $client->get('http://redirect.test:'.$port.'/acme/docs.git');
        } catch (EgressRefused $refused) {
            return $refused;
        }

        $this->fail('the redirect was followed or accepted');
    }
}
