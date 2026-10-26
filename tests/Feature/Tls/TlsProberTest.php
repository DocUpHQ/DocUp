<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Egress\TlsHandshake;
use App\Models\CertificateIssuanceAttempt;
use App\Models\Domain;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\Csr;
use App\Tls\TlsProber;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * 🛑 §8.10.17's prober, and §19's exit criterion: "The prober records an
 * issuance failure the proxy never reported."
 *
 * > "A scheduled outbound TLS handshake prober MUST run against every active
 * > domain at least every six hours, recording expiry, issuer and error,
 * > **because the proxy never calls the permission endpoint back on issuance
 * > failure**. Without it there is no issuance-failure observability at all."
 *
 * The scenario the criterion describes, exactly: a domain that is verified,
 * active and permitted — every table and every screen says it is healthy —
 * whose handshake does not work. Nothing else in the installation can tell.
 *
 * 🛑 The handshake is faked here and the **recording** is not. A real
 * outbound TLS connection to a hostname that is deliberately broken cannot
 * be arranged in a unit suite without a listener and a DNS entry, and the
 * fact under test is what DocUp does with the answer. The real handshake is
 * exercised against a running Caddy in the `tls` CI job; what is asserted
 * there is that `TlsHandshakeProbe` can read a certificate at all.
 */
final class TlsProberTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hosted Co',
            'slug' => 'hosted-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The criterion itself: a domain that looks perfect and does not
     * serve, found by the only thing that can find it.
     */
    public function test_the_prober_records_an_issuance_failure_the_proxy_never_reported(): void
    {
        $domain = $this->activeDomain('broken.'.$this->uniqueApex());

        $prober = new TlsProber($this->handshakeThatFails('tls: no certificate available'));

        $probe = $prober->probe($domain);

        $this->assertFalse($probe->ok());

        $fresh = $this->refreshed($domain);

        $this->assertNotNull($fresh->tls_last_probed_at);
        $this->assertSame('tls: no certificate available', $fresh->tls_probe_error);
        $this->assertNull($fresh->tls_not_after);

        $attempt = CertificateIssuanceAttempt::query()->where('host', $domain->host)->first();

        $this->assertNotNull($attempt, '🛑 without this row there is no issuance-failure observability at all');
        $this->assertSame('failed', $attempt->outcome);
        $this->assertSame('handshake_failed', $attempt->reason);
        $this->assertSame('edge', $attempt->source, 'the proxy issued it, or failed to');
    }

    /** A healthy host records expiry and issuer and writes no failure. */
    public function test_a_healthy_host_records_expiry_and_issuer(): void
    {
        $domain = $this->activeDomain('healthy.'.$this->uniqueApex());

        $prober = new TlsProber($this->handshakeServing($domain->host, days: 60));

        $probe = $prober->probe($domain);

        $this->assertTrue($probe->ok(), (string) $probe->error);

        $fresh = $this->refreshed($domain);

        $this->assertNotNull($fresh->tls_not_after);
        $this->assertNotNull($fresh->tls_issuer);
        $this->assertNull($fresh->tls_probe_error);
        $this->assertSame(0, CertificateIssuanceAttempt::query()->count());
    }

    /**
     * 🛑 A trusted certificate inside the renewal window is a renewal that
     * did not happen, and is recorded as a failure.
     *
     * The proxy renews silently and reports nothing, so this is the only
     * place an unrenewed certificate becomes visible before a reader sees
     * it expire. 21 days is the renewal slack of a 64-day certificate —
     * the lifetime arriving 2027-02-10, per §18.20's re-read.
     */
    public function test_a_certificate_inside_the_renewal_window_is_recorded(): void
    {
        $domain = $this->activeDomain('stale.'.$this->uniqueApex());

        $prober = new TlsProber($this->handshakeServing($domain->host, days: 5));

        $probe = $prober->probe($domain);

        $this->assertTrue($probe->ok(), 'the handshake itself succeeded');
        $this->assertTrue($probe->expiringWithin(21));

        $attempt = CertificateIssuanceAttempt::query()->where('host', $domain->host)->first();

        $this->assertNotNull($attempt);
        $this->assertSame('expiring', $attempt->reason);
    }

    /**
     * 🛑 A trusted handshake whose certificate could not be read is a
     * failure, not a success.
     *
     * §8.10.17 asks for "expiry, issuer and error". A row with none of the
     * three is a probe that ran and learned nothing, and recording it green
     * would produce the one thing worse than no observability — the
     * appearance of it.
     */
    public function test_a_handshake_with_no_readable_certificate_is_a_failure(): void
    {
        $domain = $this->activeDomain('opaque.'.$this->uniqueApex());

        $prober = new TlsProber(new class implements TlsHandshake
        {
            public function probe(string $host, int $port = 443): array
            {
                return ['trusted' => true, 'error' => null, 'certificate' => null];
            }
        });

        $this->assertFalse($prober->probe($domain)->ok());
    }

    /** §8.10.21: a passthrough host terminates elsewhere and is not probed. */
    public function test_a_passthrough_host_is_not_probed(): void
    {
        $domain = $this->activeDomain('lb.'.$this->uniqueApex());
        $domain->forceFill(['tls_mode' => 'passthrough'])->save();

        $prober = new TlsProber($this->handshakeThatFails('should never run'));

        foreach ($prober->run() as $probe) {
            $this->assertNotSame($domain->host, $probe->host, 'a device this installation does not run is not its to report on');
        }

        $this->assertNull($this->refreshed($domain)->tls_last_probed_at);
    }

    private function handshakeThatFails(string $error): TlsHandshake
    {
        return new class($error) implements TlsHandshake
        {
            public function __construct(private readonly string $error) {}

            public function probe(string $host, int $port = 443): array
            {
                return ['trusted' => false, 'error' => $this->error, 'certificate' => null];
            }
        };
    }

    /**
     * A handshake presenting a real certificate for this host, parsed the
     * way the real probe parses one.
     */
    private function handshakeServing(string $host, int $days): TlsHandshake
    {
        [$chain] = Csr::selfSigned($host, Csr::key(), $days);

        $leaf = openssl_x509_read($chain);
        $parsed = $leaf === false ? [] : (openssl_x509_parse($leaf) ?: []);
        $parsed['docup_fingerprint'] = hash('sha256', $chain);

        return new class($parsed) implements TlsHandshake
        {
            /** @param  array<array-key, mixed>  $certificate */
            public function __construct(private readonly array $certificate) {}

            public function probe(string $host, int $port = 443): array
            {
                return ['trusted' => true, 'error' => null, 'certificate' => $this->certificate];
            }
        };
    }

    private function activeDomain(string $host): Domain
    {
        $domain = new Domain;

        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        return $domain;
    }

    private function refreshed(Domain $domain): Domain
    {
        $fresh = $domain->fresh();

        $this->assertInstanceOf(Domain::class, $fresh, $domain->host.' disappeared');

        return $fresh;
    }

    private function uniqueApex(): string
    {
        return 'tenant-'.bin2hex(random_bytes(4)).'.example';
    }
}
