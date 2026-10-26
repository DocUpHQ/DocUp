<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Credentials\EnvelopeCipher;
use App\Models\Certificate;
use App\Models\Domain;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;
use App\Tls\CertificateSourceKind;
use App\Tls\CertificateStore;
use App\Tls\Csr;
use App\Tls\DevelopmentCertificateSource;
use App\Tls\IssuedCertificate;
use App\Tls\UploadedCertificateSource;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §8.10.14's four sources behind one contract, and §8.10.15's sealed keys.
 *
 * > "Four certificate sources MUST sit behind one contract … Uploaded and
 * > internal-PKI certificates MUST be delivered to the edge **at handshake
 * > time from the database** … All certificate private keys and ACME account
 * > keys MUST be stored with authenticated encryption, excluded from every
 * > API response and log, and every read of key material MUST be audited."
 *
 * The ACME sources have their own file — they need a certificate authority
 * to talk to, which is an integration test. What is here is everything that
 * can be proven without one: the contract, the parsing, the store, the
 * envelope and the audit.
 */
final class CertificateSourcesTest extends TestCase
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
     * 🛑 An uploaded PEM is served from the database, key and all.
     *
     * This is §19's exit criterion "an uploaded PEM certificate serves from
     * the database with the admin API disabled", on the application side:
     * the bytes a handshake would receive come out of `certificates` and
     * nowhere else. The proxy half is in `EdgeEndpointsTest`, and the
     * admin API half in `TlsConfigurationTest`.
     */
    public function test_an_uploaded_pem_is_stored_and_served_from_the_database(): void
    {
        $host = 'docs.'.$this->uniqueApex();
        [$chain, $key] = $this->selfSigned($host);

        $source = new UploadedCertificateSource($chain, $key);
        $store = new CertificateStore(app(EnvelopeCipher::class));

        $certificate = $source->issue($host);
        $stored = $store->store($host, $certificate, $source->kind(), $this->domain($host));

        $this->assertSame(CertificateSourceKind::Uploaded, $stored->source);
        $this->assertSame($host, $stored->host);
        $this->assertSame($certificate->fingerprint, $stored->fingerprint);

        $served = $store->pem($store->activeFor($host) ?? $stored);

        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $served);
        $this->assertStringContainsString('PRIVATE KEY-----', $served);
        $this->assertTrue(
            openssl_x509_check_private_key(
                openssl_x509_read($served) ?: throw new \RuntimeException('unreadable'),
                openssl_pkey_get_private($served) ?: throw new \RuntimeException('unreadable'),
            ),
            'the chain and key the edge receives must be a matching pair',
        );
    }

    /**
     * 🛑 The private key never appears in the row as it is read, or in any
     * array form of it.
     *
     * §8.10.15 says key material is "excluded from every API response and
     * log". The ciphertext is not the key — but ciphertext in an Inertia
     * prop is a gift to an offline attacker, so `$hidden` covers the
     * envelope columns too and this asserts it rather than trusting the
     * attribute list to stay correct.
     */
    public function test_the_key_is_absent_from_every_array_form_of_the_row(): void
    {
        $host = 'secret.'.$this->uniqueApex();
        [$chain, $key] = $this->selfSigned($host);

        $store = new CertificateStore(app(EnvelopeCipher::class));
        $stored = $store->store($host, IssuedCertificate::fromPem($chain, $key), CertificateSourceKind::Uploaded);

        $serialised = json_encode($stored->toArray(), JSON_THROW_ON_ERROR);

        foreach (['ciphertext', 'wrapped_key', 'kek_fingerprint', 'envelope_version'] as $column) {
            $this->assertStringNotContainsString($column, $serialised, $column.' reached a serialised row');
        }

        $this->assertStringNotContainsString('PRIVATE KEY', $serialised);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $serialised, 'the chain is public and may be read');
    }

    /** 🛑 §8.10.15: every read of key material is audited. */
    public function test_reading_a_key_writes_an_audit_event(): void
    {
        $host = 'audited.'.$this->uniqueApex();
        [$chain, $key] = $this->selfSigned($host);

        $store = new CertificateStore(app(EnvelopeCipher::class));
        $stored = $store->store($host, IssuedCertificate::fromPem($chain, $key), CertificateSourceKind::Uploaded);

        $before = DB::table('audit_events')->where('action', 'tls.certificate_key.read')->count();

        $store->pem($stored);

        $this->assertSame(
            $before + 1,
            DB::table('audit_events')->where('action', 'tls.certificate_key.read')->count(),
            '§8.10.15: "every read of key material MUST be audited"',
        );
    }

    /**
     * 🛑 A chain that does not cover the hostname is refused at upload.
     *
     * Accepted by every parser, rejected by every client — at handshake
     * time, on the live hostname, with nothing in this application's logs.
     * An operator pasting a wildcard onto the wrong host is the ordinary
     * way this happens.
     */
    public function test_a_chain_that_does_not_cover_the_host_is_refused(): void
    {
        [$chain, $key] = $this->selfSigned('other.example.test');

        $this->expectRefusal(
            CertificateRejection::HostNotCovered,
            fn () => (new UploadedCertificateSource($chain, $key))->issue('docs.example.test'),
        );
    }

    /** 🛑 A key that is not the leaf's key is refused. */
    public function test_a_mismatched_key_is_refused(): void
    {
        [$chain] = $this->selfSigned('docs.example.test');
        [, $otherKey] = $this->selfSigned('docs.example.test');

        $this->expectRefusal(
            CertificateRejection::KeyDoesNotMatch,
            fn () => (new UploadedCertificateSource($chain, $otherKey))->issue('docs.example.test'),
        );
    }

    /** An expired upload is refused before it can be served. */
    public function test_an_expired_upload_is_refused(): void
    {
        $host = 'stale.example.test';
        [$chain, $key] = $this->selfSigned($host);

        $future = Carbon::now()->addDays(DevelopmentCertificateSource::LIFETIME_DAYS + 1);

        $this->expectRefusal(
            CertificateRejection::OutsideValidity,
            fn () => (new UploadedCertificateSource($chain, $key, $future))->issue($host),
        );
    }

    /**
     * 🛑 Wildcard matching is RFC 6125's, not a suffix test.
     *
     * `*.docs.example.com` covers one label and only the leftmost one. A
     * suffix test would make the installation's own wildcard (§8.10.10)
     * appear to cover every tenant's custom domain under it, which is how a
     * handshake ends up presenting the wrong certificate with no error
     * anywhere.
     */
    public function test_a_wildcard_covers_exactly_one_label(): void
    {
        [$chain, $key] = $this->selfSigned('*.docs.example.test');
        $certificate = IssuedCertificate::fromPem($chain, $key);

        $this->assertTrue($certificate->covers('project.docs.example.test'));
        $this->assertFalse($certificate->covers('a.project.docs.example.test'), 'two labels is not one');
        $this->assertFalse($certificate->covers('docs.example.test'), 'the apex is not under the wildcard');
        $this->assertFalse($certificate->covers('project.docs.example.evil'));
    }

    /**
     * 🛑 Activating a certificate supersedes the previous one, and the
     * database is what guarantees exactly one is active.
     *
     * `active_host` is generated from `state` under a unique index, so a
     * second active row for one host is error 1062 rather than a handshake
     * whose answer depends on the plan the optimiser picked.
     */
    public function test_one_host_has_exactly_one_active_certificate(): void
    {
        $host = 'renewed.'.$this->uniqueApex();
        $store = new CertificateStore(app(EnvelopeCipher::class));

        [$first, $firstKey] = $this->selfSigned($host);
        [$second, $secondKey] = $this->selfSigned($host);

        $one = $store->store($host, IssuedCertificate::fromPem($first, $firstKey), CertificateSourceKind::Uploaded);
        $two = $store->store($host, IssuedCertificate::fromPem($second, $secondKey), CertificateSourceKind::Uploaded);

        $this->assertSame(
            1,
            Certificate::query()->where('host', $host)->where('state', 'active')->count(),
        );

        $active = $store->activeFor($host);

        $this->assertNotNull($active);
        $this->assertSame($two->id, $active->id);
        $this->assertSame('superseded', (string) $one->fresh()?->state);
    }

    /**
     * 🛑 The AAD binds the key to the hostname **and** the fingerprint, so a
     * ciphertext moved between two certificates for one host does not open.
     *
     * Binding to the hostname alone would let a renewal's key open against
     * its predecessor's chain, producing a mismatched pair that every row in
     * the database says is fine.
     */
    public function test_a_key_moved_between_rows_does_not_open(): void
    {
        $host = 'bound.'.$this->uniqueApex();
        $store = new CertificateStore(app(EnvelopeCipher::class));

        [$a, $aKey] = $this->selfSigned($host);
        [$b, $bKey] = $this->selfSigned($host);

        $first = $store->store($host, IssuedCertificate::fromPem($a, $aKey), CertificateSourceKind::Uploaded);
        $second = $store->store($host, IssuedCertificate::fromPem($b, $bKey), CertificateSourceKind::Uploaded);

        $first->forceFill([
            'envelope_version' => $second->envelope_version,
            'kek_fingerprint' => $second->kek_fingerprint,
            'wrapped_key' => $second->wrapped_key,
            'ciphertext' => $second->ciphertext,
        ])->save();

        $this->expectException(\Throwable::class);

        $store->pem($first->refresh());
    }

    /**
     * 🛑 §8.10.14's development issuer refuses to exist outside a local
     * environment.
     *
     * In the constructor rather than in `issue()`, so a production
     * container cannot hold one — §20.4's invariant is that no security
     * control sits behind a flag that defaults open, and the cheapest
     * reading here is a source with no flag at all.
     */
    public function test_the_development_issuer_is_refused_in_production(): void
    {
        $this->expectException(CertificateRefused::class);

        new DevelopmentCertificateSource('production');
    }

    /** And it issues something real in a local environment. */
    public function test_the_development_issuer_issues_a_usable_certificate(): void
    {
        $host = 'local.'.$this->uniqueApex();

        $certificate = (new DevelopmentCertificateSource('testing'))->issue($host);

        $this->assertTrue($certificate->covers($host), 'the SAN must carry the hostname, not only the CN');
        $this->assertTrue($certificate->notAfter->isFuture());
        $this->assertSame(
            DevelopmentCertificateSource::LIFETIME_DAYS,
            (int) round($certificate->notBefore->diffInDays($certificate->notAfter, absolute: true)),
        );
    }

    /**
     * @return array{0: string, 1: string}
     */
    private function selfSigned(string $host): array
    {
        return Csr::selfSigned($host, Csr::key(), 30);
    }

    private function domain(string $host): Domain
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

    private function expectRefusal(CertificateRejection $expected, \Closure $work): void
    {
        try {
            $work();
        } catch (CertificateRefused $refused) {
            $this->assertSame($expected, $refused->rejection, 'wrong refusal: '.$refused->getMessage());

            return;
        }

        $this->fail('expected '.$expected->value.' and nothing was refused');
    }

    private function uniqueApex(): string
    {
        return 'tenant-'.bin2hex(random_bytes(4)).'.example';
    }
}
