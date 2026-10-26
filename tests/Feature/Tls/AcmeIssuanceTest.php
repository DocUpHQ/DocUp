<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Credentials\EnvelopeCipher;
use App\Egress\AddressGuard;
use App\Egress\EgressOptions;
use App\Egress\HardenedEgressClient;
use App\Egress\PinnedCurlTransport;
use App\Models\AcmeAccount;
use App\Models\Domain;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\Acme\AcmeAccountKey;
use App\Tls\Acme\AcmeChallenges;
use App\Tls\AcmeCertificateSource;
use App\Tls\CertificateSourceKind;
use App\Tls\CertificateStore;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * 🛑 §19's exit criterion: "An internal ACME directory issues for an
 * air-gapped name."
 *
 * Against a **real certificate authority** — Pebble, from `compose.tls.yaml`
 * — because the claim is about a protocol exchange and a stub would only
 * assert what we believe RFC 8555 says. Pebble is stricter than Let's
 * Encrypt on purpose: it rejects 5% of nonces at random, which is how a
 * client with no `badNonce` retry is caught before an operator is.
 *
 * 🛑 **Pebble's validation is real, not stubbed.** `deploy/pebble-config.json`
 * moves the HTTP-01 port to 80, Docker's embedded DNS resolves
 * `docup-acme.test` to the app container, and Pebble fetches the challenge
 * from DocUp's own route. So this test also proves §8.10.18's ordering end
 * to end: a challenge route registered after the documentation catch-all
 * would be answered by §8.9.3's hard 404 and the validation would fail.
 *
 * 🛑 And it proves the §8.3.9 carve-out this phase added. Pebble is on a
 * private address; `HardenedEgressClient` refuses those. The directory is
 * reachable only because `pebble` is declared an internal destination
 * (§8.10.14), which is the whole mechanism, exercised rather than described.
 */
final class AcmeIssuanceTest extends TestCase
{
    use DatabaseTransactions;

    /** The hostname `compose.tls.yaml` aliases to the app container. */
    private const string HOST = 'docup-acme.test';

    private OrganisationContext $context;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        $directory = (string) config('tls.acme.directory');

        if ($directory === '') {
            $this->markTestSkipped('no ACME directory configured; run with compose.tls.yaml (DOCUP_E2E=1 makes this a failure)');
        }

        /*
         * 🛑 The shared cache, not the suite's `array` driver.
         *
         * `AcmeChallenges` publishes a key authorization that a **different
         * process** must serve: the CA fetches
         * `/.well-known/acme-challenge/<token>` over HTTP, which lands in an
         * FPM worker, not in this one. With the array driver the value lives
         * only in the test process's memory, the worker answers 404, and the
         * validation fails with nothing wrong in the client.
         *
         * That cross-process hand-off is not an artefact of testing — it is
         * exactly how it works in production, where the queued job that
         * orders a certificate is never the process that answers the
         * challenge. So the test uses the store production uses.
         */
        config(['cache.default' => 'redis']);

        Cache::flush();

        /*
         * 🛑 The internal-destination declaration, set here rather than read
         * from `deploy/internal-destinations.conf`.
         *
         * The shipped file must stay empty — `EgressConfigurationTest`
         * asserts it — so a test environment that edited it would make the
         * shipped default wrong in order to test something else. Everything
         * below the config value is the real path: the real parse, the real
         * `AddressGuard`, the real client.
         */
        $host = parse_url($directory, PHP_URL_HOST);
        config(['egress.internal_destinations' => [is_string($host) ? $host : 'pebble']]);

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
        /*
         * 🛑 `isset`, because `setUp()` skips before assigning when the
         * overlay is absent — and PHPUnit still runs `tearDown()` after a
         * skip. Without the guard, every skipped test in this file reports
         * "must not be accessed before initialization" instead, which turns
         * a correct skip in the ordinary suite into six failures that look
         * like the feature is broken.
         */
        if (isset($this->context)) {
            $this->context->forget();
        }

        parent::tearDown();
    }

    /**
     * 🛑 Register, order, satisfy an http-01 challenge, finalise, and serve
     * the result from the database.
     *
     * One test rather than five, because the steps are not independently
     * meaningful: an account that registers but cannot order is not half a
     * working client, and splitting them would mean five tests each paying
     * for a CA round trip.
     */
    public function test_an_internal_directory_issues_for_an_air_gapped_name(): void
    {
        $account = $this->account();
        $source = $this->source($account);

        $registered = $source->register();

        $this->assertTrue($registered->isRegistered(), 'the account must carry the CA-issued kid');
        $this->assertNotNull($registered->account_url);
        $this->assertStringStartsWith('https://', (string) $registered->account_url);

        /*
         * 🛑 The account key is sealed, and the row never carries it in the
         * clear. §8.10.15, asserted on the row the CA exchange just wrote
         * rather than on one the test constructed.
         */
        $this->assertStringNotContainsString(
            'PRIVATE KEY',
            json_encode($registered->fresh()?->toArray() ?? [], JSON_THROW_ON_ERROR),
        );

        $certificate = $this->source($registered)->issue(self::HOST);

        $this->assertTrue($certificate->covers(self::HOST));
        $this->assertTrue($certificate->notAfter->isFuture());
        $this->assertStringContainsString('Pebble', $certificate->issuer, 'the issuer is read from the leaf, not from us');

        /*
         * 🛑 More than one PEM block: a leaf alone is a chain a client
         * cannot build a path from, and "it worked in curl" is how that
         * ships — curl has the intermediate cached from another connection.
         */
        $this->assertGreaterThan(
            1,
            substr_count($certificate->chainPem, '-----BEGIN CERTIFICATE-----'),
            'the chain must carry its intermediates',
        );

        $stored = (new CertificateStore(app(EnvelopeCipher::class)))->store(
            self::HOST,
            $certificate,
            CertificateSourceKind::InternalAcme,
            $this->domain(self::HOST),
            $registered->id,
        );

        $this->assertSame(CertificateSourceKind::InternalAcme, $stored->source);
        $this->assertSame($certificate->fingerprint, $stored->fingerprint);
    }

    /**
     * 🛑 §8.10.14's "one contract" is not a figure of speech: the same class
     * drives a public and an internal directory, and only `kind` differs.
     *
     * Asserted because the alternative — two implementations of RFC 8555 —
     * is the thing that drifts, and the drift shows up as an air-gapped
     * installation whose issuance stops working after a change nobody
     * tested against it.
     */
    public function test_one_implementation_serves_both_directories(): void
    {
        $internal = $this->source($this->account('internal'));
        $public = $this->source($this->account('public', label: 'public-'.bin2hex(random_bytes(3))));

        $this->assertSame(CertificateSourceKind::InternalAcme, $internal->kind());
        $this->assertSame(CertificateSourceKind::PublicAcme, $public->kind());
        $this->assertSame($internal::class, $public::class);
    }

    private function account(string $kind = 'internal', ?string $label = null): AcmeAccount
    {
        $keys = new AcmeAccountKey(app(EnvelopeCipher::class));
        $id = Uuid::v7();
        [, $sealed] = $keys->create($id);

        $account = new AcmeAccount;

        $account->forceFill([
            'id' => $id,
            'label' => $label ?? 'test-'.bin2hex(random_bytes(4)),
            'kind' => $kind,
            'directory_url' => (string) config('tls.acme.directory'),
            'contact' => 'tls@docup.test',
            'envelope_version' => $sealed->version,
            'kek_fingerprint' => $sealed->kekFingerprint,
            'wrapped_key' => $sealed->wrappedKey,
            'ciphertext' => $sealed->ciphertext,
            'state' => 'pending',
        ])->save();

        return $account;
    }

    /**
     * A source over a client built from the **real** options, with the
     * internal destination the setUp declared.
     */
    private function source(AcmeAccount $account): AcmeCertificateSource
    {
        $client = new HardenedEgressClient(
            app(AddressGuard::class),
            new PinnedCurlTransport,
            EgressOptions::fromConfig(),
        );

        return new AcmeCertificateSource(
            $account,
            new AcmeAccountKey(app(EnvelopeCipher::class)),
            $client,
            app(AcmeChallenges::class),
        );
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
}
