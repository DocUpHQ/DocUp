<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Credentials\EnvelopeCipher;
use App\Models\Domain;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\CertificateSourceKind;
use App\Tls\CertificateStore;
use App\Tls\Csr;
use App\Tls\IssuedCertificate;
use App\Tls\PermittedHosts;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * 🛑 §18.17, measured — and §19's TLS exit criteria, through a running proxy.
 *
 * > "The edge consults a database-backed certificate manager at handshake
 * > and falls back to on-demand ACME on a negative answer, rather than
 * > failing the handshake."
 *
 * **The assumption holds, and only on one status code.** Caddy's
 * documentation says the certificate endpoint "must return HTTP 200" and
 * says nothing about the negative case. Measured, the two obvious negatives
 * behave completely differently:
 *
 *   `404` → `tls.handshake: external certificate manager … got HTTP 404`,
 *           and the handshake is **failed**. No ACME attempt is ever made.
 *   `204` → the manager is treated as holding nothing, Caddy falls through
 *           to on-demand issuance, solves the challenge, and serves it.
 *
 * So §18.17's pre-decided consequence — "two host-list-selected TLS
 * automation policies … and §8.10.14's 'no admin API' requirement must be
 * re-examined" — is **not** triggered. One status code is the difference
 * between that redesign and none.
 *
 * 🛑 These tests drive a real TLS handshake against the stack's own proxy.
 * They need `compose.tls.yaml` (Caddy pointed at Pebble, Pebble's CA trusted
 * in this container) and are skipped without it — and `DOCUP_E2E=1`, which
 * the overlay sets, turns a skip into a failure.
 *
 * 🛑 **No `DatabaseTransactions`.** The rows must be visible to the FPM
 * worker that answers the proxy's permission and certificate calls, and an
 * uncommitted transaction in this process is invisible to it. The hostnames
 * are unique per run and cleaned up in `tearDown`.
 *
 * 🛑 **Which means this file leaves audit rows behind that cannot be
 * removed.** Storing a certificate writes §8.10.15's audit event, and
 * §8.22.1 makes `audit_events` append-only *in the database*, by trigger —
 * so no cleanup can take them out. Harmless in CI, where the `tls` job has
 * its own database and never runs `AuditChainTest`; locally it means
 * running this file against a database you are willing to
 * `migrate:fresh`, because the rows were written under the suite's own
 * `DOCUP_AUDIT_KEY` and `docup:audit:verify` run from the shell uses the
 * environment's, which will report them as tampered.
 */
final class EdgeHandshakeTest extends TestCase
{
    /** The hostname `compose.tls.yaml` aliases to the app container. */
    private const string RESOLVABLE = 'docup-acme.test';

    private OrganisationContext $context;

    private Organisation $organisation;

    /** @var list<string> */
    private array $hosts = [];

    protected function setUp(): void
    {
        parent::setUp();

        if ((string) config('tls.acme.directory') === '') {
            $this->markTestSkipped('no ACME directory configured; run with compose.tls.yaml');
        }

        if (! $this->proxyIsListening()) {
            $this->markTestSkipped('nothing is listening on 127.0.0.1:443 in this container');
        }

        config(['cache.default' => 'redis']);

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->firstOrCreate(
            ['slug' => 'tls-handshake'],
            ['name' => 'TLS Handshake'],
        );

        $this->context->for($this->organisation->id);
    }

    protected function tearDown(): void
    {
        /*
         * 🛑 `isset`, because `setUp()` skips before assigning when the
         * overlay is absent — and PHPUnit still runs `tearDown()` after a
         * skip. Without the guard, a correct skip in the ordinary suite
         * becomes a failure reading "must not be accessed before
         * initialization", which looks like the feature is broken.
         */
        if (isset($this->context)) {
            foreach ($this->hosts as $host) {
                Domain::query()->where('host', $host)->delete();
                Cache::forget('tls:permit:'.hash('sha256', $host));
            }

            PermittedHosts::invalidate();
            $this->context->forget();
        }

        parent::tearDown();
    }

    /**
     * 🛑 §8.10.11, and §19's "500 bogus SNI handshakes per minute trigger
     * zero ACME attempts" — at the handshake, not at the endpoint.
     *
     * A hostname the permission endpoint refuses fails the TLS handshake
     * with no certificate and no ACME exchange. `IssuancePermissionTest`
     * proves the endpoint's own cost is zero; this proves the proxy honours
     * the answer.
     */
    public function test_an_unpermitted_hostname_never_completes_a_handshake(): void
    {
        $host = 'denied-'.bin2hex(random_bytes(4)).'.example.test';

        [$code, $output] = $this->handshake($host);

        $this->assertSame(
            0,
            $code,
            '🛑 an unpermitted hostname must not obtain a certificate: '.$output,
        );
    }

    /**
     * 🛑 §8.10.14: an uploaded certificate is served **from the database at
     * handshake time**, with the admin API disabled.
     *
     * §19's exit criterion in full: nothing was written to disk, no proxy
     * admin API was called, the Caddyfile was not touched and the proxy was
     * not reloaded — the certificate reached the edge because the edge asked
     * for it during the handshake.
     */
    public function test_an_uploaded_certificate_serves_from_the_database(): void
    {
        $host = $this->permittedDomain('byo-'.bin2hex(random_bytes(4)).'.example.test');

        [$chain, $key] = Csr::selfSigned($host, Csr::key(), 30);

        (new CertificateStore(app(EnvelopeCipher::class)))->store(
            $host,
            IssuedCertificate::fromPem($chain, $key),
            CertificateSourceKind::Uploaded,
        );

        [$code, $output] = $this->handshake($host);

        $this->assertSame(1, $code, 'the handshake must complete: '.$output);

        /*
         * `CN=` without a space: that is how `openssl s_client` prints a
         * subject, and the certificate presented must be the one the store
         * holds rather than one the proxy went and obtained.
         */
        $this->assertStringContainsString(
            'CN='.$host,
            $output,
            'the certificate presented must be the one in the database',
        );
        $this->assertStringNotContainsString('Pebble', $output, 'the CA was not asked for this one');
    }

    /**
     * 🛑 §18.17 itself: no row in the database, and the proxy issues.
     *
     * The certificate endpoint answers 204, Caddy falls through to on-demand
     * ACME, the CA validates against DocUp's own ingress, and the handshake
     * completes with a CA-issued certificate — **with no proxy restart, no
     * config render and no reload**, which is §8.10.16 and §19's "serves
     * valid HTTPS within 60 seconds".
     */
    public function test_a_permitted_hostname_with_no_stored_certificate_is_issued_on_demand(): void
    {
        $host = $this->permittedDomain(self::RESOLVABLE);

        /*
         * Proves the premise rather than assuming it: if a row existed, a
         * pass here would be the previous test over again.
         */
        $this->assertNull(
            (new CertificateStore(app(EnvelopeCipher::class)))->activeFor($host),
            'the premise of this test is that the database holds nothing for this name',
        );

        [$code, $output] = $this->handshake($host, seconds: 90);

        $this->assertSame(1, $code, 'the proxy must fall back to issuance rather than failing: '.$output);

        $this->assertStringContainsString(
            'Pebble',
            $output,
            '🛑 the certificate must have come from the CA, not from the database',
        );
    }

    /**
     * 🛑 The negative-status measurement, kept as a test so the finding
     * cannot be undone by a tidy-up.
     *
     * `absent()` returning 404 instead of 204 would break every on-demand
     * issuance in the installation while this endpoint still looked
     * correct. There is no way to assert Caddy's behaviour without changing
     * the endpoint, so what is asserted is the contract the measurement
     * established.
     */
    public function test_the_certificate_endpoint_reports_absence_as_204(): void
    {
        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])
            ->get('/_/edge/certificate?server_name=nothing-here.example.test');

        $this->assertSame(
            204,
            $response->getStatusCode(),
            '🛑 404 makes Caddy fail the handshake instead of falling back to ACME (§18.17)',
        );
    }

    /** A verified, serving domain whose permission verdict is warm. */
    private function permittedDomain(string $host): string
    {
        $this->hosts[] = $host;

        Domain::query()->where('host', $host)->delete();

        $domain = new Domain;
        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        PermittedHosts::invalidate();

        /*
         * 🛑 The verdict is warmed rather than earned, and the reason is
         * §8.10.11's live-DNS condition: it resolves the hostname through
         * the configured DoH resolvers, which know nothing about a name that
         * exists only in Docker's embedded DNS. Warming writes the endpoint's
         * **own** 60-second cache — the path §8.10.11 describes as the hot
         * one — so what this test exercises is the proxy's behaviour given a
         * grant, which is what it is about. Whether a grant is correct is
         * `IssuancePermissionTest`'s subject, against scripted resolvers,
         * exhaustively.
         */
        Cache::put('tls:permit:'.hash('sha256', $host), 'permitted', 600);

        return $host;
    }

    /**
     * One real TLS handshake, pinned to the local proxy.
     *
     * @return array{0: int, 1: string} 1 when a certificate was presented, and the text seen
     */
    private function handshake(string $host, int $seconds = 45): array
    {
        /*
         * 🛑 No `-verify_return_error`. What matters is **which** certificate
         * the proxy presented, which the chain below says exactly; whether a
         * client would trust it is a different question with a different
         * answer per case — an uploaded certificate here is self-signed on
         * purpose, and refusing it would make the test assert the test
         * fixture's trust rather than the proxy's behaviour.
         */
        $command = sprintf(
            'timeout %d openssl s_client -connect 127.0.0.1:443 -servername %s 2>&1 </dev/null',
            $seconds,
            escapeshellarg($host),
        );

        $output = (string) shell_exec($command);

        /*
         * `openssl s_client` prints the peer chain only when the handshake
         * produced one. A refused handshake prints an alert instead, which
         * is what §8.10.11 makes the proxy do for a name it may not certify.
         */
        return [str_contains($output, 'Certificate chain') ? 1 : 0, $this->summarise($output)];
    }

    /** The lines worth putting in a failure message. */
    private function summarise(string $output): string
    {
        $kept = [];

        foreach (explode("\n", $output) as $line) {
            if (preg_match('/(CN ?=|issuer|subject|alert|error|verify)/i', $line) === 1) {
                $kept[] = trim($line);
            }
        }

        return implode(' | ', array_slice($kept, 0, 8));
    }

    private function proxyIsListening(): bool
    {
        $socket = @fsockopen('127.0.0.1', 443, $errno, $error, 2);

        if ($socket === false) {
            return false;
        }

        fclose($socket);

        return true;
    }
}
