<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Credentials\EnvelopeCipher;
use App\Domains\AgreeingResolvers;
use App\Models\Certificate;
use App\Models\Domain;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\Acme\AcmeChallenges;
use App\Tls\CertificateSourceKind;
use App\Tls\CertificateStore;
use App\Tls\Csr;
use App\Tls\IssuanceBreaker;
use App\Tls\IssuanceBudgets;
use App\Tls\IssuancePermission;
use App\Tls\IssuedCertificate;
use App\Tls\PermittedHosts;
use Illuminate\Cache\RateLimiter;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\FakeDnsRecords;
use Tests\TestCase;

/**
 * §20.2's three edge endpoints, as HTTP.
 *
 * 🛑 Two of them are "internal, session-free edge endpoints" and one of
 * them hands out **private keys**, so the first thing asserted is that
 * nothing off loopback can reach them. The third is public by protocol —
 * a certificate authority fetches it with no credentials — and the test
 * says why that is safe rather than leaving it to look like an oversight.
 */
final class EdgeEndpointsTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private const string INGRESS = '203.0.113.10';

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

        config(['domains.ingress_addresses' => [self::INGRESS]]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 Off loopback, the two internal endpoints do not exist.
     *
     * 404 rather than 403, because a 403 confirms that the caller found
     * the certificate store. There is nothing to gain from telling them.
     */
    public function test_the_internal_endpoints_are_unreachable_from_anywhere_else(): void
    {
        foreach (['/_/edge/tls-permission?domain=x.example', '/_/edge/certificate?server_name=x.example'] as $path) {
            $response = $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])->get($path);

            $response->assertStatus(404);
            $this->assertSame('', $response->getContent());
        }
    }

    /**
     * 🛑 And a forwarded header does not let anybody claim to be the proxy.
     *
     * §8.9.4 forbids a trusted project-resolution request header "in any
     * environment", and the argument is stronger here: believing
     * `X-Forwarded-For` would let whoever can reach the application ask for
     * a private key.
     */
    public function test_a_forwarded_header_does_not_make_a_caller_local(): void
    {
        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])
            ->withHeaders(['X-Forwarded-For' => '127.0.0.1'])
            ->get('/_/edge/certificate?server_name=x.example');

        $response->assertStatus(404);
    }

    /** The permission endpoint answers 200 or 403 and never a body. */
    public function test_the_permission_endpoint_answers_with_a_status_and_nothing_else(): void
    {
        $host = 'docs.'.$this->uniqueApex();
        $this->provenDomain($host);
        $this->bindPermission([$host => [self::INGRESS]]);

        $granted = $this->fromLoopback('/_/edge/tls-permission?domain='.$host);

        $granted->assertStatus(200);
        $this->assertSame('', $granted->getContent(), 'the reason never crosses this boundary');
        $this->assertStringContainsString('no-store', (string) $granted->headers->get('Cache-Control'));

        $denied = $this->fromLoopback('/_/edge/tls-permission?domain=nobody.example.test');

        $denied->assertStatus(403);
        $this->assertSame('', $denied->getContent());
    }

    /** A missing `domain` parameter fails closed. */
    public function test_the_permission_endpoint_fails_closed_without_a_domain(): void
    {
        $this->bindPermission([]);

        $this->fromLoopback('/_/edge/tls-permission')->assertStatus(403);
    }

    /**
     * 🛑 §8.10.14: the certificate endpoint serves a stored chain and key.
     *
     * This is §19's "an uploaded PEM certificate serves from the database"
     * at the boundary Caddy actually calls, with the query parameter Caddy
     * actually sends.
     */
    public function test_the_certificate_endpoint_serves_a_stored_pem(): void
    {
        $host = 'byo.'.$this->uniqueApex();
        $this->storeCertificate($host, days: 30);

        $response = $this->fromLoopback('/_/edge/certificate?server_name='.$host);

        $response->assertStatus(200);
        $response->assertHeader('Content-Type', 'application/x-pem-file');
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $body = (string) $response->getContent();

        $this->assertStringContainsString('-----BEGIN CERTIFICATE-----', $body);
        $this->assertStringContainsString('PRIVATE KEY-----', $body);
    }

    /**
     * 🛑 A hostname DocUp holds nothing for answers **204, not 404**, and
     * the difference is the whole of §18.17.
     *
     * Measured against a running Caddy (`EdgeHandshakeTest`): a 404 makes
     * the proxy log `external certificate manager … got HTTP 404` and
     * **fail the handshake** with no ACME attempt; a 204 makes it fall
     * through to on-demand issuance. §8.10.11's design has the proxy obtain
     * most custom domains' certificates itself, so "no row" is the common
     * case — and on 404 the common case would have been broken while this
     * endpoint looked correct.
     */
    public function test_an_unknown_name_is_absent_rather_than_an_error(): void
    {
        $response = $this->fromLoopback('/_/edge/certificate?server_name=unknown.example.test');

        $response->assertStatus(204);
        $this->assertSame('', $response->getContent());
    }

    /**
     * 🛑 An expired certificate is withheld, which makes the proxy fall
     * back to issuance.
     *
     * The prober runs every six hours; a certificate that expired between
     * two runs would otherwise be handed over and served, and every reader
     * would see an expiry warning while the installation believed it was
     * healthy.
     */
    public function test_an_expired_certificate_is_withheld(): void
    {
        $host = 'lapsed.'.$this->uniqueApex();
        $stored = $this->storeCertificate($host, days: 30);

        $stored->forceFill(['not_after' => Carbon::now()->subDay()])->save();

        $this->fromLoopback('/_/edge/certificate?server_name='.$host)->assertStatus(204);
    }

    /** An SNI value that is not a hostname cannot reach a query. */
    public function test_a_malformed_server_name_is_absent(): void
    {
        foreach (['', '..', 'a_b.example.test'] as $sni) {
            $this->fromLoopback('/_/edge/certificate?server_name='.urlencode($sni))->assertStatus(204);
        }
    }

    /**
     * RFC 8555 §8.3's challenge response, at §8.10.18's path.
     *
     * 🛑 Deliberately public: the CA fetches it with no credentials. The
     * value is `token.thumbprint` of a **public** key, and the CA checks
     * that the account presenting the order owns that thumbprint — so
     * serving it to the whole internet proves nothing to anybody who is not
     * already the account holder.
     */
    public function test_a_published_challenge_is_served_to_anybody(): void
    {
        $challenges = app(AcmeChallenges::class);
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        $challenges->publish($token, $token.'.thumbprint');

        $response = $this
            ->withServerVariables(['REMOTE_ADDR' => '198.51.100.9'])
            ->get('/.well-known/acme-challenge/'.$token);

        $response->assertStatus(200);
        $this->assertSame($token.'.thumbprint', $response->getContent());
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        $challenges->withdraw($token);

        $this->get('/.well-known/acme-challenge/'.$token)->assertStatus(404);
    }

    /**
     * 🛑 An unpublished token gets an empty 404, never a plausible body.
     *
     * A CA treats any unexpected body as a failed validation, and a failed
     * validation costs authorization-failure budget — five an hour per
     * identifier — so an endpoint that guessed would spend a budget it
     * cannot see.
     */
    public function test_an_unpublished_token_is_an_empty_404(): void
    {
        $response = $this->get('/.well-known/acme-challenge/'.str_repeat('z', 43));

        $response->assertStatus(404);
        $this->assertSame('', $response->getContent());
    }

    /** @return TestResponse<Response> */
    private function fromLoopback(string $path): TestResponse
    {
        return $this->withServerVariables(['REMOTE_ADDR' => '127.0.0.1'])->get($path);
    }

    /** @param  array<string, list<string>>  $addresses */
    private function bindPermission(array $addresses): void
    {
        $resolvers = [];

        foreach (['alpha', 'beta'] as $label) {
            $resolver = new FakeDnsRecords($label);

            foreach ($addresses as $name => $answer) {
                $resolver->withAddresses($name, $answer);
            }

            $resolvers[] = $resolver;
        }

        $this->app->instance(IssuancePermission::class, new IssuancePermission(
            new PermittedHosts,
            new IssuanceBudgets,
            new IssuanceBreaker,
            new AgreeingResolvers($resolvers),
            app(RateLimiter::class),
        ));
    }

    private function provenDomain(string $host): Domain
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

        PermittedHosts::invalidate();

        return $domain;
    }

    private function storeCertificate(string $host, int $days): Certificate
    {
        [$chain, $key] = Csr::selfSigned($host, Csr::key(), $days);

        return (new CertificateStore(app(EnvelopeCipher::class)))->store(
            $host,
            IssuedCertificate::fromPem($chain, $key),
            CertificateSourceKind::Uploaded,
        );
    }

    private function uniqueApex(): string
    {
        return 'tenant-'.bin2hex(random_bytes(4)).'.example';
    }
}
