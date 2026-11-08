<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Oidc;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Oidc\AuthorisationRequest;
use App\Auth\Providers\Oidc\OidcExchange;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Auth\Providers\Oidc\OidcRejection;
use App\Auth\Providers\Oidc\ProviderMetadata;
use App\Models\Domain;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's two stateful requirements: single-use `nonce`, and PKCE that
 * cannot be omitted.
 *
 * `IdTokenVerifierTest` covers the five refusals that are properties of a
 * token. These two are properties of the stored exchange — single use needs a
 * row to latch, and "mandatory" needs a builder with no way to opt out — so
 * they are asserted here, against the real table.
 */
final class OidcExchangeTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private Domain $domain;

    private string $bindingId;

    private const string CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Exchange Co',
            'slug' => 'exch-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'exch-'.bin2hex(random_bytes(3)),
            'name' => 'Guarded',
            'visibility' => 'members',
        ]);

        /*
         * `domains` carries no project: a project reaches a host through
         * `domain_mounts` (§8.7), which is what lets one host serve several
         * projects at different prefixes. The first version of this fixture
         * wrote a `project_id` column that does not exist.
         */
        $domainId = Uuid::toBytes(Uuid::v7());

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => 'docs-'.bin2hex(random_bytes(3)).'.example.test',
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $domain = $this->context->acrossAllOrganisations(
            static fn (): ?Domain => Domain::query()->whereKey($domainId)->first(),
        );

        $this->assertInstanceOf(Domain::class, $domain);

        $this->domain = $domain;

        $operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'exch-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $bindings = app(Bindings::class);

        $this->bindingId = $bindings->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: 'oidc',
            name: 'the realm',
            config: [
                'issuer' => 'https://idp.example.test/realms/acme',
                'client_id' => 'docup-client',
            ],
            organisationId: $this->organisation->id,
        );

        $bindings->transition($this->bindingId, BindingState::Verifying);
        $bindings->recordTestLogin($this->bindingId, $operator->id);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // -------------------------------------- §8.12.18's single-use `nonce`

    /**
     * 🛑 §17: "a reused `nonce` … rejected with distinct audit events".
     *
     * The latch is on the exchange rather than on the nonce itself, and that is
     * what makes it atomic: one `UPDATE` whose `WHERE` holds every condition,
     * so two concurrent callbacks presenting the same `state` cannot both
     * proceed. A `SELECT` then an `UPDATE` has the race whose outcome is
     * whether one authorisation code mints two sessions.
     */
    public function test_a_state_is_consumable_exactly_once(): void
    {
        $exchange = app(OidcExchange::class);

        $opened = $this->open($exchange);

        $first = $exchange->consume($opened['state']);

        $this->assertSame($this->bindingId, $first['binding_id']);
        $this->assertSame($this->domain->id, $first['domain_id']);

        try {
            $exchange->consume($opened['state']);
            $this->fail('a state was consumed twice');
        } catch (OidcRefused $refused) {
            $this->assertSame(
                OidcRejection::StateExpired,
                $refused->rejection,
                '🛑 §8.12.18: the nonce is single-use, by the exchange\'s latch',
            );
        }
    }

    /** 🛑 And the nonce is matched against a stored **hash**, never a plaintext. */
    public function test_the_nonce_is_compared_against_a_stored_digest(): void
    {
        $exchange = app(OidcExchange::class);

        $opened = $this->open($exchange);
        $consumed = $exchange->consume($opened['state']);

        $this->assertTrue($exchange->nonceMatches($consumed['nonce_hash'], $opened['nonce']));
        $this->assertFalse($exchange->nonceMatches($consumed['nonce_hash'], 'some other nonce'));

        /*
         * 🛑 §9.1.4: "security tokens are CSPRNG, stored hashed". So the
         * plaintext nonce must appear nowhere in the row — asserted directly,
         * because a column that held it would make the hash decorative.
         */
        $row = DB::table('oidc_authorisation_requests')->where('id', $consumed['id'])->first();

        $this->assertNotNull($row);

        foreach ((array) $row as $column => $value) {
            if (is_string($value)) {
                $this->assertStringNotContainsString(
                    $opened['nonce'],
                    $value,
                    '🛑 §9.1.4: the nonce is stored hashed, so `'.$column.'` must not hold it',
                );
                $this->assertStringNotContainsString(
                    $opened['state'],
                    $value,
                    '🛑 §9.1.4: and neither may the state',
                );
            }
        }
    }

    /** An unknown state is distinguished from a spent one. */
    public function test_an_unknown_state_is_its_own_refusal(): void
    {
        try {
            app(OidcExchange::class)->consume('docup_oidc_state_'.str_repeat('z', 40));
            $this->fail('an unknown state resolved');
        } catch (OidcRefused $refused) {
            $this->assertSame(OidcRejection::StateUnknown, $refused->rejection);
        }
    }

    /** An expired exchange is refused, and the row is not resurrected. */
    public function test_an_expired_exchange_is_refused(): void
    {
        $exchange = app(OidcExchange::class);
        $opened = $this->open($exchange);

        DB::table('oidc_authorisation_requests')->update([
            'expires_at' => now()->subMinute()->format('Y-m-d H:i:s.v'),
        ]);

        try {
            $exchange->consume($opened['state']);
            $this->fail('an expired exchange was consumed');
        } catch (OidcRefused $refused) {
            $this->assertSame(OidcRejection::StateExpired, $refused->rejection);
        }
    }

    /** The sweep removes spent rows and leaves live ones. */
    public function test_the_sweep_leaves_a_live_exchange_alone(): void
    {
        $exchange = app(OidcExchange::class);
        $this->open($exchange);

        $this->assertSame(0, $exchange->sweep());
        $this->assertSame(1, DB::table('oidc_authorisation_requests')->count());

        DB::table('oidc_authorisation_requests')->update([
            'expires_at' => now()->subDays(2)->format('Y-m-d H:i:s.v'),
        ]);

        $this->assertSame(1, $exchange->sweep());
    }

    // ------------------------------------------ §8.12.18's mandatory PKCE

    /**
     * 🛑 §17: "Omitted PKCE … rejected".
     *
     * Asserted as a **structural** property rather than by passing a flag:
     * `AuthorisationRequest::url()` has no parameter that could omit PKCE, so
     * the test is that every URL it builds carries `code_challenge` and
     * `S256`, and that a verifier too weak to be one is refused.
     */
    public function test_every_authorisation_url_carries_s256_pkce(): void
    {
        $exchange = app(OidcExchange::class);
        $opened = $this->open($exchange);

        $url = AuthorisationRequest::url(
            metadata: $this->metadata(),
            clientId: 'docup-client',
            redirectUri: 'https://app.example.test/_/auth/oidc/callback',
            state: $opened['state'],
            nonce: $opened['nonce'],
            verifier: $opened['verifier'],
        );

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        $this->assertSame('S256', $query['code_challenge_method'] ?? null);
        $this->assertSame('code', $query['response_type'] ?? null, '🛑 §8.12.18: no implicit flow');
        $this->assertSame('query', $query['response_mode'] ?? null);

        /* 🛑 The challenge is RFC 7636 §4.2's S256 over the verifier. */
        $expected = rtrim(strtr(base64_encode(hash('sha256', $opened['verifier'], true)), '+/', '-_'), '=');

        $this->assertSame($expected, $query['code_challenge'] ?? null);

        /* And the verifier itself is never in the URL. */
        $this->assertStringNotContainsString($opened['verifier'], $url);

        /*
         * 🛑 `email` is not requested. §8.12.1: "email MUST NEVER be used for
         * linking or lookup", and a scope DocUp does not need is personal data
         * it should not hold.
         */
        $scope = $query['scope'] ?? '';

        /*
         * `parse_str` types a value as string-or-array, so the assertion is
         * made on a narrowed value rather than on a cast — and an array here
         * would be a repeated `scope` parameter, which is itself worth failing
         * on.
         */
        $this->assertIsString($scope);
        $this->assertStringNotContainsString('email', $scope);
    }

    /** 🛑 A verifier too short to be one is refused rather than used. */
    public function test_a_weak_pkce_verifier_is_refused(): void
    {
        foreach (['', 'short', str_repeat('a', 42), str_repeat('a', 129), 'has spaces in it '.str_repeat('a', 30)] as $verifier) {
            try {
                AuthorisationRequest::url(
                    metadata: $this->metadata(),
                    clientId: 'docup-client',
                    redirectUri: 'https://app.example.test/_/auth/oidc/callback',
                    state: 'state',
                    nonce: 'nonce',
                    verifier: $verifier,
                );
                $this->fail('a verifier of '.strlen($verifier).' characters was accepted');
            } catch (OidcRefused $refused) {
                $this->assertSame(OidcRejection::PkceMissing, $refused->rejection);
            }
        }
    }

    /**
     * 🛑 An endpoint's own query survives, and DocUp's parameters win.
     *
     * RFC 6749 §3.1 permits a query on the authorization endpoint. The case
     * that matters is the third one: a provider parameter must not be able to
     * shadow one DocUp sets.
     */
    public function test_the_endpoints_own_query_cannot_shadow_docups_parameters(): void
    {
        $exchange = app(OidcExchange::class);
        $opened = $this->open($exchange);

        $metadata = ProviderMetadata::fromDocument([
            'issuer' => 'https://idp.example.test/realms/acme',
            'authorization_endpoint' => 'https://idp.example.test/auth?kc_idp_hint=google&response_type=token',
            'token_endpoint' => 'https://idp.example.test/token',
            'jwks_uri' => 'https://idp.example.test/certs',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ], 'https://idp.example.test/realms/acme');

        $url = AuthorisationRequest::url(
            metadata: $metadata,
            clientId: 'docup-client',
            redirectUri: 'https://app.example.test/_/auth/oidc/callback',
            state: $opened['state'],
            nonce: $opened['nonce'],
            verifier: $opened['verifier'],
        );

        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        /* The provider's own harmless parameter is kept. */
        $this->assertSame('google', $query['kc_idp_hint'] ?? null);

        /* 🛑 And the one that would have changed the flow is overridden. */
        $this->assertSame(
            'code',
            $query['response_type'] ?? null,
            '🛑 §8.12.18: an endpoint query must not be able to select the implicit flow',
        );
    }

    // ---------------------------------------------------------- fixtures

    /** @return array{state: string, nonce: string, verifier: string} */
    private function open(OidcExchange $exchange): array
    {
        return $exchange->open(
            organisationId: (string) $this->organisation->id,
            bindingId: $this->bindingId,
            domainId: (string) $this->domain->id,
            projectId: (string) $this->project->id,
            handoffChallenge: self::CHALLENGE,
            returnPath: '/en/v1/',
        );
    }

    private function metadata(): ProviderMetadata
    {
        return ProviderMetadata::fromDocument([
            'issuer' => 'https://idp.example.test/realms/acme',
            'authorization_endpoint' => 'https://idp.example.test/realms/acme/protocol/openid-connect/auth',
            'token_endpoint' => 'https://idp.example.test/realms/acme/protocol/openid-connect/token',
            'jwks_uri' => 'https://idp.example.test/realms/acme/protocol/openid-connect/certs',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ], 'https://idp.example.test/realms/acme');
    }
}
