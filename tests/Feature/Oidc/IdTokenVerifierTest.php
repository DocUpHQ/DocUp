<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Oidc;

use App\Auth\Providers\Oidc\IdTokenVerifier;
use App\Auth\Providers\Oidc\JwksStore;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Auth\Providers\Oidc\OidcRejection;
use App\Auth\Providers\Oidc\ProviderMetadata;
use App\Egress\AddressGuard;
use App\Egress\EgressOptions;
use App\Egress\HardenedEgressClient;
use App\Egress\IpAddressClassifier;
use Illuminate\Support\Facades\Cache;
use Tests\Support\FakeDnsResolver;
use Tests\Support\FakeTransport;
use Tests\Support\OidcTokens;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's OIDC validation, one test per named refusal.
 *
 * > "Omitted PKCE, a reused `nonce`, a wrong `iss`, a wrong `aud`, `alg: none`,
 * > a missing `at_hash` and an unpinned `kid` are each rejected with **distinct
 * > audit events**." (§17, Phase 24)
 *
 * Five of the seven are properties of a token and live here. The other two —
 * omitted PKCE and a **reused** nonce — are properties of the stored exchange
 * and live in `OidcExchangeTest`, because single-use needs a row to latch.
 *
 * 🛑 **Every test asserts the specific rejection, never merely that it threw.**
 * The requirement is "distinct audit events", so a test that accepted any
 * refusal would pass against an implementation that collapsed all seven into
 * one — which is the exact failure the requirement forbids.
 *
 * 🛑 And every test starts from a token that **does** verify, changing one
 * thing. A hostile-token test that never shows the valid case passes equally
 * well against a verifier that refuses everything.
 */
final class IdTokenVerifierTest extends TestCase
{
    private const string ISSUER = 'https://idp.example.test/realms/acme';

    private const string CLIENT = 'docup-client';

    private const string NONCE = 'the-nonce-this-exchange-asked-for';

    private const string ACCESS = 'test-access-token';

    private const string JWKS_URI = 'https://idp.example.test/realms/acme/protocol/openid-connect/certs';

    private OidcTokens $provider;

    private string $bindingId;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->provider = new OidcTokens;
        $this->bindingId = random_bytes(16);
    }

    // ------------------------------------------------- the case that works

    /** A correct token verifies, and its claims come back. */
    public function test_a_correct_token_verifies(): void
    {
        $claims = $this->verify($this->token());

        $this->assertSame('reader-subject-1', $claims['sub']);
        $this->assertSame(self::ISSUER, $claims['iss']);
    }

    // --------------------------------------- §17's five token-borne refusals

    /** 🛑 `alg: none`, in both serialisations. */
    public function test_alg_none_is_refused(): void
    {
        foreach ([false, true] as $twoSegments) {
            $token = OidcTokens::unsignedToken([
                'iss' => self::ISSUER,
                'sub' => 'reader-subject-1',
                'aud' => self::CLIENT,
                'exp' => time() + 300,
                'iat' => time(),
                'nonce' => self::NONCE,
            ], $twoSegments);

            $this->assertRefusal(
                OidcRejection::AlgorithmNotAllowed,
                $token,
                '🛑 §8.12.18: an algorithm allowlist excluding `none` ('
                    .($twoSegments ? 'two segments' : 'empty signature').')',
            );
        }
    }

    /**
     * 🛑 And `alg: HS256`, which is the one an attacker reaches for.
     *
     * The published RSA key becomes the HMAC secret, so anybody who can read
     * the JWKS can mint. Refused on the algorithm, before any key is fetched.
     */
    public function test_a_symmetric_algorithm_is_refused(): void
    {
        $header = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'HS256', 'kid' => $this->provider->kid])), '+/', '-_'), '=');
        $payload = rtrim(strtr(base64_encode((string) json_encode(['iss' => self::ISSUER, 'sub' => 'x'])), '+/', '-_'), '=');

        $this->assertRefusal(
            OidcRejection::AlgorithmNotAllowed,
            $header.'.'.$payload.'.c2lnbmF0dXJl',
            '🛑 §8.12.18: no HS* — the verification key would be the client secret',
        );
    }

    /** 🛑 A wrong `iss`, including the suffix form RFC 9700 §4.4 names. */
    public function test_a_wrong_issuer_is_refused(): void
    {
        foreach ([
            'https://evil.example.test/realms/acme',
            /* 🛑 The one a `str_contains` or `str_ends_with` check would admit. */
            self::ISSUER.'.attacker.test',
            'https://idp.example.test/realms/other',
            /* A trailing slash is a different string, and exact means exact. */
            self::ISSUER.'/',
        ] as $issuer) {
            $this->assertRefusal(
                OidcRejection::IssuerMismatch,
                $this->token(['iss' => $issuer]),
                '🛑 §8.12.18: exact `iss`, not a prefix or suffix match ('.$issuer.')',
            );
        }
    }

    /** 🛑 A wrong `aud`, absent `aud`, and the several-audiences case. */
    public function test_a_wrong_audience_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::AudienceMismatch,
            $this->token(['aud' => 'another-client']),
            '🛑 §8.12.18: exact `aud`',
        );

        $this->assertRefusal(
            OidcRejection::AudienceMismatch,
            $this->token(['aud' => null]),
            'a token with no `aud` is for nobody',
        );

        /*
         * 🛑 Several audiences including ours, and no `azp`. OIDC Core
         * §3.1.3.7 step 4 requires `azp` then — without it, a token minted for
         * another client at the same provider is replayable here.
         */
        $this->assertRefusal(
            OidcRejection::AudienceMismatch,
            $this->token(['aud' => [self::CLIENT, 'another-client']]),
            '🛑 several audiences and no `azp`',
        );

        /* And `azp` naming somebody else. */
        $this->assertRefusal(
            OidcRejection::AudienceMismatch,
            $this->token(['aud' => [self::CLIENT, 'another-client'], 'azp' => 'another-client']),
            '🛑 `azp` must be this client',
        );

        /* Several audiences with a correct `azp` is legitimate. */
        $claims = $this->verify($this->token([
            'aud' => [self::CLIENT, 'another-client'],
            'azp' => self::CLIENT,
        ]));

        $this->assertSame('reader-subject-1', $claims['sub']);
    }

    /** 🛑 A missing or wrong `at_hash`, which §8.12.18 makes mandatory. */
    public function test_a_missing_at_hash_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::AtHashInvalid,
            $this->provider->idToken(self::ISSUER, self::CLIENT, self::NONCE, accessToken: null),
            '🛑 §8.12.18 requires `at_hash` even for the code flow',
        );

        $this->assertRefusal(
            OidcRejection::AtHashInvalid,
            $this->token(['at_hash' => OidcTokens::atHash('a different access token', 'RS256')]),
            '🛑 the `at_hash` must bind THIS access token',
        );
    }

    /** 🛑 An unpinned `kid`, and a missing one. */
    public function test_an_unpinned_kid_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::KeyNotPinned,
            $this->token(headers: ['kid' => 'a-key-the-provider-does-not-publish']),
            '🛑 §8.12.18: JWKS pinned by `kid`',
        );

        /*
         * 🛑 A token naming no key at all. Trying every published key would
         * give an attacker as many signature attempts as the provider has
         * keys, so "no `kid`" is "not pinnable" rather than "try them all".
         */
        $unkeyed = new OidcTokens(kid: '');

        $this->assertRefusal(
            OidcRejection::KeyNotPinned,
            $unkeyed->idToken(self::ISSUER, self::CLIENT, self::NONCE),
            '🛑 a token with no `kid` cannot be pinned',
        );
    }

    // ------------------------------------------------- the rest of §8.12.18

    /** A nonce from another exchange. */
    public function test_a_nonce_from_another_exchange_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::NonceMismatch,
            $this->token(['nonce' => 'a-nonce-from-some-other-login']),
            'the token must answer THIS request',
        );

        $this->assertRefusal(
            OidcRejection::NonceMismatch,
            $this->token(['nonce' => null]),
            'a token with no `nonce` answers no request',
        );
    }

    /** A forged signature under a published `kid`. */
    public function test_a_forged_signature_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::SignatureInvalid,
            $this->provider->forged([
                'iss' => self::ISSUER,
                'sub' => 'reader-subject-1',
                'aud' => self::CLIENT,
                'exp' => time() + 300,
                'iat' => time(),
                'nonce' => self::NONCE,
                'at_hash' => OidcTokens::atHash(self::ACCESS, 'RS256'),
            ]),
            'the signature is checked against the pinned key, not merely parsed',
        );
    }

    /** Expiry, and an absent `exp`, which the library alone would allow. */
    public function test_expiry_is_enforced_including_an_absent_claim(): void
    {
        $this->assertRefusal(
            OidcRejection::TokenExpired,
            $this->token(['exp' => time() - 3600, 'iat' => time() - 3700]),
            'an expired token is refused',
        );

        /*
         * 🛑 The case the library's own check misses: `JWT::$leeway` applies to
         * a claim that is *past*, and a token with no `exp` decodes cleanly. So
         * the absence is checked separately.
         */
        $this->assertRefusal(
            OidcRejection::TokenExpired,
            $this->token(['exp' => null]),
            '🛑 OIDC Core makes `exp` REQUIRED; absent is not valid-forever',
        );

        $this->assertRefusal(
            OidcRejection::TokenExpired,
            $this->token(['iat' => null]),
            '🛑 and `iat` likewise',
        );
    }

    /** A token with no `sub` identifies nobody, and email is never a fallback. */
    public function test_a_token_with_no_subject_is_refused(): void
    {
        $this->assertRefusal(
            OidcRejection::SubjectMissing,
            $this->token(['sub' => null, 'email' => 'somebody@example.test']),
            '🛑 §8.12.1: email MUST NEVER be used for linking or lookup',
        );
    }

    // ------------------------------------------- the key set's own defences

    /**
     * 🛑 A symmetric key in a published key set is dropped, not used.
     *
     * The key is public by definition, so verifying with it means anybody who
     * can read the JWKS can mint. Presents as `KeyNotPinned`, which is honest:
     * DocUp holds no key it is willing to verify that token with.
     */
    public function test_a_published_symmetric_key_is_not_usable(): void
    {
        $store = $this->storeServing($this->provider->symmetricJwks());

        $verifier = new IdTokenVerifier($store);

        try {
            $verifier->claimsFor(
                $this->token(),
                $this->bindingId,
                $this->metadata(),
                self::CLIENT,
                self::NONCE,
                self::ACCESS,
            );
            $this->fail('a symmetric key from a published key set was used');
        } catch (OidcRefused $refused) {
            $this->assertSame(OidcRejection::JwksFailed, $refused->rejection);
        }
    }

    /**
     * 🛑 A key published without `alg` still works, and its algorithm comes
     * from `kty` rather than from the token.
     *
     * RFC 7517 §4.4 makes `alg` OPTIONAL and some providers omit it. The naive
     * fix is to pass the token's own `alg` as the default, which makes the
     * library's key/header check a tautology and opens the confusion family.
     */
    public function test_a_key_without_alg_is_usable_and_the_token_does_not_choose(): void
    {
        $store = $this->storeServing($this->provider->jwks(withAlg: false));

        $claims = (new IdTokenVerifier($store))->claimsFor(
            $this->token(),
            $this->bindingId,
            $this->metadata(),
            self::CLIENT,
            self::NONCE,
            self::ACCESS,
        );

        $this->assertSame('reader-subject-1', $claims['sub']);
    }

    /**
     * 🛑 §8.12.18's **bounded refresh floor**: an unknown `kid` does not buy
     * an outbound request.
     *
     * Without the floor, anybody who can reach a documentation host mints
     * tokens with random `kid`s and costs DocUp one HTTPS request each — a
     * denial of service against the provider's rate limit and against §8.3.9's
     * egress budget. Asserted by counting fetches.
     */
    public function test_an_unknown_kid_does_not_buy_an_unbounded_refresh(): void
    {
        $transport = null;

        $store = $this->storeServing($this->provider->jwks(), $transport);
        $verifier = new IdTokenVerifier($store);

        for ($attempt = 0; $attempt < 5; $attempt++) {
            try {
                $verifier->claimsFor(
                    $this->token(headers: ['kid' => 'unknown-'.$attempt]),
                    $this->bindingId,
                    $this->metadata(),
                    self::CLIENT,
                    self::NONCE,
                    self::ACCESS,
                );
                $this->fail('an unknown kid verified');
            } catch (OidcRefused $refused) {
                $this->assertSame(OidcRejection::KeyNotPinned, $refused->rejection);
            }
        }

        /*
         * 🛑 Two: the first populates the cache, the second is the one refresh
         * the floor allows. Five attempts, two requests — and the next hundred
         * attempts inside the window would add none.
         */
        $this->assertSame(
            2,
            $transport->callsFor(self::JWKS_URI),
            '🛑 §8.12.18: the refresh floor bounds what an unknown `kid` costs',
        );
    }

    // ---------------------------------------------------------- fixtures

    /**
     * @param  array<string, mixed>  $overrides
     * @param  array<string, mixed>  $headers
     */
    private function token(array $overrides = [], array $headers = []): string
    {
        return $this->provider->idToken(
            self::ISSUER,
            self::CLIENT,
            self::NONCE,
            self::ACCESS,
            $overrides,
            $headers,
        );
    }

    /** @return array<string, mixed> */
    private function verify(string $token): array
    {
        return (new IdTokenVerifier($this->storeServing($this->provider->jwks())))->claimsFor(
            $token,
            $this->bindingId,
            $this->metadata(),
            self::CLIENT,
            self::NONCE,
            self::ACCESS,
        );
    }

    private function assertRefusal(OidcRejection $expected, string $token, string $because): void
    {
        try {
            $this->verify($token);
            $this->fail($because.' — but the token verified');
        } catch (OidcRefused $refused) {
            $this->assertSame($expected, $refused->rejection, $because);
        }
    }

    private function metadata(): ProviderMetadata
    {
        return ProviderMetadata::fromDocument([
            'issuer' => self::ISSUER,
            'authorization_endpoint' => 'https://idp.example.test/realms/acme/protocol/openid-connect/auth',
            'token_endpoint' => 'https://idp.example.test/realms/acme/protocol/openid-connect/token',
            'jwks_uri' => self::JWKS_URI,
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ], self::ISSUER);
    }

    /**
     * A `JwksStore` backed by the **real** `HardenedEgressClient`, with only
     * the wire stubbed.
     *
     * 🛑 The seam is {@see Transport}, not the client, because the client is
     * `final` (§8.3.9 wants exactly one) and because everything before the wire
     * is part of what this phase has to get right: the scheme allowlist, the
     * resolve-then-pin and the port policy all still run. A mocked client would
     * assert that the OIDC code can parse a key set; this asserts that it
     * fetches one through the hardened path.
     *
     * @param  array<string, mixed>  $document
     * @param  FakeTransport|null  $transport  assigned by reference, so a caller
     *                                         can count what was fetched
     *
     * @param-out FakeTransport $transport  always assigned, never left null
     */
    private function storeServing(array $document, ?FakeTransport &$transport = null): JwksStore
    {
        $transport = (new FakeTransport)->json(self::JWKS_URI, $document);

        $client = new HardenedEgressClient(
            new AddressGuard(
                (new FakeDnsResolver)->stable('idp.example.test', ['93.184.216.34']),
                new IpAddressClassifier,
            ),
            $transport,
            new EgressOptions(
                allowedSchemes: ['https'],
                allowedPorts: [443],
                timeoutSeconds: 5,
                maxResponseBytes: 262144,
                /*
                 * 93.184.216.34 is a routable public address the classifier calls
                 * public, so the policy is left **on**: the fixture is a
                 * routable address by design rather than by exemption.
                 */
                enforceAddressPolicy: true,
            ),
        );

        return new JwksStore($client);
    }
}
