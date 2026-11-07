<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use Firebase\JWT\BeforeValidException;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\SignatureInvalidException;

/**
 * 🛑 §8.12.18's protocol validation, and the word that matters is
 * **framework-enforced**.
 *
 * > "Protocol validation MUST be framework-enforced, not driver-optional.
 * > **OIDC:** PKCE S256 mandatory, `state` bound to the originating domain,
 * > single-use `nonce`, exact `iss`/`aud`, `at_hash`, a signing-algorithm
 * > allowlist excluding `none`, JWKS pinned by `kid` with a bounded refresh
 * > floor, no implicit flow."
 *
 * **Not driver-optional** is an architectural claim, not a quality bar, and it
 * is what shapes this class:
 *
 * - It is `final` and its one public method takes every input it needs. There
 *   is no setter, no option bag and no `$strict = true` — because a flag that
 *   can be turned off is a flag that will be, by a third-party driver author
 *   who found their provider easier to integrate without it.
 * - {@see OidcDriver} does not call it with a configuration; it calls it with
 *   facts. The driver cannot choose which checks run, so a future `oidc`-like
 *   driver cannot either.
 * - Every refusal is a {@see OidcRejection} case, so §17's "each rejected with
 *   **distinct audit events**" is a property of the vocabulary rather than of
 *   the care taken at each call site.
 *
 * 🛑 **`state` and `nonce` single-use are *not* here**, and that is deliberate.
 * Both are properties of a stored exchange, not of a token: single-use needs an
 * atomic conditional write, which belongs in {@see OidcExchange} beside the row
 * it latches. This class is pure — it takes a token and some expectations and
 * returns claims — which is what makes it testable against a corpus of hostile
 * tokens without a database.
 */
final readonly class IdTokenVerifier
{
    /**
     * 🛑 The signing-algorithm allowlist, excluding `none`.
     *
     * A `const`, so there is no code path that extends it. §8.12.18 requires
     * the exclusion; what the allowlist *includes* is the second decision, and
     * it is narrow on purpose:
     *
     * - **RS256** because it is what every provider defaults to.
     * - **RS384/RS512, ES256/ES384/ES512** because providers offer them and
     *   refusing a stronger algorithm would be perverse.
     * - **No `HS*`.** A symmetric id_token signature means the client secret is
     *   the verification key, so every party holding it can mint — and a
     *   confidential client's secret is held by DocUp *and* by the provider.
     *   It is also the key type the algorithm-confusion attacks need, since
     *   `JwksStore` would otherwise have to hand an asymmetric key to an HMAC
     *   verifier.
     * - **No `PS*`.** Nothing DocUp targets issues them, and an allowlist
     *   entry nothing uses is an entry nobody tests.
     * - **No `EdDSA`.** DocUp's own grant uses it (§8.12.11) and that is a
     *   different trust relationship: DocUp holds both halves. Accepting it
     *   from a provider would mean one algorithm serving two purposes, and the
     *   grep for "where is EdDSA verified" would stop giving one answer.
     *
     * @var list<string>
     */
    public const array ALGORITHMS = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];

    /**
     * 🛑 Clock skew, in seconds, and it is small.
     *
     * §8.12.18 fixes SAML's at "≤120 s" and says nothing about OIDC's, so this
     * is a decision rather than a quotation. 60 seconds, because an id_token's
     * own lifetime is typically 300: a skew of 120 would be 40% of the token's
     * life spent outside its own validity, and an installation whose clock is
     * more than a minute out has a problem `docup:doctor` should report rather
     * than one this class should absorb.
     */
    public const int LEEWAY_SECONDS = 60;

    public function __construct(private JwksStore $keys) {}

    /**
     * Verify an id_token and return its claims.
     *
     * 🛑 The order is the interesting part, and it is **cheapest-and-most-
     * structural first**: the header is parsed and the algorithm checked before
     * any key is fetched, so a token with `alg: none` costs no outbound request
     * and no signature verification. A verifier that fetched the key first
     * would make every malformed token an egress event.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @param  string  $expectedNonce  the nonce this exchange asked for
     * @param  string|null  $accessToken  for `at_hash`; null means the token
     *                                    endpoint returned none, which is
     *                                    itself a refusal
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return array<string, mixed> the verified claim set
     *
     * @throws OidcRefused
     */
    public function verify(
        string $token,
        string $bindingId,
        ProviderMetadata $metadata,
        string $clientId,
        string $expectedNonce,
        ?string $accessToken,
        ?int $now = null,
    ): array {
        $now ??= time();

        [$header, $algorithm, $kid] = self::header($token);

        /*
         * 🛑 §8.12.18's allowlist, applied to the token's own claim about
         * itself, before anything else. `alg: none` dies here — and so does
         * `alg: HS256`, which is the one an attacker picks when they have the
         * public key.
         */
        if (! in_array($algorithm, self::ALGORITHMS, true)) {
            throw OidcRefused::of(
                OidcRejection::AlgorithmNotAllowed,
                'the token declares `'.$algorithm.'`',
            );
        }

        /*
         * And against what this provider says it signs with. A token claiming
         * ES512 from a provider advertising only RS256 is not a token this
         * provider issued.
         */
        if (! in_array($algorithm, $metadata->algorithms, true)) {
            throw OidcRefused::of(
                OidcRejection::AlgorithmNotAllowed,
                'the provider does not advertise `'.$algorithm.'`',
            );
        }

        if ($kid === null) {
            /*
             * 🛑 A missing `kid` is {@see OidcRejection::KeyNotPinned}, not a
             * malformed token, and the distinction is the requirement: "JWKS
             * pinned by `kid`" cannot be satisfied by a token that names no
             * key. Trying every published key instead — which some libraries
             * do — gives an attacker as many signature attempts as the
             * provider has keys.
             */
            throw OidcRefused::of(
                OidcRejection::KeyNotPinned,
                'the token header names no `kid`, so it cannot be pinned',
            );
        }

        $key = $this->keys->keyFor($bindingId, $metadata->jwksUri, $kid, $algorithm);

        /*
         * 🛑 `JWT::$leeway` is a **static** property on the library, so it is
         * set and restored around the call. Left set, it would widen the skew
         * for DocUp's own grant verifier (§8.12.11, which runs with
         * `LEEWAY = 0`) depending on request order — a cross-contamination
         * between two verifiers that share nothing but a library.
         */
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = self::LEEWAY_SECONDS;

        try {
            $decoded = JWT::decode($token, $key);
        } catch (ExpiredException $e) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token has expired');
        } catch (BeforeValidException $e) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token is not yet valid');
        } catch (SignatureInvalidException $e) {
            throw OidcRefused::of(OidcRejection::SignatureInvalid, 'the signature does not verify');
        } catch (\Throwable $e) {
            /*
             * Everything else the library raises is a shape problem: a
             * segment that is not base64url, a claim set that is not an
             * object, an algorithm/key mismatch it caught itself.
             */
            throw OidcRefused::of(OidcRejection::TokenMalformed, 'the token would not decode');
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        /*
         * 🛑 A cast, not a JSON round trip. `JWT::decode()` returns a
         * `stdClass` (JWT.php:86), so casting gives string keys **by
         * construction** — which is both faster and the reason the claim
         * accessors below can be typed `array<string, mixed>` honestly. The
         * first version re-encoded and decoded, which produced
         * `array<mixed, mixed>`: a JSON array decodes to integer keys, so the
         * analyser was right to refuse it and a payload that was a JSON array
         * would have reached the accessors.
         */
        $claims = (array) $decoded;

        self::assertIssuer($claims, $metadata->issuer);
        self::assertAudience($claims, $clientId);
        self::assertNonce($claims, $expectedNonce);
        self::assertAtHash($claims, $accessToken, $algorithm);
        self::assertExpiry($claims, $now);

        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) || $subject === '') {
            /*
             * 🛑 §8.12.1 keys a reader identity on `(binding_id, subject_hash)`,
             * so a token with no `sub` identifies nobody. Refused rather than
             * substituted — and **never** substituted with `email`, which that
             * requirement forbids by name: "email MUST NEVER be used for
             * linking or lookup … find-or-create-by-email would let any tenant
             * mint an installation owner."
             */
            throw OidcRefused::of(OidcRejection::SubjectMissing, 'the token carries no `sub`');
        }

        unset($header);

        return $claims;
    }

    /**
     * The token's header, decoded without trusting it.
     *
     * 🛑 Parsed by hand rather than by the library, because the library's
     * parse is bound up with verification and this has to happen *before* a key
     * is chosen. Nothing read here is trusted — it selects a key and an
     * algorithm, both of which are then checked against the provider's own
     * published facts.
     *
     * @return array{array<string, mixed>, string, ?string}
     *
     * @throws OidcRefused
     */
    private static function header(string $token): array
    {
        $segments = explode('.', $token);

        /*
         * 🛑 Exactly three segments. Two is an unsigned JWS — the serialisation
         * `alg: none` produces — and five is JWE, which §8.12.18 does not
         * provide for and which DocUp has no decryption key for anyway.
         */
        if (count($segments) !== 3) {
            throw OidcRefused::of(
                count($segments) === 2 ? OidcRejection::AlgorithmNotAllowed : OidcRejection::TokenMalformed,
                'the token has '.count($segments).' segments, not three',
            );
        }

        if ($segments[2] === '') {
            /*
             * 🛑 An empty signature with three segments is the other `alg:
             * none` serialisation, and it is reported as the algorithm refusal
             * rather than as a bad signature — because that is what an operator
             * reading the audit chain needs to see.
             */
            throw OidcRefused::of(OidcRejection::AlgorithmNotAllowed, 'the token carries an empty signature');
        }

        $raw = base64_decode(strtr($segments[0], '-_', '+/'), true);

        if ($raw === false) {
            throw OidcRefused::of(OidcRejection::TokenMalformed, 'the header is not base64url');
        }

        $header = json_decode($raw, true);

        if (! is_array($header)) {
            throw OidcRefused::of(OidcRejection::TokenMalformed, 'the header is not a JSON object');
        }

        $algorithm = $header['alg'] ?? null;

        if (! is_string($algorithm) || $algorithm === '') {
            throw OidcRefused::of(OidcRejection::AlgorithmNotAllowed, 'the header declares no `alg`');
        }

        $kid = $header['kid'] ?? null;

        return [$header, $algorithm, is_string($kid) && $kid !== '' ? $kid : null];
    }

    /**
     * 🛑 §8.12.18's "exact `iss`".
     *
     * Exact, by `hash_equals`, against the issuer the *discovery document*
     * declared — which {@see ProviderMetadata} has already checked equals the
     * one the operator configured. So the comparison is transitively against
     * operator intent, and the two-step is what closes the mix-up attack RFC
     * 9700 §4.4 describes: a prefix or suffix comparison would accept
     * `https://idp.example.com.attacker.test`.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws OidcRefused
     */
    private static function assertIssuer(array $claims, string $issuer): void
    {
        $actual = $claims['iss'] ?? null;

        if (! is_string($actual) || ! hash_equals($issuer, $actual)) {
            throw OidcRefused::of(OidcRejection::IssuerMismatch, 'the token names another issuer');
        }
    }

    /**
     * 🛑 §8.12.18's "exact `aud`", and `azp` where there are several.
     *
     * OIDC Core §3.1.3.7 steps 3 and 4: `aud` must contain the client id, and
     * where it contains more than one audience `azp` must be present and must
     * be the client id. The second half is what stops a token minted for
     * another client at the same provider being replayed here — it is a
     * genuinely valid token, correctly signed, for somebody else.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws OidcRefused
     */
    private static function assertAudience(array $claims, string $clientId): void
    {
        $audience = $claims['aud'] ?? null;

        $audiences = match (true) {
            is_string($audience) => [$audience],
            is_array($audience) => array_values(array_filter($audience, 'is_string')),
            default => [],
        };

        if ($audiences === []) {
            throw OidcRefused::of(OidcRejection::AudienceMismatch, 'the token carries no `aud`');
        }

        $found = false;

        foreach ($audiences as $one) {
            if (hash_equals($clientId, $one)) {
                $found = true;
                break;
            }
        }

        if (! $found) {
            throw OidcRefused::of(OidcRejection::AudienceMismatch, 'the token is not for this client');
        }

        if (count($audiences) === 1) {
            return;
        }

        $azp = $claims['azp'] ?? null;

        if (! is_string($azp) || ! hash_equals($clientId, $azp)) {
            throw OidcRefused::of(
                OidcRejection::AudienceMismatch,
                'the token names several audiences and `azp` is not this client',
            );
        }
    }

    /**
     * 🛑 The `nonce` claim is the one this exchange asked for.
     *
     * Single-use is {@see OidcExchange}'s job, by the row's latch; this is the
     * other half — that the token answers *this* request. Without it, a token
     * obtained from a reader's earlier login could be injected into a later
     * exchange, which is OIDC Core §3.1.3.7 step 11 and the reason `nonce`
     * exists at all.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws OidcRefused
     */
    private static function assertNonce(array $claims, string $expected): void
    {
        $actual = $claims['nonce'] ?? null;

        if (! is_string($actual) || $actual === '') {
            throw OidcRefused::of(OidcRejection::NonceMismatch, 'the token carries no `nonce`');
        }

        if (! hash_equals($expected, $actual)) {
            throw OidcRefused::of(OidcRejection::NonceMismatch, 'the token answers a different request');
        }
    }

    /**
     * 🛑 §8.12.18's `at_hash`, which is **mandatory here** though OIDC Core
     * makes it optional for the code flow.
     *
     * Core §3.3.2.11 requires it only for the hybrid flow. §8.12.18 lists it
     * unconditionally, and the stricter reading is the right one: `at_hash`
     * binds the id_token to the access token that arrived beside it, so a
     * token *pair* cannot be assembled from two exchanges. Without it the
     * access token DocUp holds is unbound from the identity DocUp believes it
     * belongs to — and DocUp uses that access token to call `userinfo`.
     *
     * The algorithm is fixed by the signing algorithm's digest length (Core
     * §3.1.3.6): the left-most half of the hash of the ASCII access token.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws OidcRefused
     */
    private static function assertAtHash(array $claims, ?string $accessToken, string $algorithm): void
    {
        $claimed = $claims['at_hash'] ?? null;

        if (! is_string($claimed) || $claimed === '') {
            throw OidcRefused::of(
                OidcRejection::AtHashInvalid,
                'the token carries no `at_hash`, which §8.12.18 requires',
            );
        }

        if ($accessToken === null || $accessToken === '') {
            throw OidcRefused::of(
                OidcRejection::AtHashInvalid,
                'the token carries an `at_hash` and the exchange returned no access token to check it against',
            );
        }

        $digest = match (substr($algorithm, 2)) {
            '384' => 'sha384',
            '512' => 'sha512',
            default => 'sha256',
        };

        $hash = hash($digest, $accessToken, true);
        $expected = rtrim(strtr(base64_encode(substr($hash, 0, intdiv(strlen($hash), 2))), '+/', '-_'), '=');

        if (! hash_equals($expected, $claimed)) {
            throw OidcRefused::of(OidcRejection::AtHashInvalid, 'the `at_hash` does not match the access token');
        }
    }

    /**
     * `exp` and `iat`, checked here as well as by the library.
     *
     * 🛑 Not redundant: the library's own check is what `JWT::$leeway` applies
     * to, and a claim that is absent rather than past slips through it — an
     * id_token with no `exp` decodes cleanly. OIDC Core makes both REQUIRED, so
     * their absence is a refusal.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws OidcRefused
     */
    private static function assertExpiry(array $claims, int $now): void
    {
        $exp = $claims['exp'] ?? null;
        $iat = $claims['iat'] ?? null;

        if (! is_int($exp) && ! is_float($exp)) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token carries no `exp`');
        }

        if (! is_int($iat) && ! is_float($iat)) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token carries no `iat`');
        }

        if ((int) $exp + self::LEEWAY_SECONDS <= $now) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token has expired');
        }

        if ((int) $iat - self::LEEWAY_SECONDS > $now) {
            throw OidcRefused::of(OidcRejection::TokenExpired, 'the token was issued in the future');
        }
    }
}
