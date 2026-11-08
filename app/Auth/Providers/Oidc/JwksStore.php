<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use App\Egress\EgressRefused;
use App\Egress\HardenedEgressClient;
use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Illuminate\Support\Facades\Cache;

/**
 * 🛑 §8.12.18's "JWKS pinned by `kid` with a bounded refresh floor".
 *
 * Two requirements in one sentence, and the second is the one that gets left
 * out.
 *
 * ## Pinned by `kid`
 *
 * A token names its signing key in the header. The verifier asks this class for
 * **that key and no other**, so a token cannot choose to be verified by a key
 * it supplies, and a provider holding ten keys does not have ten chances at a
 * signature. `firebase/php-jwt` would accept a whole key set and pick by `kid`
 * itself; the lookup is done here instead so the miss is *visible* — it is the
 * miss that triggers the refresh, and the refresh is what needs bounding.
 *
 * ## The bounded refresh floor
 *
 * 🛑 **An unknown `kid` must not be a free outbound request.**
 *
 * The naive shape is "`kid` not found → fetch the JWKS again", and it is a
 * remote-triggered amplifier: anybody who can reach a documentation host can
 * mint a syntactically valid JWS with a random `kid` and cost DocUp one
 * outbound HTTPS request per attempt. That is a denial of service against the
 * identity provider (whose rate limit DocUp then trips, breaking real logins)
 * and against §8.3.9's own egress budget.
 *
 * So a refresh is permitted at most once per {@see REFRESH_FLOOR_SECONDS} per
 * binding, tracked in its own cache key, and an unknown `kid` inside that
 * window is {@see OidcRejection::KeyNotPinned} rather than a fetch. Key
 * rotation still works: the window is a minute, and a provider rotating keys
 * publishes the new one before signing with it (RFC 7517 §5 is the practice,
 * and every major provider follows it) — so the first token signed with a new
 * key arrives after the key has been publishable for far longer than a minute.
 *
 * 🛑 The floor is **per binding**, not global. One misconfigured provider must
 * not be able to stop a second provider's key rotation from being noticed.
 */
final readonly class JwksStore
{
    /**
     * How long a fetched key set is trusted without re-asking.
     *
     * 🛑 Deliberately long relative to the floor. A key set is a public
     * document that changes on the order of months; the cache is what keeps a
     * reader's login from costing an outbound request, and the floor below is
     * what makes a *miss* safe. Two different mechanisms for two different
     * failure modes.
     */
    public const int CACHE_SECONDS = 3600;

    /**
     * 🛑 The refresh floor. One fetch per binding per minute, however many
     * unknown `kid`s arrive.
     *
     * A minute rather than an hour because key rotation has to remain
     * automatic — an operator should never have to clear a cache to recover
     * from a rotation — and rather than a second because a second is not a
     * bound: at one request per second an attacker still generates 86,400
     * outbound requests a day from one documentation host.
     */
    public const int REFRESH_FLOOR_SECONDS = 60;

    /**
     * 🛑 The byte cap for a key set.
     *
     * `HardenedEgressClient` caps the response too (§8.3.9), and this is the
     * semantic cap on top: a document larger than this is not a key set, and
     * `JWK::parseKeySet()` on a megabyte of nested JSON is work DocUp should
     * not do. Sized for roughly a hundred RSA keys, which no real provider
     * approaches.
     */
    private const int MAX_BYTES = 256 * 1024;

    public function __construct(private HardenedEgressClient $egress) {}

    /**
     * The key a token's `kid` names, fetching once if the floor allows.
     *
     * @param  string  $bindingId  raw 16 bytes; scopes the cache and the floor
     *
     * @throws OidcRefused when the key is unknown and cannot be re-fetched,
     *                     or when the key set will not parse
     */
    public function keyFor(string $bindingId, string $jwksUri, string $kid, string $algorithm): Key
    {
        $keys = $this->cached($bindingId, $jwksUri);

        if (isset($keys[$kid])) {
            return self::usable($keys[$kid], $kid, $algorithm);
        }

        /*
         * 🛑 The miss, and the floor. `Cache::add` is the latch: it writes only
         * if the key is absent, atomically, so two concurrent misses produce
         * one fetch rather than two. A `has` then `put` would be the race this
         * class exists to close.
         */
        if (! Cache::add($this->floorKey($bindingId), 1, self::REFRESH_FLOOR_SECONDS)) {
            throw OidcRefused::of(
                OidcRejection::KeyNotPinned,
                'the token names a key outside the pinned set and the refresh floor forbids re-fetching yet',
            );
        }

        Cache::forget($this->cacheKey($bindingId));

        $keys = $this->cached($bindingId, $jwksUri);

        if (! isset($keys[$kid])) {
            throw OidcRefused::of(
                OidcRejection::KeyNotPinned,
                'the token names a key the provider does not publish',
            );
        }

        return self::usable($keys[$kid], $kid, $algorithm);
    }

    /**
     * Fetch a key set now, for a probe.
     *
     * 🛑 Bypasses the cache and **not** the floor-protected path above, because
     * a probe is an operator asking a question: it should see what the provider
     * is publishing right now, and it is rate-limited by being a human action
     * rather than by a cache. {@see Bindings::probe()} is the only caller.
     *
     * @return list<string> the `kid`s published, for the probe's summary
     *
     * @throws OidcRefused
     */
    public function refresh(string $bindingId, string $jwksUri): array
    {
        Cache::forget($this->cacheKey($bindingId));

        return array_keys($this->cached($bindingId, $jwksUri));
    }

    /**
     * @return array<string, Key>
     *
     * @throws OidcRefused
     */
    private function cached(string $bindingId, string $jwksUri): array
    {
        /*
         * 🛑 The raw document is cached, not the `Key` objects. A `Key` wraps
         * an `OpenSSLAsymmetricKey` resource, which does not survive
         * serialisation — cached, it comes back as an unusable stub and every
         * verification fails with an error that names neither the cache nor
         * the key. Found the honest way: by caching the wrong thing.
         */
        $document = Cache::remember(
            $this->cacheKey($bindingId),
            self::CACHE_SECONDS,
            fn (): array => $this->fetch($jwksUri),
        );

        if ($document === []) {
            throw OidcRefused::of(OidcRejection::JwksFailed, 'the cached key set is empty');
        }

        try {
            /** @var array<string, Key> $keys */
            $keys = JWK::parseKeySet(self::normalise($document));
        } catch (\Throwable $e) {
            /*
             * 🛑 Forget the cached document, or a provider that published one
             * broken key set has broken every login for an hour.
             */
            Cache::forget($this->cacheKey($bindingId));

            throw OidcRefused::of(
                OidcRejection::JwksFailed,
                'the key set would not parse: '.$e->getMessage(),
            );
        }

        return $keys;
    }

    /**
     * @return array<string, mixed>
     *
     * @throws OidcRefused
     */
    private function fetch(string $jwksUri): array
    {
        try {
            $response = $this->egress->get($jwksUri, ['Accept' => 'application/json']);
        } catch (EgressRefused $e) {
            /*
             * 🛑 The egress refusal is **not** re-raised. §8.3.9's rejections
             * name private addresses and DNS rebinding; a reader's login must
             * not be the place that reports an operator's misconfigured issuer
             * URL in those terms, and {@see OidcRejection::JwksFailed} is what
             * the audit chain can act on. The detail carries the cause.
             */
            throw OidcRefused::of(
                OidcRejection::JwksFailed,
                'the key set could not be fetched: '.$e->rejection->value,
            );
        }

        if (! $response->successful()) {
            throw OidcRefused::of(
                OidcRejection::JwksFailed,
                'the key set endpoint answered '.$response->status,
            );
        }

        if (strlen($response->body) > self::MAX_BYTES) {
            throw OidcRefused::of(
                OidcRejection::JwksFailed,
                'the key set exceeds '.self::MAX_BYTES.' bytes, so it is not a key set',
            );
        }

        $decoded = $response->json();

        if ($decoded === null || ! isset($decoded['keys']) || ! is_array($decoded['keys']) || $decoded['keys'] === []) {
            throw OidcRefused::of(OidcRejection::JwksFailed, 'the key set has no `keys` array');
        }

        return $decoded;
    }

    /**
     * 🛑 Fill in a missing `alg` **from the key**, and drop symmetric keys.
     *
     * Two problems with handing a key set straight to `JWK::parseKeySet()`.
     *
     * 1. **`alg` is OPTIONAL in RFC 7517 §4.4 and the library requires it.**
     *    `parseKey()` throws `JWK must contain an "alg" parameter` unless a
     *    default is passed, so a provider that publishes bare keys — legal,
     *    and some do — would break every login with a parse error naming
     *    neither the provider nor the cause.
     *
     * 2. 🛑 **The obvious default is the token's own `alg`, and it must not
     *    be.** `JWT::decode()` verifies with `$key->getAlgorithm()` and refuses
     *    a token whose header disagrees (JWT.php:155) — so the key's algorithm
     *    is the authority, and letting the token supply it makes that check a
     *    tautology. That is the algorithm-confusion family: hand an RSA public
     *    key to an HMAC verifier and the *public* key becomes the shared
     *    secret, so anybody holding the published JWKS can forge.
     *
     * So the default comes from `kty` and `crv`, which the provider published
     * and an attacker cannot choose, and a key whose type DocUp cannot place is
     * **dropped** rather than guessed at. A dropped key presents as
     * {@see OidcRejection::KeyNotPinned}, which is the honest outcome: DocUp
     * has no key it is willing to verify that token with.
     *
     * 🛑 **`oct` keys are dropped unconditionally**, even when they carry an
     * `alg`. A symmetric key in a *published* key set is a shared secret that
     * is not secret; verifying an id_token with one means anybody who can read
     * the JWKS can mint one. §8.12.11 makes the same argument for DocUp's own
     * grant — "an edge-held HMAC key makes every edge node a minter" — and it
     * applies with more force to a key the provider serves to the world.
     *
     * @param  array<string, mixed>  $document
     * @return array<string, mixed>
     */
    private static function normalise(array $document): array
    {
        /** @var list<mixed> $keys */
        $keys = is_array($document['keys'] ?? null) ? $document['keys'] : [];

        $usable = [];

        foreach ($keys as $jwk) {
            if (! is_array($jwk)) {
                continue;
            }

            $kty = is_string($jwk['kty'] ?? null) ? $jwk['kty'] : '';

            if ($kty === 'oct') {
                continue;
            }

            if (! isset($jwk['alg']) || ! is_string($jwk['alg'])) {
                $derived = self::algorithmFor($kty, is_string($jwk['crv'] ?? null) ? $jwk['crv'] : '');

                if ($derived === null) {
                    continue;
                }

                $jwk['alg'] = $derived;
            }

            /*
             * And the declared `alg` still has to be one DocUp accepts. A key
             * published for `none` is dropped here rather than reaching the
             * parser, where it would become a `Key` nothing should hold.
             */
            if (! in_array($jwk['alg'], IdTokenVerifier::ALGORITHMS, true)) {
                continue;
            }

            $usable[] = $jwk;
        }

        if ($usable === []) {
            throw OidcRefused::of(
                OidcRejection::JwksFailed,
                'the key set publishes no asymmetric key with an algorithm DocUp accepts',
            );
        }

        return ['keys' => $usable];
    }

    /**
     * The algorithm a bare key implies, from its own type.
     *
     * RSA defaults to RS256 — the OIDC Core §15.1 default and what every
     * provider that omits `alg` means. An EC key's curve determines its
     * algorithm exactly (RFC 7518 §3.4), so there is nothing to choose. `OKP`
     * is absent deliberately: Ed25519 id_tokens are not something any OIDC
     * provider DocUp targets issues, and {@see IdTokenVerifier::ALGORITHMS}
     * does not accept `EdDSA` for a *provider* token — only DocUp's own grant
     * uses it, where DocUp holds both halves.
     */
    private static function algorithmFor(string $kty, string $curve): ?string
    {
        return match (true) {
            $kty === 'RSA' => 'RS256',
            $kty === 'EC' && $curve === 'P-256' => 'ES256',
            $kty === 'EC' && $curve === 'P-384' => 'ES384',
            $kty === 'EC' && $curve === 'P-521' => 'ES512',
            default => null,
        };
    }

    /**
     * 🛑 The key may only be used with the algorithm the token declared, and
     * only with one DocUp allows.
     *
     * `JWK::parseKeySet()` reads `alg` from the JWK when the provider sets it,
     * and leaves it null when they do not. Either way the *token's* algorithm
     * is what the verifier will use, so it is checked against the allowlist
     * here and against the key's own declared `alg` where there is one — which
     * is the defence against an RSA key being used to verify an HMAC, the
     * confusion CVE-2016-10555 and its descendants are about.
     *
     * @throws OidcRefused
     */
    private static function usable(Key $key, string $kid, string $algorithm): Key
    {
        if (! in_array($algorithm, IdTokenVerifier::ALGORITHMS, true)) {
            throw OidcRefused::of(
                OidcRejection::AlgorithmNotAllowed,
                'the token declares `'.$algorithm.'`, which is not in DocUp\'s allowlist',
            );
        }

        $declared = $key->getAlgorithm();

        if ($declared !== $algorithm) {
            throw OidcRefused::of(
                OidcRejection::AlgorithmNotAllowed,
                'key `'.$kid.'` is published for `'.$declared.'` and the token declares `'.$algorithm.'`',
            );
        }

        return $key;
    }

    private function cacheKey(string $bindingId): string
    {
        return 'oidc:jwks:'.bin2hex($bindingId);
    }

    private function floorKey(string $bindingId): string
    {
        return 'oidc:jwks:floor:'.bin2hex($bindingId);
    }
}
