<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use Firebase\JWT\JWT;

/**
 * An identity provider's signing key and the tokens it mints, for tests.
 *
 * 🛑 **Hostile tokens are built by hand, not by asking a library to misbehave.**
 * §8.12.18's seven named refusals are each a token a real attacker would
 * construct, and a test that produced them by passing odd arguments to
 * `JWT::encode()` would be testing the library's argument handling rather than
 * DocUp's validation. `alg: none` in particular cannot be produced by
 * `firebase/php-jwt` at all — the library refuses to emit it — which is exactly
 * why the corpus has to assemble the segments itself.
 *
 * 🛑 The key is generated per instance and never written to disk, so nothing
 * here is a committed secret (§6 of CLAUDE.md, and §9.1.4's rule that a test
 * fixture is not a place for one).
 */
final class OidcTokens
{
    /** @var \OpenSSLAsymmetricKey */
    private $privateKey;

    /** @var array<string, mixed> */
    private array $jwk;

    public function __construct(
        public readonly string $kid = 'test-key-1',
        public readonly string $algorithm = 'RS256',
    ) {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
            /*
             * 2048 rather than 4096: this runs once per test and the test is
             * about claim validation, not about key strength. Stated so nobody
             * reads it as a recommendation.
             */
            'private_key_bits' => 2048,
        ]);

        if ($key === false) {
            throw new \RuntimeException('openssl could not generate a test key');
        }

        $this->privateKey = $key;

        $details = openssl_pkey_get_details($key);

        if ($details === false || ! isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('openssl returned no RSA parameters');
        }

        $this->jwk = [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => $this->algorithm,
            'kid' => $this->kid,
            'n' => self::base64url($details['rsa']['n']),
            'e' => self::base64url($details['rsa']['e']),
        ];
    }

    /**
     * The JWKS document this provider publishes.
     *
     * @param  bool  $withAlg  false drops `alg`, which RFC 7517 §4.4 makes
     *                         OPTIONAL and which some providers omit
     * @return array<string, mixed>
     */
    public function jwks(bool $withAlg = true): array
    {
        $jwk = $this->jwk;

        if (! $withAlg) {
            unset($jwk['alg']);
        }

        return ['keys' => [$jwk]];
    }

    /**
     * A key set advertising a symmetric key, which §8.12.18 must refuse.
     *
     * @return array<string, mixed>
     */
    public function symmetricJwks(): array
    {
        return ['keys' => [[
            'kty' => 'oct',
            'alg' => 'HS256',
            'kid' => $this->kid,
            'k' => self::base64url('not a secret, and that is the point'),
        ]]];
    }

    /**
     * A well-formed id_token.
     *
     * @param  array<string, mixed>  $overrides  claims to replace or, with a
     *                                           null value, to remove
     * @param  array<string, mixed>  $headers  header members to replace
     */
    public function idToken(
        string $issuer,
        string $clientId,
        string $nonce,
        ?string $accessToken = 'test-access-token',
        array $overrides = [],
        array $headers = [],
        ?int $now = null,
    ): string {
        $now ??= time();

        $claims = [
            'iss' => $issuer,
            'sub' => 'reader-subject-1',
            'aud' => $clientId,
            'exp' => $now + 300,
            'iat' => $now,
            'nonce' => $nonce,
        ];

        if ($accessToken !== null) {
            $claims['at_hash'] = self::atHash($accessToken, $this->algorithm);
        }

        foreach ($overrides as $claim => $value) {
            if ($value === null) {
                unset($claims[$claim]);

                continue;
            }

            $claims[$claim] = $value;
        }

        /*
         * 🛑 The `kid` goes in the **positional** argument, not in `$headers`.
         *
         * `JWT::encode($payload, $key, $alg, $keyId, $head)` merges `$head`
         * first and then writes `$keyId` over it, so a `kid` passed in the
         * header array is silently discarded. The first version of this helper
         * did exactly that, and two tests passed a token that still named the
         * published key — so "an unpinned `kid` is refused" was asserting
         * nothing. Honouring the override here is what makes those tests real.
         */
        $keyId = is_string($headers['kid'] ?? null) ? $headers['kid'] : $this->kid;

        unset($headers['kid']);

        return JWT::encode($claims, $this->privateKey, $this->algorithm, $keyId, $headers);
    }

    /**
     * 🛑 `alg: none`, assembled by hand because no library will emit it.
     *
     * Two serialisations exist and both are tried by real attackers: three
     * segments with an empty signature, and two segments with no signature at
     * all. `$twoSegments` picks which.
     *
     * @param  array<string, mixed>  $claims
     */
    public static function unsignedToken(array $claims, bool $twoSegments = false): string
    {
        $header = self::base64url((string) json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = self::base64url((string) json_encode($claims));

        return $twoSegments ? $header.'.'.$payload : $header.'.'.$payload.'.';
    }

    /**
     * A token signed with a **different** key of the same `kid`.
     *
     * The shape a signature-forgery attempt takes once an attacker knows the
     * `kid` the provider publishes: everything looks right and only the
     * signature is wrong.
     *
     * @param  array<string, mixed>  $claims
     */
    public function forged(array $claims): string
    {
        $other = new self($this->kid, $this->algorithm);

        return JWT::encode($claims, $other->privateKey, $other->algorithm, $other->kid);
    }

    /** The `at_hash` for an access token, per OIDC Core §3.1.3.6. */
    public static function atHash(string $accessToken, string $algorithm): string
    {
        $digest = match (substr($algorithm, 2)) {
            '384' => 'sha384',
            '512' => 'sha512',
            default => 'sha256',
        };

        $hash = hash($digest, $accessToken, true);

        return self::base64url(substr($hash, 0, intdiv(strlen($hash), 2)));
    }

    private static function base64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
