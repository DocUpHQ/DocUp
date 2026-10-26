<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Tls;

use App\Tls\Acme\Jws;
use PHPUnit\Framework\TestCase;

/**
 * RFC 8555's JWS, which an ACME server will reject in silence if any detail
 * of it is wrong.
 *
 * 🛑 This test exists because the two failures below are the ones that look
 * like something else. An ECDSA signature in DER form, base64url-encoded
 * into a JWS, is well-formed, the right length to within a byte or two, and
 * rejected by every verifier — which reads at the call site as "the CA says
 * my signature is bad", with the signature right there and looking fine. And
 * a JWK whose members are reordered produces a different thumbprint, which
 * produces a different key authorization, which makes every challenge fail
 * **at the CA**, with nothing wrong on this side.
 *
 * Neither is caught by an integration test that happens to pass; both are
 * caught here, deterministically, without a certificate authority.
 */
final class JwsTest extends TestCase
{
    /**
     * 🛑 The signature is raw `r || s`, 64 bytes, not DER.
     *
     * RFC 7518 §3.4 for ES256. OpenSSL hands back DER; the difference is
     * invisible until a verifier refuses.
     */
    public function test_the_signature_is_raw_r_s_and_verifies(): void
    {
        $key = $this->key();
        $jws = new Jws($key);

        $signed = json_decode($jws->sign('https://ca.test/order', 'nonce-1', ['a' => 'b']), true);

        $this->assertIsArray($signed);
        $this->assertArrayHasKey('protected', $signed);
        $this->assertArrayHasKey('payload', $signed);
        $this->assertArrayHasKey('signature', $signed);

        $raw = self::decode((string) $signed['signature']);

        $this->assertSame(64, strlen($raw), 'ES256 is two 32-byte halves; a DER signature is 70-72 bytes');

        // And it verifies, once converted back to the DER OpenSSL wants.
        $signing = $signed['protected'].'.'.$signed['payload'];

        /*
         * The **public** half: `openssl_verify` errors rather than returning
         * 0 when handed a private key object, which reads as "the signature
         * is wrong" and is not.
         */
        $details = openssl_pkey_get_details($key);
        $this->assertIsArray($details);
        $public = openssl_pkey_get_public((string) $details['key']);
        $this->assertInstanceOf(\OpenSSLAsymmetricKey::class, $public);

        $this->assertSame(
            1,
            openssl_verify($signing, self::toDer($raw), $public, OPENSSL_ALGO_SHA256),
            'the signature must verify over protected.payload',
        );
    }

    /**
     * 🛑 The JWK's members are in RFC 7638's order, because the thumbprint
     * is a hash of its serialisation.
     *
     * Reordering these three changes every key authorization the
     * installation will ever compute, and the failure appears on the CA's
     * side as "could not validate".
     */
    public function test_the_jwk_is_in_thumbprint_order(): void
    {
        $jwk = (new Jws($this->key()))->jwk();

        $this->assertSame(['crv', 'kty', 'x', 'y'], array_keys($jwk));
        $this->assertSame('P-256', $jwk['crv']);
        $this->assertSame('EC', $jwk['kty']);
        $this->assertSame(32, strlen(self::decode($jwk['x'])), 'P-256 coordinates are padded to 32 bytes');
        $this->assertSame(32, strlen(self::decode($jwk['y'])));
    }

    /** RFC 8555 §8.1's key authorization is `token.thumbprint`. */
    public function test_the_key_authorization_is_the_token_and_the_thumbprint(): void
    {
        $jws = new Jws($this->key());

        $this->assertSame(
            'tok3n.'.$jws->thumbprint(),
            $jws->keyAuthorization('tok3n'),
        );

        // base64url of a SHA-256: 43 characters, no padding.
        $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]{43}\z/', $jws->thumbprint());
    }

    /**
     * 🛑 `newAccount` carries an inline JWK; everything else carries a `kid`,
     * and never both.
     *
     * A request with both is answered `malformed`, with no indication of
     * which field was wrong.
     */
    public function test_exactly_one_of_jwk_and_kid_is_sent(): void
    {
        $jws = new Jws($this->key());

        $first = $this->protectedHeader($jws->sign('https://ca.test/new-account', 'n', []));

        $this->assertArrayHasKey('jwk', $first);
        $this->assertArrayNotHasKey('kid', $first);

        $later = $this->protectedHeader($jws->sign('https://ca.test/order', 'n', [], 'https://ca.test/acct/1'));

        $this->assertArrayHasKey('kid', $later);
        $this->assertArrayNotHasKey('jwk', $later);
        $this->assertSame('https://ca.test/acct/1', $later['kid']);
    }

    /**
     * 🛑 RFC 8555 §6.3's POST-as-GET signs an **empty string**, not the JSON
     * `null`.
     *
     * A server distinguishes the two: an empty payload is a read, and
     * `"null"` is a malformed write.
     */
    public function test_post_as_get_signs_an_empty_payload(): void
    {
        $signed = json_decode((new Jws($this->key()))->sign('https://ca.test/authz/1', 'n', null, 'kid'), true);

        $this->assertIsArray($signed);
        $this->assertSame('', $signed['payload']);
    }

    /** Every member is base64url with no padding (RFC 7515 §2). */
    public function test_the_encoding_is_unpadded_base64url(): void
    {
        $signed = json_decode((new Jws($this->key()))->sign('https://ca.test/x', 'n', ['k' => 'v']), true);

        $this->assertIsArray($signed);

        foreach (['protected', 'payload', 'signature'] as $member) {
            $this->assertMatchesRegularExpression('/\A[A-Za-z0-9_-]*\z/', (string) $signed[$member], $member);
        }
    }

    private function key(): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        $this->assertInstanceOf(\OpenSSLAsymmetricKey::class, $key);

        return $key;
    }

    /** @return array<string, mixed> */
    private function protectedHeader(string $jws): array
    {
        $decoded = json_decode($jws, true);

        $this->assertIsArray($decoded);

        $header = json_decode(self::decode((string) $decoded['protected']), true);

        $this->assertIsArray($header);
        $this->assertSame('ES256', $header['alg'], 'one algorithm, hard-coded');

        /** @var array<string, mixed> $header */
        return $header;
    }

    private static function decode(string $value): string
    {
        return (string) base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);
    }

    /** The inverse of the conversion under test, so the verify is independent of it. */
    private static function toDer(string $raw): string
    {
        $integer = static function (string $half): string {
            $half = ltrim($half, "\0");
            $half = $half === '' ? "\0" : $half;

            if (ord($half[0]) > 0x7F) {
                $half = "\0".$half;
            }

            return "\x02".chr(min(255, strlen($half))).$half;
        };

        $body = $integer(substr($raw, 0, 32)).$integer(substr($raw, 32));

        /*
         * One length byte is enough: two 33-byte INTEGERs plus their headers
         * is 70 bytes, which is well inside DER's short form. `min` is there
         * for the type checker, not for a case that can occur.
         */
        return "\x30".chr(min(255, strlen($body))).$body;
    }
}
