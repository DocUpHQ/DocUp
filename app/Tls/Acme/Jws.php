<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls\Acme;

use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;

/**
 * RFC 8555's flattened JWS, with ES256 and nothing else.
 *
 * 🛑 **One algorithm, hard-coded.** `alg` is a field an attacker controls in
 * every JWS vulnerability ever published — `none`, HS256-with-the-public-key,
 * and the rest all begin with a library that reads the algorithm out of the
 * header it is verifying. This class only ever *signs*, which removes that
 * class of bug outright, and it signs with exactly one algorithm so there is
 * no negotiation to get wrong either. §9.1.4's spirit, one protocol along.
 *
 * ES256 rather than RS256 because every ACME server must support it (RFC 8555
 * §6.2), the keys are 32 bytes rather than 256, and OpenSSL's P-256 path is
 * the one most exercised.
 */
final readonly class Jws
{
    public function __construct(private \OpenSSLAsymmetricKey $key) {}

    /**
     * Sign a payload for one ACME URL.
     *
     * @param  array<string, mixed>|null  $payload  null for RFC 8555 §6.3's
     *                                              POST-as-GET, which signs an
     *                                              **empty string** rather than
     *                                              the JSON `null`
     * @param  string|null  $kid  the account URL once registered; null sends the
     *                            JWK inline, which `newAccount` requires and
     *                            every other request forbids
     *
     * @throws CertificateRefused
     */
    public function sign(string $url, string $nonce, ?array $payload, ?string $kid = null): string
    {
        $protected = ['alg' => 'ES256', 'nonce' => $nonce, 'url' => $url];

        /*
         * 🛑 Exactly one of `jwk` and `kid`, never both, and the server
         * rejects a request carrying both. Expressed as a branch rather than
         * two assignments so that a future edit cannot leave both set.
         */
        if ($kid === null) {
            $protected['jwk'] = $this->jwk();
        } else {
            $protected['kid'] = $kid;
        }

        $encodedProtected = self::base64url(self::json($protected));

        /*
         * 🛑 Three payload shapes, and the middle one is a trap.
         *
         *   null → the empty string. RFC 8555 §6.3's POST-as-GET, which a
         *          server distinguishes from a POST that carries a payload.
         *   []   → `{}`. RFC 8555 §7.5.1 triggers a challenge with an empty
         *          **object**, and `json_encode([])` produces `[]` — a JSON
         *          array. An ACME server answers that with `malformed` and
         *          "Error unmarshaling body JSON", which names the body
         *          rather than the bracket, and the request looks right in
         *          every log. Found against a real server; a stub would
         *          have accepted it.
         *   other → the object it already is.
         */
        $encodedPayload = match (true) {
            $payload === null => '',
            $payload === [] => self::base64url('{}'),
            default => self::base64url(self::json($payload)),
        };

        $signature = '';
        $signed = openssl_sign(
            $encodedProtected.'.'.$encodedPayload,
            $signature,
            $this->key,
            OPENSSL_ALGO_SHA256,
        );

        if (! $signed) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'openssl_sign failed');
        }

        return self::json([
            'protected' => $encodedProtected,
            'payload' => $encodedPayload,
            'signature' => self::base64url(self::derToRaw($signature)),
        ]);
    }

    /**
     * The public key as a JWK, with its members in the order RFC 7638 fixes.
     *
     * 🛑 The order is not cosmetic: the thumbprint below is a hash of this
     * object's canonical serialisation, and the key authorization a challenge
     * is validated against is built from that thumbprint. Reordering these
     * three members changes every challenge response the installation will
     * ever compute, and the failure appears as "the CA could not validate",
     * on the CA's side, with nothing wrong here.
     *
     * @return array<string, string>
     */
    public function jwk(): array
    {
        $details = openssl_pkey_get_details($this->key);

        if ($details === false || ! isset($details['ec']['x'], $details['ec']['y'])) {
            throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'the account key is not an EC key');
        }

        return [
            'crv' => 'P-256',
            'kty' => 'EC',
            'x' => self::base64url(self::pad((string) $details['ec']['x'])),
            'y' => self::base64url(self::pad((string) $details['ec']['y'])),
        ];
    }

    /** RFC 7638's thumbprint, which is half of every key authorization. */
    public function thumbprint(): string
    {
        return self::base64url(hash('sha256', self::json($this->jwk()), true));
    }

    /**
     * RFC 8555 §8.1's key authorization: the challenge token, the thumbprint.
     */
    public function keyAuthorization(string $token): string
    {
        return $token.'.'.$this->thumbprint();
    }

    public static function base64url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * 🛑 ECDSA signatures come out of OpenSSL DER-encoded and go into a JWS
     * as the raw `r || s` pair (RFC 7518 §3.4).
     *
     * Nothing warns about the difference. A DER signature base64url-encoded
     * into a JWS is well-formed, the right length to within a byte or two,
     * and rejected by every verifier — which reads at the call site as "the
     * CA says my signature is bad", with the signature right there and
     * looking fine.
     */
    private static function derToRaw(string $der): string
    {
        $offset = 0;

        $expect = static function (string $what) use ($der, &$offset): int {
            if (! isset($der[$offset]) || ord($der[$offset]) !== ($what === 'seq' ? 0x30 : 0x02)) {
                throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'malformed ECDSA signature');
            }

            $offset++;
            $length = ord($der[$offset] ?? "\0");
            $offset++;

            return $length;
        };

        $expect('seq');

        $rLength = $expect('int');
        $r = substr($der, $offset, $rLength);
        $offset += $rLength;

        $sLength = $expect('int');
        $s = substr($der, $offset, $sLength);

        return self::pad(ltrim($r, "\0")).self::pad(ltrim($s, "\0"));
    }

    /** P-256 coordinates and signature halves are exactly 32 bytes. */
    private static function pad(string $value): string
    {
        return str_pad($value, 32, "\0", STR_PAD_LEFT);
    }

    /** @param  array<array-key, mixed>  $value */
    private static function json(array $value): string
    {
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }
}
