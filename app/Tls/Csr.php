<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * Key generation and certificate signing requests, in one place.
 *
 * 🛑 It is one place because of `subjectAltName`. PHP's `openssl_csr_new()`
 * has **no parameter** for it: the only way to put a DNS name in a SAN
 * extension is an `openssl.cnf` fragment on disk, passed as `config`, with
 * `req_extensions` naming the section. Every caller that needs a certificate
 * therefore needs the same temporary file and the same fragment — and a
 * second copy of it is a second chance to ship a certificate whose name is
 * only in the common name, which no browser has read since 2017.
 */
final class Csr
{
    /**
     * A fresh P-256 key.
     *
     * ECDSA rather than RSA: every ACME server must support it, the key is
     * 32 bytes rather than 256, handshakes are cheaper, and it is what
     * {@see Acme\Jws} signs with, so an installation has one curve rather
     * than two algorithms.
     *
     * @throws CertificateRefused
     */
    public static function key(): \OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_type' => OPENSSL_KEYTYPE_EC,
            'curve_name' => 'prime256v1',
        ]);

        if ($key === false) {
            throw CertificateRefused::of(CertificateRejection::KeyUnreadable, 'openssl_pkey_new failed');
        }

        return $key;
    }

    /**
     * A certificate signing request for one hostname, DER-encoded.
     *
     * DER because that is what RFC 8555 §7.4 finalises an order with, as
     * base64url. The conversion is a PEM export with its armour stripped:
     * OpenSSL has no DER export for a CSR through PHP's binding.
     *
     * @throws CertificateRefused
     */
    public static function der(string $host, \OpenSSLAsymmetricKey $key): string
    {
        return self::withConfig($host, static function (array $options) use ($host, $key): string {
            $csr = openssl_csr_new(['commonName' => substr($host, 0, 64)], $key, $options);

            if (! $csr instanceof \OpenSSLCertificateSigningRequest) {
                throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'openssl_csr_new failed');
            }

            $pem = '';

            if (! openssl_csr_export($csr, $pem)) {
                throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'openssl_csr_export failed');
            }

            $base64 = preg_replace('/-----(BEGIN|END) CERTIFICATE REQUEST-----|\s+/', '', $pem);
            $der = base64_decode((string) $base64, true);

            if ($der === false) {
                throw CertificateRefused::of(CertificateRejection::AcmeUnreadable, 'the CSR did not decode');
            }

            return $der;
        });
    }

    /**
     * A self-signed certificate and its key, as PEM.
     *
     * @return array{0: string, 1: string} the chain and the private key
     *
     * @throws CertificateRefused
     */
    public static function selfSigned(string $host, \OpenSSLAsymmetricKey $key, int $days): array
    {
        return self::withConfig($host, static function (array $options) use ($host, $key, $days): array {
            $csr = openssl_csr_new(['commonName' => substr($host, 0, 64)], $key, $options);

            if (! $csr instanceof \OpenSSLCertificateSigningRequest) {
                throw CertificateRefused::of(CertificateRejection::ChainUnreadable, 'openssl_csr_new failed');
            }

            $signed = openssl_csr_sign($csr, null, $key, $days, $options, random_int(1, PHP_INT_MAX));

            if ($signed === false) {
                throw CertificateRefused::of(CertificateRejection::ChainUnreadable, 'openssl_csr_sign failed');
            }

            $chain = '';
            openssl_x509_export($signed, $chain);

            $private = '';
            openssl_pkey_export($key, $private, null, $options);

            return [$chain, $private];
        });
    }

    /**
     * Run a callback with an `openssl.cnf` carrying this host's SAN, and
     * remove the file afterwards whatever happened.
     *
     * @template TReturn
     *
     * @param  \Closure(array<string, string>): TReturn  $work
     * @return TReturn
     *
     * @throws CertificateRefused
     */
    private static function withConfig(string $host, \Closure $work): mixed
    {
        /*
         * 🛑 `$host` is normalised punycode A-labels by the time it reaches
         * here (§8.10.7 refuses anything else), so it carries only
         * `[a-z0-9.-]` and cannot break out of the config syntax. The check
         * is restated rather than assumed because this string is written to
         * a file and handed to a parser, and the distance between the
         * normaliser and this line is the whole application.
         */
        if (preg_match('/\A[a-z0-9.*-]{1,253}\z/', $host) !== 1) {
            throw CertificateRefused::of(CertificateRejection::HostNotCovered, 'unnormalised hostname');
        }

        /*
         * 🛑 A private directory of our own, not `tempnam()`, and the Pest
         * security preset is right to forbid the latter.
         *
         * `tempnam()` returns a path in a world-readable directory. What
         * goes in it here is an OpenSSL configuration that OpenSSL then
         * **parses** — so between the write and the read, another local
         * process can replace the file and choose the extensions on a
         * certificate this installation is about to sign. The content being
         * unremarkable does not make the window safe; the parser is the
         * asset.
         *
         * `mkdir` with a random name is atomic and fails if the name exists,
         * so there is no race to win, and 0700 means nothing else can even
         * traverse into it.
         */
        $directory = sys_get_temp_dir().'/docup-tls-'.bin2hex(random_bytes(16));

        if (! @mkdir($directory, 0o700) || ! is_dir($directory)) {
            throw CertificateRefused::of(CertificateRejection::ChainUnreadable, 'no private directory');
        }

        $path = $directory.'/openssl.cnf';

        try {
            file_put_contents($path, <<<CONF
                [req]
                distinguished_name = dn
                req_extensions     = v3_req
                prompt             = no

                [dn]
                CN = {$host}

                [v3_req]
                basicConstraints = CA:FALSE
                keyUsage         = digitalSignature, keyEncipherment
                extendedKeyUsage = serverAuth
                subjectAltName   = DNS:{$host}
                CONF);

            return $work(['config' => $path, 'digest_alg' => 'sha256', 'x509_extensions' => 'v3_req']);
        } finally {
            @unlink($path);
            @rmdir($directory);
        }
    }
}
