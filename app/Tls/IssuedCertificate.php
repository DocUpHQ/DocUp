<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use Illuminate\Support\Carbon;

/**
 * What a {@see CertificateSource} produces: a chain, a key, and the facts
 * read back out of the chain itself.
 *
 * 🛑 Every field after `privateKeyPem` is **parsed from the leaf**, never
 * taken from the issuer's own account of what it issued. A source that
 * reports a `not_after` its certificate does not carry would make §8.10.17's
 * prober agree with the database and disagree with reality, which is the one
 * failure the prober exists to catch.
 */
final readonly class IssuedCertificate
{
    private function __construct(
        public string $chainPem,
        public string $privateKeyPem,
        public string $serial,
        public string $issuer,
        public string $fingerprint,
        public Carbon $notBefore,
        public Carbon $notAfter,
        /** @var list<string> every name the leaf is valid for, lowercased */
        public array $names,
    ) {}

    /**
     * Parse a PEM chain and its key into the facts the store records.
     *
     * @param  string  $chainPem  the leaf first, then intermediates, as a TLS
     *                            handshake wants them
     *
     * @throws CertificateRefused when the chain is unparseable, the key does
     *                            not match the leaf, or either is missing
     */
    public static function fromPem(string $chainPem, string $privateKeyPem): self
    {
        $leaf = @openssl_x509_read($chainPem);

        if ($leaf === false) {
            throw new CertificateRefused(CertificateRejection::ChainUnreadable);
        }

        $key = @openssl_pkey_get_private($privateKeyPem);

        if ($key === false) {
            throw new CertificateRefused(CertificateRejection::KeyUnreadable);
        }

        /*
         * 🛑 The pairing check, and it is not a formality. An operator
         * uploading a replacement commonly pastes the new chain beside the
         * old key, and a mismatched pair is accepted by every parser and
         * rejected by every client — at handshake time, on the live
         * hostname, with no error anywhere in this application.
         */
        if (! openssl_x509_check_private_key($leaf, $key)) {
            throw new CertificateRefused(CertificateRejection::KeyDoesNotMatch);
        }

        $parsed = openssl_x509_parse($leaf);

        if ($parsed === false) {
            throw new CertificateRefused(CertificateRejection::ChainUnreadable);
        }

        $der = '';
        if (! openssl_x509_export($leaf, $der, false)) {
            throw new CertificateRefused(CertificateRejection::ChainUnreadable);
        }

        return new self(
            chainPem: self::normalisePem($chainPem),
            privateKeyPem: trim($privateKeyPem)."\n",
            serial: self::serialOf($parsed),
            issuer: self::issuerOf($parsed),
            fingerprint: hash('sha256', $der),
            notBefore: Carbon::createFromTimestampUTC(self::intOf($parsed, 'validFrom_time_t')),
            notAfter: Carbon::createFromTimestampUTC(self::intOf($parsed, 'validTo_time_t')),
            names: self::namesOf($parsed),
        );
    }

    /** Whether this certificate is valid for a hostname, wildcards included. */
    public function covers(string $host): bool
    {
        $host = strtolower($host);

        foreach ($this->names as $name) {
            if ($name === $host) {
                return true;
            }

            /*
             * 🛑 RFC 6125 §6.4.3: a wildcard matches exactly one label and
             * only the leftmost one. `*.example.com` covers
             * `docs.example.com` and does NOT cover `a.docs.example.com` or
             * `example.com` itself. Matching with a bare suffix test here
             * would make the installation's own wildcard (§8.10.10) appear
             * to cover every tenant's custom domain under it.
             */
            if (str_starts_with($name, '*.')) {
                $suffix = substr($name, 1);              // ".example.com"
                $prefix = substr($host, 0, -strlen($suffix));

                if ($prefix !== '' && str_ends_with($host, $suffix) && ! str_contains($prefix, '.')) {
                    return true;
                }
            }
        }

        return false;
    }

    /** @param  array<array-key, mixed>  $parsed */
    private static function serialOf(array $parsed): string
    {
        $serial = $parsed['serialNumberHex'] ?? $parsed['serialNumber'] ?? '';

        return is_scalar($serial) ? substr((string) $serial, 0, 64) : '';
    }

    /** @param  array<array-key, mixed>  $parsed */
    private static function issuerOf(array $parsed): string
    {
        $issuer = $parsed['issuer'] ?? null;

        if (! is_array($issuer)) {
            return 'unknown';
        }

        $parts = [];

        foreach (['O', 'CN'] as $field) {
            $value = $issuer[$field] ?? null;

            if (is_string($value) && $value !== '') {
                $parts[] = $value;
            }
        }

        return $parts === [] ? 'unknown' : substr(implode(' / ', $parts), 0, 255);
    }

    /** @param  array<array-key, mixed>  $parsed */
    private static function intOf(array $parsed, string $key): int
    {
        $value = $parsed[$key] ?? 0;

        return is_numeric($value) ? (int) $value : 0;
    }

    /**
     * Subject alternative names, falling back to the common name.
     *
     * The fallback is for a development issuer and nothing else: a CA has
     * not issued a certificate whose only name was in the CN since 2017, and
     * every browser stopped reading it before that.
     *
     * @param  array<array-key, mixed>  $parsed
     * @return list<string>
     */
    private static function namesOf(array $parsed): array
    {
        $names = [];
        $extensions = $parsed['extensions'] ?? [];
        $san = is_array($extensions) ? ($extensions['subjectAltName'] ?? '') : '';

        if (is_string($san) && $san !== '') {
            foreach (explode(',', $san) as $entry) {
                $entry = trim($entry);

                if (str_starts_with($entry, 'DNS:')) {
                    $names[] = strtolower(substr($entry, 4));
                }
            }
        }

        if ($names === []) {
            $subject = $parsed['subject'] ?? [];
            $common = is_array($subject) ? ($subject['CN'] ?? null) : null;

            if (is_string($common) && $common !== '') {
                $names[] = strtolower($common);
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * One trailing newline, no leading whitespace, nothing between blocks.
     *
     * The edge concatenates this with the key and hands the result to a TLS
     * library; a stray blank line is tolerated by most parsers and not by
     * all, and "most" is not a property to ship a handshake on.
     */
    private static function normalisePem(string $pem): string
    {
        $blocks = [];

        if (preg_match_all('/-----BEGIN [^-]+-----.*?-----END [^-]+-----/s', $pem, $matches) === false) {
            return trim($pem)."\n";
        }

        foreach ($matches[0] as $block) {
            $blocks[] = trim($block);
        }

        return $blocks === [] ? trim($pem)."\n" : implode("\n", $blocks)."\n";
    }
}
