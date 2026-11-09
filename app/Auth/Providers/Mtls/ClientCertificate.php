<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Mtls;

use App\Auth\Providers\Drivers\MtlsDriver;

/**
 * 🛑 One forwarded client certificate, parsed — and the §8.12.18 boundary for
 * `mtls`: "Protocol validation MUST be framework-enforced, not
 * driver-optional."
 *
 * Every option a driver might want to weaken is absent from this class. There
 * is no `$skipValidity`, no `$allowSelfSigned`, no `$ignoreIssuer`. A
 * certificate either parses into this object or {@see self::parse()} throws, and
 * the three facts a binding pins — issuer, validity window, fingerprint — are
 * methods rather than flags, so the driver can ask and cannot excuse.
 *
 * ## 🛑 What this class can establish, and what it cannot
 *
 * **A certificate is a public document.** It is handed out in every handshake,
 * it is in certificate-transparency logs, and anybody who has ever seen one can
 * copy it byte for byte. Possession of the matching **private key** is what
 * identifies a reader, and that proof exists only inside the TLS handshake —
 * which in DocUp's topology happens at the terminator (§11.3: PHP never
 * terminates TLS).
 *
 * So this class verifies the certificate's **content** and
 * {@see MtlsRejection::HandshakeNotVouched} covers its **possession**,
 * by requiring the terminator to say so. That asymmetry is the whole honest
 * story of the `mtls` driver and {@see MtlsDriver}'s class note states what it
 * buys over `header_trust`.
 *
 * ## 🛑 Why the issuer is compared as a set of attributes
 *
 * An operator will copy the issuer DN from `openssl x509 -noout -issuer`, from
 * a Windows CA console, or from their terminator's log — and those three print
 * the same DN with the attributes in different orders and different spacing. A
 * string comparison would refuse a correct configuration for a cosmetic
 * reason, and the symptom is "nobody can read anything", which an operator
 * fixes by loosening whatever they can reach.
 *
 * So {@see self::issuerMatches()} compares normalised attribute **sets**:
 * attribute names upper-cased, values trimmed and case-folded, sorted. The
 * residual is that two DNs differing only in attribute order compare equal,
 * which no certificate authority produces — and which would in any case still
 * have to be signed by a CA the terminator trusts.
 */
final readonly class ClientCertificate
{
    /**
     * 🛑 A ceiling on the forwarded value, applied before OpenSSL sees it.
     *
     * A certificate with a 4096-bit key and a few extensions is under 2 KB;
     * 16 KB is room for an unusual one and a bound on what an attacker who can
     * reach a trusted hop can make this installation parse. Without it, the
     * header's own size limit — which belongs to the terminator, not to DocUp —
     * would be the only one.
     */
    private const int MAX_BYTES = 16384;

    /**
     * @param  string  $subjectDn  the full subject, normalised for display only
     * @param  string  $issuerDn  the full issuer, normalised for display only
     * @param  string|null  $commonName  the subject's `CN`, or null
     * @param  string|null  $emailAddress  the subject's `emailAddress`, or the
     *                                     first `email:` in the subject
     *                                     alternative name
     * @param  int  $validFrom  `notBefore`, as a Unix timestamp
     * @param  int  $validTo  `notAfter`, as a Unix timestamp
     * @param  string  $fingerprint  lower-case hex SHA-256 of the DER
     * @param  string  $serial  the serial number in hex, for an operator
     *                          matching a revocation list by eye
     * @param  array<string, string|list<string>>  $issuer  the issuer's
     *                                                      attributes as
     *                                                      OpenSSL reports them
     */
    private function __construct(
        public string $subjectDn,
        public string $issuerDn,
        public ?string $commonName,
        public ?string $emailAddress,
        public int $validFrom,
        public int $validTo,
        public string $fingerprint,
        public string $serial,
        private array $issuer,
    ) {}

    /**
     * Parse what the terminator forwarded.
     *
     * 🛑 The validity window is **not** checked here, and the omission is
     * deliberate: this method answers "is this a certificate", and
     * {@see self::assertCurrent()} answers "is it in date". Folding the two
     * would mean a parse failure and an expired certificate were the same
     * exception, and §8.12.23 treats them differently — one is a
     * misconfiguration that must not be reported to a reader, the other is a
     * credential the reader should be told to renew. See
     * {@see MtlsRejection}'s class note.
     *
     * @throws MtlsRefused
     */
    public static function parse(string $raw, CertificateFormat $format): self
    {
        if (strlen($raw) > self::MAX_BYTES) {
            throw MtlsRefused::of(
                MtlsRejection::Unparseable,
                'forwarded value exceeds '.self::MAX_BYTES.' bytes',
            );
        }

        $pem = self::toPem($raw, $format);

        /*
         * 🛑 Silenced, and the error reported as our own. OpenSSL's own
         * warnings reach the PHP error log with the offending bytes in them,
         * and the bytes came from a header.
         */
        $parsed = @openssl_x509_parse($pem);

        if (! is_array($parsed)) {
            throw MtlsRefused::of(
                MtlsRejection::Unparseable,
                'openssl could not read it as a certificate',
            );
        }

        $fingerprint = @openssl_x509_fingerprint($pem, 'sha256');

        if (! is_string($fingerprint) || $fingerprint === '') {
            /*
             * 🛑 Unreachable in practice — a certificate OpenSSL parsed will
             * fingerprint — and kept because the alternative is a `null`
             * fingerprint reaching an allowlist comparison, where "no
             * fingerprint" and "a fingerprint that did not match" would be one
             * value.
             */
            throw MtlsRefused::of(
                MtlsRejection::Unparseable,
                'the certificate parsed and would not fingerprint',
            );
        }

        $subject = self::attributes($parsed, 'subject');
        $issuer = self::attributes($parsed, 'issuer');

        return new self(
            subjectDn: self::dnOf($subject),
            issuerDn: self::dnOf($issuer),
            commonName: self::single($subject, 'CN', 'CN'),
            emailAddress: self::single($subject, 'emailAddress', 'emailAddress')
                ?? self::sanEmail($parsed),
            validFrom: self::timestamp($parsed, 'validFrom_time_t'),
            validTo: self::timestamp($parsed, 'validTo_time_t'),
            fingerprint: strtolower($fingerprint),
            serial: self::stringOf($parsed, 'serialNumberHex'),
            issuer: $issuer,
        );
    }

    /**
     * 🛑 Refuse a certificate outside its validity window.
     *
     * Checked by DocUp as well as by the terminator, which looks redundant and
     * is not: the terminator's trust store and clock are configured separately
     * from DocUp's, and the case this catches is a terminator whose CRL fetch
     * or clock has drifted. It costs one comparison.
     *
     * @throws MtlsRefused
     */
    public function assertCurrent(int $now): void
    {
        if ($this->validTo < $now) {
            throw MtlsRefused::of(MtlsRejection::Expired, $this->serial);
        }

        if ($this->validFrom > $now) {
            throw MtlsRefused::of(MtlsRejection::NotYetValid, $this->serial);
        }
    }

    /**
     * Whether this certificate's issuer is the one a binding pinned.
     *
     * See the class note on why this is a set comparison. An unparseable
     * configured DN returns false rather than matching everything — the
     * difference between a gate that is wrong and a gate that is absent.
     */
    public function issuerMatches(string $configured): bool
    {
        $wanted = self::normaliseDn($configured);

        if ($wanted === '') {
            return false;
        }

        return hash_equals($wanted, self::normaliseDn(self::dnOf($this->issuer)));
    }

    /**
     * The subject value a binding's `subject_attribute` names.
     *
     * 🛑 Returns the certificate's raw value, which may be an email address.
     * Hashing it is {@see MtlsDriver}'s job and not this class's, because this
     * class is also what a probe and an operator-facing diagnostic read — and
     * §8.12.1's rule is about what is **stored and looked up**, not about what
     * is held for the length of one comparison.
     *
     * @throws MtlsRefused
     */
    public function subjectValue(string $attribute): string
    {
        $value = match ($attribute) {
            'common_name' => $this->commonName,
            'email' => $this->emailAddress,
            default => null,
        };

        if ($value === null || $value === '') {
            throw MtlsRefused::of(MtlsRejection::SubjectMissing, $attribute);
        }

        return $value;
    }

    /**
     * The forwarded value as PEM, whatever the terminator did to it.
     *
     * @throws MtlsRefused
     */
    private static function toPem(string $raw, CertificateFormat $format): string
    {
        $raw = trim($raw);

        if ($raw === '') {
            throw MtlsRefused::of(MtlsRejection::Unparseable, 'empty');
        }

        if ($format === CertificateFormat::EscapedPem) {
            /*
             * 🛑 `urldecode` rather than `rawurldecode`, because nginx escapes
             * with `%20` and never with `+` — and `rawurldecode` would leave a
             * literal `+` from the base64 alphabet alone, which is what we
             * want, while `urldecode` would turn it into a space. nginx does
             * not produce `+`-encoded spaces, so the two differ only on input
             * nginx cannot have sent.
             *
             * Measured rather than reasoned: base64 contains `+`, so the wrong
             * choice here corrupts roughly every other certificate and leaves
             * the rest working.
             */
            $raw = rawurldecode($raw);
        }

        /*
         * Strip the armour and every byte of whitespace, then re-wrap. One path
         * for all three formats: {@see CertificateFormat::DerBase64} simply has
         * no armour to strip, so a special case for it would only be a second
         * place to get this wrong. This is what makes
         * {@see CertificateFormat::Pem} tolerant of a terminator that folded
         * the newlines into tabs or spaces, and it leaves a correctly-formed
         * PEM unchanged.
         */
        $body = preg_replace('/-----(BEGIN|END) CERTIFICATE-----/', '', $raw) ?? '';
        $body = preg_replace('/\s+/', '', $body) ?? '';

        if ($body === '' || preg_match('#^[A-Za-z0-9+/]+={0,2}$#', $body) !== 1) {
            throw MtlsRefused::of(
                MtlsRejection::Unparseable,
                'not base64 after decoding as '.$format->value,
            );
        }

        return "-----BEGIN CERTIFICATE-----\n"
            .chunk_split($body, 64, "\n")
            ."-----END CERTIFICATE-----\n";
    }

    /**
     * One section of `openssl_x509_parse()`'s output.
     *
     * 🛑 Values are `string|array` — OpenSSL returns an array when an attribute
     * appears more than once — and narrowing that is the whole reason this
     * method exists rather than an array access at each call site. A `CN` that
     * arrived as an array and was used as a string would be `"Array"`, compared
     * against a configured suffix, and would not match: a refusal reached by
     * accident.
     *
     * @param  array<array-key, mixed>  $parsed
     * @return array<string, string|list<string>>
     */
    private static function attributes(array $parsed, string $section): array
    {
        $raw = $parsed[$section] ?? null;

        if (! is_array($raw)) {
            return [];
        }

        $attributes = [];

        foreach ($raw as $attribute => $value) {
            if (! is_string($attribute) || $attribute === '') {
                continue;
            }

            if (is_string($value)) {
                $attributes[$attribute] = $value;

                continue;
            }

            if (! is_array($value)) {
                continue;
            }

            $many = [];

            foreach ($value as $one) {
                if (is_string($one) && $one !== '') {
                    $many[] = $one;
                }
            }

            if ($many !== []) {
                $attributes[$attribute] = $many;
            }
        }

        return $attributes;
    }

    /**
     * One attribute that must appear exactly once.
     *
     * 🛑 An attribute present twice is {@see MtlsRejection::SubjectAmbiguous}
     * rather than the first of the two. See that case's own note.
     *
     * @param  array<string, string|list<string>>  $attributes
     *
     * @throws MtlsRefused
     */
    private static function single(array $attributes, string $key, string $label): ?string
    {
        $value = $attributes[$key] ?? null;

        if ($value === null) {
            return null;
        }

        if (is_array($value)) {
            throw MtlsRefused::of(
                MtlsRejection::SubjectAmbiguous,
                $label.' appears '.count($value).' times',
            );
        }

        return $value === '' ? null : $value;
    }

    /**
     * The first `email:` in the subject alternative name.
     *
     * Modern certificate authorities put the email in the SAN rather than in
     * the subject DN — RFC 5280 §4.2.1.6 — so a certificate issued in the last
     * decade will have `emailAddress` nowhere else.
     *
     * @param  array<array-key, mixed>  $parsed
     */
    private static function sanEmail(array $parsed): ?string
    {
        $extensions = $parsed['extensions'] ?? null;

        if (! is_array($extensions)) {
            return null;
        }

        $san = $extensions['subjectAltName'] ?? null;

        if (! is_string($san)) {
            return null;
        }

        foreach (explode(',', $san) as $entry) {
            $entry = trim($entry);

            if (stripos($entry, 'email:') === 0) {
                $value = trim(substr($entry, 6));

                return $value === '' ? null : $value;
            }
        }

        return null;
    }

    /**
     * A distinguished name from OpenSSL's attribute array, for display.
     *
     * @param  array<string, string|list<string>>  $attributes
     */
    private static function dnOf(array $attributes): string
    {
        $pairs = [];

        foreach ($attributes as $attribute => $value) {
            foreach (is_array($value) ? $value : [$value] as $one) {
                $pairs[] = strtoupper($attribute).'='.$one;
            }
        }

        return implode(',', $pairs);
    }

    /**
     * A distinguished name as a sorted, case-folded set, for comparison.
     *
     * 🛑 Split on **unescaped** commas only. RFC 4514 escapes a comma inside a
     * value as `\,`, and splitting on every comma would cut `O=Corp\, Inc` in
     * half — turning one attribute into two that happen to compare equal
     * against a configuration cut the same wrong way, and unequal against one
     * that was not.
     */
    private static function normaliseDn(string $dn): string
    {
        $parts = [];

        foreach (preg_split('/(?<!\\\\),/', trim($dn)) ?: [] as $pair) {
            $pair = trim($pair);

            if ($pair === '') {
                continue;
            }

            $equals = strpos($pair, '=');

            if ($equals === false || $equals === 0) {
                /*
                 * 🛑 The whole DN is refused, not the one malformed attribute.
                 * Dropping it would compare a shorter set against a longer one
                 * and could only ever fail — but it would fail for a reason the
                 * operator cannot see, where an empty return makes the probe
                 * say the DN did not parse.
                 */
                return '';
            }

            $parts[] = strtoupper(trim(substr($pair, 0, $equals)))
                .'='.mb_strtolower(trim(substr($pair, $equals + 1)));
        }

        if ($parts === []) {
            return '';
        }

        sort($parts);

        return implode(',', $parts);
    }

    /** @param  array<array-key, mixed>  $parsed */
    private static function timestamp(array $parsed, string $key): int
    {
        $value = $parsed[$key] ?? null;

        return is_int($value) ? $value : 0;
    }

    /** @param  array<array-key, mixed>  $parsed */
    private static function stringOf(array $parsed, string $key): string
    {
        $value = $parsed[$key] ?? null;

        return is_string($value) ? $value : '';
    }
}
