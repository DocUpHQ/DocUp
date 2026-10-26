<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * 🛑 §8.10.7's normalisation and confusable rejection, stated once.
 *
 * > "Hostnames MUST be normalised to lowercase punycode A-labels, and
 * > mixed-script or Unicode-confusable hostnames MUST be rejected."
 *
 * Two rules and they do different jobs. **Normalisation** makes one hostname
 * one row: `Example.COM`, `example.com.` and `еxample.com`'s A-label must all
 * compare equal or §8.10.5's uniqueness index guards nothing — two spellings
 * of one name would be two proven claims. **Confusable rejection** is about
 * the reader: `аpple.com` with a Cyrillic `а` is a different hostname that
 * looks identical in an address bar, and an installation that issued a
 * certificate for it would be handing out a phishing origin with its own
 * branding on the sign-in page.
 *
 * 🛑 **Rejection is by script mixing within a label**, not by a confusable
 * table. A curated list of lookalike pairs is always incomplete and dates
 * badly; "this label mixes Latin with another script" catches the whole class
 * and is decidable from the string. The cost is that a legitimately mixed
 * label — which is vanishingly rare in a hostname, since registries largely
 * forbid it too — is refused, and that is the right side to err on.
 */
final class Hostname
{
    /** The maximum length of a DNS name, and of `domains.host`. */
    public const MAX_LENGTH = 253;

    /** The maximum length of one label. */
    public const MAX_LABEL = 63;

    /**
     * An A-label after punycode conversion: letters, digits and hyphens, never
     * at an edge. `_` is permitted as a leading character on a label so that
     * `_docup-challenge.<apex>` is expressible, because §8.10.4 names that
     * record and a normaliser that refused it could not describe the proof.
     */
    private const LABEL = '/^_?[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/';

    /**
     * Normalise a hostname to its lowercase punycode A-label form.
     *
     * @throws DomainRefused when it is not a hostname, or when a label mixes
     *                       scripts (§8.10.7)
     */
    public static function normalise(string $input): string
    {
        $host = trim($input);

        // A fully-qualified name's trailing dot is the DNS root, and two rows
        // differing only by it would be two claims on one name.
        $host = rtrim($host, '.');

        if ($host === '') {
            throw DomainRefused::of(DomainRejection::HostMalformed, 'empty');
        }

        /*
         * 🛑 Lowercased BEFORE the confusable check and before punycode.
         * `ⅯAIL.example.com` uses U+216F ROMAN NUMERAL ONE THOUSAND, which
         * case-folds to U+217F — a check that ran first would see one script
         * and the conversion would then produce a different name.
         */
        $host = mb_strtolower($host, 'UTF-8');

        $labels = explode('.', $host);
        $normalised = [];

        foreach ($labels as $label) {
            $normalised[] = self::label($label, $host);
        }

        $result = implode('.', $normalised);

        if (strlen($result) > self::MAX_LENGTH) {
            throw DomainRefused::of(DomainRejection::HostMalformed, 'longer than '.self::MAX_LENGTH.' bytes');
        }

        return $result;
    }

    /** Whether a hostname normalises, for a caller that wants no exception. */
    public static function isUsable(string $input): bool
    {
        try {
            self::normalise($input);

            return true;
        } catch (DomainRefused) {
            return false;
        }
    }

    /**
     * Every apex a hostname could be claimed under, longest first.
     *
     * `docs.api.example.com` yields `api.example.com`, `example.com`, `com` —
     * the hostname itself is **not** included, because §8.10.4's parent claim
     * is about binding a host *under* a claimed apex and a row for the host
     * itself is a per-host claim, which is a different mechanism with a
     * different record.
     *
     * 🛑 This is what replaces §10.5's reversed-label column: a hostname has
     * at most a handful of suffixes, so ancestor lookup is one indexed
     * `whereIn` rather than an unindexable prefix comparison. See the
     * migration for why the reversal bought nothing.
     *
     * @return list<string>
     */
    public static function parentApexes(string $host): array
    {
        $labels = explode('.', $host);
        $apexes = [];

        for ($i = 1; $i < count($labels); $i++) {
            $apexes[] = implode('.', array_slice($labels, $i));
        }

        return $apexes;
    }

    /** Whether `$host` is the apex itself or sits under it. */
    public static function isUnder(string $host, string $apex): bool
    {
        return $host === $apex || str_ends_with($host, '.'.$apex);
    }

    /**
     * Whether a hostname is an apex — a registrable name with no subdomain.
     *
     * A two-label heuristic, deliberately, and its limits are stated rather
     * than papered over: `example.co.uk` is an apex and this calls it a
     * subdomain of `co.uk`. The only correct answer needs the Public Suffix
     * List, which is a 15,000-line file that changes weekly and would have to
     * be fetched, pinned and audited — §8.3.4's whole argument against
     * network dependencies in a decision path. What the answer is *used* for
     * is which DNS instructions to show (§8.10.8), and
     * {@see DnsInstructions} shows the apex case's extra options to anybody
     * who asks, so a wrong guess costs a reader one irrelevant paragraph
     * rather than a broken setup.
     */
    public static function looksLikeApex(string $host): bool
    {
        return substr_count($host, '.') <= 1;
    }

    /**
     * One label, normalised and script-checked.
     *
     * @throws DomainRefused
     */
    private static function label(string $label, string $host): string
    {
        if ($label === '') {
            throw DomainRefused::of(DomainRejection::HostMalformed, 'empty label in '.$host);
        }

        if (preg_match('/^[\x20-\x7e]*$/', $label) !== 1) {
            self::assertSingleScript($label, $host);

            $converted = idn_to_ascii($label, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);

            if (! is_string($converted) || $converted === '') {
                throw DomainRefused::of(DomainRejection::HostMalformed, 'cannot be converted to punycode: '.$label);
            }

            $label = $converted;
        }

        if (strlen($label) > self::MAX_LABEL || preg_match(self::LABEL, $label) !== 1) {
            throw DomainRefused::of(DomainRejection::HostMalformed, 'not a label: '.$label);
        }

        /*
         * 🛑 An `xn--` label that was typed rather than converted. It reaches
         * here as plain ASCII, so the script check above never saw it — and
         * decoding it is the only way to find out what it will render as.
         */
        if (str_starts_with($label, 'xn--')) {
            $decoded = idn_to_utf8($label, IDNA_NONTRANSITIONAL_TO_UNICODE, INTL_IDNA_VARIANT_UTS46);

            if (is_string($decoded) && $decoded !== '' && $decoded !== $label) {
                self::assertSingleScript($decoded, $host);
            }
        }

        return $label;
    }

    /**
     * 🛑 §8.10.7's mixed-script rejection.
     *
     * A label may be wholly Latin, wholly Greek, wholly Cyrillic, wholly Han
     * — but not a mixture, because a mixture is how a lookalike is built.
     * Digits, hyphens and the common/inherited scripts carry no identity and
     * are not counted.
     *
     * @throws DomainRefused
     */
    private static function assertSingleScript(string $label, string $host): void
    {
        $scripts = [];
        $length = mb_strlen($label, 'UTF-8');

        for ($i = 0; $i < $length; $i++) {
            $character = mb_substr($label, $i, 1, 'UTF-8');

            if (preg_match('/[\p{Common}\p{Inherited}]/u', $character) === 1) {
                continue;
            }

            foreach (['Latin', 'Greek', 'Cyrillic', 'Han', 'Hiragana', 'Katakana', 'Hangul', 'Arabic', 'Hebrew', 'Thai', 'Devanagari'] as $script) {
                if (preg_match('/\p{'.$script.'}/u', $character) === 1) {
                    $scripts[$script] = true;

                    continue 2;
                }
            }

            /*
             * A character in none of the scripts above. Refused rather than
             * ignored: an unrecognised script in a hostname is not something
             * to wave through on the grounds that this list is short.
             */
            throw DomainRefused::of(
                DomainRejection::HostConfusable,
                'unrecognised script in '.$host,
            );
        }

        /*
         * Japanese legitimately mixes Han with the two kana, and refusing it
         * would exclude a whole writing system rather than an attack. The
         * three are treated as one script for this purpose, which is what
         * UTS 39's "Japanese" augmented script set does.
         */
        foreach (['Hiragana', 'Katakana'] as $kana) {
            if (isset($scripts[$kana]) && isset($scripts['Han'])) {
                unset($scripts[$kana]);
            }
        }

        if (count($scripts) > 1) {
            throw DomainRefused::of(
                DomainRejection::HostConfusable,
                $host.' mixes '.implode(' and ', array_keys($scripts)),
            );
        }
    }
}
