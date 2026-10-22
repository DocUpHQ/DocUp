<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §8.9.6 — the first thing that touches a request, and the only thing that
 * may touch it first.
 *
 * §8.9.6: "Any request path not **byte-identical to its own canonical
 * normalisation** MUST be rejected with 400, **before any cache lookup or
 * resolution**. This is the web-cache-deception defence and its position in the
 * pipeline is the whole of its value."
 *
 * Read that last clause carefully, because it is unusual for a specification to
 * say it. A 400 returned *after* a cache lookup satisfies the status code and
 * none of the requirement: the poisoned entry is already stored. So this class
 * has no dependencies at all — no container, no config, no models — and the
 * middleware that calls it runs before anything else on the documentation
 * origin. Its purity is what makes the ordering auditable.
 *
 * **Why byte-identity rather than normalisation.** Normalising `/a//b/../c` to
 * `/a/c` and serving it means one document has unboundedly many URLs. Every one
 * of them is a distinct cache key, and the attacker picks the key. Rejecting
 * instead collapses the surface to one URL per document, which is also what
 * makes a strong ETag meaningful.
 *
 * **Why the check is on the raw bytes.** Corpus case `path-002` is
 * `/en/latest/%2e%2e%2f%2e%2e%2fetc/passwd`, and its note is the whole lesson:
 * "must be rejected on the raw path, not after decoding". A decode-then-check
 * implementation is one decode away from `path-003`'s double-encoded variant,
 * and then one more away from the next. Checking canonicality of the bytes as
 * they arrived has no such ladder.
 */
final class CanonicalPath
{
    /**
     * Bytes permitted to appear raw in a path segment.
     *
     * RFC 3986's `pchar` minus `;` and minus `%`. `;` is excluded because it is
     * the path-parameter half of the cache-deception pair (corpus
     * `cache_deception-002`); `%` only ever appears as the start of an escape,
     * and a literal one arrives as `%25`.
     *
     * Everything else — including every non-ASCII byte — must be
     * percent-encoded. That is what browsers send, and requiring it means one
     * byte sequence per document rather than two.
     */
    private const RAW_ALLOWED = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&\'()*+,=:@';

    /**
     * Bytes that must never appear, raw or encoded.
     *
     * `/` is the separator and may not be smuggled into a segment as `%2F`;
     * `\` is refused outright; `;`, `?` and `#` are delimiters whose literal
     * presence in a served path is always either an attack or a mistake.
     *
     * 🛑 `%` is in this list, which means `%25` is refused and **no path DocUp
     * serves may contain a literal percent sign**. That is a deliberate
     * restriction with a real cost — a document named `100%.html` cannot be
     * served — taken for corpus case `path-003`,
     * `/en/latest/%252e%252e%252fadmin`, whose note reads "double-encoded; a
     * single decode pass would let this through".
     *
     * `%252e` is the *correct* canonical encoding of the literal text `%2e`, so
     * byte-identity alone accepts it. It is only dangerous if something later
     * decodes the path a second time — a CDN, a proxy, a storage backend — at
     * which point it becomes `..` inside a path that was already validated.
     * Refusing the literal percent removes the ladder entirely rather than
     * guessing how many decodes the stack performs. The alternative, accepting
     * `%25` and auditing every downstream hop forever, is the kind of defence
     * that holds until somebody adds a CDN.
     */
    private const NEVER_DECODED = '/\\;?#%';

    /**
     * Extensions whose presence in a **non-final** segment is the
     * cache-deception shape.
     *
     * Kept to document types rather than every known extension: the attack
     * needs the *final* segment to look cacheable and static, which is why the
     * check is on the earlier segment looking like a document. A directory
     * named `x.css` is odd but harmless; one named `x.html` is the attack.
     */
    private const DOCUMENT_EXTENSIONS = ['html', 'htm', 'xhtml', 'pdf', 'epub', 'txt', 'json', 'xml'];

    /**
     * The ceiling on a request path, in bytes.
     *
     * Below any real limit a web server imposes, and here so that the checks
     * below are bounded work on attacker-chosen input rather than merely
     * bounded by whatever the edge happened to accept.
     */
    private const MAX_BYTES = 2048;

    /**
     * The §8.9.6 gate.
     *
     * @param  string  $path  the raw request path, exactly as it arrived, with
     *                        no decoding and no normalisation applied
     * @return RejectionReason|null null when the path is its own canonical form
     */
    public static function reject(string $path): ?RejectionReason
    {
        if (strlen($path) > self::MAX_BYTES) {
            return RejectionReason::PathTooLong;
        }

        if (! str_starts_with($path, '/')) {
            return RejectionReason::PathNotAbsolute;
        }

        /*
         * Checked on the whole raw string before anything splits it, because a
         * NUL truncates the path in any C library that later sees it — so
         * `safe.html%00.css` would be validated as one path and opened as
         * another. Corpus case `path-004`.
         */
        if (preg_match('/[\x00-\x1F\x7F]/', $path) === 1) {
            return RejectionReason::PathControlByte;
        }

        if (str_contains($path, '\\')) {
            return RejectionReason::PathBackslash;
        }

        // `//` anywhere. This also catches the protocol-relative `//evil.com`
        // of corpus case `path-007`, which a normalising implementation would
        // happily turn into a redirect target.
        if (str_contains($path, '//')) {
            return RejectionReason::PathEmptySegment;
        }

        $segments = explode('/', substr($path, 1));
        $last = count($segments) - 1;

        foreach ($segments as $index => $segment) {
            // A trailing slash leaves one empty final segment, which is the
            // directory form and is legitimate (§8.9.7 redirects to it).
            if ($segment === '' && $index === $last) {
                continue;
            }

            if ($segment === '') {
                return RejectionReason::PathEmptySegment;
            }

            $reason = self::rejectSegment($segment);

            if ($reason !== null) {
                return $reason;
            }

            /*
             * 🛑 The cache-deception check, on every segment but the last.
             * See RejectionReason::PathSuffixConfusion for why this is
             * structural rather than an existence check.
             */
            if ($index !== $last && self::looksLikeADocument($segment)) {
                return RejectionReason::PathSuffixConfusion;
            }
        }

        return null;
    }

    /** Whether a path is already canonical. */
    public static function isCanonical(string $path): bool
    {
        return self::reject($path) === null;
    }

    /**
     * Every rule that applies within one segment.
     *
     * Split out so the dot-segment and escape rules are applied to the segment
     * **as it arrived** and to its decoded form in the same place. A `.`
     * smuggled as `%2E` is a dot segment; checking the two forms in different
     * methods is how one of them ends up unchecked.
     */
    private static function rejectSegment(string $segment): ?RejectionReason
    {
        $decoded = '';
        $length = strlen($segment);

        for ($i = 0; $i < $length; $i++) {
            $byte = $segment[$i];

            if ($byte !== '%') {
                if (! str_contains(self::RAW_ALLOWED, $byte)) {
                    return RejectionReason::PathIllegalByte;
                }

                $decoded .= $byte;

                continue;
            }

            $hex = substr($segment, $i + 1, 2);

            if (strlen($hex) !== 2 || preg_match('/^[0-9A-F]{2}$/', $hex) !== 1) {
                /*
                 * Uppercase hex only. RFC 3986 §6.2.2.1 makes uppercase the
                 * normal form, so `%2f` and `%2F` are two spellings of one
                 * path — and two cache keys. Rejecting the lowercase spelling
                 * costs nothing: every client that percent-encodes emits
                 * uppercase.
                 */
                return RejectionReason::PathNonCanonicalEscape;
            }

            /*
             * `hex2bin` then `ord`, rather than `chr(hexdec(...))`. Two hex
             * digits are a byte, and going through the byte makes that true by
             * construction instead of true by argument — `hexdec` returns
             * `int|float`, so the analyser cannot see that the regex above
             * bounds it to 0..255, and clamping to satisfy it would add a branch
             * that can never be taken.
             *
             * The regex guarantees two uppercase hex digits, so hex2bin cannot
             * fail here; the fallback keeps the types honest without pretending
             * the branch is reachable.
             */
            $byte = hex2bin($hex);
            $char = $byte === false ? "\0" : $byte;
            $value = ord($char);
            $i += 2;

            if ($value <= 0x1F || $value === 0x7F) {
                return RejectionReason::PathControlByte;
            }

            if (str_contains(self::NEVER_DECODED, $char)) {
                // `%2F`, `%5C`, `%3B`, `%3F`, `%23`. A separator or delimiter
                // smuggled into a segment, which is corpus case `path-002`'s
                // mechanism.
                return RejectionReason::PathIllegalByte;
            }

            if ($value < 0x80 && str_contains(self::RAW_ALLOWED, $char)) {
                // Over-encoded: this byte did not need escaping, so the path is
                // not its own canonical form. `%2E` for `.`, `%61` for `a`.
                return RejectionReason::PathNonCanonicalEscape;
            }

            $decoded .= $char;
        }

        /*
         * The dot check runs on the DECODED segment.
         *
         * In practice it only ever fires for a *literal* `.` or `..`: the
         * over-encoding rule above refuses `%2E` first, because `.` never needs
         * escaping, and `%` itself is refused so there is no second decode to
         * worry about. So this is not the line that stops an encoded traversal —
         * canonicality is. It is kept as the one that stops the plain traversal,
         * and as the line that would still stop an encoded one if the
         * canonicality rules were ever relaxed. Said plainly because a comment
         * claiming this check catches `%2E%2E` would be describing an intention
         * rather than the code.
         */
        if ($decoded === '.' || $decoded === '..') {
            return RejectionReason::PathDotSegment;
        }

        // A decoded segment must be well-formed UTF-8. A lone continuation byte
        // is not a filename; it is a decoder probe.
        if ($decoded !== '' && preg_match('//u', $decoded) !== 1) {
            return RejectionReason::PathNotUtf8;
        }

        return null;
    }

    /**
     * Whether a segment carries a document extension.
     *
     * Case-insensitive, because `INDEX.HTML` is the same attack as
     * `index.html` and a case-sensitive check would be a one-character bypass.
     */
    private static function looksLikeADocument(string $segment): bool
    {
        $dot = strrpos($segment, '.');

        if ($dot === false || $dot === 0) {
            return false;
        }

        return in_array(strtolower(substr($segment, $dot + 1)), self::DOCUMENT_EXTENSIONS, true);
    }
}
