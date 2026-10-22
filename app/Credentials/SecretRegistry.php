<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Credentials;

/**
 * Every secret value this process has handled, so the log scrubber can find it.
 *
 * 🛑 §8.5.21 requires redaction "by **literal, base64 and URL-encoded** match
 * before persistence or broadcast". Pattern matching alone cannot deliver
 * that: a deploy key is base64 with no distinguishing prefix, an OAuth access
 * token from a self-hosted Gitea is an opaque hex string, and neither is
 * recognisable as a secret from its shape. The only reliable way to redact a
 * value is to know the value — so every secret that passes through
 * {@see SecretString} registers itself here, and the three encodings are
 * pre-computed once rather than per log line.
 *
 * 🛑 **This holds plaintext in process memory, deliberately.** It is the same
 * memory the credential already occupies while it is in use, so the exposure
 * is not new; what is new is that it outlives the request if the process is a
 * worker. {@see forget()} is called when a credential is closed, and the
 * registry is capped so a long-lived worker cannot accumulate without bound.
 * Nothing here is ever written to disk, a cache or a queue.
 */
final class SecretRegistry
{
    /**
     * A worker handling thousands of jobs must not grow this without limit.
     * The cap is generous relative to the number of credentials one build or
     * one request touches, and small enough to bound the memory.
     */
    private const MAX_ENTRIES = 256;

    /**
     * Encoded forms, keyed by the literal.
     *
     * @var array<string, list<string>>
     */
    private static array $values = [];

    /**
     * Register a secret and its encodings.
     *
     * Short values are ignored. A three-character secret would match
     * everywhere and turn every log line into redaction marks, which destroys
     * the log's usefulness and therefore the chance anyone reads it. Eight is
     * below any credential a provider in §8.3.1 issues.
     */
    public static function remember(string $value): void
    {
        if (strlen($value) < 8 || isset(self::$values[$value])) {
            return;
        }

        if (count(self::$values) >= self::MAX_ENTRIES) {
            array_shift(self::$values);
        }

        self::$values[$value] = array_values(array_unique(array_filter([
            $value,
            base64_encode($value),
            rtrim(base64_encode($value), '='),
            strtr(rtrim(base64_encode($value), '='), '+/', '-_'),
            rawurlencode($value),
            urlencode($value),
        ], static fn (string $form): bool => strlen($form) >= 8)));
    }

    public static function forget(string $value): void
    {
        unset(self::$values[$value]);
    }

    /** Only for tests, which must not leak registrations into one another. */
    public static function flush(): void
    {
        self::$values = [];
    }

    /**
     * Replace every registered secret, in every encoding, with the marker.
     *
     * Longest first: a credential that contains another registered value as a
     * prefix — a token and the same token with a suffix — must be redacted
     * whole, or the remainder is left in the log as a usable fragment.
     */
    public static function scrub(string $text, string $marker): string
    {
        if (self::$values === [] || $text === '') {
            return $text;
        }

        $forms = array_merge(...array_values(self::$values));
        usort($forms, static fn (string $a, string $b): int => strlen($b) <=> strlen($a));

        return str_replace($forms, $marker, $text);
    }

    public static function count(): int
    {
        return count(self::$values);
    }
}
