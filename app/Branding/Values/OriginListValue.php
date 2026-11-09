<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 §8.14.16's `frame-ancestors` token: "a per-project token defaulting to
 * `'self'`, with an explicit origin allowlist and never `*`".
 *
 * The one token whose value is a security header rather than a style, which is
 * why it is a token at all: a per-project embedding allowlist belongs with the
 * other per-project decisions an operator reviews in one place, and §8.14.1's
 * cascade gives an organisation the ability to set it once for every project it
 * owns.
 *
 * ## What `*` would mean, and why it is refused by the grammar
 *
 * `frame-ancestors *` lets any site frame the documentation, which turns a
 * private project into a clickjacking target and makes the reader's session a
 * resource any page can drive. §8.14.16 says "never `*`", and the refusal is
 * here rather than in a controller because a header assembled from a stored
 * value is assembled in more than one place over a product's life.
 *
 * `'none'` **is** accepted: refusing all framing is the strict direction, and
 * an operator who wants it should not have to find another mechanism.
 */
final readonly class OriginListValue implements TokenValue
{
    /** How many origins one allowlist may name. */
    private const MAX_ORIGINS = 16;

    /**
     * The CSP keywords this token admits.
     *
     * 🛑 `'unsafe-inline'`, `'unsafe-eval'` and the nonce and hash forms are
     * absent: they are meaningless in `frame-ancestors`, and admitting a
     * keyword this token cannot use would invite reuse of the type for a
     * directive where they are not meaningless at all.
     *
     * @var list<string>
     */
    private const KEYWORDS = ["'self'", "'none'"];

    /**
     * @param  list<string>  $sources  keywords and origins, in order
     */
    private function __construct(public array $sources) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path): self
    {
        $parts = preg_split('/[\s,]+/', trim($raw), -1, PREG_SPLIT_NO_EMPTY);

        if ($parts === false || $parts === []) {
            throw TokenRefused::of(
                TokenRejection::MalformedOrigin,
                $path,
                "an origin list names at least 'self', 'none' or one https:// origin",
            );
        }

        if (count($parts) > self::MAX_ORIGINS) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                $path,
                sprintf('%d sources; the limit is %d', count($parts), self::MAX_ORIGINS),
            );
        }

        $sources = [];

        foreach ($parts as $part) {
            $sources[] = self::source($part, $path);
        }

        /*
         * 🛑 `'none'` cannot be combined. CSP's own grammar says a source list
         * of `'none'` must be `'none'` alone, and a browser given
         * `'none' https://x` behaves as the more permissive of the two — so a
         * list DocUp accepted would mean the opposite of what it read like.
         */
        if (in_array("'none'", $sources, true) && count($sources) > 1) {
            throw TokenRefused::of(
                TokenRejection::MalformedOrigin,
                $path,
                "'none' cannot be combined with another source",
            );
        }

        return new self(array_values(array_unique($sources)));
    }

    /** @throws TokenRefused */
    private static function source(string $part, string $path): string
    {
        $lower = strtolower($part);

        if ($lower === '*' || str_contains($lower, '*')) {
            /*
             * 🛑 Any wildcard, not only a bare `*`. `https://*.example.com` is
             * CSP-legal and delegates framing to whoever can obtain a
             * subdomain — which on a shared hosting provider is anybody.
             * §8.14.16 says "an explicit origin allowlist", and a wildcard is
             * the opposite of explicit.
             */
            throw TokenRefused::of(
                TokenRejection::WildcardOrigin,
                $path,
                'a wildcard is refused: §8.14.16 requires an explicit origin allowlist and never *',
            );
        }

        if (in_array($lower, self::KEYWORDS, true)) {
            return $lower;
        }

        /*
         * An origin and nothing else: scheme, host, optional port. No path, no
         * query, no userinfo — CSP ignores a path in `frame-ancestors`, so one
         * written here would read as a restriction that was not being applied.
         */
        if (preg_match('#^https?://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$#', $lower) !== 1) {
            throw TokenRefused::of(
                TokenRejection::MalformedOrigin,
                $path,
                sprintf('%s is not a scheme-and-host origin', $part),
            );
        }

        return $lower;
    }

    public function serialise(): string
    {
        return implode(' ', $this->sources);
    }

    public function toStorage(): string
    {
        return $this->serialise();
    }
}
