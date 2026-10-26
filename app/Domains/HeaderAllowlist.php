<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Serving\ArtifactHandoff;

/**
 * 🛑 §8.10.22's single shared allowlist of per-domain response headers.
 *
 * > "Per-domain custom response headers MUST be restricted to a single shared
 * > allowlist constant, asserted byte-identical between the application and
 * > the proxy configuration by an automated test."
 *
 * **Byte-identical** is the operative word, and the reason is that the two
 * failure modes are both silent. A header the application accepts and the
 * proxy strips looks to an operator like their configuration did not save. A
 * header the proxy passes and the application never validated is an
 * injection point on every response from that hostname. Neither shows up as
 * an error anywhere, so the lists are compared character for character by
 * `HeaderAllowlistTest` rather than kept in step by discipline.
 *
 * 🛑 **Nothing in §8.9.8's preserved set may appear here.** Those headers
 * carry the authorisation and caching decisions of the serving path —
 * `Cache-Control`, `Vary`, `ETag`, `Content-Type` — and an operator
 * overriding one is overriding a decision rather than decorating a response.
 * {@see self::assertDisjointFromHandoff()} is what keeps that true as both
 * lists grow, and the test calls it.
 */
final class HeaderAllowlist
{
    /** Where the proxy reads the same list from. */
    public const FILE = 'deploy/header-allowlist.conf';

    /**
     * The allowlist, lowercase, in the file's order.
     *
     * Order is part of "byte-identical": a list that agreed as a set and
     * differed in order would pass a set comparison and fail the one the
     * requirement asks for, and a reader diffing the two files would see
     * noise.
     *
     * @var list<string>
     */
    public const NAMES = [
        'content-security-policy',
        'content-security-policy-report-only',
        'cross-origin-embedder-policy',
        'cross-origin-opener-policy',
        'cross-origin-resource-policy',
        'permissions-policy',
        'referrer-policy',
        'report-to',
        'x-dns-prefetch-control',
        'x-frame-options',
        'x-permitted-cross-domain-policies',
    ];

    /**
     * Whether an operator may set this header on a domain.
     *
     * Case-insensitive, because HTTP field names are — and a check that was
     * not would accept `X-Frame-Options` from one client and refuse it from
     * another.
     */
    public static function permits(string $name): bool
    {
        return in_array(strtolower(trim($name)), self::NAMES, true);
    }

    /**
     * Validate a whole header set.
     *
     * @param  array<string, string>  $headers
     *
     * @throws DomainRefused
     */
    public static function assertUsable(array $headers): void
    {
        foreach (array_keys($headers) as $name) {
            if (! self::permits((string) $name)) {
                throw DomainRefused::of(DomainRejection::HeaderNotAllowed, (string) $name);
            }
        }
    }

    /**
     * The names the proxy configuration file lists.
     *
     * @return list<string>
     */
    public static function fromFile(string $path): array
    {
        $names = [];

        foreach (explode("\n", (string) file_get_contents($path)) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $names[] = $line;
        }

        return $names;
    }

    /**
     * 🛑 The headers the serving path **decides**, which an operator may
     * never override.
     *
     * Not simply "everything in §8.9.8's preserved set", and the distinction
     * is a finding rather than a convenience. Most of that set carries a
     * decision: `Cache-Control` and `Vary` are §9.3.2's privacy answer,
     * `ETag` and `Last-Modified` are the validators, `Content-Type` and
     * `Content-Disposition` are §8.9.11's, `X-Content-Type-Options` is
     * §8.9.11's unconditional `nosniff`, `X-Robots-Tag` is **derived** from
     * §8.10.2's canonical mode so "the canonical domain is never silently
     * noindexed", and `Link` carries `rel=canonical` and `hreflang`.
     * Overriding any of those is overriding a decision — the worst case
     * being a private project's pages made publicly cacheable from one
     * hostname's configuration.
     *
     * `Content-Security-Policy` is the exception, and it is the header the
     * whole feature exists for: DocUp sets a default and a per-domain policy
     * **replacing** it is exactly what an operator configuring one wants. So
     * it is in the allowlist and absent here, deliberately.
     *
     * @var list<string>
     */
    public const SERVING_DECISIONS = [
        'cache-control',
        'cdn-cache-control',
        'vary',
        'cache-tag',
        'content-type',
        'content-disposition',
        'content-encoding',
        'link',
        'x-robots-tag',
        'x-content-type-options',
        'etag',
        'last-modified',
    ];

    /**
     * Any allowlisted header that would override a serving-path decision.
     *
     * @return list<string> empty when the two are properly separated
     */
    public static function assertDisjointFromHandoff(): array
    {
        return array_values(array_intersect(self::NAMES, self::SERVING_DECISIONS));
    }

    /**
     * 🛑 Every protected header is one the serving path actually sets.
     *
     * Without this the list above could drift into a set of names nobody
     * emits, and would then protect nothing while looking like it did.
     *
     * @return list<string> protected names §8.9.8 does not preserve
     */
    public static function unmatchedServingDecisions(): array
    {
        $preserved = array_map(strtolower(...), ArtifactHandoff::PRESERVED_HEADERS);

        return array_values(array_diff(self::SERVING_DECISIONS, $preserved));
    }
}
