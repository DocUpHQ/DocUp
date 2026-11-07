<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

use App\Auth\OrganisationContext;
use App\Domains\Hostname;
use App\Models\Domain;

/**
 * 🛑 §8.11.2's target rule, which is the one that keeps a redirect from
 * becoming an attack.
 *
 * > "Targets MUST be root-relative same-origin paths matching the §7.3
 * > grammar; an absolute `http(s)://` target MUST be either refused at save
 * > time or permitted only to a hostname the same organisation has verified,
 * > so a redirect rule cannot become an open redirect or a
 * > traffic-exfiltration primitive."
 *
 * **DocUp takes the second reading**, and it is the stricter one in
 * practice. "Refuse every absolute target" sounds safer and is not: an
 * organisation that moved its guide from `docs.example.com` to
 * `handbook.example.com` genuinely needs the redirect, and refusing it means
 * they keep the old project alive forever or point a rule at `/` and lose
 * the page. Phase 18 already built the predicate that makes the permissive
 * reading safe — a **proven** claim is `domains.claimed_host IS NOT NULL`
 * for a domain that organisation owns — so the check is a lookup, not a
 * judgement.
 *
 * 🛑 The two things this refuses are worth naming, because they are what a
 * redirect rule turns into when nobody checks:
 *
 *  - an **open redirect**: `https://docs.example.com/login` → an attacker's
 *    host, on a domain readers trust, which is a phishing primitive and a
 *    way past an OAuth redirect allowlist;
 *  - **traffic exfiltration**: a rule nobody reads pointing a popular page
 *    at a host that logs the `Referer` and the reader's address.
 *
 * Neither needs a vulnerability. Both need one careless row.
 */
final class RedirectTarget
{
    /** Long enough for a deep path under a component mount; short enough to log. */
    public const int MAX_BYTES = 1024;

    /**
     * Validate a target and return it normalised.
     *
     * @param  string  $organisationId  raw 16 bytes; the organisation whose
     *                                  proven hostnames an absolute target
     *                                  may point at
     *
     * @throws RedirectRefused
     */
    public static function normalise(string $target, string $organisationId): string
    {
        $target = trim($target);

        if ($target === '' || strlen($target) > self::MAX_BYTES) {
            throw RedirectRefused::of(
                RedirectRejection::TargetMalformed,
                $target === '' ? 'empty' : strlen($target).' bytes, over the '.self::MAX_BYTES.'-byte cap',
            );
        }

        /*
         * 🛑 Control bytes and whitespace first, before anything parses.
         *
         * A `Location` header carrying CR or LF is response splitting, and
         * the checks below would otherwise be reasoning about a string the
         * header writer will treat as two. The same refusal covers a tab,
         * which some clients strip before following and some do not —
         * disagreement between a validator and a client is where this class
         * of bug lives.
         */
        if (preg_match('/[\x00-\x20\x7f]/', $target) === 1) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'control byte or whitespace');
        }

        /*
         * 🛑 A scheme-relative target (`//evil.test/`) is an absolute URL
         * that looks relative, and it is the single most common way an
         * open-redirect check is bypassed. Refused before the
         * root-relative branch, because it starts with a slash and would
         * otherwise take it.
         *
         * `/\` is the same attack for the browsers that normalise a
         * backslash to a slash, which is all of them.
         */
        if (str_starts_with($target, '//') || str_starts_with($target, '/\\')) {
            throw RedirectRefused::of(
                RedirectRejection::TargetMalformed,
                'a scheme-relative target is an absolute URL wearing a relative shape',
            );
        }

        if (str_starts_with($target, '/')) {
            return self::rootRelative($target);
        }

        return self::absolute($target, $organisationId);
    }

    /**
     * Whether a target leaves this origin — the engine needs to know,
     * because a cross-origin target cannot participate in the hop cap.
     */
    public static function isAbsolute(string $target): bool
    {
        return ! str_starts_with($target, '/');
    }

    /** @throws RedirectRefused */
    private static function rootRelative(string $target): string
    {
        /*
         * §7.3's grammar, as far as a target is concerned: no dot segments,
         * no empty segments, no backslash. The serving path's own
         * `CanonicalPath` refuses those on the way **in**; a target that
         * produced one would be a `Location` the next request rejects with
         * a 400, which reads to the reader as the site being broken rather
         * than as a bad rule.
         */
        [$path, $query] = self::splitQuery($target);

        foreach (explode('/', ltrim($path, '/')) as $segment) {
            if ($segment === '.' || $segment === '..') {
                throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'dot segment in "'.$path.'"');
            }
        }

        if (str_contains($path, '//')) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'empty segment in "'.$path.'"');
        }

        if (str_contains($target, '\\')) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'backslash in "'.$target.'"');
        }

        return $path.$query;
    }

    /** @throws RedirectRefused */
    private static function absolute(string $target, string $organisationId): string
    {
        $parts = parse_url($target);

        if ($parts === false || ! isset($parts['scheme'], $parts['host'])) {
            throw RedirectRefused::of(
                RedirectRejection::TargetMalformed,
                'neither a root-relative path nor an absolute URL',
            );
        }

        $scheme = strtolower((string) $parts['scheme']);

        if ($scheme !== 'http' && $scheme !== 'https') {
            throw RedirectRefused::of(
                RedirectRejection::TargetSchemeRefused,
                $scheme.': only http and https may appear in a Location this application writes',
            );
        }

        /*
         * 🛑 Credentials in the authority are refused outright. A target of
         * `https://docs.example.com@evil.test/` points at `evil.test` and
         * reads to a human as `docs.example.com` — the oldest confusion in
         * URL parsing, and the one a reviewer approving a redirect rule is
         * most likely to miss.
         */
        if (isset($parts['user']) || isset($parts['pass'])) {
            throw RedirectRefused::of(
                RedirectRejection::TargetMalformed,
                'credentials in the authority: this URL does not point where it reads',
            );
        }

        try {
            $host = Hostname::normalise((string) $parts['host']);
        } catch (\Throwable $refused) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, $refused->getMessage());
        }

        if (! self::isProvenBy($host, $organisationId)) {
            throw RedirectRefused::of(
                RedirectRejection::TargetNotProven,
                $host.' is not a hostname this organisation has proven (§8.10.4); '.
                'an absolute target to an unproven host is an open redirect',
            );
        }

        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = isset($parts['path']) && $parts['path'] !== '' ? (string) $parts['path'] : '/';
        $query = isset($parts['query']) ? '?'.$parts['query'] : '';

        return $scheme.'://'.$host.$port.$path.$query;
    }

    /**
     * 🛑 A **proven** claim, held by **this** organisation.
     *
     * Both halves matter. Without "proven", a tenant could add a domain
     * they do not control, never verify it, and use it as a redirect target
     * — which is the open redirect again with an extra step. Without "this
     * organisation", one tenant could point their readers at another
     * tenant's host.
     *
     * The query spans tenants because the question is about ownership and a
     * scope would answer it by hiding the row; the organisation is then
     * compared explicitly, which is the only way to get a "no" that means
     * "somebody else's" rather than "none".
     */
    private static function isProvenBy(string $host, string $organisationId): bool
    {
        return app(OrganisationContext::class)->acrossAllOrganisations(
            static fn (): bool => Domain::query()
                ->where('claimed_host', $host)
                ->where('organisation_id', $organisationId)
                ->exists(),
        );
    }

    /** @return array{0: string, 1: string} */
    private static function splitQuery(string $target): array
    {
        $at = strpos($target, '?');

        return $at === false ? [$target, ''] : [substr($target, 0, $at), substr($target, $at)];
    }
}
