<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Models\Domain;

/**
 * 🛑 §8.10.19's HSTS rules.
 *
 * > "HSTS MUST default to **off**. 🛑 `includeSubDomains` and `preload` MUST
 * > be validation errors on any shared apex or any hostname that is a DNS
 * > suffix of another claimed hostname — one tenant must not be able to
 * > break HTTPS for another."
 *
 * The attack is a denial of service that nobody can undo. `includeSubDomains`
 * on `example.com` tells every browser that reaches it that **everything**
 * under `example.com` must be HTTPS, for `max-age` seconds — including
 * `legacy.example.com`, which belongs to a different tenant and serves plain
 * HTTP. The victim cannot fix it from their own configuration, and the
 * header is cached in the browser, so removing it tomorrow does not help
 * anybody who already visited. `preload` is the same thing baked into
 * browser binaries, where the removal process takes months.
 *
 * 🛑 **Off by default, and the default is the column's.** `hsts_max_age` is
 * nullable with no default, so a domain created by any path — the API, a
 * seeder, an import — has HSTS off without that path having to know HSTS
 * exists.
 */
final class HstsPolicy
{
    /**
     * A sane maximum, so a typo cannot pin a hostname for a decade.
     *
     * Two years is the preload list's own requirement and a reasonable
     * ceiling for everything else; a longer value is almost always a
     * misplaced digit, and a misplaced digit here is unrecoverable.
     */
    public const MAX_AGE_CEILING = 63_072_000;

    /**
     * Validate a proposed policy for a hostname.
     *
     * `$otherClaimedHosts` is every **proven** hostname on the installation
     * other than this one. The caller supplies it rather than this class
     * querying, so the rule stays pure and the one query lives with the
     * other domain queries.
     *
     * @param  list<string>  $otherClaimedHosts
     *
     * @throws DomainRefused
     */
    public static function assertUsable(
        Domain $domain,
        ?int $maxAge,
        bool $includeSubdomains,
        bool $preload,
        array $otherClaimedHosts,
    ): void {
        if ($maxAge !== null && ($maxAge < 0 || $maxAge > self::MAX_AGE_CEILING)) {
            throw DomainRefused::of(
                DomainRejection::HstsWouldSpanTenants,
                'max-age must be between 0 and '.self::MAX_AGE_CEILING,
            );
        }

        if (! $includeSubdomains && ! $preload) {
            return;
        }

        /*
         * 🛑 `preload` implies `includeSubDomains` in the preload list's own
         * rules, so permitting it without the flag would be a way around
         * everything below. Refused here rather than silently corrected: an
         * operator who asked for one and got the other has a configuration
         * that does not say what it does.
         */
        if ($preload && ! $includeSubdomains) {
            throw DomainRefused::of(
                DomainRejection::HstsWouldSpanTenants,
                'preload requires includeSubDomains',
            );
        }

        if ($domain->shared_origin) {
            throw DomainRefused::of(
                DomainRejection::HstsWouldSpanTenants,
                $domain->host.' is a shared origin',
            );
        }

        foreach ($otherClaimedHosts as $other) {
            /*
             * 🛑 The directive reaches every name **under** this one. A
             * hostname that is this one, or that sits beneath it, is a
             * tenant whose HTTPS this header would decide.
             */
            if ($other !== $domain->host && Hostname::isUnder($other, $domain->host)) {
                throw DomainRefused::of(
                    DomainRejection::HstsWouldSpanTenants,
                    $other.' sits under '.$domain->host,
                );
            }
        }
    }

    /**
     * The header value, or null when HSTS is off.
     *
     * Null rather than `max-age=0`: §8.10.19 says HSTS defaults to off, and
     * `max-age=0` is not "off" but "actively clear any policy you have",
     * which is a different instruction to a browser and not one an operator
     * who never enabled HSTS asked us to send.
     */
    public static function header(Domain $domain): ?string
    {
        if ($domain->hsts_max_age === null) {
            return null;
        }

        $value = 'max-age='.$domain->hsts_max_age;

        if ($domain->hsts_include_subdomains) {
            $value .= '; includeSubDomains';
        }

        if ($domain->hsts_preload) {
            $value .= '; preload';
        }

        return $value;
    }
}
