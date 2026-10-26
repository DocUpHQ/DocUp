<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * §8.10.10's own zones, and why nothing inside them is ever issued per host.
 *
 * > "🛑 Certificates for the installation's own wildcard zones MUST be
 * > obtained by a **single DNS-01 wildcard by default**, so creating a
 * > project consumes zero issuances. Per-host HTTP-01 as the default is
 * > rejected: Let's Encrypt's 50-new-certificates-per-registered-domain-per-7-days
 * > ceiling is global across accounts, so bootstrapping 500 projects under
 * > one apex would take roughly eleven weeks."
 *
 * 🛑 The arithmetic is the whole requirement, so it is worth restating where
 * somebody might weaken it: **50 per 7 days is per registered domain, not
 * per account**, so a second ACME account buys nothing, and every project's
 * default subdomain lives under one apex. 500 projects ÷ 50 per week is ten
 * weeks of bootstrap during which most projects have no HTTPS. One wildcard
 * for `*.docs.example.com` costs one issuance for all of them, for ever.
 *
 * 🛑 The corollary §8.10.11 asks this class for: a hostname inside an own
 * zone is **refused** on-demand issuance. Permitting it would mean the proxy
 * quietly issuing per-host certificates for names the wildcard already
 * covers, which is exactly the eleven weeks this requirement exists to avoid
 * — and it would happen silently, because each individual issuance succeeds.
 *
 * The wildcard itself is DNS-01 and therefore needs a registrar API, which
 * §4.2 puts out of scope. The operator obtains it (`certbot --manual`,
 * `lego`, their DNS provider's console, or whatever their organisation
 * already uses) and uploads it through §8.10.14's third source. That is a
 * documented operator step, not a gap: an installation with one wildcard to
 * renew every sixty days is a different operational problem from one with
 * two thousand.
 */
final class WildcardZones
{
    /**
     * The apexes this installation serves its own names under.
     *
     * @return list<string>
     */
    public static function all(): array
    {
        $zones = [];

        foreach (['docs', 'preview', 'assets', 'app'] as $key) {
            $origin = config('docup.origins.'.$key);

            if (! is_string($origin) || $origin === '') {
                continue;
            }

            $host = parse_url($origin, PHP_URL_HOST);
            $host = is_string($host) ? $host : $origin;
            $host = strtolower(trim($host, '.'));

            if ($host !== '' && ! in_array($host, $zones, true)) {
                $zones[] = $host;
            }
        }

        return $zones;
    }

    /**
     * Whether a hostname is covered by a wildcard this installation holds.
     *
     * 🛑 One label, like a real wildcard (RFC 6125 §6.4.3). `*.docs.example.com`
     * covers `project.docs.example.com` and does **not** cover
     * `a.project.docs.example.com` — and the apex itself is covered too,
     * because the operator's certificate carries both names and because an
     * installation that issued per-host for its own apex would be issuing
     * for the one name it is certain to already have.
     */
    public static function covers(string $host): bool
    {
        $host = strtolower(trim($host, '.'));

        foreach (self::all() as $zone) {
            if ($host === $zone) {
                return true;
            }

            if (str_ends_with($host, '.'.$zone)) {
                $label = substr($host, 0, -strlen($zone) - 1);

                if ($label !== '' && ! str_contains($label, '.')) {
                    return true;
                }
            }
        }

        return false;
    }
}
