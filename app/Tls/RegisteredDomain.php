<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * The key §8.10.13's budget is counted against.
 *
 * > "Issuance budgets MUST be tracked per **registered domain** with a
 * > warning at 40 and a hard block at 50 per 7 days."
 *
 * A certificate authority computes the registered domain from the Public
 * Suffix List: `docs.example.co.uk` is registered under `example.co.uk`,
 * `a.github.io` under `a.github.io`, because `github.io` is itself a public
 * suffix.
 *
 * 🛑 **DocUp does not bundle the PSL, and the consequence is deliberate.**
 * The list is a 220 KB data file that changes weekly; a stale copy is a
 * silently wrong rate limiter, and a fresh copy is a scheduled download onto
 * a security-critical path. Instead the last two labels are used, which is
 * exact for the overwhelming majority of names and **wrong in one direction
 * only**:
 *
 *  - `docs.example.com`    → `example.com`      — exact.
 *  - `docs.example.co.uk`  → `co.uk`            — a *superset* of the CA's
 *    `example.co.uk`, so every `.co.uk` host in the installation shares one
 *    bucket and the installation stops issuing **earlier** than the CA would.
 *  - `a.github.io`         → `github.io`        — likewise a superset.
 *
 * Over-grouping costs issuance throughput on a multi-label suffix.
 * Under-grouping would cost the CA's own limit, and a rate limiter that
 * exceeds the limit it is modelling is not a rate limiter. A budget may only
 * ever be wrong in the safe direction, so this is the direction chosen, and
 * it is documented for the operator rather than hidden.
 *
 * An installation that needs exact bucketing on a multi-label suffix can set
 * `DOCUP_PUBLIC_SUFFIXES` to the suffixes it serves under; each named suffix
 * then takes one more label, which is what the PSL would have said.
 */
final class RegisteredDomain
{
    /**
     * @param  list<string>  $extraSuffixes  operator-declared public suffixes,
     *                                       normalised and without a leading dot
     */
    public static function of(string $host, array $extraSuffixes = []): string
    {
        $host = trim(strtolower($host), '.');

        if ($host === '') {
            return '';
        }

        $labels = explode('.', $host);

        if (count($labels) <= 2) {
            return $host;
        }

        /*
         * The operator's list wins where it applies, longest match first, so
         * declaring both `uk` and `co.uk` behaves the way the PSL does
         * rather than the way the array happens to be ordered.
         */
        $suffixes = array_map(static fn (string $s): string => trim(strtolower($s), '.'), $extraSuffixes);
        usort($suffixes, static fn (string $a, string $b): int => substr_count($b, '.') <=> substr_count($a, '.'));

        foreach ($suffixes as $suffix) {
            if ($suffix !== '' && str_ends_with($host, '.'.$suffix)) {
                $depth = substr_count($suffix, '.') + 2;

                return implode('.', array_slice($labels, -$depth));
            }
        }

        return implode('.', array_slice($labels, -2));
    }

    /** The configured suffix list, as `of()` wants it. */
    public static function fromConfig(string $host): string
    {
        $configured = config('tls.public_suffixes');

        $suffixes = [];

        foreach (is_array($configured) ? $configured : [] as $suffix) {
            if (is_string($suffix) && trim($suffix) !== '') {
                $suffixes[] = trim($suffix);
            }
        }

        return self::of($host, $suffixes);
    }
}
