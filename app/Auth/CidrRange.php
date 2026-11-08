<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Auth\Providers\Drivers\IpAllowlistDriver;
use App\Egress\IpAddressClassifier;
use App\Http\Middleware\OnlyFromLoopback;

/**
 * 🛑 One address-range matcher, for everything in DocUp that compares a client
 * address against an operator's list.
 *
 * Two features need this: §8.12.17's `ip_allowlist` reader gate and §8.13.6's
 * "optional CIDR binding" on a dashboard API token. Phase 23 wrote the first
 * one inside {@see IpAllowlistDriver}; Phase 26b needed the second and
 * extracted it here rather than writing it twice.
 *
 * ## 🛑 Why a second copy would have been a bug and not just duplication
 *
 * The subtleties are not obvious and each one is a bypass if it is got wrong in
 * one of two places:
 *
 * - **Different families must never match.** Without the length check an IPv4
 *   address and an IPv6 range would be compared over the shorter length, and a
 *   short prefix would appear to cover everything.
 * - 🛑 **An IPv4-mapped IPv6 address never matches an IPv4 range**, and
 *   that is a decision rather than a consequence: it is `provider-013` in the
 *   permanent abuse corpus (§9.4), whose note reads *"an allowlist that
 *   normalised the mapped form would admit from a family the operator never
 *   entered"*.
 *
 *   🛑 The asymmetry with {@see IpAddressClassifier}, which
 *   **does** normalise `::ffff:` forms, is the whole point and not an
 *   inconsistency. A **deny** list must recognise every spelling of a
 *   forbidden address or an attacker picks the one it misses; an **allow** list
 *   must refuse every spelling the operator did not enter, because there the
 *   fail-closed direction is refusal. Phase 26b nearly normalised this while
 *   adding §8.13.6's token binding, and the corpus case is what stopped it.
 *
 *   An operator who needs both spellings lists both, which is exactly what
 *   {@see OnlyFromLoopback} does.
 * - **Host bits must be zeroed.** `10.0.0.1/8` means `10.0.0.0/8`, and storing
 *   the operator's spelling while comparing against the network means the UI
 *   shows a range that is not the one in force.
 *
 * Two implementations would agree on the easy cases and diverge on exactly
 * these, which is the shape of a hole nobody finds by reading either one.
 *
 * 🛑 In `App\Auth` rather than `App\Support` deliberately: §9.4 raises PHPStan
 * to level 9 for `app/Auth` because "a type error in authorisation code is a
 * security bug rather than a crash", and moving this to a level-8 namespace
 * would LOWER the bar on code whose only job is to decide whether an address is
 * admitted. CLAUDE.md's gate rule forbids that, and the rule is right here:
 * every refusal in this file fails closed, which is only safe while the types
 * are checked.
 */
final readonly class CidrRange
{
    /**
     * Whether a range covers an address.
     *
     * 🛑 Compared on **packed bytes**, same family only, host bits masked. See
     * the class note for why each of those three is load-bearing.
     */
    public static function covers(string $range, string $address): bool
    {
        $parsed = self::parse($range);
        $packed = @inet_pton($address);

        if ($parsed === null || $packed === false) {
            return false;
        }

        if (strlen($packed) !== strlen($parsed['packed'])) {
            return false;
        }

        $bits = $parsed['bits'];
        $fullBytes = intdiv($bits, 8);
        $remainder = $bits % 8;

        if ($fullBytes > 0 && ! hash_equals(
            substr($parsed['packed'], 0, $fullBytes),
            substr($packed, 0, $fullBytes),
        )) {
            return false;
        }

        if ($remainder === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($packed[$fullBytes]) & $mask) === (ord($parsed['packed'][$fullBytes]) & $mask);
    }

    /**
     * Whether any range in a list covers an address.
     *
     * 🛑 **No early return.** The loop runs to the end whatever it finds, so the
     * time taken does not depend on which entry matched — the same discipline
     * `MtlsDriver` applies to its fingerprint list. An allowlist is not a
     * secret, but the position of a match in it is information about the
     * operator's network that costs nothing to withhold.
     *
     * @param  list<string>  $ranges
     */
    public static function anyCovers(array $ranges, string $address): bool
    {
        $covered = false;

        foreach ($ranges as $range) {
            $covered = self::covers($range, $address) || $covered;
        }

        return $covered;
    }

    /**
     * The canonical spelling of a range, or null when it is not one.
     *
     * A bare address is a host route — `/32` for IPv4, `/128` for IPv6 — which
     * is what an operator typing one address means.
     *
     * 🛑 Host bits are **zeroed**, so `10.0.0.1/8` canonicalises to
     * `10.0.0.0/8`. The canonical form is what is stored, what the dashboard
     * shows and what the comparison uses, and an operator must never see a
     * range in the UI that differs from the one in force.
     */
    public static function canonicalise(string $range): ?string
    {
        return self::parse($range)['canonical'] ?? null;
    }

    /**
     * Parse a range into its network, prefix and canonical spelling.
     *
     * @return array{packed: string, bits: int, canonical: string}|null
     */
    private static function parse(string $range): ?array
    {
        $range = trim($range);

        if ($range === '') {
            return null;
        }

        $slash = strrpos($range, '/');
        $address = $slash === false ? $range : substr($range, 0, $slash);
        $packed = @inet_pton($address);

        if ($packed === false) {
            return null;
        }

        $width = strlen($packed) * 8;

        if ($slash === false) {
            $bits = $width;
        } else {
            $suffix = substr($range, $slash + 1);

            if ($suffix === '' || preg_match('/^\d{1,3}$/', $suffix) !== 1) {
                return null;
            }

            $bits = (int) $suffix;

            if ($bits > $width) {
                return null;
            }
        }

        $network = self::maskTo($packed, $bits);
        $printable = @inet_ntop($network);

        if ($printable === false) {
            return null;
        }

        return [
            'packed' => $network,
            'bits' => $bits,
            'canonical' => $printable.'/'.$bits,
        ];
    }

    /** Zero every bit after the prefix. */
    private static function maskTo(string $packed, int $bits): string
    {
        $bytes = str_split($packed);

        foreach ($bytes as $index => $byte) {
            $offset = $index * 8;

            if ($offset >= $bits) {
                $bytes[$index] = "\0";

                continue;
            }

            $remaining = $bits - $offset;

            if ($remaining < 8) {
                $mask = (0xFF << (8 - $remaining)) & 0xFF;
                $bytes[$index] = chr(ord($byte) & $mask);
            }
        }

        return implode('', $bytes);
    }
}
