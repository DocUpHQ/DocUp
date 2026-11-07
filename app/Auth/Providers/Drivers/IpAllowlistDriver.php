<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * 🛑 §8.12.17's `ip_allowlist`, and the whole reason §8.12.7 exists:
 *
 * > "`ip_allowlist` is the reason §8.12.7 exists: it is a **gate, never an
 * > identity**, so a requirement tree satisfiable by it alone is rejected at
 * > write time."
 *
 * So this driver's most important property is what it returns: `{gate}`, which
 * {@see AccessLeaf::bearsIdentity()} answers false for, which makes
 * `Requirement::satisfiedWithoutIdentity()` true for a tree that rests on it,
 * which makes `ReaderPolicies` refuse that tree when it is written. Four
 * classes, one fact, and this is where the fact starts.
 *
 * 🛑 **It returns no subject**, and that is the same fact expressed again. An
 * address is not a person: §20.3 keeps raw IPs to `security_events` for seven
 * days and calls that "the only place a raw IP exists", so a subject derived
 * from one would put a network address into the decision log under a name that
 * implies a reader.
 *
 * 🛑 And it is a driver rather than a middleware for one reason worth stating:
 * as a middleware it would run *before* §12.3's decision and could allow. As a
 * leaf it can only ever contribute to a conjunction the decision function
 * evaluates — so "on the office network" can narrow access and can never grant
 * it on its own.
 */
final class IpAllowlistDriver implements AuthComponent
{
    /**
     * 🛑 A cap on the list, because every entry is compared on every request
     * for every reader on a guarded project.
     *
     * Two hundred CIDRs is a generous corporate estate and a bounded loop;
     * without a cap, an operator pasting a threat feed into this field would be
     * a per-request cost nobody measured.
     */
    private const int MAX_RANGES = 200;

    public static function type(): string
    {
        return 'ip_allowlist';
    }

    /** 🛑 `{gate}`. See the class note; this is the load-bearing line. */
    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Gate;
    }

    public static function allowsProjectScope(): bool
    {
        /*
         * 🛑 Permitted at project scope, unlike `ldap`/`mtls`/`header_trust`.
         * §8.12.17's table says `any` scope, and the reason those three are
         * installation-only does not apply: an allowlist reaches nothing and
         * asserts nothing about the TLS terminator. It reads one value the
         * proxy already resolved.
         */
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array{ranges: list<string>}
     */
    public function validate(array $config): array
    {
        $ranges = $config['ranges'] ?? null;

        if (! is_array($ranges) || $ranges === []) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'ip_allowlist needs a non-empty `ranges` list',
            );
        }

        if (count($ranges) > self::MAX_RANGES) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'ip_allowlist accepts at most '.self::MAX_RANGES.' ranges',
            );
        }

        $normalised = [];

        foreach ($ranges as $range) {
            if (! is_string($range)) {
                throw BindingRefused::of(BindingRejection::ConfigInvalid, 'every range must be a string');
            }

            $parsed = self::parse(trim($range));

            if ($parsed === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '"'.$range.'" is not an address or a CIDR range',
                );
            }

            /*
             * 🛑 Stored **normalised**, so the stored form and the compared
             * form are the same string. An operator typing `10.0.0.1/8` means
             * `10.0.0.0/8`, and storing their spelling while comparing against
             * the network would make the dashboard show a range that is not the
             * one in force.
             */
            $normalised[] = $parsed['canonical'];
        }

        return ['ranges' => array_values(array_unique($normalised))];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        $ranges = $binding->strings('ranges');

        if ($ranges === null || $ranges === []) {
            /*
             * 🛑 A gate with no ranges admits nobody, which is fail-closed and
             * therefore safe — and it is still a failed probe, because a gate
             * that admits nobody is not what the operator configured. §8.12.19
             * exists to catch exactly this before a reader does.
             */
            return ProbeResult::fail('no ranges configured; this gate would admit nobody');
        }

        return ProbeResult::pass(count($ranges).' range(s) configured');
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $address = $presented->remoteAddress;
        $ranges = $binding->strings('ranges');

        if ($address === null || $ranges === null) {
            /*
             * 🛑 `unsatisfied`, never `rejected`. §8.12.23's case (a) is "a
             * credential was presented and rejected", and an address is not a
             * credential — see {@see ReaderPresentation::carriesCredential()},
             * which excludes it for the same reason. Treating a non-matching
             * address as a rejected credential would turn every anonymous 404
             * on a gated project into a 401.
             */
            return AttemptResult::unsatisfied();
        }

        foreach ($ranges as $range) {
            if (self::covers($range, $address)) {
                /*
                 * 🛑 No subject. An address is not a person; see the class
                 * note and §20.3's rule about where a raw IP may exist.
                 */
                return AttemptResult::satisfiedBy(AccessLeaf::Gate);
            }
        }

        return AttemptResult::unsatisfied();
    }

    /**
     * Whether a CIDR range covers an address.
     *
     * 🛑 Compared on **packed bytes**, not strings, and the same family only.
     * `::ffff:10.0.0.1` and `10.0.0.1` are one address spelled two ways — the
     * technique `OnlyFromLoopback` already uses — and a string comparison would
     * let the second form walk past a range written in the first.
     */
    public static function covers(string $range, string $address): bool
    {
        $parsed = self::parse($range);
        $packed = @inet_pton($address);

        if ($parsed === null || $packed === false) {
            return false;
        }

        /*
         * 🛑 Different families never match. Without this an IPv4 address and
         * an IPv6 range would be compared over the shorter length and a /0-ish
         * prefix would appear to cover everything.
         */
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
     * Parse an address or CIDR range into its network, prefix and canonical
     * spelling.
     *
     * A bare address is a host route — `/32` for IPv4 and `/128` for IPv6 —
     * which is what an operator typing one address means.
     *
     * @return array{packed: string, bits: int, canonical: string}|null
     */
    private static function parse(string $range): ?array
    {
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

        /*
         * 🛑 Host bits are **zeroed**, so `10.0.0.1/8` stores as `10.0.0.0/8`.
         * The canonical form is what the dashboard shows and what the
         * comparison uses, and an operator should never see a range in the UI
         * that differs from the one in force.
         */
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
