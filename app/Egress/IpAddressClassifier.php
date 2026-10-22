<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * Classification of a literal IP address against §8.3.4's deny list.
 *
 * 🛑 This is the whole of the SSRF defence that is not about *when* we check.
 * §8.3.4 names "RFC1918, loopback, link-local, ULA and `169.254.169.254`"; a
 * classifier that implements only those five lines is bypassed before it ships,
 * because every one of them has an alternative spelling that a naive string or
 * `ip2long` comparison does not recognise:
 *
 * - `::ffff:10.0.0.1` is `10.0.0.1` to the kernel and an unfamiliar IPv6
 *   address to a deny list written in dotted quads.
 * - `64:ff9b::a00:1` is `10.0.0.1` through any NAT64 gateway.
 * - `2002:0a00:0001::` is `10.0.0.1` through a 6to4 relay.
 * - `2001:0:0:0:0:0:f5ff:fffe` is a Teredo wrapper for `10.0.0.1`.
 * - `0.0.0.0` is "this host" to the Linux network stack, and it is in none of
 *   the five ranges.
 * - `100.64.0.0/10` is carrier-grade NAT, which on a cloud host routes to the
 *   provider's internal fabric.
 *
 * So the table below is deliberately longer than the specification's sentence,
 * and every entry that is not in that sentence carries the reason it is here.
 * Addresses are compared as **packed bytes** from `inet_pton`, never as text
 * and never through `ip2long`, which is signed on 32-bit builds and returns
 * `false` for a perfectly valid address it does not like.
 *
 * 🛑 Deny by default: anything this class cannot parse or does not recognise as
 * globally routable is {@see AddressClass::Reserved}, which is refused. The
 * failure mode of the opposite default is a bypass; the failure mode of this
 * one is a support ticket.
 */
final class IpAddressClassifier
{
    /**
     * Prefixes in evaluation order. First match wins, so the narrow controls
     * precede the ranges that contain them.
     *
     * @var list<array{0: string, 1: AddressClass, 2: string}>
     */
    private const PREFIXES = [
        // ------------------------------------------------------------- IPv4

        // Before 169.254.0.0/16: the metadata endpoint earns its own name.
        ['169.254.169.254/32', AddressClass::Metadata, 'cloud instance metadata'],

        ['0.0.0.0/32', AddressClass::Unspecified, 'unspecified; Linux routes it to the local host'],
        ['0.0.0.0/8', AddressClass::Reserved, 'this network'],
        ['10.0.0.0/8', AddressClass::Private, 'RFC1918'],
        ['100.64.0.0/10', AddressClass::Private, 'carrier-grade NAT; provider fabric on a cloud host'],
        ['127.0.0.0/8', AddressClass::Loopback, 'loopback'],
        ['169.254.0.0/16', AddressClass::LinkLocal, 'link-local'],
        ['172.16.0.0/12', AddressClass::Private, 'RFC1918'],
        ['192.0.0.0/24', AddressClass::Reserved, 'IETF protocol assignments'],
        ['192.0.2.0/24', AddressClass::Reserved, 'TEST-NET-1'],
        ['192.88.99.0/24', AddressClass::Reserved, '6to4 relay anycast'],
        ['192.168.0.0/16', AddressClass::Private, 'RFC1918'],
        ['198.18.0.0/15', AddressClass::Private, 'benchmarking; routes into lab networks'],
        ['198.51.100.0/24', AddressClass::Reserved, 'TEST-NET-2'],
        ['203.0.113.0/24', AddressClass::Reserved, 'TEST-NET-3'],
        ['224.0.0.0/4', AddressClass::Reserved, 'multicast'],
        ['240.0.0.0/4', AddressClass::Reserved, 'reserved, including the broadcast address'],

        // ------------------------------------------------------------- IPv6

        // Before fc00::/7, for the same reason as the IPv4 metadata address.
        ['fd00:ec2::254/128', AddressClass::Metadata, 'IPv6 cloud instance metadata'],

        ['::/128', AddressClass::Unspecified, 'unspecified'],
        ['::1/128', AddressClass::Loopback, 'loopback'],
        ['64:ff9b:1::/48', AddressClass::Reserved, 'NAT64 local use; the embedded address is not at a fixed offset'],
        ['100::/64', AddressClass::Reserved, 'discard-only'],
        ['2001:db8::/32', AddressClass::Reserved, 'documentation'],
        ['fc00::/7', AddressClass::UniqueLocal, 'unique local addresses'],
        ['fe80::/10', AddressClass::LinkLocal, 'link-local'],
        ['fec0::/10', AddressClass::Private, 'deprecated site-local, still configured on real networks'],
        ['ff00::/8', AddressClass::Reserved, 'multicast'],
    ];

    /** @var list<array{0: string, 1: int, 2: AddressClass}>|null packed, parsed once */
    private static ?array $compiled = null;

    /**
     * The class of a literal address.
     *
     * @param  string  $address  an IPv4 or IPv6 literal, without brackets or a zone id
     */
    public function classify(string $address): AddressClass
    {
        $packed = @inet_pton($address);

        if ($packed === false) {
            // Not an address we can reason about, so not an address we will
            // route to. See the deny-by-default note in the class docblock.
            return AddressClass::Reserved;
        }

        if (strlen($packed) === 16) {
            $unwrapped = $this->unwrapEmbeddedIpv4($packed);

            if ($unwrapped !== null) {
                $packed = $unwrapped;
            }
        }

        foreach ($this->compiled() as [$prefix, $bits, $class]) {
            if (strlen($prefix) === strlen($packed) && $this->inPrefix($packed, $prefix, $bits)) {
                return $class;
            }
        }

        return AddressClass::Public;
    }

    /** True when egress to this literal address is permitted. */
    public function isRoutable(string $address): bool
    {
        return $this->classify($address)->isRoutable();
    }

    /**
     * The IPv4 address an IPv6 address carries inside it, if any.
     *
     * 🛑 The point of unwrapping rather than denying these prefixes outright is
     * that the embedded address may be perfectly public — `::ffff:93.184.216.34`
     * is a legitimate way to write a routable host, and refusing the whole
     * `::ffff:0:0/96` prefix would break IPv4-only origins reached through a
     * dual-stack resolver. What must not happen is that the embedded address
     * escapes the IPv4 table, so we re-enter it with four bytes.
     */
    private function unwrapEmbeddedIpv4(string $packed): ?string
    {
        // ::ffff:0:0/96 — IPv4-mapped.
        if (str_starts_with($packed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff")) {
            return substr($packed, 12, 4);
        }

        // 64:ff9b::/96 — the NAT64 well-known prefix.
        if (str_starts_with($packed, "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00")) {
            return substr($packed, 12, 4);
        }

        // 2002::/16 — 6to4. The embedded IPv4 is bytes 2..5.
        if (str_starts_with($packed, "\x20\x02")) {
            return substr($packed, 2, 4);
        }

        // 2001::/32 — Teredo. The client IPv4 is the last four bytes, obfuscated
        // by a bitwise complement so it does not appear verbatim in the address.
        if (str_starts_with($packed, "\x20\x01\x00\x00")) {
            return substr($packed, 12, 4) ^ "\xff\xff\xff\xff";
        }

        /*
         * ::a00:1 — the deprecated IPv4-compatible form. Excluded for :: and
         * ::1, which the prefix table classifies on their own and which would
         * otherwise unwrap to 0.0.0.0 and 0.0.0.1.
         */
        if (str_starts_with($packed, str_repeat("\x00", 12)) && substr($packed, 12, 4) > "\x00\x00\x00\x01") {
            return substr($packed, 12, 4);
        }

        return null;
    }

    /** @return list<array{0: string, 1: int, 2: AddressClass}> */
    private function compiled(): array
    {
        if (self::$compiled !== null) {
            return self::$compiled;
        }

        $compiled = [];

        foreach (self::PREFIXES as [$cidr, $class]) {
            [$network, $bits] = explode('/', $cidr, 2);
            $packed = inet_pton($network);

            if ($packed === false) {
                throw new \LogicException("unparseable prefix in the egress deny table: {$cidr}");
            }

            $compiled[] = [$packed, (int) $bits, $class];
        }

        return self::$compiled = $compiled;
    }

    /** Packed-byte prefix comparison, including the partial final byte. */
    private function inPrefix(string $packed, string $prefix, int $bits): bool
    {
        $wholeBytes = intdiv($bits, 8);

        if ($wholeBytes > 0 && ! str_starts_with($packed, substr($prefix, 0, $wholeBytes))) {
            return false;
        }

        $remainder = $bits % 8;

        if ($remainder === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remainder)) & 0xFF;

        return (ord($packed[$wholeBytes]) & $mask) === (ord($prefix[$wholeBytes]) & $mask);
    }
}
