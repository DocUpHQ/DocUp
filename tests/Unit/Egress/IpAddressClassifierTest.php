<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Egress;

use App\Egress\AddressClass;
use App\Egress\IpAddressClassifier;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The §8.3.4 deny table, address by address.
 *
 * 🛑 The cases that matter most are the **alternative spellings**. Every
 * address in §8.3.4's sentence — RFC1918, loopback, link-local, ULA,
 * `169.254.169.254` — can be written in a form that a deny list in dotted
 * quads does not recognise, and each of those forms is a complete bypass of
 * the control on its own. They are tested here, one per encoding, so a
 * regression names the encoding it lost.
 */
final class IpAddressClassifierTest extends TestCase
{
    /** @return \Generator<string, array{0: string, 1: AddressClass}> */
    public static function addresses(): \Generator
    {
        // ---------------------------------------------------- what §8.3.4 names
        yield 'metadata v4' => ['169.254.169.254', AddressClass::Metadata];
        yield 'metadata v6' => ['fd00:ec2::254', AddressClass::Metadata];
        yield 'rfc1918 10/8' => ['10.0.0.1', AddressClass::Private];
        yield 'rfc1918 172.16/12' => ['172.20.1.1', AddressClass::Private];
        yield 'rfc1918 192.168/16' => ['192.168.1.1', AddressClass::Private];
        yield 'loopback v4' => ['127.0.0.1', AddressClass::Loopback];
        yield 'loopback v4, not .1' => ['127.1.2.3', AddressClass::Loopback];
        yield 'loopback v6' => ['::1', AddressClass::Loopback];
        yield 'link-local v4' => ['169.254.1.1', AddressClass::LinkLocal];
        yield 'link-local v6' => ['fe80::1', AddressClass::LinkLocal];
        yield 'ula' => ['fd00::1', AddressClass::UniqueLocal];
        yield 'ula, low half of fc00::/7' => ['fc00::1', AddressClass::UniqueLocal];

        // ------------------------------------------- what §8.3.4 does not name
        yield 'unspecified v4' => ['0.0.0.0', AddressClass::Unspecified];
        yield 'unspecified v6' => ['::', AddressClass::Unspecified];
        yield 'cgnat' => ['100.64.0.1', AddressClass::Private];
        yield 'benchmarking' => ['198.18.0.1', AddressClass::Private];
        yield 'deprecated site-local v6' => ['fec0::1', AddressClass::Private];
        yield 'broadcast' => ['255.255.255.255', AddressClass::Reserved];
        yield 'multicast v4' => ['224.0.0.1', AddressClass::Reserved];
        yield 'multicast v6' => ['ff02::1', AddressClass::Reserved];
        yield 'documentation v6' => ['2001:db8::1', AddressClass::Reserved];

        // ----------------------------------- 🛑 the bypasses, one per encoding
        yield 'IPv4-mapped loopback' => ['::ffff:127.0.0.1', AddressClass::Loopback];
        yield 'IPv4-mapped rfc1918' => ['::ffff:10.0.0.1', AddressClass::Private];
        yield 'IPv4-mapped metadata' => ['::ffff:169.254.169.254', AddressClass::Metadata];
        yield 'IPv4-mapped, hex spelling' => ['::ffff:a00:1', AddressClass::Private];
        yield 'NAT64 well-known' => ['64:ff9b::a00:1', AddressClass::Private];
        yield 'NAT64 metadata' => ['64:ff9b::a9fe:a9fe', AddressClass::Metadata];
        yield 'NAT64 local-use prefix' => ['64:ff9b:1::1', AddressClass::Reserved];
        yield '6to4 wrapping rfc1918' => ['2002:0a00:0001::', AddressClass::Private];
        yield '6to4 wrapping metadata' => ['2002:a9fe:a9fe::', AddressClass::Metadata];
        yield 'teredo wrapping rfc1918' => ['2001::f5ff:fffe', AddressClass::Private];
        yield 'IPv4-compatible v6' => ['::10.0.0.1', AddressClass::Private];

        // ------------------------------------------------- legitimately public
        yield 'public v4' => ['93.184.216.34', AddressClass::Public];
        yield 'public v6' => ['2606:2800:220:1:248:1893:25c8:1946', AddressClass::Public];
        yield 'IPv4-mapped public, which must NOT be denied' => ['::ffff:93.184.216.34', AddressClass::Public];
        yield '6to4 wrapping a public address' => ['2002:5db8:d822::', AddressClass::Public];

        // --------------------------------------------------- deny by default
        yield 'not an address at all' => ['not-an-address', AddressClass::Reserved];
        yield 'empty' => ['', AddressClass::Reserved];
        yield 'decimal-encoded 127.0.0.1' => ['2130706433', AddressClass::Reserved];
        yield 'octal-encoded 127.0.0.1' => ['0177.0.0.1', AddressClass::Reserved];
    }

    #[DataProvider('addresses')]
    public function test_it_classifies_an_address(string $address, AddressClass $expected): void
    {
        $this->assertSame(
            $expected,
            (new IpAddressClassifier)->classify($address),
            $address.' was classified wrongly',
        );
    }

    /**
     * 🛑 The routability answer is the one the egress client acts on, so it is
     * asserted separately rather than inferred from the class above. A future
     * edit that added a routable-looking case to `AddressClass` would be
     * caught here rather than in whatever ships next.
     */
    #[DataProvider('addresses')]
    public function test_only_public_addresses_are_routable(string $address, AddressClass $expected): void
    {
        $this->assertSame(
            $expected === AddressClass::Public,
            (new IpAddressClassifier)->isRoutable($address),
        );
    }

    /**
     * Every non-public class maps to its own rejection identifier.
     *
     * Distinctness, asserted as a property rather than case by case: two
     * classes sharing an identifier is exactly the collapse Phase 05's exit
     * criteria forbid, and it is the sort of thing a hurried `match` arm does.
     */
    public function test_every_denied_class_has_a_distinct_rejection(): void
    {
        $identifiers = [];

        foreach (AddressClass::cases() as $class) {
            if ($class === AddressClass::Public) {
                continue;
            }

            $identifiers[] = $class->rejection()->value;
        }

        $this->assertSame($identifiers, array_values(array_unique($identifiers)));
        $this->assertCount(7, $identifiers);
    }
}
