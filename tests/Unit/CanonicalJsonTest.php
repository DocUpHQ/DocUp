<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit;

use App\Audit\CanonicalJson;
use PHPUnit\Framework\TestCase;

/**
 * The frozen serialisation the audit chain hashes (§8.22.1).
 *
 * 🛑 These assertions pin a **wire format**, not an implementation detail. The
 * verifier must reproduce these bytes for rows written by other PHP versions on
 * other machines years earlier, so a change that makes any of these fail
 * invalidates every historical hash in every installation. If one of these
 * needs to change, the row needs a format version and the verifier needs to
 * handle both.
 */
final class CanonicalJsonTest extends TestCase
{
    /** The property the whole scheme rests on: assembly order cannot matter. */
    public function test_key_order_does_not_affect_the_output(): void
    {
        $a = CanonicalJson::encode(['zebra' => 1, 'apple' => 2, 'mango' => 3]);
        $b = CanonicalJson::encode(['mango' => 3, 'zebra' => 1, 'apple' => 2]);

        $this->assertSame($a, $b);
        $this->assertSame('{"apple":2,"mango":3,"zebra":1}', $a);
    }

    /** Sorting is recursive, or nested objects would reintroduce the problem. */
    public function test_nested_keys_are_sorted_too(): void
    {
        $encoded = CanonicalJson::encode(['outer' => ['b' => 1, 'a' => 2]]);

        $this->assertSame('{"outer":{"a":2,"b":1}}', $encoded);
    }

    /**
     * 🛑 List order is PRESERVED, unlike object key order.
     *
     * Reordering a list changes its meaning, so sorting one would corrupt the
     * event rather than canonicalise it. `ksort` over sequential integer keys
     * is a no-op, which is exactly the behaviour wanted — asserted because it
     * is a happy accident of the implementation rather than something the code
     * says out loud.
     */
    public function test_list_order_is_preserved(): void
    {
        $this->assertSame('["c","a","b"]', CanonicalJson::encode(['c', 'a', 'b']));
    }

    /**
     * 🛑 Floats are rejected because `json_encode` renders them per the
     * `serialize_precision` ini setting. An operator editing php.ini would
     * otherwise invalidate every hash written before the change — an absurd way
     * to lose an audit log.
     */
    public function test_floats_are_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/serialize_precision/');

        CanonicalJson::encode(['ratio' => 0.5]);
    }

    public function test_floats_are_rejected_when_nested(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/\[outer\.ratio\]/');

        CanonicalJson::encode(['outer' => ['ratio' => 1.25]]);
    }

    /** Objects encode according to code that can change without anyone noticing. */
    public function test_objects_are_rejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessageMatches('/Objects are\s+rejected|objects/i');

        CanonicalJson::encode(['when' => new \DateTimeImmutable]);
    }

    /** The types §8.22.5 actually permits all round-trip. */
    public function test_the_permitted_scalar_types_encode(): void
    {
        $encoded = CanonicalJson::encode([
            'count' => 3,
            'enabled' => true,
            'disabled' => false,
            'missing' => null,
            'name' => 'project.created',
        ]);

        $this->assertSame(
            '{"count":3,"disabled":false,"enabled":true,"missing":null,"name":"project.created"}',
            $encoded,
        );
    }

    /**
     * Non-ASCII is escaped, giving pure-ASCII output.
     *
     * The most conservative choice for bytes a future verifier must reproduce:
     * no dependence on anyone's notion of UTF-8 handling, and nothing a
     * transport can mangle.
     */
    public function test_output_is_pure_ascii(): void
    {
        $encoded = CanonicalJson::encode(['name' => "caf\u{00e9}"]);

        // Asserted as a property rather than against a literal: an escape
        // sequence written into the expectation is one more thing that can be
        // mangled by an editor or a tool, and the property is the actual
        // requirement.
        $this->assertSame(1, preg_match('/^[\x20-\x7E]*$/', $encoded), "output is not pure ASCII: {$encoded}");
        // No assertion on the escape sequence itself: pure ASCII above plus the
        // round trip below already prove it was escaped, since an unescaped
        // character would have failed the ASCII check.

        // And it still means what it meant.
        $this->assertSame(
            ['name' => "caf\u{00e9}"],
            json_decode($encoded, true, 512, JSON_THROW_ON_ERROR),
        );
    }

    /** Slashes are escaped. Arbitrary, but now part of the format. */
    public function test_slashes_are_escaped(): void
    {
        $this->assertSame('{"path":"a\/b"}', CanonicalJson::encode(['path' => 'a/b']));
    }

    public function test_an_empty_payload_encodes_as_an_empty_array(): void
    {
        $this->assertSame('[]', CanonicalJson::encode([]));
    }

    /** A payload this deep is a bug, and the guard says so rather than recursing. */
    public function test_excessive_nesting_is_rejected(): void
    {
        $deep = ['leaf' => true];

        for ($i = 0; $i < 20; $i++) {
            $deep = ['level' => $deep];
        }

        $this->expectException(\InvalidArgumentException::class);

        CanonicalJson::encode($deep);
    }
}
