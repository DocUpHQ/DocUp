<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit;

use App\Support\Uuid;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * {@see Uuid} is pure, so it is tested without booting Laravel.
 *
 * It earns a unit test of its own rather than coverage borrowed from the
 * Eloquent tests: every primary and foreign key in the schema passes through
 * these six functions, and ADR 0006 is on record that the damage from getting
 * key conversion wrong is silent. `find()` matches nothing and
 * `belongsToMany` returns an empty collection; neither raises.
 *
 * Note for anyone adding to this directory: `tests/Pest.php` binds
 * `Tests\TestCase` to Feature only, so a Unit test gets PHPUnit's own base
 * class with no application container. That is deliberate - anything needing
 * the container is not a unit test - and it is why this file extends
 * PHPUnit's TestCase directly.
 */
final class UuidTest extends TestCase
{
    private const CANONICAL = '018f1b0c-7e3a-7c1d-9f2b-6a4d5e8f0a1b';

    public function test_canonical_text_converts_to_sixteen_bytes(): void
    {
        $bytes = Uuid::toBytes(self::CANONICAL);

        $this->assertSame(16, strlen($bytes));
        $this->assertSame(str_replace('-', '', self::CANONICAL), bin2hex($bytes));
    }

    public function test_bytes_convert_back_to_the_same_canonical_text(): void
    {
        $this->assertSame(self::CANONICAL, Uuid::toText(Uuid::toBytes(self::CANONICAL)));
    }

    /**
     * Both directions are idempotent, and that is load-bearing rather than a
     * convenience. Conversion happens at explicit call sites (ADR 0006), so a
     * value may legitimately reach one of these functions already converted -
     * a route binding resolving a model that is then re-serialised, say. If
     * conversion were not idempotent, the second pass would corrupt the key
     * instead of refusing, and corruption of a key is the silent failure ADR
     * 0006 is about.
     */
    public function test_conversion_is_idempotent_in_both_directions(): void
    {
        $bytes = Uuid::toBytes(self::CANONICAL);

        $this->assertSame($bytes, Uuid::toBytes($bytes));
        $this->assertSame(self::CANONICAL, Uuid::toText(self::CANONICAL));
    }

    /**
     * @return list<array{string}>
     */
    public static function rubbish(): array
    {
        return [
            ['not-a-uuid'],
            [''],
            ['1'],
            [str_repeat('z', 36)],
            // Right shape, wrong alphabet: 36 characters with hyphens in the
            // right places, which a length or format check alone would accept.
            ['zzzzzzzz-zzzz-zzzz-zzzz-zzzzzzzzzzzz'],
            // 🛑 Exactly 16 characters, which is the whole point. Before Phase
            // 01 tightened isBytes(), a length-only check accepted this as raw
            // key bytes and toBytes() returned it unconverted — reporting
            // success on attacker-controlled text.
            ['../../etc/passwd'],
            // Also exactly 16 bytes, and also previously accepted. A valid
            // UUID never has a zero version nibble.
            [str_repeat("\x00", 16)],
            // 17 bytes: close enough to 16 to pass a sloppy length check.
            [str_repeat("\x00", 17)],
        ];
    }

    /**
     * @param  string  $value  a value that is not a UUID in either form
     */
    #[DataProvider('rubbish')]
    public function test_rubbish_is_rejected_rather_than_coerced(string $value): void
    {
        $this->expectException(\InvalidArgumentException::class);

        Uuid::toBytes($value);
    }

    public function test_generated_keys_are_sixteen_bytes_and_distinct(): void
    {
        $a = Uuid::v7();
        $b = Uuid::v7();

        $this->assertSame(16, strlen($a));
        $this->assertSame(16, strlen($b));
        $this->assertNotSame($a, $b);
    }

    /**
     * 🛑 SPEC 9.1.1 chose v7 for time ordering, and BINARY(16) storage is only
     * worth its index locality if the bytes actually sort in creation order.
     * Asserted on the raw bytes, because that is what InnoDB compares.
     */
    public function test_generated_keys_sort_in_creation_order(): void
    {
        $keys = [];

        for ($i = 0; $i < 25; $i++) {
            $keys[] = Uuid::v7();
            usleep(1500);
        }

        $sorted = $keys;
        sort($sorted, SORT_STRING);

        $this->assertSame($keys, $sorted, 'UUIDv7 keys must sort lexicographically in creation order');
    }

    /**
     * 🛑 SPEC 9.1.4: v7 embeds a readable creation timestamp, so it is for
     * entity keys only and never for a security token. This asserts the
     * timestamp really is recoverable - the reason for the prohibition, stated
     * as a fact rather than a warning in a comment, so nobody has to take it
     * on trust before reaching for v7 somewhere it does not belong.
     */
    public function test_the_version_7_timestamp_is_readable_which_is_why_tokens_may_not_use_it(): void
    {
        $bytes = Uuid::v7();

        // Layout: the first 48 bits are big-endian Unix milliseconds.
        $milliseconds = hexdec(substr(bin2hex($bytes), 0, 12));

        $this->assertEqualsWithDelta(
            (int) (microtime(true) * 1000),
            $milliseconds,
            60_000,
            'the v7 timestamp should decode to roughly now'
        );

        // And the version nibble really is 7.
        $this->assertSame('7', substr(bin2hex($bytes), 12, 1));
    }

    public function test_is_bytes_distinguishes_raw_bytes_from_canonical_text(): void
    {
        $this->assertTrue(Uuid::isBytes(Uuid::toBytes(self::CANONICAL)));
        $this->assertFalse(Uuid::isBytes(self::CANONICAL));
        $this->assertFalse(Uuid::isBytes('short'));
    }

    public function test_all_to_bytes_maps_a_list_for_a_where_in_binding(): void
    {
        $other = '018f1b0c-7e3a-7c1d-9f2b-6a4d5e8f0a1c';

        $this->assertSame(
            [Uuid::toBytes(self::CANONICAL), Uuid::toBytes($other)],
            Uuid::allToBytes([self::CANONICAL, $other]),
        );
        $this->assertSame([], Uuid::allToBytes([]));
    }
}
