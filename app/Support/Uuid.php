<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Support;

use Illuminate\Support\Str;

/**
 * Conversion between the canonical 36-character UUID form and the 16 raw bytes
 * stored in the database.
 *
 * SPEC 9.1.1 stores every primary and foreign key as BINARY(16) for index
 * locality: InnoDB copies the primary key into every secondary index, so
 * CHAR(36) costs 20 extra bytes per index entry per row.
 *
 * ADR 0006 measured why conversion lives here, at explicit call sites, rather
 * than in an Eloquent attribute cast: a cast applies to attributes but not to
 * query bindings, pivot inserts or find(), so a cast key makes find() and
 * whereIn() match nothing and makes belongsToMany return SILENTLY empty.
 */
final class Uuid
{
    /** The 16 raw bytes for a canonical UUID string. Idempotent on binary input. */
    public static function toBytes(string $value): string
    {
        if (self::isBytes($value)) {
            return $value;
        }

        if (! Str::isUuid($value)) {
            throw new \InvalidArgumentException('Not a UUID: '.substr($value, 0, 64));
        }

        $bytes = hex2bin(str_replace('-', '', $value));

        // hex2bin returns false on odd-length or non-hex input. Str::isUuid has
        // already excluded that, so this is belt and braces for a future edit.
        if ($bytes === false) {
            throw new \InvalidArgumentException('Unconvertible UUID.');
        }

        return $bytes;
    }

    /**
     * {@see toBytes()}, returning null instead of throwing.
     *
     * For the boundary where a malformed identifier is a 404 rather than an
     * error: a controller taking a UUID out of a URL should answer "no such
     * thing" for `../../etc`, not raise. Added in Phase 06 for the §8.5.24
     * provenance endpoint, which is the first route to take a raw UUID — and
     * §8.2.2's "404, never 403" reasoning applies to malformed input for the
     * same reason it applies to another tenant's row.
     */
    public static function tryToBytes(string $value): ?string
    {
        try {
            return self::toBytes($value);
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /** The canonical 36-character form for 16 raw bytes. Idempotent on canonical input. */
    public static function toText(string $value): string
    {
        if (Str::isUuid($value)) {
            return $value;
        }

        if (! self::isBytes($value)) {
            throw new \InvalidArgumentException('Not 16 bytes.');
        }

        $hex = bin2hex($value);

        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12),
        );
    }

    /**
     * A fresh UUIDv7 as raw bytes.
     *
     * SPEC 9.1.1 requires v7 specifically: it is time-ordered, which is the
     * whole point of BINARY(16) storage, and ADR 0006 confirmed Laravel's
     * Str::uuid7() keys sort lexicographically in creation order.
     *
     * 🛑 SPEC 9.1.4: this is for entity keys only. Security-sensitive,
     * enumerable values - share tokens, API tokens, webhook secrets, domain
     * verification tokens, handoff codes - MUST NOT use v7, because v7 embeds
     * a readable creation timestamp. Use random_bytes() for those.
     */
    public static function v7(): string
    {
        return self::toBytes(Str::uuid7()->toString());
    }

    /** True when the value really is the 16 raw bytes of a UUID. */
    public static function isBytes(string $value): bool
    {
        if (strlen($value) !== 16 || Str::isUuid($value)) {
            return false;
        }

        // 🛑 Length alone is not identification, and this check used to be
        // length alone. '../../etc/passwd' is exactly 16 characters, so it was
        // accepted as raw key bytes and toBytes() handed it straight back
        // unconverted - reporting success on attacker-controlled text. So were
        // 16 null bytes. Found by tests/Unit/UuidTest.php in Phase 01.
        //
        // Parameter binding meant this was never SQL injection, and such a key
        // simply matched no row, so nothing was exploitable. It was still
        // wrong in the way SPEC 9.1 cares about: a conversion function that
        // guesses from length validates nothing, and the next caller to treat
        // a successful toBytes() as proof of a well-formed key would have been
        // relying on a check that was not happening.
        //
        // A real UUID carries its own structure in the bytes - RFC 9562 fixes
        // the version nibble at 1-8 and the variant bits at 10xx - so verify
        // that instead of trusting the length. Every DocUp key is v7, so this
        // is strictly weaker than requiring v7 and therefore safe for any
        // UUID that legitimately reaches here.
        $hex = bin2hex($value);
        $version = (int) hexdec($hex[12]);
        $variant = (int) hexdec($hex[16]);

        return $version >= 1 && $version <= 8 && ($variant & 0b1100) === 0b1000;
    }

    /**
     * Map canonical strings to raw bytes for a whereIn-style binding.
     *
     * @param  iterable<string>  $values
     * @return list<string>
     */
    public static function allToBytes(iterable $values): array
    {
        $out = [];

        foreach ($values as $value) {
            $out[] = self::toBytes($value);
        }

        return $out;
    }
}
