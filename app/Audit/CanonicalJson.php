<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Audit;

/**
 * The byte-exact serialisation the audit chain hashes (§8.22.1).
 *
 * 🛑 **This is a wire format, not a convenience.** `hash = HMAC(k_audit,
 * canonical_json ‖ prev_hash)`, so `docup:audit:verify` must reproduce these
 * bytes exactly — for a row written by a different PHP version, on a different
 * machine, years later. Any change to the output changes every historical hash
 * and makes the entire log fail verification. Treat the rules below as frozen;
 * a new format needs a version marker on the row and a verifier that handles
 * both.
 *
 * The rules, and why each one:
 *
 * - **Keys sorted, recursively.** PHP preserves insertion order, so the same
 *   logical event assembled in a different order would otherwise hash
 *   differently.
 * - **Fixed flags**, listed in {@see self::FLAGS}. Defaults are not relied on
 *   because defaults change between releases.
 * - 🛑 **Floats are rejected.** `json_encode` renders them according to the
 *   `serialize_precision` ini setting, so an operator editing php.ini would
 *   silently invalidate every hash written before the change. That is an
 *   absurd way to lose an audit log. §8.22.5 restricts the payload to
 *   identifiers, codes and references anyway, none of which is a float, so
 *   rejecting them costs nothing and removes a whole class of environmental
 *   fragility.
 * - **Objects are rejected**, including those implementing `JsonSerializable`:
 *   their encoding depends on code that can change without anyone thinking
 *   about the audit log.
 */
final class CanonicalJson
{
    /**
     * 🛑 Frozen. Changing these changes every historical hash.
     *
     * Deliberately NOT using `JSON_UNESCAPED_UNICODE` or
     * `JSON_UNESCAPED_SLASHES`: the default escaping emits pure ASCII, which is
     * the most conservative choice for bytes that must be reproduced exactly by
     * some future verifier. Readability of the stored JSON is worth nothing
     * here — nobody reads it, the verifier compares it.
     */
    private const FLAGS = JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION;

    /** Depth guard: a payload this deep is a bug, not an audit event. */
    private const MAX_DEPTH = 16;

    /**
     * Encode a payload to its canonical form.
     *
     * @param  array<array-key, mixed>  $payload
     *
     * @throws \InvalidArgumentException when the payload contains a value whose
     *                                   encoding is not stable across
     *                                   environments
     * @throws \JsonException when encoding fails
     */
    public static function encode(array $payload): string
    {
        return json_encode(self::normalise($payload, 0), self::FLAGS, self::MAX_DEPTH);
    }

    /**
     * Recursively sort keys and reject anything unstable.
     *
     * @param  array<array-key, mixed>  $value
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function normalise(array $value, int $depth, string $path = ''): array
    {
        if ($depth >= self::MAX_DEPTH) {
            throw new \InvalidArgumentException(
                'Audit payload nests deeper than '.self::MAX_DEPTH." levels at [{$path}]."
            );
        }

        // Sort by key so assembly order cannot affect the hash. A list stays a
        // list: ksort on sequential integer keys is a no-op, which is what we
        // want — reordering a list WOULD change its meaning.
        ksort($value, SORT_STRING);

        $out = [];

        foreach ($value as $key => $item) {
            $here = $path === '' ? (string) $key : $path.'.'.$key;

            $out[$key] = match (true) {
                is_array($item) => self::normalise($item, $depth + 1, $here),
                is_string($item), is_int($item), is_bool($item), $item === null => $item,

                // The two rejections that matter, each with its reason in the
                // message so whoever hits it understands rather than works around.
                is_float($item) => throw new \InvalidArgumentException(
                    "Audit payload contains a float at [{$here}]. Floats are rejected because "
                    .'json_encode renders them per the serialize_precision ini setting, so a php.ini '
                    .'change would invalidate every hash written before it. Pass an integer, or a '
                    .'string if the exact decimal matters.'
                ),
                is_object($item) => throw new \InvalidArgumentException(
                    'Audit payload contains an object ('.$item::class."), at [{$here}]. Objects are "
                    .'rejected because their encoding depends on code that can change without anyone '
                    .'considering the audit log. Pass the identifier you want recorded (§8.22.5).'
                ),

                default => throw new \InvalidArgumentException(
                    'Audit payload contains an unsupported '.gettype($item)." at [{$here}]."
                ),
            };
        }

        return $out;
    }
}
