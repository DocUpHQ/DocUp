<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * Typed reads of `config/builds.php`.
 *
 * 🛑 `config()` returns `mixed`, and the build pipeline runs at Larastan
 * level 9 where casting `mixed` is an error. That rule is not bureaucracy
 * here: these values become a container's memory ceiling, its PID limit and
 * the name of the volume it mounts, and `(int) config('builds.limits.pids')`
 * on a mistyped configuration file silently yields `0` — a PID limit of zero
 * is not a limit, it is a container that cannot fork.
 *
 * 🛑 **Every fallback is the safe value**, never a neutral one. A
 * configuration file that is missing, truncated or mistyped must produce the
 * specification's policy rather than an unbounded one, because a failure
 * that removes a limit is invisible until something exploits it.
 */
final class BuildConfig
{
    public static function string(string $key, string $fallback): string
    {
        $value = config('builds.'.$key);

        return is_string($value) && $value !== '' ? $value : $fallback;
    }

    /**
     * @param  positive-int  $fallback
     * @return positive-int
     */
    public static function positiveInt(string $key, int $fallback): int
    {
        $value = config('builds.'.$key);

        if (is_int($value) && $value > 0) {
            return $value;
        }

        // A numeric string is what an `env()` default produces, and refusing
        // it would mean the documented environment variables did nothing.
        if (is_string($value) && ctype_digit($value) && (int) $value > 0) {
            return (int) $value;
        }

        return $fallback;
    }

    /** @return array<string, mixed> */
    public static function map(string $key): array
    {
        $value = config('builds.'.$key);

        if (! is_array($value)) {
            return [];
        }

        $map = [];

        foreach ($value as $name => $item) {
            if (is_string($name)) {
                $map[$name] = $item;
            }
        }

        return $map;
    }

    /**
     * The CPU limit, which Docker takes as a decimal string rather than an
     * integer — `0.5` is a legitimate half-core and `(int)` would make it
     * zero, which Docker reads as "no limit".
     */
    public static function cpus(): string
    {
        $value = config('builds.limits.cpus');

        if (is_string($value) && preg_match('/^\d+(\.\d+)?$/', $value) === 1 && (float) $value > 0) {
            return $value;
        }

        if (is_int($value) && $value > 0) {
            return (string) $value;
        }

        return '1';
    }
}
