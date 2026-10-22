<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * Which of §8.9.3's resolution steps a hostname is a candidate for.
 *
 * §8.9.3 fixes the order: "exact verified custom domain → single-label default
 * subdomain → preview host (split on the **last** `--`) → look-alike rejection
 * → **hard 404**."
 *
 * The order is a priority, not a preference. A custom domain that someone has
 * proven control of (§8.10.4) outranks a pattern match against the
 * documentation apex, because the proof is stronger evidence than the shape of
 * a string.
 */
enum HostKind: string
{
    /** An exact, verified hostname somebody proved control of (§8.10.4). */
    case Custom = 'custom';

    /** One label under the documentation apex: `<project>.docs.example.com`. */
    case DefaultSubdomain = 'default_subdomain';

    /** A pull-request preview host under the preview apex (§8.20.1). */
    case Preview = 'preview';

    /** The order §8.9.3 fixes. Lower sorts first. */
    public function precedence(): int
    {
        return match ($this) {
            self::Custom => 0,
            self::DefaultSubdomain => 1,
            self::Preview => 2,
        };
    }
}
