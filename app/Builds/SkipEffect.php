<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * What a matching §8.5.4 rule decides.
 *
 * 🛑 Two cases rather than a boolean named `skip`, because the monorepo case
 * §8.6.8 calls "the mechanism that makes a monorepo feeding N projects
 * tractable" is written the other way round: *build* when `docs/**` changed,
 * skip otherwise. A list that could only say "skip" would need a trailing
 * catch-all whose absence is silent — the operator writes three skip rules,
 * forgets the fourth, and every unmatched push builds.
 */
enum SkipEffect: string
{
    case Skip = 'skip';
    case Build = 'build';
}
