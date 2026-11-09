<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * What a pair in the §8.14.5 contrast matrix is for, and therefore which
 * thresholds apply to it.
 *
 * 🛑 **§8.14.5 states one pair of numbers — "warn below 4.5:1, **refuse
 * publication below 3:1**" — and WCAG 2.2 states two.** 4.5:1 is SC 1.4.3, for
 * text. 3:1 is SC 1.4.11, for a user-interface component's boundary and for a
 * focus indicator. A matrix that applied 4.5:1 to a focus ring would warn on
 * every theme that meets WCAG exactly, and an operator who learns that the
 * contrast warning fires on a conforming theme is an operator who stops
 * reading contrast warnings — the failure ADR 0002 names for injection
 * warnings, arrived at from the other direction.
 *
 * So the refusal floor is §8.14.5's 3:1 for **every** pair, and the warning
 * threshold is the one WCAG attaches to that pair's role. No pair is judged
 * more leniently than §8.14.5 requires; two are not judged more strictly than
 * WCAG requires.
 */
enum ContrastRole: string
{
    /** Text on a background: WCAG 2.2 SC 1.4.3, so 4.5:1 is the warning line. */
    case Text = 'text';

    /**
     * A control boundary or focus indicator: WCAG 2.2 SC 1.4.11 and 2.4.11.
     *
     * The warning line is 3:1, which coincides with §8.14.5's refusal floor —
     * so for these pairs a warning is never issued and anything short of
     * conforming is refused outright. That is the stricter outcome, not the
     * looser one.
     */
    case NonText = 'non_text';

    /** The ratio below which publication is refused (§8.14.5). */
    public function refuseBelow(): float
    {
        return 3.0;
    }

    /** The ratio below which a warning is raised. */
    public function warnBelow(): float
    {
        return match ($this) {
            self::Text => 4.5,
            self::NonText => 3.0,
        };
    }

    /** The WCAG success criterion this pair is judged against, for the report. */
    public function criterion(): string
    {
        return match ($this) {
            self::Text => 'WCAG 2.2 SC 1.4.3 (contrast minimum)',
            self::NonText => 'WCAG 2.2 SC 1.4.11 (non-text contrast)',
        };
    }
}
