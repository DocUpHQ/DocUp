<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/** What §8.14.5's two thresholds say about one pair. */
enum ContrastVerdict: string
{
    /** At or above the pair's warning threshold. */
    case Pass = 'pass';

    /**
     * Below the warning threshold and at or above 3:1.
     *
     * Publication proceeds. §8.14.5 asks for a warning here and not a refusal,
     * and the reason is in its own last sentence: the gate "is a safety net and
     * still permits shipping AA-failing themes". A system that refused every
     * AA failure would be a system operators turned off.
     */
    case Warn = 'warn';

    /** 🛑 Below 3:1. §8.14.5 refuses publication, subject to an audited override. */
    case Refuse = 'refuse';
}
