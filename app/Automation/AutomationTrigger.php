<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

/**
 * §8.6.8's two triggers: "version **creation or disappearance**".
 *
 * 🛑 Two, not three. There is no `version_updated`: a push to a branch that
 * already has a version is an ordinary build trigger, and giving it a rule
 * would mean every push re-evaluating every rule against a version whose
 * visibility an operator may since have set by hand. §8.6.8's actions are
 * about a version's lifecycle, and a version has exactly two lifecycle
 * events.
 */
enum AutomationTrigger: string
{
    case VersionCreated = 'version_created';
    case VersionDisappeared = 'version_disappeared';
}
