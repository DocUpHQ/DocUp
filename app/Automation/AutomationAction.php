<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Automation;

/**
 * §8.6.8's actions, plus §8.6.15's `delete_version`.
 *
 * > "activate, hide, make public or private, set as default, or trigger a
 * > build"
 *
 * `deactivate` and `show` are here as the inverses of `activate` and `hide`,
 * because §8.6.2's four axes are independent and a rule set that can only
 * move one of them in one direction is not a rule set: an operator who
 * hides every `wip/*` branch needs a way to stop hiding one.
 */
enum AutomationAction: string
{
    case Activate = 'activate';
    case Deactivate = 'deactivate';

    /** §8.6.2's `listed`. 🛑 Hidden is not private — it still serves. */
    case Hide = 'hide';
    case Show = 'show';

    case MakePublic = 'make_public';
    case MakePrivate = 'make_private';

    /** §8.6.14's stored pointer, which an automation rule may set. */
    case SetDefault = 'set_default';

    case Build = 'build';

    /**
     * 🛑 §8.6.15, and the only action that destroys reader-visible URLs.
     *
     * > "removal MUST be an automation-rule action (`delete_version`)
     * > triggered by ref disappearance rather than by ref creation. Nothing
     * > may delete reader-visible URLs without either an explicit rule or an
     * > explicit action."
     *
     * Which is why {@see isValidFor()} refuses it on creation: a rule
     * deleting a version the moment its ref appears is not something the
     * requirement contemplates, and the only way to write one by accident is
     * to pick the wrong trigger from a dropdown.
     */
    case DeleteVersion = 'delete_version';

    /**
     * Whether this action may be attached to that trigger.
     *
     * 🛑 Enforced on write, not merely on fire. A rule that silently never
     * ran would be worse than one refused at creation: the operator believes
     * their tidy-up is configured.
     */
    public function isValidFor(AutomationTrigger $trigger): bool
    {
        return match ($this) {
            self::DeleteVersion => $trigger === AutomationTrigger::VersionDisappeared,

            /*
             * Building a version whose ref has just disappeared would fetch
             * a ref the provider no longer has, and §8.5.1 pins with
             * `ls-remote` before anything runs — so the build would fail at
             * `plan` with a source error, every time, for ever.
             */
            self::Build, self::SetDefault => $trigger === AutomationTrigger::VersionCreated,

            default => true,
        };
    }

    /** Whether firing this action needs §8.6.3's guarded-inheritance check re-run. */
    public function changesVisibility(): bool
    {
        return $this === self::MakePublic || $this === self::MakePrivate;
    }
}
