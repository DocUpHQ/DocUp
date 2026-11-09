<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * The scopes a branding token cascades through (§8.14.1).
 *
 * > "Branding MUST be a **closed registry of typed design tokens** cascading
 * > installation → organisation → project → domain mount, with per-path
 * > locking at any level […] Version scope is limited to colour-scheme default
 * > and a banner."
 *
 * 🛑 **Five cases for a four-level cascade, and the fifth is deliberately
 * narrow.** `Version` is not a fifth rung every token may be set at: §8.14.1
 * limits it to the colour-scheme default and a banner, and
 * {@see BrandingToken::$deepest} is what enforces that per token. Modelling it
 * as an enum case rather than as a special-cased `if` means the restriction is
 * data the operator documentation can print, and a token that tried to claim
 * version scope would have to say so in the registry where it is reviewable.
 *
 * 🛑 **The order is the resolution order and nothing else may define it.**
 * {@see self::ordinal()} is the single source of "deeper than", used by both
 * the cascade and the lock check — two implementations of "is this level below
 * that one" is how a lock ends up enforced on three rungs and not the fourth.
 */
enum CascadeLevel: string
{
    /** The operator's own installation. Above tenancy (§12.1), so no organisation. */
    case Installation = 'installation';

    /** One tenant. */
    case Organisation = 'organisation';

    /** One project. */
    case Project = 'project';

    /**
     * One `domain_mounts` row.
     *
     * The deepest level for all but two tokens, and the reason the cascade has
     * four rungs rather than three: the same project served at two mounts —
     * a vendor's white-labelled domain and the operator's own subdomain — is
     * exactly the case §8.14's goal statement is about.
     */
    case Mount = 'mount';

    /**
     * One `project_versions` row, for the two tokens §8.14.1 admits here.
     *
     * A version may say "this one is dark by default" and "this one carries
     * this banner". It may not restyle the portal, because a version is
     * content the build produced and a theme is a decision the tenant made.
     */
    case Version = 'version';

    /**
     * Depth, where a larger number is more specific.
     *
     * 🛑 Not `array_search` over a list of cases and not the enum's own
     * declaration order read reflectively: both would make the resolution
     * order an accident of how the file is written, and reordering the cases
     * for readability would silently reorder the cascade.
     */
    public function ordinal(): int
    {
        return match ($this) {
            self::Installation => 0,
            self::Organisation => 1,
            self::Project => 2,
            self::Mount => 3,
            self::Version => 4,
        };
    }

    /** Whether this level sits below `$other` and so may override it. */
    public function isDeeperThan(self $other): bool
    {
        return $this->ordinal() > $other->ordinal();
    }

    /**
     * The levels in resolution order, shallowest first.
     *
     * @return list<self>
     */
    public static function inOrder(): array
    {
        return [self::Installation, self::Organisation, self::Project, self::Mount, self::Version];
    }

    /**
     * The four rungs that may hold a theme revision of their own.
     *
     * 🛑 `Version` is absent, and that is the asymmetry §8.14.1 asks for: a
     * version does not get a theme, it gets two token overrides. Giving it a
     * revision would give it the other forty-three as well.
     *
     * @return list<self>
     */
    public static function revisionScopes(): array
    {
        return [self::Installation, self::Organisation, self::Project, self::Mount];
    }
}
