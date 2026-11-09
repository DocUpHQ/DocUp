<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Serving\SnapshotProject;

/**
 * Which consumer a theme is being resolved for.
 *
 * 🛑 **Identifiers only, and every one nullable.** The cascade's rungs are
 * independent: a credential page resolves with nothing set (§8.14.12), a
 * dashboard page with an organisation, a documentation request with all four.
 * Modelling it as one object with four optional ids rather than four methods
 * means {@see Themes::resolve()} is one function, and §8.14.1's ordering is
 * read in one place.
 *
 * 🛑 **No `Project` or `DomainMount` model.** The serving path resolves a theme
 * on a request that has already loaded a {@see SnapshotProject},
 * which is a few fields rather than a row — and §9.2's budgets are why. A
 * resolver that took models would make the serving path load two.
 */
final readonly class ThemeTarget
{
    public function __construct(
        public ?string $organisationId = null,
        public ?string $projectId = null,
        public ?string $mountId = null,
        public ?string $versionId = null,
    ) {}

    /**
     * 🛑 §8.14.12's target: the installation, and nothing else.
     *
     * > "Pages that accept credentials MUST carry **no project or organisation
     * > branding**."
     *
     * A named constructor rather than `new ThemeTarget()` so the call site says
     * what it is doing. {@see CredentialPageBranding} is the only caller, and a
     * grep for this method finds every page that claims the exemption.
     */
    public static function installation(): self
    {
        return new self;
    }

    /** Whether any tenant rung is in play. */
    public function isInstallationOnly(): bool
    {
        return $this->organisationId === null
            && $this->projectId === null
            && $this->mountId === null
            && $this->versionId === null;
    }
}
