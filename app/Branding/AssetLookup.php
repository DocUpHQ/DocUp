<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * What {@see TokenGrammar} needs to know about an uploaded asset.
 *
 * 🛑 An interface rather than a query, so the grammar is a unit and not an
 * integration. §8.14.2's grammar is the most security-relevant code in this
 * phase and the least pleasant to drive through a database — a colour parser
 * whose tests need a migration is a colour parser with fewer tests.
 *
 * The implementation ({@see ThemeAssets}) is also where the **scope** check
 * lives: an asset belongs to an organisation, and a project in organisation A
 * may not reference organisation B's logo. The grammar asks "what kind is this
 * asset, as far as this writer is concerned" and gets `null` for both "no such
 * asset" and "not yours", which is §8.2.2's 404-never-403 rule applied to a
 * token value.
 */
interface AssetLookup
{
    /**
     * The `theme_assets.kind` of an asset this writer may reference, or null.
     *
     * @param  string  $assetId  canonical UUID text
     */
    public function kindOf(string $assetId): ?string;
}
