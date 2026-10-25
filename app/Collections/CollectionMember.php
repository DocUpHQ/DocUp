<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

/**
 * One entry of a collection index, as a reader may see it.
 *
 * 🛑 **Only what a reader may see.** This object is built by
 * {@see CollectionIndex} after the visibility filter, so there is no field
 * here that could leak a member the filter excluded — not a count, not an
 * identifier, not a "hidden" flag. §8.2.7 requires a private project's
 * absence to be "indistinguishable from non-existence", and a DTO carrying
 * `isVisible: false` is how that requirement is defeated by a template that
 * renders a placeholder.
 *
 * `$href` is the member's mount root. §8.9.7 redirects it to the member's
 * default version, which is the right landing: a flyout that linked straight
 * at a version would pin every reader to whatever was default when the index
 * was cached.
 */
final readonly class CollectionMember
{
    public function __construct(
        public string $alias,
        public string $projectSlug,
        public string $name,
        public string $href,
        public bool $isParent = false,
    ) {}
}
