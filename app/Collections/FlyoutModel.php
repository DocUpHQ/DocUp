<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

/**
 * What a reader's flyout shows, assembled once (§8.15.2, §8.15.6).
 *
 * 🛑 **One flyout for a whole collection, which is Phase 16's point.** Read
 * the Docs models a subproject as a separate project, so its flyout is its
 * own: a reader three clicks into a subproject sees that subproject's
 * versions and no way back. §8.2.5 makes a collection a presentation
 * construct over projects that keep their own versions, so the flyout a
 * member serves names the whole collection — and the test for that is that
 * every URL in the collection produces the same `collection` and the same
 * `members`.
 *
 * 🛑 **Not the `/_/addons` payload.** §8.15.2 gives that contract to Phase 28
 * — "The versioned `/_/addons` payload contract" is its deliverable, versioned
 * because §8.1.11 makes it one of the three independently versioned public
 * contracts. This is the model behind it, built now because a language
 * switcher and a collection index need the same three lists and because
 * assembling them in two places is how the index and the switcher come to
 * disagree about which members exist.
 */
final readonly class FlyoutModel
{
    /**
     * @param  list<CollectionMember>  $members  🛑 already visibility-filtered
     * @param  list<array{language: string, href: string}>  $languages  §8.6.12's switcher
     * @param  list<array{slug: string, href: string}>  $versions  listed and servable only
     */
    public function __construct(
        public ?string $collectionSlug,
        public ?string $collectionName,
        public array $members,
        public array $languages,
        public array $versions,
    ) {}

    /** Whether this project is presented as part of a collection at all. */
    public function hasCollection(): bool
    {
        return $this->collectionSlug !== null;
    }
}
