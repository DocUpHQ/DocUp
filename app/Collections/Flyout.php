<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

use App\Auth\OrganisationContext;
use App\Models\Collection;
use App\Models\CollectionProject;
use App\Serving\CanonicalLocations;
use App\Serving\SnapshotMount;
use App\Serving\SnapshotVersion;
use App\Serving\Translations;
use App\Serving\VersionUrl;

/**
 * Assembles {@see FlyoutModel} for a resolved document.
 *
 * Three lists, three owners, one place they are joined:
 *
 * - **members** come from {@see CollectionIndex}, which applies §8.12.8's
 *   intersection — so a private member cannot reach a flyout even if this
 *   class forgot to filter, because there is nothing here to filter;
 * - **languages** come from {@see Translations}, which reads §8.6.12's group
 *   rather than matching slugs;
 * - **versions** come from the routing snapshot, which already holds them for
 *   the resolver (§8.9.1) — so the flyout costs no query for the part a
 *   reader uses most.
 */
final readonly class Flyout
{
    public function __construct(
        private CollectionIndex $index,
        private Translations $translations,
        private CanonicalLocations $canonical,
        private OrganisationContext $context,
    ) {}

    /**
     * The flyout for a document resolved on this mount, in this version.
     */
    public function for(SnapshotMount $mount, SnapshotVersion $version): FlyoutModel
    {
        $project = $mount->project;
        $location = $this->canonical->for($project->id, $project->routingEpoch);

        $collection = $this->collectionFor($project->id);

        return new FlyoutModel(
            collectionSlug: $collection?->slug,
            collectionName: $collection?->name,
            members: $collection === null ? [] : $this->index->publicMembersOf($collection),
            languages: $location === null ? [] : $this->translations->languageRoots($project, $location),
            versions: $this->versionsOn($mount, $version),
        );
    }

    /**
     * The collection this project is presented through, if any.
     *
     * Membership first, then parenthood. A project can legitimately be both —
     * the parent of one collection and a member of another — and the
     * membership is the one that decided its URL, so it is the one whose
     * siblings a reader at that URL expects to see.
     *
     * @param  string  $projectId  raw 16 bytes
     */
    private function collectionFor(string $projectId): ?Collection
    {
        return $this->context->acrossAllOrganisations(function () use ($projectId): ?Collection {
            $membership = CollectionProject::query()
                ->where('project_id', $projectId)
                ->orderBy('created_at')
                ->first();

            if ($membership !== null) {
                return Collection::query()->whereKey($membership->collection_id)->first();
            }

            return Collection::query()->where('parent_project_id', $projectId)->first();
        });
    }

    /**
     * The versions a reader may switch to, from the snapshot.
     *
     * 🛑 `listed` **and** servable. §8.6.2 keeps the four axes independent and
     * `listed` is the flyout's own: "an unlisted version serves by direct URL
     * and is absent from the flyout, the sitemap and search". The resolver
     * must not read it; this must.
     *
     * 🛑 And only this version's **language**. Under `lang_and_version` the
     * language switcher moves between languages and the version switcher
     * moves between versions — a list mixing both would offer `/ja/v1/` as a
     * version of `/en/v2/`, which is two moves presented as one.
     *
     * @return list<array{slug: string, href: string}>
     */
    private function versionsOn(SnapshotMount $mount, SnapshotVersion $current): array
    {
        $scheme = $mount->versioningScheme();
        $versions = [];

        foreach ($mount->project->versions as $version) {
            if (! $version->listed || ! $version->isServable()) {
                continue;
            }

            if ($scheme === 'lang_and_version' && $version->language !== $current->language) {
                continue;
            }

            if (! $mount->exposes($version->slug)) {
                // §10.5's `version_scope`: this mount is configured not to
                // show it, so offering it would be a link to a 404.
                continue;
            }

            $versions[] = [
                'slug' => $version->slug,
                'href' => VersionUrl::root($mount, $scheme, $version),
            ];
        }

        return $versions;
    }
}
