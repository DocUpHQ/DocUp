<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Models\Collection;
use App\Serving\RoutingSnapshotLoader;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The anonymous reader's view of a collection (§8.2.7, §8.12.8).
 *
 * > "🛑 Private projects MUST be absent from it, and their absence MUST be
 * > indistinguishable from non-existence." (§8.2.7, of the project index; a
 * > collection index is the same promise over a smaller set.)
 *
 * 🛑 **Fail-closed, and that is why the filter is `=== public` rather than a
 * decision.** §4.3/7 and §12.3 give every reader access decision exactly one
 * call site — `EffectiveAccess`, which arrives in Phase 21 — and a second one
 * written here would be the duplicate that requirement exists to forbid. So
 * this is not a decision at all: it is the subset of members that are
 * **provably public** by the two stored columns §8.12.8 intersects, and
 * everything else is absent. When Phase 21 lands, the predicate below is
 * replaced by the real decision for an identified reader, and the anonymous
 * answer it gives must equal this one — which is a test Phase 21 owes.
 *
 * Fail-closed is the right direction for the error: a member wrongly absent
 * is a missing link, a member wrongly present is a disclosure.
 */
final readonly class CollectionIndex
{
    public function __construct(private OrganisationContext $context) {}

    /**
     * The members an anonymous reader may see, in presentation order.
     *
     * The parent project is included — it is part of the collection a reader
     * sees, even though it is not a `collection_projects` row — and is
     * subject to exactly the same filter. A private parent with public
     * members yields an index of the members and no parent, which is correct:
     * nothing about the parent's existence is revealed.
     *
     * @return list<CollectionMember>
     */
    public function publicMembersOf(Collection $collection): array
    {
        return $this->context->acrossAllOrganisations(function () use ($collection): array {
            $members = [];

            foreach ($this->rowsFor($collection) as $row) {
                $visibility = AccessLevel::tryFrom((string) $row->visibility);

                if ($visibility === null) {
                    continue;
                }

                /*
                 * 🛑 §8.12.8's intersection, on the read side: the member is
                 * public only if *both* the project and the mount it is
                 * served through are. A project at `public` reached through a
                 * mount whose exposure narrows it to `members` is not a
                 * public page, and listing it would advertise a URL that is
                 * about to refuse the reader.
                 */
                if (MountExposure::effective($visibility, (string) $row->mount_exposure) !== AccessLevel::Public) {
                    continue;
                }

                /*
                 * 🛑 §8.10.6 again: a member whose host cannot serve is not
                 * in the index. Its absence here matches its absence from
                 * the resolver, which is the only way the index and the site
                 * can agree.
                 */
                if (! RoutingSnapshotLoader::canServe(
                    (string) $row->kind,
                    (string) $row->state,
                    $row->verified_at === null ? null : (string) $row->verified_at,
                )) {
                    continue;
                }

                $members[] = new CollectionMember(
                    alias: (string) $row->alias,
                    projectSlug: (string) $row->slug,
                    name: (string) $row->name,
                    href: 'https://'.$row->host.'/'.($row->path_prefix === '' ? '' : $row->path_prefix.'/'),
                    isParent: (bool) $row->is_parent,
                );
            }

            return $members;
        });
    }

    /**
     * Parent and members as one ordered row set.
     *
     * One query rather than two, because the parent is filtered by the same
     * rules and a second query would be a second place to forget one of them.
     * The parent sorts first — it is the collection's root and a flyout that
     * listed it between two members would read as a sibling.
     *
     * @return list<object{alias: string, slug: string, name: string, visibility: string, mount_exposure: string, path_prefix: string, host: string, kind: string, state: string, verified_at: string|null, is_parent: int, position: int}>
     */
    private function rowsFor(Collection $collection): array
    {
        $members = DB::table('collection_projects')
            ->join('projects', 'projects.id', '=', 'collection_projects.project_id')
            ->join('domain_mounts', 'domain_mounts.id', '=', 'collection_projects.domain_mount_id')
            ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
            ->where('collection_projects.collection_id', $collection->id)
            ->whereNull('projects.deleted_at')
            ->select([
                'collection_projects.alias',
                'projects.slug',
                'projects.name',
                'projects.visibility',
                'domain_mounts.mount_exposure',
                'domain_mounts.path_prefix',
                'domains.host',
                'domains.kind',
                'domains.state',
                'domains.verified_at',
                DB::raw('0 as is_parent'),
                'collection_projects.position',
            ]);

        if (is_string($collection->parent_project_id)) {
            $parent = DB::table('projects')
                ->join('domain_mounts', 'domain_mounts.project_id', '=', 'projects.id')
                ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
                ->where('projects.id', $collection->parent_project_id)
                ->where('domain_mounts.mode', 'canonical')
                ->whereNull('projects.deleted_at')
                ->select([
                    DB::raw("'' as alias"),
                    'projects.slug',
                    'projects.name',
                    'projects.visibility',
                    'domain_mounts.mount_exposure',
                    'domain_mounts.path_prefix',
                    'domains.host',
                    'domains.kind',
                    'domains.state',
                    'domains.verified_at',
                    DB::raw('1 as is_parent'),
                    DB::raw('0 as position'),
                ]);

            $members = $parent->unionAll($members);
        }

        /** @var list<object{alias: string, slug: string, name: string, visibility: string, mount_exposure: string, path_prefix: string, host: string, kind: string, state: string, verified_at: string|null, is_parent: int, position: int}> */
        return $members
            ->orderByDesc('is_parent')
            ->orderBy('position')
            ->orderBy('alias')
            ->get()
            ->all();
    }
}
