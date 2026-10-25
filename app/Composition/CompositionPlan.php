<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Composition\Navigation\NavNode;
use App\Support\Uuid;

/**
 * The whole resolved composition of one project version, before it is
 * written into a manifest revision.
 *
 * One object rather than six return values, because §8.7's pieces are not
 * independent: the nav is spliced from the mounts, the cross-reference map
 * names the same mounts, and the link issues are what the references in
 * those mounts' builds could not find in that map. Computing them apart
 * would mean three walks of the same list and three chances to walk a
 * different one.
 */
final readonly class CompositionPlan
{
    /**
     * @param  list<ResolvedMount>  $mounts
     * @param  list<NavNode>  $nav  §8.7.6, spliced and prefixed
     * @param  array<string, array{mount_path: string, build_id: string|null, objects_inv: bool}>  $xref
     *                                                                                                    §8.7.16's per-version cross-reference map, keyed by component key
     * @param  list<array{component_id: string, source_path: string, target_component_key: string, target_path: string, kind: string}>  $linkIssues
     * @param  array<string, string>  $shadowRedirects  §8.7.15, shadowed URL => target
     */
    public function __construct(
        public array $mounts,
        public array $nav,
        public array $xref,
        public array $linkIssues,
        public array $shadowRedirects,
        public int $shadowOverflow = 0,
    ) {}

    /** The mount §8.7.19 lets emit offline formats, or null. */
    public function primary(): ?ResolvedMount
    {
        foreach ($this->mounts as $mount) {
            if ($mount->mount->is_primary) {
                return $mount;
            }
        }

        return null;
    }

    /**
     * The `mounts` array a version manifest stores (§8.8.3).
     *
     * 🛑 `min_access` is the **snapshot** taken at mount time, not the
     * component's current ceiling. §8.7.7 requires the ceiling
     * "denormalised into the published manifest", and a manifest that read
     * through to the component would make a loosening retroactive — the one
     * thing §8.7.7's "separate audited action that re-validates every
     * existing mount" exists to prevent.
     *
     * @return list<array<string, mixed>>
     */
    public function toManifestMounts(): array
    {
        $rows = [];

        foreach ($this->mounts as $mount) {
            $rows[] = [
                'mount_path' => $mount->mountPath,
                'component_id' => Uuid::toText($mount->component->id),
                'component_key' => $mount->componentKey(),
                'build_id' => $mount->resolution->build === null
                    ? null
                    : Uuid::toText($mount->resolution->build->id),
                'is_primary' => $mount->mount->is_primary,
                'min_access' => $mount->mount->min_access_snapshot->value,

                /*
                 * §8.7.21's answer to "which commit of which repository
                 * produced this URL", written into the immutable document
                 * rather than joined at read time — the build row can be
                 * swept (§8.8.9) while the manifest must stay answerable.
                 */
                'selector_kind' => $mount->resolution->kind->value,
                'resolved_ref' => $mount->resolution->ref,
                'commit_sha' => $mount->resolution->commitSha,
                'resolution' => $mount->resolution->outcome->value,
            ];
        }

        return $rows;
    }
}
