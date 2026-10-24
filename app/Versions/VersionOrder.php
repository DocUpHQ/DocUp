<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Models\Project;
use App\Models\ProjectVersion;

/**
 * §8.6.5's version order, which is the flyout's and the API's.
 *
 * > "🛑 The flyout's version order MUST use the §8.6.4 comparator —
 * > `semver` (default), `pep440`, `calver`, `alphabetical` or an explicit
 * > custom order — with a separate per-project toggle for whether `latest`
 * > and `stable` are pinned to the top of the list or sorted in place.
 * > `v1.10` sorting below `v1.9` is the first bug report every new
 * > installation receives."
 *
 * 🛑 **The same comparator as `stable`**, from the same column. A list
 * ordered one way and a pointer derived another is §8.6.4's named failure,
 * and the only defence against it is that neither has a comparator of its
 * own to get wrong.
 *
 * 🛑 **`listed` is applied here and nowhere else in the serving path.**
 * §8.6.2 is explicit that `hidden` is not `private`: an unlisted version
 * "serves by direct URL but is absent from the flyout, sitemap, `llms.txt`
 * and search". So the resolver must never consult `listed` — and this
 * class, which produces the list, must always.
 */
final readonly class VersionOrder
{
    /**
     * The versions a reader may be offered, newest first.
     *
     * @param  list<ProjectVersion>  $versions
     * @return list<ProjectVersion>
     */
    public function forFlyout(Project $project, array $versions): array
    {
        $listed = array_values(array_filter(
            $versions,
            static fn (ProjectVersion $version): bool => $version->listed && $version->active,
        ));

        return $this->sorted($project, $listed);
    }

    /**
     * Every version, listed or not, newest first.
     *
     * For an operator's dashboard, which must show the hidden ones — they
     * are hidden from readers, not from the people who hid them.
     *
     * @param  list<ProjectVersion>  $versions
     * @return list<ProjectVersion>
     */
    public function forDashboard(Project $project, array $versions): array
    {
        return $this->sorted($project, $versions);
    }

    /**
     * @param  list<ProjectVersion>  $versions
     * @return list<ProjectVersion>
     */
    private function sorted(Project $project, array $versions): array
    {
        $comparator = VersionComparator::fromStored($project->version_comparator);

        usort($versions, static function (ProjectVersion $a, ProjectVersion $b) use ($comparator): int {
            // Newest first, so the comparator's ascending result is inverted.
            $order = $comparator->compare((string) ($b->ref_name ?? $b->slug), (string) ($a->ref_name ?? $a->slug));

            // 🛑 A total order, always. Two versions the comparator calls
            // equal — `v1.0` as a branch and `v1.0` as a tag, say — would
            // otherwise come back in whatever order the database returned,
            // which differs between a sort and a re-sort and makes the
            // flyout flicker between page loads.
            return $order !== 0 ? $order : strcmp($a->slug, $b->slug);
        });

        if (! $project->pin_channels_to_top) {
            return $versions;
        }

        return $this->pinChannels($project, $versions);
    }

    /**
     * §8.6.5's toggle: `latest` and `stable` at the top.
     *
     * In that order, because `latest` is where a reader following a link
     * from the project's front page lands and `stable` is what they pick
     * deliberately. Both are omitted when they resolve to nothing, rather
     * than appearing as a dead entry — §8.6.4 makes "no `stable` at all" a
     * valid state and a flyout entry for it would be a 404 with a name.
     *
     * @param  list<ProjectVersion>  $versions
     * @return list<ProjectVersion>
     */
    private function pinChannels(Project $project, array $versions): array
    {
        $pinnedIds = array_values(array_filter([
            $project->resolved_latest_version_id,
            $project->resolved_stable_version_id,
        ], static fn (?string $id): bool => is_string($id) && $id !== ''));

        if ($pinnedIds === []) {
            return $versions;
        }

        $top = [];
        $rest = [];

        foreach ($versions as $version) {
            if (in_array($version->id, $pinnedIds, true)) {
                continue;
            }

            $rest[] = $version;
        }

        foreach ($pinnedIds as $id) {
            foreach ($versions as $version) {
                if ($version->id === $id) {
                    $top[] = $version;

                    break;
                }
            }
        }

        return array_merge($top, $rest);
    }
}
