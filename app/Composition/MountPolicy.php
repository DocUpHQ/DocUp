<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Auth\AccessLevel;
use App\Models\Component;
use App\Models\ComponentGrant;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\TeamMember;

/**
 * §8.7.7's ceiling and §8.7.8's grant — the two questions asked before any
 * mount exists.
 *
 * 🛑 A pure policy, with no writes. It is separate from {@see Mounts}
 * because §8.7.7 asks the ceiling question in **three** places and they must
 * agree:
 *
 *   1. "validated when a mount is created" — {@see Mounts::attach()};
 *   2. "denormalised into the published manifest" — the publisher's
 *      `min_access_snapshot`;
 *   3. "**re-evaluated on every request after mount matching**" — the
 *      serving path.
 *
 * Three call sites and one implementation, because three implementations of
 * a confidentiality rule is three chances to disagree, and the one that
 * disagrees in the permissive direction is a disclosure.
 */
final readonly class MountPolicy
{
    /**
     * 🛑 §8.7.7: may this component be mounted on this version at all?
     *
     * > "Mounting a component whose ceiling is stricter than the target
     * > version's effective visibility MUST be **refused, not warned**."
     *
     * "Effective visibility" is the **maximum order of project and version
     * visibility**, which §12.3's own table spells out — a public version of
     * a members-only project is members-only, because the project is a
     * ceiling too. Taking the version's alone would let a public version
     * inside a private project mount anything.
     */
    public function permitsMount(Component $component, ProjectVersion $version, ?Project $project = null): bool
    {
        return ! $component->min_access->stricter($this->effectiveVisibility($version, $project));
    }

    /**
     * The visibility a mount is measured against.
     *
     * 🛑 The stricter of the project's and the version's, never one of
     * them. §12.3: "effective visibility is the maximum order of project and
     * version visibility."
     */
    public function effectiveVisibility(ProjectVersion $version, ?Project $project = null): AccessLevel
    {
        $project ??= $version->project;

        $versionLevel = $version->visibility;

        if (! $project instanceof Project) {
            /*
             * A version with no project cannot be reasoned about, so the
             * strictest answer is the only safe one. This is unreachable
             * through the application — the foreign key is NOT NULL — and
             * is here because "unreachable" is a claim about today's code
             * and `restricted` costs nothing if it is wrong.
             */
            return AccessLevel::Restricted;
        }

        return $versionLevel->stricter($project->visibility) ? $versionLevel : $project->visibility;
    }

    /**
     * 🛑 §8.7.8: "Mounting a component a team does not own MUST require an
     * explicit `component_grants` row. Mounting is not implicitly
     * organisation-wide."
     *
     * Three ways to be permitted, and the first is the one that makes the
     * rule usable rather than theatrical:
     *
     *   1. The component is **organisation-owned** (`owner_team_id` null).
     *      Nobody's team owns it, so nobody needs a grant from them. Every
     *      component created before grants existed is in this state, and a
     *      reading in which those became unmountable would have been a
     *      migration that broke every installation.
     *   2. The actor is in the **owning team**. Owning is the permission.
     *   3. An explicit `component_grants` row names a team the actor is in.
     *
     * 🛑 A null actor is the SYSTEM, and the system is permitted. The build
     * pipeline and the §8.6.8 automation rules mount nothing today, but
     * when one does it is acting on an operator's earlier decision, and
     * refusing it would mean an automation rule that silently never fires —
     * which §8.6.8's own validation exists to prevent elsewhere.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null for the system
     */
    public function permitsActor(Component $component, ?string $actorId): bool
    {
        if ($actorId === null || $component->owner_team_id === null) {
            return true;
        }

        $teams = TeamMember::query()
            ->where('user_id', $actorId)
            ->pluck('team_id')
            ->all();

        if (in_array($component->owner_team_id, $teams, true)) {
            return true;
        }

        if ($teams === []) {
            return false;
        }

        return ComponentGrant::query()
            ->where('component_id', $component->id)
            ->where('capability', 'mount')
            ->whereIn('team_id', $teams)
            ->exists();
    }
}
