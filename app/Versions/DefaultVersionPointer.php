<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Invalidation;

/**
 * §8.6.14's explicit pointer, and what happens when its target goes away.
 *
 * > "🛑 The system MUST hold the default version as an explicit stored
 * > pointer on the project, not as a derived value, because §8.9.7's
 * > empty-path redirect, §8.6.11's `/page/<filename>` resolution and
 * > §8.11.5's 404 chain all depend on it. The pointer MUST be settable by
 * > an operator and by an automation rule, MUST be **re-pointed
 * > automatically with an audit event** when its target is deleted or
 * > deactivated, and MUST have a stated fallback order when unset."
 *
 * 🛑 **Stored, and this class never derives it on read.** `SnapshotProject`
 * reads the column; nothing computes a default on the serving path. What
 * this class does is move the pointer when the thing it points at stops
 * being servable — which is a write, happening once, rather than a
 * computation happening on every request that omits a version.
 *
 * 🛑 **The fallback order is stated here because §8.6.14 requires one, and
 * it deliberately does not end in "the first row".** A project with no
 * servable version has no default, and `/` then 404s rather than
 * redirecting somewhere arbitrary. An arbitrary redirect is worse: it is a
 * URL a reader bookmarks that changes meaning the next time a version is
 * created.
 */
final readonly class DefaultVersionPointer
{
    /**
     * §8.6.14's fallback order, applied when the pointer is unset or dead.
     *
     * 1. `latest`, because that is what a reader following a link from a
     *    project's front page expects and what Read the Docs does;
     * 2. `stable`, for a project that publishes releases and no tip;
     * 3. nothing.
     *
     * 🛑 Step 3 is not "the newest version". The two channels are already
     * the project's own statement about which version matters, derived by
     * §8.6.4's rules from the operator's own configuration — reaching past
     * them to a version nobody nominated would be this class inventing a
     * policy where §8.6.4 already has one.
     */
    public function fallbackFor(Project $project, ChannelOutcome $channels): ?ProjectVersion
    {
        foreach ([$channels->latest, $channels->stable] as $candidate) {
            if ($candidate instanceof ProjectVersion && $candidate->active) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Re-point the default if it no longer names a usable version.
     *
     * Returns true when the pointer moved. Called after anything that can
     * make a version unusable — a deactivation, a wipe, a ref that
     * disappeared — rather than on read, because §8.6.14's whole point is
     * that the pointer is a stored fact.
     *
     * @param  list<ProjectVersion>  $versions
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     */
    public function reconcile(
        Project $project,
        array $versions,
        ChannelOutcome $channels,
        ?string $actorId = null,
    ): bool {
        $current = $this->currentTarget($project, $versions);

        if ($current instanceof ProjectVersion) {
            return false;
        }

        $replacement = $this->fallbackFor($project, $channels);

        if ($project->default_version_id === $replacement?->id) {
            return false;
        }

        $previous = $project->default_version_id;

        $project->forceFill(['default_version_id' => $replacement?->id])->save();

        /*
         * 🛑 §8.6.14 asks for the audit event by name, and the reason is
         * that this is a change nobody made. An operator who finds `/`
         * landing somewhere new needs to be able to discover that the
         * version it used to point at was deactivated, and when.
         */
        Audit::record(
            action: 'version.default_repointed',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $project->organisation_id,
            actorId: $actorId,
            subjectType: 'project',
            subjectId: $project->id,
            payload: [
                'from' => $previous === null ? null : bin2hex($previous),
                'to' => $replacement === null ? null : bin2hex($replacement->id),
                'slug' => $replacement?->slug,
                'reason' => 'the previous default is no longer active',
            ],
        );

        Invalidation::bumpRouting(
            projectId: $project->id,
            cause: 'version pointer change',
            organisationId: $project->organisation_id,
            actorId: $actorId,
        );

        return true;
    }

    /**
     * The version the pointer names, if it is still usable.
     *
     * 🛑 `active` only, not `published`. A project whose default version is
     * active and has nothing published yet is a project mid-setup, and
     * re-pointing away from it the moment it is created would fight the
     * operator — the empty-path redirect answers that case with a 404 from
     * `SnapshotProject::defaultVersion()`, which is the honest answer and
     * not a reason to move the pointer.
     *
     * @param  list<ProjectVersion>  $versions
     */
    private function currentTarget(Project $project, array $versions): ?ProjectVersion
    {
        if ($project->default_version_id === null) {
            return null;
        }

        foreach ($versions as $version) {
            if ($version->id === $project->default_version_id) {
                return $version->active ? $version : null;
            }
        }

        return null;
    }
}
