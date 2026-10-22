<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Project and organisation deletion (§8.2.8, §8.22.6).
 *
 * §8.2.8 requires deletion semantics to be stated **explicitly**: domains
 * released into quarantine, certificates revoked, artifacts garbage-collected,
 * search documents purged, audit events retained, and the slug reserved
 * against reuse.
 *
 * 🛑 What this class does today, and what it deliberately does not:
 *
 * - **Slug reserved, permanently.** Implemented here, because it is the one
 *   consequence that outlives everything else and cannot be retrofitted: the
 *   §8.22.6 hard purge destroys the row thirty days later, and a reservation
 *   created then would have nothing to read the slug from.
 * - **Audit events retained.** Free, and by construction: `audit_events`
 *   carries no foreign keys (§10.6, forced by partitioning), so nothing
 *   cascades. Worth stating because the absence of a constraint looks like an
 *   oversight until you know it is the requirement.
 * - **Domains, certificates, artifacts and search documents.** Not implemented,
 *   because none of those subsystems exists yet — they arrive in Phases 03,
 *   10 and 29. Each is listed in the build log as owed, rather than quietly
 *   dropped: a deletion routine that silently omits half its obligations is
 *   worse than one that is honest about being partial, because the gap is
 *   invisible at the call site.
 */
final class Deletions
{
    /**
     * 🛑 §8.22.6: "a mandatory scheduled hard purge at 30 days, not
     * operator-optional, documented as the erasure latency floor."
     */
    public const RECOVERY_WINDOW_DAYS = 30;

    /**
     * Soft-delete a project and reserve its slug for ever.
     *
     * 🛑 The reservation is written in the SAME transaction as the deletion.
     * Written afterwards, a crash between the two would free the slug — and
     * §8.2.8 forbids reuse because a slug appears in published URLs, external
     * links and readers' bookmarks. Recycling one silently points an existing
     * audience at different content under a URL they already trust, which is a
     * far worse failure than a collision error at creation time.
     */
    public function deleteProject(Project $project, ?User $actor = null): void
    {
        DB::transaction(function () use ($project, $actor): void {
            // Idempotent: a double-click must not create two reservations, and
            // the unique index would otherwise turn that into an error page.
            $exists = DB::table('project_slug_reservations')
                ->where('organisation_id', $project->organisation_id)
                ->where('slug', $project->slug)
                ->exists();

            if (! $exists) {
                DB::table('project_slug_reservations')->insert([
                    'id' => Uuid::v7(),
                    'organisation_id' => $project->organisation_id,
                    'slug' => $project->slug,
                    'former_project_id' => $project->id,
                    'reserved_at' => now(),
                ]);
            }

            $project->delete();

            Audit::record(
                action: 'project.deleted',
                actorType: $actor === null ? ActorType::System : ActorType::User,
                organisationId: $project->organisation_id,
                actorId: $actor?->id,
                subjectType: 'project',
                subjectId: $project->id,
                payload: [
                    'slug_reserved' => true,
                    'hard_purge_after_days' => self::RECOVERY_WINDOW_DAYS,
                ],
            );
        });
    }

    /**
     * Whether a slug may be used in an organisation.
     *
     * Checks the reservations as well as the live and soft-deleted rows,
     * because the reservation is the only record that survives the purge.
     */
    public function slugIsAvailable(Organisation $organisation, string $slug): bool
    {
        $reserved = DB::table('project_slug_reservations')
            ->where('organisation_id', $organisation->id)
            ->where('slug', $slug)
            ->exists();

        if ($reserved) {
            return false;
        }

        // withTrashed(), because a soft-deleted project still holds its slug
        // during the recovery window.
        return ! Project::query()
            ->withTrashed()
            ->where('slug', $slug)
            ->exists();
    }

    /**
     * Soft-delete an organisation.
     *
     * Projects are left to cascade on the hard purge rather than being
     * soft-deleted individually: §8.22.6 makes `deleted_at` a recovery window,
     * and an operator restoring an organisation within it expects to find its
     * projects as they were. Marking each one deleted would make restoration a
     * reconstruction.
     */
    public function deleteOrganisation(Organisation $organisation, ?User $actor = null): void
    {
        DB::transaction(function () use ($organisation, $actor): void {
            $organisation->delete();

            Audit::record(
                action: 'organisation.deleted',
                actorType: $actor === null ? ActorType::System : ActorType::User,
                organisationId: $organisation->id,
                actorId: $actor?->id,
                subjectType: 'organisation',
                subjectId: $organisation->id,
                payload: ['hard_purge_after_days' => self::RECOVERY_WINDOW_DAYS],
            );
        });
    }
}
