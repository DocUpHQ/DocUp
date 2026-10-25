<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Build;
use App\Models\DriftEvent;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.8.8's drift events, and §8.8.7's approval gate.
 *
 * > "Every selector resolution MUST be recorded as an append-only row, and
 * > every unpublished composition change as a drift event carrying the
 * > per-mount before/after ref, commit and build id." (§8.8.8)
 *
 * > "`publish_mode` MUST default to `auto` for channel-kind versions and
 * > `manual` for release-kind versions." (§8.8.7)
 *
 * The two clauses are one mechanism. A composition change on a `manual`
 * version does not publish: it becomes a `pending` row describing exactly
 * what would change, and a human decides. On an `auto` version it publishes
 * and becomes an `auto` row describing exactly what did change.
 *
 * 🛑 **`auto` is recorded, not skipped**, and §18.25 is why. The assumption
 * under test is that "approval-gated publication survives contact with
 * operators, rather than `publish_mode='auto'` becoming universal and the
 * drift gate becoming theatre", and its pre-decided consequence is "Keep
 * the drift event and audit record for every **automatic** publication so
 * the evidence trail survives either outcome". A table holding only the
 * gated cases could not tell anyone which outcome happened.
 *
 * 🛑 **The first publish is never drift.** There is nothing to drift from,
 * and gating it would leave a release-kind version unable to publish at all
 * without an approval of a change from nothing to something.
 */
final readonly class DriftGate
{
    /**
     * Whether this version's composition changes may publish themselves.
     *
     * §8.8.7's default is applied by the column, not here; this reads what
     * the column says. A version explicitly set to `auto` publishes even if
     * it is release-kind, which is the operator's call to make and is why
     * §18.25's consequence keeps the evidence either way.
     */
    public function permitsAutomaticPublication(ProjectVersion $version): bool
    {
        return $version->publish_mode !== 'manual';
    }

    /**
     * 🛑 An approval that has not been acted on yet, or null.
     *
     * Without this the gate would be a wall: a `manual` version whose drift
     * a human approved would be refused again on its next trigger, because
     * the composition would still differ from the published manifest. The
     * approval is what opens it, exactly once — {@see self::settle()} then
     * stamps the revision it produced, so a second change needs a second
     * approval.
     */
    public function approvedPending(ProjectVersion $version): ?DriftEvent
    {
        return DriftEvent::query()
            ->where('project_version_id', $version->id)
            ->where('state', 'approved')
            ->whereNull('manifest_id')
            ->orderBy('created_at')
            ->first();
    }

    /**
     * Bind an approved event to the revision it let through.
     *
     * @param  string  $manifestId  raw 16 bytes
     */
    public function settle(DriftEvent $event, string $manifestId): void
    {
        $event->forceFill(['manifest_id' => $manifestId])->save();
    }

    /**
     * 🛑 §8.8.8's "per-mount before/after ref, commit and build id".
     *
     * Compared against the **published manifest**, not against the previous
     * resolution rows: the manifest is what readers are being served, and
     * that is the thing an approval is about. A mount whose selector
     * resolved somewhere else and back again between publishes has not
     * drifted, and a comparison against the last resolution would say it
     * had.
     *
     * @return list<array{mount_path: string, component: string, before: array<string, mixed>|null, after: array<string, mixed>}>
     */
    public function changes(ProjectVersion $version, CompositionPlan $plan): array
    {
        $before = $this->publishedMounts($version);
        $changes = [];

        foreach ($plan->mounts as $mount) {
            $build = $mount->resolution->build;

            $after = [
                'ref' => $mount->resolution->ref,
                'commit_sha' => $mount->resolution->commitSha,
                'build_id' => $build instanceof Build ? Uuid::toText($build->id) : null,
            ];

            $previous = $before[$mount->mountPath] ?? null;

            if ($previous !== null && $this->same($previous, $after)) {
                continue;
            }

            $changes[] = [
                'mount_path' => $mount->mountPath,
                'component' => $mount->componentKey(),
                'before' => $previous,
                'after' => $after,
            ];
        }

        /*
         * A mount that has gone is drift too, and in the direction that
         * matters most: a reader loses a section. Detected by what the
         * published manifest has and the plan does not.
         */
        $planned = [];

        foreach ($plan->mounts as $mount) {
            $planned[$mount->mountPath] = true;
        }

        foreach ($before as $mountPath => $previous) {
            if (! isset($planned[$mountPath])) {
                $changes[] = [
                    'mount_path' => $mountPath,
                    'component' => is_string($previous['component'] ?? null) ? $previous['component'] : '',
                    'before' => $previous,
                    'after' => ['ref' => null, 'commit_sha' => null, 'build_id' => null],
                ];
            }
        }

        return $changes;
    }

    /**
     * Record one drift event.
     *
     * @param  list<array{mount_path: string, component: string, before: array<string, mixed>|null, after: array<string, mixed>}>  $changes
     * @param  string|null  $manifestId  raw 16 bytes; the revision an `auto`
     *                                   publication produced, null for a `pending` one
     */
    public function record(
        ProjectVersion $version,
        array $changes,
        string $state,
        ?string $manifestId = null,
        ?string $actorId = null,
    ): DriftEvent {
        $event = new DriftEvent;

        DB::transaction(static function () use ($event, $version, $changes, $state, $manifestId): void {
            $event->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $version->organisation_id,
                'project_version_id' => $version->id,
                'state' => $state,
                'changes_json' => ['schema' => 'docup.drift/1', 'mounts' => $changes],
                'manifest_id' => $manifestId,
            ])->save();
        });

        Audit::record(
            action: $state === 'pending' ? 'composition.drift_detected' : 'composition.drift_published',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $version->organisation_id,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $version->id,
            // 🛑 §8.22.5: identifiers and counts, never slugs or refs. The
            // detail is in the row; the chain hashes only what it may.
            payload: ['drift_event' => Uuid::toText($event->id), 'mounts_changed' => count($changes)],
        );

        return $event;
    }

    /**
     * The composition the version is currently serving, by mount path.
     *
     * @return array<string, array<string, mixed>>
     */
    private function publishedMounts(ProjectVersion $version): array
    {
        $manifestId = $version->getRawOriginal('published_manifest_id');

        if (! is_string($manifestId)) {
            return [];
        }

        $json = DB::table('project_version_manifests')->where('id', $manifestId)->value('mounts_json');

        if (! is_string($json)) {
            return [];
        }

        $decoded = json_decode($json, true);

        if (! is_array($decoded) || ! is_array($decoded['mounts'] ?? null)) {
            return [];
        }

        $mounts = [];

        foreach ($decoded['mounts'] as $mount) {
            if (! is_array($mount) || ! is_string($mount['mount_path'] ?? null)) {
                continue;
            }

            $mounts[$mount['mount_path']] = [
                'component' => $mount['component_key'] ?? null,
                'ref' => $mount['resolved_ref'] ?? null,
                'commit_sha' => $mount['commit_sha'] ?? null,
                'build_id' => $mount['build_id'] ?? null,
            ];
        }

        return $mounts;
    }

    /**
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     */
    private function same(array $before, array $after): bool
    {
        /*
         * The build id alone decides. Two builds of one commit are
         * different bytes — §18.13's determinism is stated per format and
         * measured, not assumed — so republishing a rebuilt commit IS a
         * change a release-kind version should be asked about.
         */
        return ($before['build_id'] ?? null) === ($after['build_id'] ?? null);
    }
}
