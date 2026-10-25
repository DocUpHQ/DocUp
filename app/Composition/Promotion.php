<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Artifacts\Publisher;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\ComponentMount;
use App\Models\DriftEvent;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.8.7's snapshot-on-promote, and the other end of §8.8.8's gate.
 *
 * > "A release-kind version MUST rewrite every mount to `pinned_build` at
 * > promotion, so a shipped release can never drift."
 *
 * **Rewrite, not freeze.** The tempting implementation is a flag that makes
 * the resolver stop resolving; this instead changes the selectors
 * themselves, so a human reading the mount rows of a shipped release sees
 * build identifiers rather than a tracking selector plus a flag they have
 * to know about. The selector is the record.
 *
 * 🛑 **`pinned_build`, not `pinned_ref`**, and §8.8.7's own words say why: "a
 * shipped release can **never** drift". A tag can be force-pushed, so a ref
 * names a commit only until somebody moves it; a build id names bytes that
 * already exist and are immutable under §8.8.1. The difference is invisible
 * until the week somebody re-tags `v2.0`, which is precisely the week a
 * shipped release must not change.
 */
final readonly class Promotion
{
    public function __construct(private SelectorResolver $selectors = new SelectorResolver) {}

    /**
     * Pin every mount of a version to the build it currently resolves to.
     *
     * Idempotent: a mount already on `pinned_build` resolves to that build
     * and is rewritten to the same value, which is what makes "promote
     * twice" harmless rather than something callers have to guard.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     * @return int how many mounts changed selector
     */
    public function pinMounts(ProjectVersion $version, ?string $actorId = null): int
    {
        /** @var list<ComponentMount> $mounts */
        $mounts = array_values(
            ComponentMount::query()->where('project_version_id', $version->id)->get()->all(),
        );

        $pinned = 0;

        foreach ($mounts as $mount) {
            $resolution = $this->selectors->resolve($mount, $version);
            $build = $resolution->build;

            if ($build === null) {
                /*
                 * 🛑 A mount that resolves to nothing is left alone rather
                 * than pinned to null. §8.7.20 makes a required mount that
                 * cannot resolve fail the next publish closed, which is the
                 * right place for that refusal — pinning it here would turn
                 * "this release is not ready" into "this release is pinned
                 * to nothing", which looks deliberate.
                 */
                continue;
            }

            $wanted = Uuid::toText($build->id);

            if ($mount->selector_kind === SelectorKind::PinnedBuild->value
                && $mount->selector_value === $wanted) {
                continue;
            }

            $previous = $mount->selector_kind;

            $mount->forceFill([
                'selector_kind' => SelectorKind::PinnedBuild->value,
                'selector_value' => $wanted,

                // Meaningless once pinned, and a stale value here would read
                // as configuration on a mount that no longer consults it.
                'mirror_fallback' => null,
            ])->save();

            $pinned++;

            Audit::record(
                action: 'component.mount_pinned',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $version->organisation_id,
                actorId: $actorId,
                subjectType: 'component_mount',
                subjectId: $mount->id,
                payload: [
                    'from_selector' => $previous,
                    'to_build' => $wanted,
                ],
            );
        }

        return $pinned;
    }

    /**
     * 🛑 §8.8.8's approval, which is the only thing that lets a `manual`
     * version's drift become what readers see.
     *
     * Approving records the decision and nothing else: the publish happens
     * on the next trigger, through the same {@see Publisher}
     * path every other publish uses. Making approval itself publish would
     * be a second publish path, and §8.8.4's compare-and-swap is one
     * mechanism on purpose.
     *
     * @param  string|null  $actorId  raw 16 bytes
     */
    public function approve(DriftEvent $event, ?string $actorId = null, string $reason = ''): void
    {
        $this->decide($event, 'approved', $actorId, $reason);
    }

    /** @param  string|null  $actorId  raw 16 bytes */
    public function reject(DriftEvent $event, ?string $actorId = null, string $reason = ''): void
    {
        $this->decide($event, 'rejected', $actorId, $reason);
    }

    /** @param  string|null  $actorId  raw 16 bytes */
    private function decide(DriftEvent $event, string $state, ?string $actorId, string $reason): void
    {
        DB::transaction(static function () use ($event, $state, $actorId, $reason): void {
            $event->forceFill([
                'state' => $state,
                'decided_at' => now(),
                'decided_by' => $actorId,
                'decision_reason' => mb_strcut($reason, 0, 255),
            ])->save();
        });

        Audit::record(
            action: 'composition.drift_'.$state,
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $event->organisation_id,
            actorId: $actorId,
            subjectType: 'project_version',
            subjectId: $event->project_version_id,
            payload: ['drift_event' => Uuid::toText($event->id)],
        );
    }

    /**
     * Whether a version has an approved drift event nobody has published yet.
     *
     * Read by the publisher's gate so an approval actually opens it: without
     * this an approved change would be refused again on its next trigger,
     * and the gate would be a wall.
     */
    public function hasApprovedDrift(ProjectVersion $version): bool
    {
        return DriftEvent::query()
            ->where('project_version_id', $version->id)
            ->where('state', 'approved')
            ->whereNull('manifest_id')
            ->exists();
    }
}
