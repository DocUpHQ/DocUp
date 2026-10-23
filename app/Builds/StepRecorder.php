<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\Build;
use App\Models\BuildStep;
use Illuminate\Support\Facades\DB;

/**
 * The step rows, and the heartbeat lease that guards them (§10.3).
 *
 * > "`build_steps` (claimed under a **heartbeat lease**, because builds
 * > outlive queue visibility timeouts …)"
 *
 * 🛑 **Why a lease and not a queue reservation.** A queue's visibility timeout
 * is a fixed clock the worker does not control: a build that takes 25 minutes
 * under a 90-second timeout is redelivered sixteen times, and each delivery
 * starts the work again. The lease inverts the relationship — the holder
 * extends its own expiry while it is alive, so the deadline tracks liveness
 * rather than a guess about duration. A runner that dies simply stops
 * extending, and the reaper notices within one lease.
 *
 * 🛑 **Every claim and renewal is a conditional UPDATE, never a read then a
 * write.** `UPDATE … WHERE id = ? AND lease_owner = ?` returning zero rows is
 * how a holder learns it has lost the lease — which it can, if it paused long
 * enough for the reaper to act. A read-then-write would let two runners both
 * believe they hold the same step, and the second would overwrite the first's
 * result with its own.
 */
final readonly class StepRecorder
{
    public function __construct(private string $owner) {}

    /** A stable identity for this process, so a reclaim can name who died. */
    public static function forThisProcess(): self
    {
        return new self(gethostname().':'.getmypid());
    }

    /**
     * Create the twelve rows for a build, in §8.5.6's order.
     *
     * All twelve up front rather than one at a time, because Phase 06's exit
     * criterion is "watch step rows advance" — and a UI that discovers the
     * pipeline one row at a time cannot show a reader how far through they
     * are, which is the only thing they want to know.
     *
     * @return array<string, BuildStep> keyed by stage value
     */
    public function createPipeline(Build $build): array
    {
        $steps = [];

        foreach (Stage::pipeline() as $stage) {
            $step = new BuildStep;
            $step->forceFill([
                'organisation_id' => $build->organisation_id,
                'build_id' => $build->id,
                'stage' => $stage->value,
                'sequence' => $stage->sequence(),
                'state' => 'pending',
                'attempt' => 1,
            ])->save();

            $steps[$stage->value] = $step;
        }

        return $steps;
    }

    /**
     * Claim a step, or null when somebody else holds it.
     *
     * 🛑 The `WHERE` is the whole lock. A row is claimable when it is
     * `pending`, or when it is `running` with a lapsed lease — the second
     * case being a runner that died, which is the situation the lease exists
     * for. Expressing both in one statement means there is no window between
     * "decide it is abandoned" and "take it".
     */
    public function claim(BuildStep $step): ?BuildStep
    {
        $ttl = BuildConfig::positiveInt('lease_seconds', 60);
        $now = now();

        $claimed = DB::table('build_steps')
            ->where('id', $step->id)
            ->where(function ($query) use ($now): void {
                $query->where('state', 'pending')
                    ->orWhere(function ($inner) use ($now): void {
                        $inner->where('state', 'running')->where('lease_expires_at', '<', $now);
                    });
            })
            ->update([
                'state' => 'running',
                'lease_owner' => $this->owner,
                'lease_expires_at' => $now->copy()->addSeconds($ttl),
                'started_at' => $now,
                'updated_at' => $now,
            ]);

        if ($claimed === 0) {
            return null;
        }

        return $step->fresh();
    }

    /**
     * Extend the lease. False means it was lost — stop working.
     *
     * The caller must act on false. A runner that keeps going after losing
     * its lease is the duplicate-execution case the lease exists to prevent,
     * and it will write its result over whoever took the step from it.
     */
    public function renew(BuildStep $step): bool
    {
        $ttl = BuildConfig::positiveInt('lease_seconds', 60);

        $renewed = DB::table('build_steps')
            ->where('id', $step->id)
            ->where('lease_owner', $this->owner)
            ->where('state', 'running')
            ->update([
                'lease_expires_at' => now()->addSeconds($ttl),
                'lease_renewals' => DB::raw('lease_renewals + 1'),
                'updated_at' => now(),
            ]);

        return $renewed === 1;
    }

    public function succeed(BuildStep $step, ?int $exitCode = 0): void
    {
        $this->settle($step, 'succeeded', ['exit_code' => $exitCode]);
    }

    public function skip(BuildStep $step, string $reason): void
    {
        /*
         * A skipped step records *why* in the failure identifier even though
         * it is not a failure. §8.5.4 insists a skip "MUST resolve to
         * `skipped` and never `failed`"; it says nothing about throwing the
         * reason away, and the reason is the only thing that distinguishes
         * "nothing to do" from "silently did nothing".
         */
        $this->settle($step, 'skipped', ['failure_identifier' => $reason]);
    }

    public function fail(BuildStep $step, BuildFailure $failure): void
    {
        $this->settle($step, 'failed', $failure->columns());
    }

    /**
     * Reclaim steps whose runner stopped renewing.
     *
     * 🛑 Classified `infra`, which §8.5.17 then excludes from the governor:
     * "Infrastructure failures MUST NEVER disable a tenant". A runner dying
     * is ours, and counting it against the tenant whose build happened to be
     * running would disable webhooks for somebody who did nothing.
     *
     * @return int how many were reclaimed
     */
    public function reapAbandoned(): int
    {
        $abandoned = BuildStep::query()
            ->where('state', 'running')
            ->whereNotNull('lease_expires_at')
            ->where('lease_expires_at', '<', now())
            ->get();

        foreach ($abandoned as $step) {
            $this->settle($step, 'failed', [
                'failure_class' => FailureClass::Infra->value,
                'failure_identifier' => 'infra.runner_lost',
            ]);
        }

        return $abandoned->count();
    }

    /** @param  array<string, mixed>  $columns */
    private function settle(BuildStep $step, string $state, array $columns): void
    {
        $step->forceFill(array_merge($columns, [
            'state' => $state,
            'finished_at' => now(),
            // Released, so a reaper never reclaims a step that is done.
            'lease_owner' => null,
            'lease_expires_at' => null,
        ]))->save();
    }
}
