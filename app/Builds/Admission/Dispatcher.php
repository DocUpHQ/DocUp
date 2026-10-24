<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Admission;

use App\Builds\BuildConfig;
use App\Models\Build;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.5's admission control: who runs next, and whether there is room.
 *
 * 🛑 **The fairness bug this must not reproduce, in one sentence.** Read the
 * Docs queues builds per project and takes the concurrency lock per
 * organisation, so a backlog of fifty builds in one organisation holds the
 * lock continuously and another organisation's *first* build waits behind
 * all of them. The defect is not the lock and not the queue; it is that the
 * two are scoped differently, so the thing being shared is not the thing
 * being ordered.
 *
 * Both profiles here order over the **installation** and take slots at
 * three nested scopes, so the ordering and the sharing agree:
 *
 *  - `simple` orders by arrival across the whole installation. Fifty builds
 *    queued at 10:00 are behind a build queued at 09:59, whoever owns them;
 *  - `fair` orders by deficit round-robin between organisations, so an
 *    organisation's first queued build is reached after at most one grant
 *    to each organisation ahead of it in the rotation — never after the
 *    whole of somebody's backlog.
 *
 * 🛑 **The leader lock is over the dispatcher, not over an organisation.**
 * One holder at a time decides the whole installation's next grants; it is
 * held for the length of a decision, not the length of a build. A lock
 * scoped to an organisation and held while that organisation's builds ran
 * would be the bug above rebuilt from the other side.
 */
final class Dispatcher
{
    private const LEADER_LOCK = 'docup:admission:dispatcher';

    /** Seconds. A decision is a handful of queries; a longer hold means a stuck leader. */
    private const LOCK_SECONDS = 10;

    public function __construct(
        private readonly AdmissionProfile $profile,
    ) {}

    public static function fromConfig(): self
    {
        return new self(AdmissionProfile::fromConfig(config('builds.admission.profile')));
    }

    public function profile(): AdmissionProfile
    {
        return $this->profile;
    }

    /**
     * May this build start now?
     *
     * 🛑 Taken under the leader lock, because the question is "is there room
     * *and* am I next", and both halves are read from a snapshot that two
     * concurrent dispatchers would otherwise read identically and both act
     * on. The database's `inflight` unique index (§10.3) catches the
     * per-version case afterwards; the installation and organisation
     * ceilings have no such index and this lock is what enforces them.
     */
    public function admit(Build $build): AdmissionDecision
    {
        $lock = Cache::lock(self::LEADER_LOCK, self::LOCK_SECONDS);

        if (! $lock->block(5, static fn (): bool => true)) {
            /*
             * Five seconds of contention on a lock held for one decision
             * means a leader died holding it or the cache is unwell. A
             * build that waits is recoverable; a build admitted past the
             * ceilings is a host with more containers than it has memory.
             */
            return AdmissionDecision::wait('admission.dispatcher_busy', 1);
        }

        try {
            return $this->decide($build);
        } finally {
            $lock->release();
        }
    }

    private function decide(Build $build): AdmissionDecision
    {
        $running = $this->runningCounts();

        $installationSlots = BuildConfig::positiveInt('admission.installation_slots', 4);
        $organisationSlots = BuildConfig::positiveInt('admission.organisation_slots', 2);

        $order = $this->order();
        $position = array_search(bin2hex($build->id), $order, true);

        // Not queued, or queued and already gone: nothing to admit.
        if ($position === false) {
            return AdmissionDecision::wait('admission.not_queued', 1);
        }

        $organisation = bin2hex($build->organisation_id);

        if (($running['total'] ?? 0) >= $installationSlots) {
            return AdmissionDecision::wait('admission.installation_at_capacity', $position + 1);
        }

        if (($running[$organisation] ?? 0) >= $organisationSlots) {
            return AdmissionDecision::wait('admission.organisation_at_capacity', $position + 1);
        }

        /*
         * 🛑 Am I next *among the builds that could actually start*? A build
         * at the head of the order whose organisation is already at its
         * ceiling must not block the installation behind it — that would
         * turn the organisation semaphore into exactly the head-of-line
         * block the profile exists to avoid.
         */
        foreach ($order as $candidate) {
            if ($candidate === bin2hex($build->id)) {
                return AdmissionDecision::admit();
            }

            $candidateOrganisation = $this->organisationOf($candidate);

            if ($candidateOrganisation !== null && ($running[$candidateOrganisation] ?? 0) < $organisationSlots) {
                return AdmissionDecision::wait('admission.waiting_for_a_slot', $position + 1);
            }
        }

        return AdmissionDecision::admit();
    }

    /**
     * The order queued builds should be admitted in, as hex build ids.
     *
     * Public so it can be asserted directly: §8.5.5's starvation
     * requirement is a property of this list, and a test that had to start
     * fifty containers to check it would not be run.
     *
     * @return list<string>
     */
    public function order(): array
    {
        /** @var list<object{id: string, organisation_id: string}> $queued */
        $queued = DB::table('builds')
            ->select(['id', 'organisation_id'])
            ->where('state', 'queued')
            ->orderBy('queued_at')
            ->orderBy('id')
            ->limit(1000)
            ->get()
            ->all();

        $rows = [];

        foreach ($queued as $row) {
            $rows[] = [bin2hex((string) $row->id), bin2hex((string) $row->organisation_id)];
        }

        return $this->profile === AdmissionProfile::Fair
            ? self::deficitRoundRobin($rows, $this->weights())
            : array_map(static fn (array $row): string => $row[0], $rows);
    }

    /**
     * Deficit round-robin over organisations, in arrival order within each.
     *
     * 🛑 **A pure function over a list, deliberately.** Admission fairness
     * is the one part of this phase that cannot be demonstrated by running
     * containers — fifty of them would take half an hour — so the property
     * has to be assertable from a list of rows. `FairAdmissionTest` queues
     * fifty builds for one organisation and one for another and asserts
     * where the second lands.
     *
     * The quantum is one grant per unit of weight per pass. An organisation
     * with weight 3 gets three consecutive grants per rotation, not three
     * rotations' worth at the front: the deficit is spent as it is earned,
     * which is what keeps a large weight from becoming a monopoly between
     * passes.
     *
     * @param  list<array{0: string, 1: string}>  $rows  [build, organisation], arrival order
     * @param  array<string, int>  $weights  organisation => share
     * @return list<string>
     */
    public static function deficitRoundRobin(array $rows, array $weights = []): array
    {
        /** @var array<string, list<string>> $queues */
        $queues = [];

        foreach ($rows as [$build, $organisation]) {
            $queues[$organisation][] = $build;
        }

        $deficits = array_fill_keys(array_keys($queues), 0);
        $out = [];

        // Bounded so a weight of zero — which earns nothing and would spin
        // for ever — ends the loop instead of hanging the dispatcher.
        $passes = 0;
        $limit = count($rows) + 1;

        while ($queues !== [] && $passes++ <= $limit) {
            foreach ($queues as $organisation => $queue) {
                $deficits[$organisation] += max(1, $weights[$organisation] ?? 1);

                while ($deficits[$organisation] >= 1 && $queue !== []) {
                    $out[] = array_shift($queue);
                    $deficits[$organisation]--;
                }

                if ($queue === []) {
                    unset($queues[$organisation]);

                    continue;
                }

                $queues[$organisation] = $queue;
            }
        }

        return $out;
    }

    /**
     * Builds currently occupying a slot, by organisation plus a total.
     *
     * @return array<string, int>
     */
    private function runningCounts(): array
    {
        /** @var list<object{organisation_id: string, n: int}> $rows */
        $rows = DB::table('builds')
            ->selectRaw('organisation_id, COUNT(*) as n')
            ->where('state', 'running')
            ->groupBy('organisation_id')
            ->get()
            ->all();

        $counts = ['total' => 0];

        foreach ($rows as $row) {
            $counts[bin2hex((string) $row->organisation_id)] = (int) $row->n;
            $counts['total'] += (int) $row->n;
        }

        return $counts;
    }

    /** @return array<string, int> organisation => §8.5.5's share */
    private function weights(): array
    {
        /** @var list<object{id: string, build_share: int}> $rows */
        $rows = DB::table('organisations')->select(['id', 'build_share'])->get()->all();

        $weights = [];

        foreach ($rows as $row) {
            $weights[bin2hex((string) $row->id)] = max(1, (int) $row->build_share);
        }

        return $weights;
    }

    private function organisationOf(string $buildHex): ?string
    {
        $bytes = hex2bin($buildHex);

        if ($bytes === false) {
            return null;
        }

        $value = DB::table('builds')->where('id', $bytes)->value('organisation_id');

        return is_string($value) ? bin2hex($value) : null;
    }
}
