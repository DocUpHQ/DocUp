<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Builds\Admission\Dispatcher;
use App\Models\Build;
use Illuminate\Support\Facades\DB;

/**
 * §8.5.23's "queue position and estimated wait".
 *
 * 🛑 **The position comes from the dispatcher that will actually admit
 * the build**, not from a `COUNT(*)` of older queued rows. Under
 * §8.5.5's `fair` profile those two numbers differ by design — an
 * organisation's first build is near the front however many are queued
 * ahead of it — and showing arrival order while admitting by deficit
 * round-robin would mean the number in the UI counted down and then
 * stopped meaning anything.
 *
 * 🛑 **The estimate is a median of what this project actually did, and it
 * is null when there is nothing to base it on.** An estimate invented
 * from a default is worse than none: a reader who is told "about 2
 * minutes" and waits eleven learns to disbelieve the number, and the
 * number is the only thing standing between them and a support request.
 */
final readonly class BuildProgress implements \JsonSerializable
{
    private function __construct(
        /** 1-based place in the admission order; null once running. */
        public ?int $position,

        /** Builds ahead of this one that are already running. */
        public int $running,

        /** Seconds, or null when this project has no finished builds to learn from. */
        public ?int $estimatedWaitSeconds,

        /** The median this estimate was derived from, for the same honesty. */
        public ?int $medianDurationSeconds,
    ) {}

    public static function of(Build $build, ?Dispatcher $dispatcher = null): self
    {
        $median = self::medianDuration($build);
        $running = (int) DB::table('builds')->where('state', 'running')->count();

        if ($build->state !== 'queued') {
            return new self(null, $running, null, $median);
        }

        $order = ($dispatcher ?? Dispatcher::fromConfig())->order();
        $index = array_search(bin2hex($build->id), $order, true);

        if ($index === false) {
            return new self(null, $running, null, $median);
        }

        $position = $index + 1;

        /*
         * Slots, not workers: §8.5.5's installation semaphore is what
         * decides how many builds run at once, so the wait for position N
         * is roughly ⌈N / slots⌉ builds long. Flooring the divisor at 1
         * because a misconfigured zero would otherwise divide by nothing
         * and produce an infinite wait in the UI.
         */
        $slots = max(1, BuildConfig::positiveInt('admission.installation_slots', 4));

        return new self(
            position: $position,
            running: $running,
            estimatedWaitSeconds: $median === null ? null : (int) ceil($position / $slots) * $median,
            medianDurationSeconds: $median,
        );
    }

    /**
     * The median wall-clock duration of this project's recent builds.
     *
     * 🛑 Median, not mean. Build durations have a long tail — one
     * cold-cache build that took eleven minutes among twenty that took
     * forty seconds — and a mean would quote the outlier to everybody
     * waiting behind an ordinary build.
     */
    private static function medianDuration(Build $build): ?int
    {
        /** @var list<object{seconds: int|string|null}> $rows */
        $rows = DB::table('builds')
            ->selectRaw('TIMESTAMPDIFF(SECOND, started_at, finished_at) AS seconds')
            ->where('project_version_id', $build->project_version_id)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->whereNotNull('started_at')
            ->whereNotNull('finished_at')
            ->orderByDesc('finished_at')
            ->limit(20)
            ->get()
            ->all();

        $durations = [];

        foreach ($rows as $row) {
            $seconds = (int) ($row->seconds ?? 0);

            if ($seconds > 0) {
                $durations[] = $seconds;
            }
        }

        if ($durations === []) {
            return null;
        }

        sort($durations);
        $middle = intdiv(count($durations), 2);

        return count($durations) % 2 === 1
            ? $durations[$middle]
            : (int) round(($durations[$middle - 1] + $durations[$middle]) / 2);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'queue_position' => $this->position,
            'running_builds' => $this->running,
            'estimated_wait_seconds' => $this->estimatedWaitSeconds,
            'median_duration_seconds' => $this->medianDurationSeconds,
        ];
    }
}
