<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Automation;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Automation\CronSchedule;
use App\Builds\Jobs\RunBuild;
use App\Models\BuildRequest;
use App\Models\BuildSchedule;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Carbon\CarbonImmutable;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

/**
 * 🛑 Phase 11's last exit criterion — "A nightly schedule runs with no
 * push" — and §8.22.13's DST semantics, which the specification requires be
 * **stated**:
 *
 * > "Scheduled builds MUST take an IANA timezone with explicit DST
 * > semantics (a 02:00 nightly build skips one day and repeats another —
 * > the documentation MUST say which)."
 *
 * What DocUp says, and what this file proves:
 *
 *   - A wall-clock time that does **not exist** (spring forward) is
 *     **skipped**.
 *   - A wall-clock time that occurs **twice** (autumn back) fires **once,
 *     at the first occurrence**.
 *
 * The dates below are real transitions, not invented ones: 8 March 2026 and
 * 1 November 2026 in `America/New_York`, 29 March 2026 in `Europe/London`.
 */
final class BuildScheduleTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Nightly Co',
            'slug' => 'nightly-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'main',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => 'main',
            'ref_kind' => 'branch',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /** 🛑 "A nightly schedule runs with no push." */
    public function test_a_nightly_schedule_builds_with_no_push(): void
    {
        $schedule = $this->schedule('0 2 * * *', 'UTC');

        // Due a minute ago; nothing has pushed anything.
        $schedule->forceFill(['next_run_at' => CarbonImmutable::now()->subMinute()])->save();

        $this->runCommand('docup:schedules:run');

        Queue::assertPushed(RunBuild::class, 1);

        $request = BuildRequest::query()->where('project_version_id', $this->version->id)->sole();

        $this->assertSame('schedule', $request->trigger, '§8.5.3: a schedule is one of the eight trigger kinds');
        $this->assertSame('queued', $request->state);

        $schedule->refresh();

        $this->assertNotNull($schedule->last_run_at);
        $this->assertTrue(
            $schedule->next_run_at?->greaterThan(CarbonImmutable::now()) ?? false,
            'the pointer moved forward, so the next tick does not fire it again',
        );
    }

    /** A schedule that is not due fires nothing. */
    public function test_a_schedule_in_the_future_does_not_fire(): void
    {
        $schedule = $this->schedule('0 2 * * *', 'UTC');
        $schedule->forceFill(['next_run_at' => CarbonImmutable::now()->addHour()])->save();

        $this->runCommand('docup:schedules:run');

        Queue::assertNothingPushed();
    }

    /** A disabled schedule fires nothing, however overdue. */
    public function test_a_disabled_schedule_does_not_fire(): void
    {
        $schedule = $this->schedule('0 2 * * *', 'UTC');
        $schedule->forceFill([
            'enabled' => false,
            'next_run_at' => CarbonImmutable::now()->subDay(),
        ])->save();

        $this->runCommand('docup:schedules:run');

        Queue::assertNothingPushed();
    }

    /**
     * 🛑 A missed tick fires ONCE, not once per minute it missed.
     *
     * A scheduler that was down overnight must produce one catch-up build,
     * because the next run is computed from the instant that fired rather
     * than from how many occurrences went by.
     */
    public function test_a_schedule_overdue_by_hours_fires_once(): void
    {
        $schedule = $this->schedule('0 2 * * *', 'UTC');
        $schedule->forceFill(['next_run_at' => CarbonImmutable::now()->subHours(9)])->save();

        $this->runCommand('docup:schedules:run');

        Queue::assertPushed(RunBuild::class, 1);
        $this->assertSame(1, BuildRequest::query()->where('trigger', 'schedule')->count());
    }

    /**
     * 🛑 §8.22.13, half one: the spring-forward gap is **skipped**.
     *
     * 02:30 does not exist in `America/New_York` on 8 March 2026 — the
     * clocks go from 01:59:59 EST to 03:00:00 EDT. A nightly 02:30 build
     * does not run that day, and the next run it reports is the 9th.
     */
    public function test_a_nonexistent_wall_time_is_skipped(): void
    {
        $schedule = new CronSchedule('30 2 * * *', 'America/New_York');

        // Just after the 7th's run.
        $after = CarbonImmutable::parse('2026-03-07 07:31:00', 'UTC');

        $next = $schedule->nextAfter($after);

        $this->assertNotNull($next);
        $this->assertSame(
            '2026-03-09 06:30:00',
            $next->format('Y-m-d H:i:s'),
            '🛑 8 March is skipped entirely: 02:30 EST does not exist, and 03:30 is an hour the operator did not ask for',
        );
    }

    /** The same, in `Europe/London`, whose transition is a different date. */
    public function test_the_london_spring_forward_gap_is_skipped_too(): void
    {
        $schedule = new CronSchedule('30 1 * * *', 'Europe/London');

        $next = $schedule->nextAfter(CarbonImmutable::parse('2026-03-28 01:31:00', 'UTC'));

        $this->assertNotNull($next);
        $this->assertSame(
            '2026-03-30 00:30:00',
            $next->format('Y-m-d H:i:s'),
            '29 March 2026: 01:30 BST does not exist in London',
        );
    }

    /**
     * 🛑 §8.22.13, half two: a repeated wall time fires **once**, at the
     * first occurrence.
     *
     * 01:30 happens twice in `America/New_York` on 1 November 2026 — once
     * at 05:30 UTC in EDT and again at 06:30 UTC in EST. The schedule
     * resolves to the earlier instant, and the next run after it is the
     * 2nd rather than the second 01:30.
     */
    public function test_an_ambiguous_wall_time_fires_once_at_the_first_occurrence(): void
    {
        $schedule = new CronSchedule('30 1 * * *', 'America/New_York');

        $first = $schedule->nextAfter(CarbonImmutable::parse('2026-10-31 20:00:00', 'UTC'));

        $this->assertNotNull($first);
        $this->assertSame(
            '2026-11-01 05:30:00',
            $first->format('Y-m-d H:i:s'),
            'the FIRST 01:30, which is 05:30 UTC while EDT is still in force',
        );

        $next = $schedule->nextAfter($first);

        $this->assertNotNull($next);
        $this->assertSame(
            '2026-11-02 06:30:00',
            $next->format('Y-m-d H:i:s'),
            '🛑 not the second 01:30 an hour later: one wall time, one run',
        );
    }

    /** An ordinary day is unaffected by any of the above. */
    public function test_an_ordinary_day_resolves_to_the_expected_instant(): void
    {
        $schedule = new CronSchedule('30 2 * * *', 'America/New_York');

        $next = $schedule->nextAfter(CarbonImmutable::parse('2026-06-01 12:00:00', 'UTC'));

        $this->assertSame('2026-06-02 06:30:00', $next?->format('Y-m-d H:i:s'), '02:30 EDT is 06:30 UTC');
    }

    /** 🛑 The timezone is validated against the IANA database, not a regex. */
    public function test_an_unknown_timezone_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CronSchedule('0 2 * * *', 'Mars/Olympus_Mons');
    }

    /** And so is the expression, so a typo cannot become a schedule that never fires. */
    public function test_an_invalid_expression_is_refused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new CronSchedule('not a cron expression', 'UTC');
    }

    public function test_validity_can_be_checked_without_throwing(): void
    {
        $this->assertTrue(CronSchedule::isValid('0 2 * * *', 'Europe/London'));
        $this->assertFalse(CronSchedule::isValid('0 2 * * *', 'Nowhere/Nothing'));
        $this->assertFalse(CronSchedule::isValid('@nonsense', 'UTC'));
    }

    /**
     * A schedule with no version follows §8.6.14's pointer rather than
     * capturing it, so it keeps working when the default moves.
     */
    public function test_a_schedule_without_a_version_follows_the_default_pointer(): void
    {
        $schedule = $this->schedule('0 2 * * *', 'UTC', version: null);
        $schedule->forceFill(['next_run_at' => CarbonImmutable::now()->subMinute()])->save();

        $other = new ProjectVersion;
        $other->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'v2',
            'kind' => 'release',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
        ])->save();

        $this->project->forceFill(['default_version_id' => $other->id])->save();

        $this->runCommand('docup:schedules:run');

        $request = BuildRequest::query()->where('trigger', 'schedule')->sole();

        $this->assertSame(
            $other->id,
            $request->project_version_id,
            'the schedule built whatever the default pointer names now, not what it named when it was written',
        );
    }

    /**
     * Run a command and assert it succeeded.
     *
     * `Artisan::call()` rather than `$this->artisan()`, for the reason
     * `AuditChainTest` records: the fluent helper returns
     * `PendingCommand|int` depending on whether the test has expectations
     * on it, which is a union no static analyser can resolve — and
     * silencing that with a cast would hide the day it genuinely returns
     * the wrong thing.
     */
    private function runCommand(string $command): void
    {
        $this->assertSame(0, Artisan::call($command), $command.' must succeed');
    }

    private function schedule(string $expression, string $timezone, ?string $version = 'self'): BuildSchedule
    {
        $schedule = new BuildSchedule;

        $schedule->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'project_version_id' => $version === 'self' ? $this->version->id : null,
            'cron_expression' => $expression,
            'timezone' => $timezone,
            'enabled' => true,
        ])->save();

        return $schedule;
    }
}
