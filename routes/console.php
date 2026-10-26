<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use Illuminate\Support\Facades\Schedule;

/*
|---------------------------------------------------------------------------
| Scheduled work
|---------------------------------------------------------------------------
|
| 🛑 §8.22.1: the daily signed anchors.
|
| An anchor is what closes the one gap a hash chain cannot. A chain detects
| edits by anyone who cannot recompute it — but an attacker with database
| write access and the audit key can rewrite history, recompute every hash
| from the edit forward, and leave a chain that verifies perfectly. A signed
| anchor fixes each day's head hash, so forging one requires `k_audit` at the
| time of the forgery, and the window for undetectable rewriting closes at one
| day.
|
| Which is why this is scheduled rather than left to an operator to remember:
| a skipped day is a day that can be rewritten. `docup:audit:verify` checks
| anchors, so a missing one is visible, but visible-after-the-fact is not the
| same as prevented.
|
| 01:30 UTC, after midnight has safely passed in every timezone the events
| were recorded with — the command anchors YESTERDAY, and §8.22.13 stores all
| timestamps UTC, so there is no ambiguity about which day is finished.
|
| `withoutOverlapping` because a long run must not have a second copy writing
| the same anchors; `onOneServer` because a multi-node installation would
| otherwise race, and only the first insert would win on the
| (chain_key, anchored_on) unique index while the others errored.
*/
Schedule::command('docup:audit:anchor')
    ->dailyAt('01:30')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
| 🛑 §8.22.6: the hard purge is MANDATORY, not operator-optional.
|
| A soft delete that is never purged retains personal data indefinitely while
| the product tells people it was erased. Thirty days is the documented erasure
| latency floor, and the number only means anything if something runs — so it
| is scheduled here rather than offered as a command an operator might
| remember.
|
| 03:00 UTC, after the audit anchors, so a purged row's audit event is already
| anchored for the day it was written.
*/
Schedule::command('docup:purge')
    ->dailyAt('03:00')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
| 🛑 §8.5.3's native per-version cron schedules, ticked every minute.
|
| The minute granularity is the schedules' own: an operator writing a
| quarter-hourly expression means every fifteen minutes, and a scheduler
| that looked once an hour would turn that into once an hour without saying
| so.
|
| The command itself is cheap when nothing is due — one indexed query on
| `(enabled, next_run_at)` — so the cost of the granularity is a query a
| minute, which is what `withoutOverlapping` then bounds if a tick ever
| takes longer than one.
|
| 🛑 §8.22.13's DST semantics live in `App\Automation\CronSchedule`, NOT
| here. Laravel's own `->timezone()` would apply to this tick, which runs
| every minute in every timezone; the schedules' timezones are per row.
*/
Schedule::command('docup:schedules:run')
    ->everyMinute()
    ->withoutOverlapping()
    ->onOneServer();

/*
| §8.5.3's `ls-remote` poll, for repositories with no working webhook.
|
| 🛑 Every five minutes rather than at the configured interval, because the
| command picks its own batch by oldest-checked-first: a tick that finds
| nothing eligible costs one indexed query, and a tick that finds 4,000
| repositories still only advertises `batch_size` of them. Putting the
| interval in the cron expression instead would make `DOCUP_POLL_BATCH_SIZE`
| and `DOCUP_POLL_INTERVAL_MINUTES` interact in a way neither documents.
*/
Schedule::command('docup:repositories:poll')
    ->everyFiveMinutes()
    ->withoutOverlapping()
    ->onOneServer();

/*
| §20's 30-day retention on incoming webhook deliveries.
|
| 🛑 This is what bounds §8.19.3's weaker replay guarantee, so it is
| scheduled for the same reason §8.22.6's purge is: the number in the
| documentation only means something if something runs. See
| `App\Webhooks\DeliveryLedger` for exactly how weak the bound is.
|
| 03:30 UTC, after the hard purge, so the two do not contend for the same
| tables in a large installation.
*/
Schedule::command('docup:webhooks:prune')
    ->dailyAt('03:30')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
| 🛑 §8.10.6's daily re-verification.
|
| "Verified domains MUST be re-verified daily with exponential backoff against
| at least two independent resolvers that must agree."
|
| Scheduled rather than offered, for the reason every other entry in this file
| is: a hostname whose DNS was withdrawn keeps serving until something notices,
| and the only thing that notices is this. Phase 11 found that nothing in the
| compose file ever ran `schedule:work`, so §8.22.1's audit anchor had never
| fired in a deployment — the same hole here is a hostname serving after its
| owner stopped pointing at us.
|
| 04:00 UTC, after the purge and the webhook prune, so three daily jobs do not
| contend. The `--purge` flag folds §8.10.6's 400-day retention into the same
| run: it reads one table this job has just written and would otherwise be a
| fourth entry doing one DELETE.
*/
Schedule::command('docup:domains:verify --purge')
    ->dailyAt('04:00')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();
