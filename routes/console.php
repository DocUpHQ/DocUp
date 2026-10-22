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
