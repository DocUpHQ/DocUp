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

/*
|------------------------------------------------------------------------------
| §8.10.17's TLS handshake prober
|------------------------------------------------------------------------------
| 🛑 "A scheduled outbound TLS handshake prober MUST run against every active
| domain at least every six hours, recording expiry, issuer and error,
| **because the proxy never calls the permission endpoint back on issuance
| failure**. Without it there is no issuance-failure observability at all."
|
| That is not a monitoring nicety. §8.10.11's permission endpoint is one-way:
| the proxy asks whether it may issue, DocUp says yes, and nothing ever comes
| back. A refusal from the CA — rate limited, DNS moved, a CAA record, an
| outage — is recorded in the proxy's log and nowhere else, so every table and
| every screen in DocUp shows a healthy domain while every reader gets a TLS
| error. This job is the only thing that closes the loop.
|
| Every six hours rather than daily, because that is the floor the requirement
| sets. §18.20 predicted the interval would have to shorten as lifetimes fall,
| and the 2026-10-26 re-read says not yet: at the 64-day lifetime arriving
| 2027-02-10, two-thirds-of-life renewal still leaves 21 days of slack, and six
| hours is one per cent of it. config/tls.php carries the reasoning and the
| date the claim was checked.
|
| Offset to :30 so it does not start in the same minute as the daily jobs above.
*/
Schedule::command('docup:tls:probe')
    ->cron('30 */6 * * *')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
|------------------------------------------------------------------------------
| §12.4's reader sessions and §8.12.11's key states
|------------------------------------------------------------------------------
| Four jobs that no request can do, and the last is the one that matters.
|
| Expired sessions, spent handoff codes and long-expired reader credentials
| authorise nothing — §12.4's absolute ceiling is checked on every use, a
| handoff code dies in thirty seconds, and §8.12.16's expiry is checked on the
| request that presents the credential — so sweeping them is housekeeping:
| `docs_sessions` holds one row per reader per project per domain, and
| §8.12.15's session inventory is a security surface an operator has to be able
| to read.
|
| 🛑 The last is not housekeeping. `App\Readers\Grants\KeyState` has four
| states and three of its transitions are **time-based**, so on an installation
| where nobody runs a command a key sits in `retiring` for ever and §17's fourth
| state — the one that means "no longer trusted" — is unreachable. A state
| machine that cannot reach its final state has three states and a comment.
|
| 🛑 Retirement only. `docup:readers:maintain` deliberately does not promote a
| pending key: §8.12.11's keypair mints read access to every private project and
| is verified against a JWKS the edge caches, so every promotion is a moment
| when a stale cache becomes an outage. That stays `docup:readers:rotate`, which
| an operator runs when they mean it.
|
| Hourly rather than daily, because the window it is clearing is measured in
| minutes (§8.12.11's ≤10-minute grant plus one JWKS cache window) and a daily
| job would hold a stood-down key in the published document for most of a day.
*/
Schedule::command('docup:readers:maintain')
    ->hourly()
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
| §8.12.22's **nightly** policy linter.
|
| > "a nightly policy linter that re-validates every active rule and alerts on
| > reachability changes"
|
| 🛑 Nightly because the requirement says nightly, and the requirement says
| nightly because what it catches is not a property of the rule. Write-time
| validation already refuses a malformed requirement, a regex path pattern, an
| unsatisfiable tree (§8.12.7) and a binding named as the wrong leaf kind
| (§8.12.17) — and every one of those checks is still true tomorrow. What
| changes overnight is the world the rule points at: a binding deleted, moved
| out of §8.12.3's scope, dropped out of `active`, or re-typed. The rule is then
| still valid, still matches, still consumes §8.12.6's first-match slot, and can
| no longer be satisfied by anybody.
|
| 🛑 **03:20 UTC rather than on the hour**, for the reason `docup:purge` is
| staggered: the audit chain takes one writer per organisation
| ({@see \App\Audit\Audit}), and a linter that alerted at the same moment the
| anchor ran would contend with it for the lock on every installation that has
| both — on the one night something had changed, which is the night the alert
| matters.
|
| 🛑 It runs even on an installation where nobody has written a policy: the
| command's own first query is "every project with a reader policy", which is
| empty and cheap. A schedule conditional on there being work is a schedule that
| silently stops running once somebody deletes their last policy and starts a
| new one.
*/
Schedule::command('docup:policy:lint')
    ->dailyAt('03:20')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();

/*
| §8.16's indexing pass.
|
| 🛑 Hourly, and scheduled rather than hooked onto publish. `SearchIndexCommand`
| gives the three reasons at length; the short one is §8.16.5: a build is shared
| by every project that mounts it, so indexing is per **project** and a publish
| into one project changes what two others should serve. A hook on publish would
| run the wrong pass.
|
| 🛑 What makes an hourly pass safe rather than merely convenient is §8.12.21:
| "a project's search MUST be **disabled** while its search generation lags its
| policy generation". So an index that has not caught up with a policy change is
| an outage of search, never a disclosure — which is the whole reason indexing
| is allowed to be asynchronous. A content change without a policy change is
| served from the previous generation until the next pass, which is staleness of
| the kind §10.8 permits: no reader sees anything they may not read, they see
| yesterday's wording.
|
| `withoutOverlapping` because a pass writes a generation and swaps it, and two
| passes over one project would interleave their generations. `onOneServer`
| because a multi-node installation would otherwise run the whole corpus twice.
*/
Schedule::command('docup:search-index')
    ->hourly()
    ->withoutOverlapping()
    ->onOneServer();

/*
| §8.16.11's retention sweep.
|
| 🛑 Daily, at 03:40 UTC — after the audit anchors, the purge and the policy
| linter, and staggered off the hour for the same reason they are: the audit
| chain takes one writer per organisation and a sweep contending for it buys
| nothing.
|
| 🛑 The sweep only. `OPTIMIZE TABLE` is NOT scheduled, because §10.9 says it
| "rebuilds and therefore locks, so it belongs in the maintenance window" — and
| an application cannot know when that is. The command reports the reclaimable
| space every night so an operator sees it growing toward §8.16.11's measured
| 28% plateau, and runs `docup:search-retention --optimize` when they have a
| window. A scheduled rebuild would be a nightly stall on a §10.9 hot table.
*/
Schedule::command('docup:search-retention')
    ->dailyAt('03:40')
    ->timezone('UTC')
    ->withoutOverlapping()
    ->onOneServer();
