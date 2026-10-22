<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\Audit;
use App\Support\Uuid;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * `docup:audit:anchor` — write the daily signed anchors (§8.22.1).
 *
 * 🛑 **Why anchors exist at all**, because a hash chain alone looks sufficient
 * until you name the attacker.
 *
 * A chain detects edits by anyone who *cannot* recompute it. But an attacker
 * with database write access and the audit key can rewrite history and
 * recompute every hash from the edit forward, and the result verifies perfectly
 * — the chain is internally consistent, just not the one that was written. A
 * signed anchor defeats that: it fixes the head hash for a given day, and
 * forging a matching anchor needs `k_audit` at the time of the forgery. Export
 * the anchors off-box, or send them to the §8.22.1 external sink, and the
 * window for undetectable rewriting closes at one day.
 *
 * Anchors are immutable: the §8.22.1 guards refuse `UPDATE` on `audit_anchors`
 * outright. So this command skips a day it has already anchored rather than
 * recomputing — if a day's anchor is wrong, that is a finding to investigate,
 * not a row to correct.
 */
final class AuditAnchorCommand extends Command
{
    protected $signature = 'docup:audit:anchor
        {--date= : The day to anchor (YYYY-MM-DD, UTC). Defaults to yesterday.}
        {--json : Machine-readable output}';

    protected $description = 'Write daily signed anchors over the audit chains (SPEC 8.22.1)';

    public function handle(): int
    {
        if (! Audit::hasKey()) {
            $this->components->error('No audit key configured. Set DOCUP_AUDIT_KEY (§8.22.1).');

            return self::FAILURE;
        }

        $date = $this->resolveDate();

        if ($date === null) {
            return self::FAILURE;
        }

        $key = Audit::key();

        // Anchored by its last instant, not its first: an anchor for a day must
        // cover every event in that day.
        $upTo = $date->copy()->addDay()->format('Y-m-d H:i:s.v');

        $written = [];
        $skipped = [];

        foreach ($this->chains() as $chainKey) {
            /** @var object{hash: string, sequence: int|string}|null $head */
            $head = DB::selectOne(
                'SELECT `hash`, `sequence`
                   FROM `audit_events`
                  WHERE `chain_key` = ? AND `occurred_at` < ?
                  ORDER BY `sequence` DESC
                  LIMIT 1',
                [$chainKey, $upTo],
            );

            // A chain with no events by the end of that day has nothing to
            // anchor. Recorded as skipped rather than treated as an error: a
            // tenant created yesterday legitimately has no history the day
            // before.
            if ($head === null) {
                $skipped[] = ['chain' => $this->label($chainKey), 'reason' => 'no events by that date'];

                continue;
            }

            $existing = DB::selectOne(
                'SELECT 1 AS present FROM `audit_anchors` WHERE `chain_key` = ? AND `anchored_on` = ?',
                [$chainKey, $date->format('Y-m-d')],
            );

            if ($existing !== null) {
                $skipped[] = ['chain' => $this->label($chainKey), 'reason' => 'already anchored'];

                continue;
            }

            /** @var object{n: int|string} $count */
            $count = DB::selectOne(
                'SELECT COUNT(*) AS n FROM `audit_events` WHERE `chain_key` = ? AND `sequence` <= ?',
                [$chainKey, $head->sequence],
            );

            DB::insert(
                'INSERT INTO `audit_anchors`
                    (`id`, `chain_key`, `anchored_on`, `head_hash`, `head_sequence`, `event_count`,
                     `signature`, `created_at`, `updated_at`)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [
                    Uuid::v7(),
                    $chainKey,
                    $date->format('Y-m-d'),
                    $head->hash,
                    (int) $head->sequence,
                    (int) $count->n,
                    Audit::anchorSignature($head->hash, $chainKey, $date->format('Y-m-d'), $key),
                    now(),
                    now(),
                ],
            );

            $written[] = [
                'chain' => $this->label($chainKey),
                'head_sequence' => (int) $head->sequence,
                'event_count' => (int) $count->n,
            ];
        }

        return $this->report($date, $written, $skipped);
    }

    /**
     * The day to anchor.
     *
     * Defaults to **yesterday**, not today: an anchor is a statement about a
     * finished day, and one written at noon would pin a head that the
     * afternoon's events move past. `audit:verify` would then report the anchor
     * as describing a stale head — a false alarm manufactured by the anchoring
     * job itself.
     */
    private function resolveDate(): ?Carbon
    {
        $given = $this->option('date');

        if (! is_string($given) || $given === '') {
            return now('UTC')->subDay()->startOfDay();
        }

        try {
            $date = Carbon::createFromFormat('Y-m-d', $given, 'UTC');
        } catch (\Throwable) {
            $date = null;
        }

        // Both null and false are reachable: Carbon::createFromFormat() returns
        // false on a parse failure and is typed as nullable besides, so testing
        // only one of them leaves the other to blow up later as a method call
        // on null.
        if (! $date instanceof Carbon) {
            $this->components->error("[{$given}] is not a date in YYYY-MM-DD form.");

            return null;
        }

        $date = $date->startOfDay();

        if ($date->greaterThanOrEqualTo(now('UTC')->startOfDay())) {
            $this->components->error(
                'Refusing to anchor today or a future date: an anchor pins the head of a '
                .'FINISHED day, and one written mid-day would be overtaken by later events.'
            );

            return null;
        }

        return $date;
    }

    /** @return list<string> */
    private function chains(): array
    {
        /** @var list<object{chain_key: string}> $rows */
        $rows = DB::select('SELECT DISTINCT `chain_key` FROM `audit_events` ORDER BY `chain_key`');

        return array_map(static fn (object $row): string => (string) $row->chain_key, $rows);
    }

    private function label(string $chainKey): string
    {
        return $chainKey === str_repeat("\x00", 16) ? 'installation' : bin2hex($chainKey);
    }

    /**
     * @param  list<array{chain: string, head_sequence: int, event_count: int}>  $written
     * @param  list<array{chain: string, reason: string}>  $skipped
     */
    private function report(Carbon $date, array $written, array $skipped): int
    {
        if ($this->option('json')) {
            $this->line((string) json_encode([
                'anchored_on' => $date->format('Y-m-d'),
                'written' => $written,
                'skipped' => $skipped,
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return self::SUCCESS;
        }

        $this->newLine();
        $this->line('  <options=bold>Anchors for '.$date->format('Y-m-d').'</>');
        $this->newLine();

        foreach ($written as $entry) {
            $this->line(sprintf(
                '  <fg=green>made</>  %s — head sequence %d, %d event%s',
                $entry['chain'],
                $entry['head_sequence'],
                $entry['event_count'],
                $entry['event_count'] === 1 ? '' : 's',
            ));
        }

        foreach ($skipped as $entry) {
            $this->line(sprintf('  <fg=gray>skip</>  %s — %s', $entry['chain'], $entry['reason']));
        }

        if ($written === [] && $skipped === []) {
            $this->line('  <fg=gray>none</>  no chains exist yet');
        }

        $this->newLine();

        return self::SUCCESS;
    }
}
