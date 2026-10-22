<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\Audit;
use Illuminate\Console\Command;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * `docup:audit:export` — NDJSON export of the audit log (§8.22.1).
 *
 * 🛑 **The export is designed to be verifiable away from this installation**,
 * which is the whole point of having one. An export that could not be checked
 * independently would just be a copy, and a copy of a log proves nothing about
 * the log.
 *
 * So every line carries the fields the hash covers, plus `prev_hash` and
 * `hash`, and the anchors ship alongside by default. Given those and
 * `k_audit`, a third party can recompute each hash, walk the links, and check
 * each day's signature without touching this database.
 *
 * NDJSON rather than a JSON array: a 400-day log does not fit in a parser's
 * memory as one document, and a truncated array is invalid JSON whereas a
 * truncated NDJSON file is a valid prefix of itself.
 *
 * 🛑 §8.13.2 holds `installation.audit.export` apart from
 * `installation_owner` as a separation of duty. This command has no
 * capability check because it has no authenticated actor — running it requires
 * shell access to the application container, which is a strictly higher bar.
 * The capability governs the dashboard and API routes that expose the same
 * data, and those arrive with the endpoints.
 */
final class AuditExportCommand extends Command
{
    protected $signature = 'docup:audit:export
        {--organisation= : Export one organisation\'s chain only, by UUID}
        {--from= : Only events on or after this date (YYYY-MM-DD, UTC)}
        {--to= : Only events before this date (YYYY-MM-DD, UTC)}
        {--output= : Write to this file instead of stdout}
        {--no-anchors : Omit the anchor records}';

    protected $description = 'Export the audit log as NDJSON (SPEC 8.22.1)';

    public function handle(): int
    {
        $from = $this->date('from');
        $to = $this->date('to');

        if ($from === false || $to === false) {
            return self::FAILURE;
        }

        $output = $this->option('output');
        $handle = is_string($output) && $output !== ''
            ? @fopen($output, 'wb')
            : fopen('php://stdout', 'wb');

        if ($handle === false) {
            $this->components->error('Could not open the output for writing.');

            return self::FAILURE;
        }

        try {
            $this->writeHeader($handle, $from, $to);
            $events = $this->writeEvents($handle, $from, $to);
            $anchors = $this->option('no-anchors') === true ? 0 : $this->writeAnchors($handle);
        } finally {
            if (is_string($output) && $output !== '') {
                fclose($handle);
            }
        }

        // 🛑 To stderr, never stdout: stdout is the NDJSON stream, and a
        // friendly summary written into it would corrupt every consumer that
        // pipes this command. The one place a progress message can do real
        // damage.
        if (is_string($output) && $output !== '') {
            $this->components->info("Exported {$events} events and {$anchors} anchors to {$output}");
        } else {
            fwrite(STDERR, "Exported {$events} events and {$anchors} anchors\n");
        }

        return self::SUCCESS;
    }

    /**
     * A leading metadata line, so a consumer knows what it is holding.
     *
     * Deliberately NOT signed, and deliberately not part of any chain: it
     * describes the export rather than the evidence. Signing it would imply the
     * export itself is attested, which it is not — the per-event hashes and the
     * anchors are the attestation, and they are verifiable without trusting
     * this line at all.
     *
     * @param  resource  $handle
     */
    private function writeHeader($handle, ?Carbon $from, ?Carbon $to): void
    {
        $this->writeLine($handle, [
            'type' => 'export_metadata',
            'format' => 'docup-audit-ndjson',
            'format_version' => 1,
            'exported_at' => now('UTC')->format('Y-m-d\TH:i:s.v\Z'),
            'from' => $from?->format('Y-m-d'),
            'to' => $to?->format('Y-m-d'),
            'organisation' => $this->option('organisation'),
            'hash_algorithm' => 'hmac-sha256',
            'note' => 'Verify with docup:audit:verify, or independently: each event hash is '
                .'HMAC(k_audit, canonical_json || prev_hash) over the fields below.',
        ]);
    }

    /** @param  resource  $handle */
    private function writeEvents($handle, ?Carbon $from, ?Carbon $to): int
    {
        $where = [];
        $bindings = [];

        if (is_string($this->option('organisation')) && $this->option('organisation') !== '') {
            $where[] = '`organisation_id` = UUID_TO_BIN(?)';
            $bindings[] = $this->option('organisation');
        }

        if ($from instanceof Carbon) {
            $where[] = '`occurred_at` >= ?';
            $bindings[] = $from->format('Y-m-d H:i:s.v');
        }

        if ($to instanceof Carbon) {
            $where[] = '`occurred_at` < ?';
            $bindings[] = $to->format('Y-m-d H:i:s.v');
        }

        $sql = 'SELECT BIN_TO_UUID(`id`) AS id, `occurred_at`, `organisation_id`, `chain_key`, `sequence`,
                       `actor_id`, `actor_type`, `action`, `subject_type`, `subject_id`, `reason_code`,
                       `rule_id`, `payload`, `prev_hash`, `hash`
                  FROM `audit_events`'
            .($where === [] ? '' : ' WHERE '.implode(' AND ', $where))
            .' ORDER BY `chain_key` ASC, `sequence` ASC';

        $count = 0;

        // Cursored: a 400-day log is large by design, and an export that needs
        // it all in memory stops working exactly when someone needs it.
        foreach (DB::cursor($sql, $bindings) as $row) {
            /** @var object{id: string, occurred_at: string, organisation_id: string|null, chain_key: string, sequence: int|string, actor_id: string|null, actor_type: string, action: string, subject_type: string|null, subject_id: string|null, reason_code: string|null, rule_id: string|null, payload: string, prev_hash: string|null, hash: string} $row */
            $this->writeLine($handle, [
                'type' => 'event',
                'id' => $row->id,
                'occurred_at' => $row->occurred_at,
                'organisation_id' => $row->organisation_id === null ? null : bin2hex($row->organisation_id),
                'chain_key' => bin2hex($row->chain_key),
                'sequence' => (int) $row->sequence,
                'actor_id' => $row->actor_id === null ? null : bin2hex($row->actor_id),
                'actor_type' => $row->actor_type,
                'action' => $row->action,
                'subject_type' => $row->subject_type,
                'subject_id' => $row->subject_id === null ? null : bin2hex($row->subject_id),
                'reason_code' => $row->reason_code,
                'rule_id' => $row->rule_id === null ? null : bin2hex($row->rule_id),
                'payload' => json_decode($row->payload, true, 512, JSON_THROW_ON_ERROR),
                'prev_hash' => $row->prev_hash === null ? null : bin2hex($row->prev_hash),
                'hash' => bin2hex($row->hash),
            ]);

            $count++;
        }

        return $count;
    }

    /**
     * The anchors.
     *
     * Included by default because without them the export is only
     * self-consistent: a rewritten-and-re-hashed chain exports cleanly and
     * verifies cleanly. The anchors are what make the export evidence rather
     * than a transcript.
     *
     * @param  resource  $handle
     */
    private function writeAnchors($handle): int
    {
        $sql = 'SELECT BIN_TO_UUID(`id`) AS id, `chain_key`, `anchored_on`, `head_hash`,
                       `head_sequence`, `event_count`, `signature`
                  FROM `audit_anchors`
                 ORDER BY `chain_key` ASC, `anchored_on` ASC';

        $count = 0;

        foreach (DB::cursor($sql) as $row) {
            /** @var object{id: string, chain_key: string, anchored_on: string, head_hash: string, head_sequence: int|string, event_count: int|string, signature: string} $row */
            $this->writeLine($handle, [
                'type' => 'anchor',
                'id' => $row->id,
                'chain_key' => bin2hex($row->chain_key),
                'anchored_on' => $row->anchored_on,
                'head_hash' => bin2hex($row->head_hash),
                'head_sequence' => (int) $row->head_sequence,
                'event_count' => (int) $row->event_count,
                'signature' => bin2hex($row->signature),
            ]);

            $count++;
        }

        return $count;
    }

    /**
     * @param  resource  $handle
     * @param  array<string, mixed>  $line
     */
    private function writeLine($handle, array $line): void
    {
        fwrite($handle, json_encode($line, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)."\n");
    }

    /**
     * @return Carbon|null|false false when the option was given but unparseable
     */
    private function date(string $option): Carbon|null|false
    {
        $given = $this->option($option);

        if (! is_string($given) || $given === '') {
            return null;
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
            $this->components->error("--{$option}=[{$given}] is not a date in YYYY-MM-DD form.");

            return false;
        }

        return $date->startOfDay();
    }
}
