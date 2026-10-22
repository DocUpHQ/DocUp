<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Audit\Audit;
use App\Audit\CanonicalJson;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;

/**
 * `docup:audit:verify` — walk the hash chains and prove nothing changed
 * (§8.22.1).
 *
 * 🛑 Phase 02's exit criterion: after a manual row edit in the database this
 * MUST fail **and name the offending row**. "Verification failed" on a log with
 * four million rows is not a usable answer — the operator's next question is
 * always "which one", and if the tool cannot say, the answer is a weekend of
 * bisecting by hand.
 *
 * The hash is recomputed from each row's **columns** via
 * {@see Audit::canonicalEvent()}, not from a stored blob, so an edit to any
 * column is detected rather than only an edit to the hashed bytes.
 *
 * Four independent failures are checked, because they have different causes:
 *
 * - **hash mismatch** — the row's own contents were altered.
 * - **broken link** — `prev_hash` does not match the previous event's `hash`,
 *   so a row was inserted, removed or reordered.
 * - **sequence gap** — a row was deleted outright. The hashes of the survivors
 *   can all be individually valid, so only continuity catches this.
 * - **anchor mismatch** — the daily signature does not match the head it
 *   claims. This is the one that catches a thorough attacker: someone with
 *   write access and the audit key could rewrite history and recompute every
 *   hash, but without `k_audit` they cannot forge the anchor.
 */
final class AuditVerifyCommand extends Command
{
    protected $signature = 'docup:audit:verify
        {--organisation= : Verify one chain only, by organisation UUID}
        {--json : Machine-readable output}';

    protected $description = 'Verify the audit hash chains and daily anchors (SPEC 8.22.1)';

    /** @var list<array{chain: string, event: string|null, sequence: int|null, kind: string, detail: string}> */
    private array $failures = [];

    private int $eventsChecked = 0;

    private int $anchorsChecked = 0;

    public function handle(): int
    {
        if (! Audit::hasKey()) {
            $this->components->error('No audit key configured. Set DOCUP_AUDIT_KEY (§8.22.1).');

            return self::FAILURE;
        }

        $key = Audit::key();

        foreach ($this->chains() as $chainKey) {
            $this->verifyChain($chainKey, $key);
            $this->verifyAnchors($chainKey, $key);
        }

        return $this->report();
    }

    /**
     * Every chain present in the log.
     *
     * Read from the data rather than from the organisations table on purpose:
     * §8.22.1 retains audit events after an organisation is deleted, so a chain
     * can outlive its tenant and must still be verified. Driving this from
     * `organisations` would silently stop checking exactly the history most
     * likely to be of interest after an incident.
     *
     * @return list<string>
     */
    private function chains(): array
    {
        $only = $this->option('organisation');

        if (is_string($only) && $only !== '') {
            /** @var list<object{chain_key: string}> $rows */
            $rows = DB::select(
                'SELECT DISTINCT `chain_key` FROM `audit_events` WHERE `organisation_id` = UUID_TO_BIN(?)',
                [$only],
            );
        } else {
            /** @var list<object{chain_key: string}> $rows */
            $rows = DB::select('SELECT DISTINCT `chain_key` FROM `audit_events` ORDER BY `chain_key`');
        }

        return array_map(static fn (object $row): string => (string) $row->chain_key, $rows);
    }

    private function verifyChain(string $chainKey, string $key): void
    {
        $expectedSequence = 1;
        $previousHash = null;

        /*
         * Cursored rather than loaded: a 400-day log is large by design, and a
         * verification command that needs the whole chain in memory is one that
         * stops being runnable exactly when it matters.
         */
        $rows = DB::cursor(
            'SELECT BIN_TO_UUID(`id`) AS id_text, `id`, `occurred_at`, `organisation_id`, `chain_key`,
                    `sequence`, `actor_id`, `actor_type`, `action`, `subject_type`, `subject_id`,
                    `reason_code`, `rule_id`, `payload`, `prev_hash`, `hash`
               FROM `audit_events`
              WHERE `chain_key` = ?
              ORDER BY `sequence` ASC',
            [$chainKey],
        );

        foreach ($rows as $row) {
            $this->eventsChecked++;

            /** @var object{id_text: string, id: string, occurred_at: string, organisation_id: string|null, chain_key: string, sequence: int|string, actor_id: string|null, actor_type: string, action: string, subject_type: string|null, subject_id: string|null, reason_code: string|null, rule_id: string|null, payload: string, prev_hash: string|null, hash: string} $row */
            $sequence = (int) $row->sequence;

            if ($sequence !== $expectedSequence) {
                $this->recordFailure(
                    $chainKey,
                    $row->id_text,
                    $sequence,
                    'sequence gap',
                    "expected sequence {$expectedSequence} but found {$sequence}; "
                    .'a row has been deleted or inserted'
                );

                // Resynchronise so one deletion does not report every
                // subsequent row as a gap. The link check below still runs.
                $expectedSequence = $sequence;
            }

            $canonical = Audit::canonicalEvent([
                'action' => $row->action,
                'actor_id' => $row->actor_id === null ? null : bin2hex($row->actor_id),
                'actor_type' => $row->actor_type,
                'chain_key' => bin2hex($row->chain_key),
                'id' => bin2hex($row->id),
                'occurred_at' => $row->occurred_at,
                'organisation_id' => $row->organisation_id === null ? null : bin2hex($row->organisation_id),
                // 🛑 Re-canonicalised, NOT taken verbatim from the column.
                //
                // `payload` is a native MySQL JSON column, and the JSON type is
                // **not byte-preserving**: MySQL parses the document and stores
                // its own normalised form, sorting object keys by length and
                // then by bytes, and inserting a space after each colon. So
                // `{"from":"x","to":"y"}` comes back as `{"to": "y", "from":
                // "x"}` — different bytes, identical meaning.
                //
                // Hashing the stored string would therefore fail verification
                // on every event with a non-empty payload, immediately, which
                // is exactly how this was found: freshly written rows reported
                // as tampered while empty-payload rows passed.
                //
                // Decoding and re-encoding through CanonicalJson is stable
                // because that class fixes the key order itself and rejects the
                // types whose round trip is not exact (floats especially). The
                // column stays queryable with MySQL's JSON functions, which a
                // text column would have cost.
                'payload_json' => $this->canonicalPayload($row->payload),
                'reason_code' => $row->reason_code,
                'rule_id' => $row->rule_id === null ? null : bin2hex($row->rule_id),
                'sequence' => $sequence,
                'subject_id' => $row->subject_id === null ? null : bin2hex($row->subject_id),
                'subject_type' => $row->subject_type,
            ]);

            $recomputed = Audit::chainHash($canonical, $row->prev_hash, $key);

            // hash_equals, not ===. Comparison of a MAC is a timing-sensitive
            // operation by habit even where the attacker is not watching, and
            // habits are what survive into code where it does matter.
            if (! hash_equals($row->hash, $recomputed)) {
                $this->recordFailure(
                    $chainKey,
                    $row->id_text,
                    $sequence,
                    'hash mismatch',
                    'the row contents do not match its hash: stored '
                    .substr(bin2hex($row->hash), 0, 16).'…, recomputed '
                    .substr(bin2hex($recomputed), 0, 16).'…'
                );
            }

            $linkBroken = $previousHash === null
                ? $row->prev_hash !== null
                : ($row->prev_hash === null || ! hash_equals($previousHash, $row->prev_hash));

            if ($linkBroken) {
                $this->recordFailure(
                    $chainKey,
                    $row->id_text,
                    $sequence,
                    'broken link',
                    'prev_hash does not match the preceding event; a row was inserted, '
                    .'removed or reordered'
                );
            }

            $previousHash = $row->hash;
            $expectedSequence = $sequence + 1;
        }
    }

    private function verifyAnchors(string $chainKey, string $key): void
    {
        /** @var list<object{id_text: string, anchored_on: string, head_hash: string, head_sequence: int|string, signature: string}> $anchors */
        $anchors = DB::select(
            'SELECT BIN_TO_UUID(`id`) AS id_text, `anchored_on`, `head_hash`, `head_sequence`, `signature`
               FROM `audit_anchors`
              WHERE `chain_key` = ?
              ORDER BY `anchored_on` ASC',
            [$chainKey],
        );

        foreach ($anchors as $anchor) {
            $this->anchorsChecked++;

            $expected = Audit::anchorSignature(
                $anchor->head_hash,
                $chainKey,
                $anchor->anchored_on,
                $key,
            );

            if (! hash_equals($anchor->signature, $expected)) {
                $this->recordFailure(
                    $chainKey,
                    $anchor->id_text,
                    (int) $anchor->head_sequence,
                    'anchor signature mismatch',
                    "the anchor for {$anchor->anchored_on} is not signed with this key; the chain "
                    .'may have been rewritten and re-hashed'
                );

                continue;
            }

            // And that the anchor still describes the chain it anchors.
            /** @var object{hash: string}|null $atSequence */
            $atSequence = DB::selectOne(
                'SELECT `hash` FROM `audit_events` WHERE `chain_key` = ? AND `sequence` = ?',
                [$chainKey, $anchor->head_sequence],
            );

            if ($atSequence === null) {
                $this->recordFailure(
                    $chainKey,
                    $anchor->id_text,
                    (int) $anchor->head_sequence,
                    'anchor orphaned',
                    "the anchor for {$anchor->anchored_on} names sequence {$anchor->head_sequence}, "
                    .'which no longer exists'
                );
            } elseif (! hash_equals($atSequence->hash, $anchor->head_hash)) {
                $this->recordFailure(
                    $chainKey,
                    $anchor->id_text,
                    (int) $anchor->head_sequence,
                    'anchor head changed',
                    "the event at sequence {$anchor->head_sequence} no longer hashes to what the "
                    ."anchor for {$anchor->anchored_on} recorded"
                );
            }
        }
    }

    /**
     * The stored payload, re-encoded into the canonical form that was hashed.
     *
     * @throws \JsonException
     */
    private function canonicalPayload(string $stored): string
    {
        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($stored, true, 512, JSON_THROW_ON_ERROR);

        return CanonicalJson::encode($decoded);
    }

    // Named recordFailure(), NOT fail(): Illuminate\Console\Command declares a
    // public fail(), so a private override is a fatal error at class-load time.
    // Phase 01 hit this in DoctorCommand and the build log records it; this is
    // the second time, which is why the reason now sits beside the name.
    private function recordFailure(string $chainKey, ?string $eventId, ?int $sequence, string $kind, string $detail): void
    {
        $this->failures[] = [
            'chain' => $chainKey === str_repeat("\x00", 16) ? 'installation' : bin2hex($chainKey),
            'event' => $eventId,
            'sequence' => $sequence,
            'kind' => $kind,
            'detail' => $detail,
        ];
    }

    private function report(): int
    {
        if ($this->option('json')) {
            $this->line((string) json_encode([
                'events_checked' => $this->eventsChecked,
                'anchors_checked' => $this->anchorsChecked,
                'failures' => $this->failures,
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));

            return $this->failures === [] ? self::SUCCESS : self::FAILURE;
        }

        $this->newLine();

        if ($this->failures === []) {
            $this->line(sprintf(
                '  <fg=green>ok</>    %d event%s and %d anchor%s verify.',
                $this->eventsChecked,
                $this->eventsChecked === 1 ? '' : 's',
                $this->anchorsChecked,
                $this->anchorsChecked === 1 ? '' : 's',
            ));
            $this->newLine();

            return self::SUCCESS;
        }

        $this->line(sprintf(
            '  <fg=red>FAIL</>  %d problem%s across %d event%s (§8.22.1):',
            count($this->failures),
            count($this->failures) === 1 ? '' : 's',
            $this->eventsChecked,
            $this->eventsChecked === 1 ? '' : 's',
        ));
        $this->newLine();

        // 🛑 Naming the row is the exit criterion. The event UUID is printed
        // first and in full so it can be pasted straight into a query.
        foreach ($this->failures as $failure) {
            $this->line(sprintf(
                '    <fg=red>%s</>  event <options=bold>%s</> (chain %s, sequence %s)',
                $failure['kind'],
                $failure['event'] ?? '(unknown)',
                $failure['chain'],
                $failure['sequence'] === null ? '?' : (string) $failure['sequence'],
            ));
            $this->line('      <fg=gray>'.$failure['detail'].'</>');
        }

        $this->newLine();
        $this->line('  <fg=gray>The audit log is insert-only for the application (§8.22.1), so a mismatch</>');
        $this->line('  <fg=gray>means the row was changed outside it. Treat this as a security event.</>');
        $this->newLine();

        return self::FAILURE;
    }
}
