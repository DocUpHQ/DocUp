<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Tests\TestCase;

/**
 * NDJSON export of the audit log (§8.22.1).
 *
 * 🛑 The property under test is **independent verifiability**. An export that
 * can only be checked by this installation is a copy, and a copy of a log
 * proves nothing about the log — so every line must carry the fields the hash
 * covers, and the anchors must travel with the events.
 */
final class AuditExportTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private string $exportPath;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Export Fixture',
            'slug' => 'export-'.bin2hex(random_bytes(4)),
        ]);

        $this->exportPath = tempnam(sys_get_temp_dir(), 'docup-audit-').'.ndjson';
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        if (is_file($this->exportPath)) {
            unlink($this->exportPath);
        }

        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    private function record(string $action = 'project.created'): string
    {
        return Audit::record(
            action: $action,
            actorType: ActorType::System,
            organisationId: $this->organisation->id,
            payload: ['kind' => 'docs'],
        );
    }

    /**
     * @param  array<string, mixed>  $options
     * @return list<array<string, mixed>>
     */
    private function export(array $options = []): array
    {
        $exit = Artisan::call('docup:audit:export', array_merge(['--output' => $this->exportPath], $options));

        $this->assertSame(0, $exit, 'the export command failed');

        $lines = [];

        foreach (file($this->exportPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
            // 🛑 Every line must parse on its own. That is the point of NDJSON
            // over a JSON array: a truncated array is invalid JSON, whereas a
            // truncated NDJSON file is a valid prefix of itself.
            $lines[] = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        }

        return $lines;
    }

    public function test_the_first_line_describes_the_export(): void
    {
        $this->record();

        $lines = $this->export();

        $this->assertSame('export_metadata', $lines[0]['type']);
        $this->assertSame('docup-audit-ndjson', $lines[0]['format']);
        $this->assertSame('hmac-sha256', $lines[0]['hash_algorithm']);
    }

    /**
     * 🛑 Each event must carry everything the hash covers, or the export cannot
     * be verified away from this database.
     */
    public function test_each_event_carries_the_fields_the_hash_covers(): void
    {
        $this->record();

        $events = array_values(array_filter($this->export(), static fn (array $l): bool => $l['type'] === 'event'));

        $this->assertCount(1, $events);

        foreach (['id', 'occurred_at', 'chain_key', 'sequence', 'actor_type', 'action', 'payload', 'prev_hash', 'hash'] as $field) {
            $this->assertArrayHasKey($field, $events[0], "the export omits [{$field}], which the hash covers");
        }

        $this->assertSame(['kind' => 'docs'], $events[0]['payload']);
        $this->assertSame(64, strlen((string) $events[0]['hash']), 'the hash should be hex-encoded SHA-256');
    }

    /**
     * 🛑 Anchors travel with the events by default.
     *
     * Without them the export is only self-consistent: a chain that was
     * rewritten and re-hashed exports cleanly and verifies cleanly. The anchors
     * are what make it evidence rather than a transcript.
     */
    public function test_anchors_are_included_by_default(): void
    {
        // Recorded on a finished day so there is something to anchor. An
        // earlier version of this test recorded today's events, found no anchor
        // and asserted its absence — under a name claiming the opposite, which
        // is worse than no test at all.
        Carbon::setTestNow(now('UTC')->subDay()->setTime(9, 0));
        $this->record();
        Carbon::setTestNow();

        Artisan::call('docup:audit:anchor', ['--date' => now('UTC')->subDay()->format('Y-m-d')]);

        $lines = $this->export();
        $anchors = array_values(array_filter($lines, static fn (array $l): bool => $l['type'] === 'anchor'));

        $this->assertCount(1, $anchors, 'the export dropped the anchors');
        $this->assertSame(64, strlen((string) $anchors[0]['signature']), 'the signature should be hex-encoded SHA-256');
        $this->assertSame(64, strlen((string) $anchors[0]['head_hash']));
        $this->assertSame(1, $anchors[0]['head_sequence']);
    }

    public function test_anchors_can_be_omitted(): void
    {
        $this->record();

        $types = array_column($this->export(['--no-anchors' => true]), 'type');

        $this->assertNotContains('anchor', $types);
    }

    public function test_it_can_export_one_organisation(): void
    {
        $this->record();

        $other = Organisation::query()->create([
            'name' => 'Other',
            'slug' => 'other-'.bin2hex(random_bytes(4)),
        ]);

        Audit::record(action: 'project.created', actorType: ActorType::System, organisationId: $other->id);

        $events = array_values(array_filter(
            $this->export(['--organisation' => Uuid::toText($this->organisation->id)]),
            static fn (array $l): bool => $l['type'] === 'event',
        ));

        $this->assertCount(1, $events, 'the organisation filter leaked another tenant\'s events');
        $this->assertSame(bin2hex($this->organisation->id), $events[0]['organisation_id']);
    }

    public function test_a_malformed_date_is_rejected(): void
    {
        $this->assertSame(
            1,
            Artisan::call('docup:audit:export', ['--from' => 'nonsense', '--output' => $this->exportPath]),
        );
    }

    /** Events come out in chain-then-sequence order, so a verifier can walk them. */
    public function test_events_are_ordered_by_chain_and_sequence(): void
    {
        $this->record('a');
        $this->record('b');
        $this->record('c');

        $events = array_values(array_filter($this->export(), static fn (array $l): bool => $l['type'] === 'event'));

        $this->assertSame([1, 2, 3], array_column($events, 'sequence'));
    }
}
