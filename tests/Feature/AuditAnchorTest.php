<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * Daily signed anchors (§8.22.1).
 *
 * 🛑 What anchors are for, since a hash chain looks sufficient until the
 * attacker is named: a chain detects edits by anyone who cannot recompute it,
 * but someone with database write access **and** the audit key can rewrite
 * history, recompute every hash from the edit forward, and leave a chain that
 * verifies perfectly. An anchor fixes a finished day's head hash under a
 * signature, so forging one needs `k_audit` at the time of the forgery.
 */
final class AuditAnchorTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Anchor Fixture',
            'slug' => 'anchor-'.bin2hex(random_bytes(4)),
        ]);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /** Record events as though they happened on a day that is now finished. */
    private function recordYesterday(int $count = 2): void
    {
        Carbon::setTestNow(now('UTC')->subDay()->setTime(10, 0));

        for ($i = 0; $i < $count; $i++) {
            Audit::record(
                action: 'project.created',
                actorType: ActorType::System,
                organisationId: $this->organisation->id,
            );
        }

        Carbon::setTestNow();
    }

    /** @return array{0: int, 1: string} */
    private function anchor(?string $date = null): array
    {
        $exit = Artisan::call('docup:audit:anchor', $date === null ? [] : ['--date' => $date]);

        return [$exit, Artisan::output()];
    }

    public function test_it_anchors_a_finished_day(): void
    {
        $this->recordYesterday(3);

        [$exit] = $this->anchor();

        $this->assertSame(0, $exit);

        /** @var object{head_sequence: int|string, event_count: int|string}|null $row */
        $row = DB::selectOne(
            'SELECT `head_sequence`, `event_count` FROM `audit_anchors` WHERE `chain_key` = ?',
            [$this->organisation->id],
        );

        $this->assertNotNull($row, 'no anchor was written');
        $this->assertSame(3, (int) $row->head_sequence);
        $this->assertSame(3, (int) $row->event_count);
    }

    /** The signature must satisfy the verifier, or the anchor is decoration. */
    public function test_a_written_anchor_verifies(): void
    {
        $this->recordYesterday();
        $this->anchor();

        Artisan::call('docup:audit:verify');
        $output = Artisan::output();

        $this->assertStringContainsString('anchor', $output);
        $this->assertStringNotContainsString('anchor signature mismatch', $output);
        $this->assertSame(0, Artisan::call('docup:audit:verify'), $output);
    }

    /**
     * 🛑 An anchor pins the head of a **finished** day. One written mid-day
     * would be overtaken by the afternoon's events, and `audit:verify` would
     * then report it as describing a stale head — a false alarm manufactured by
     * the anchoring job itself.
     */
    public function test_it_refuses_to_anchor_today(): void
    {
        $this->recordYesterday();

        [$exit, $output] = $this->anchor(now('UTC')->format('Y-m-d'));

        $this->assertSame(1, $exit);
        $this->assertStringContainsString('FINISHED day', $output);
    }

    public function test_it_refuses_a_malformed_date(): void
    {
        [$exit] = $this->anchor('not-a-date');

        $this->assertSame(1, $exit);
    }

    /**
     * Re-running must skip, not rewrite. The §8.22.1 guards refuse `UPDATE` on
     * `audit_anchors` outright, so an anchor that disagrees with the chain is a
     * finding to investigate rather than a row to correct — and a job that
     * tried to correct it would simply error.
     */
    public function test_running_twice_skips_rather_than_rewriting(): void
    {
        $this->recordYesterday();

        $this->anchor();
        [$exit, $output] = $this->anchor();

        $this->assertSame(0, $exit);
        $this->assertStringContainsString('already anchored', $output);
        $this->assertSame(
            1,
            (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_anchors`')->n,
            'a second anchor row was written for the same day',
        );
    }

    /** A chain with no history by that date has nothing to anchor. */
    public function test_a_chain_with_no_events_by_that_date_is_skipped(): void
    {
        Audit::record(
            action: 'project.created',
            actorType: ActorType::System,
            organisationId: $this->organisation->id,
        );

        [$exit, $output] = $this->anchor();

        $this->assertSame(0, $exit);
        $this->assertStringContainsString('no events by that date', $output);
        $this->assertSame(0, (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_anchors`')->n);
    }

    /**
     * 🛑 The attack anchors exist to stop: history rewritten and re-hashed so
     * the chain is internally consistent again. The chain check would pass; the
     * anchor does not, because a rewriter cannot re-sign it without `k_audit`.
     *
     * Constructed by writing an anchor whose head hash does not describe the
     * event it names — the end state of such a rewrite — because the §8.22.1
     * guards refuse to let the application edit either table, which is itself
     * the protection working.
     */
    public function test_an_anchor_whose_head_no_longer_matches_is_reported(): void
    {
        $this->recordYesterday();

        $key = Audit::key();
        $anchoredOn = now('UTC')->subDay()->format('Y-m-d');
        $wrongHead = random_bytes(32);

        DB::insert(
            'INSERT INTO `audit_anchors`
                (`id`, `chain_key`, `anchored_on`, `head_hash`, `head_sequence`, `event_count`,
                 `signature`, `created_at`, `updated_at`)
             VALUES (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?, NOW(3), NOW(3))',
            [
                $this->organisation->id,
                $anchoredOn,
                $wrongHead,
                2,
                2,
                // Correctly signed, so the signature check passes and the
                // head-comparison is what catches it. Signing it wrongly would
                // have tested the easier of the two detectors.
                Audit::anchorSignature($wrongHead, $this->organisation->id, $anchoredOn, $key),
            ],
        );

        $exit = Artisan::call('docup:audit:verify');
        $output = Artisan::output();

        $this->assertSame(1, $exit, 'a mismatched anchor verified clean:
'.$output);
        $this->assertStringContainsString('anchor head changed', $output);
    }

    /** The application cannot remove an anchor to hide a mismatch. */
    public function test_the_application_cannot_delete_an_anchor_to_hide_a_mismatch(): void
    {
        $this->recordYesterday();
        $this->anchor();

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/maintenance principal/');

        DB::delete('DELETE FROM `audit_anchors` WHERE `chain_key` = ?', [$this->organisation->id]);
    }
}
