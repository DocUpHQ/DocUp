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
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * The tamper-evident audit chain (§8.22.1, §8.22.4, §8.22.5).
 *
 * Two of Phase 02's four exit criteria live in this file and are marked 🛑
 * below. Both run against real MySQL, which is not incidental: one of them
 * exists because MySQL's native JSON column is not byte-preserving, and a
 * portable test would have proved nothing about the behaviour that actually
 * broke.
 */
final class AuditChainTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private string $actorId;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Audit Fixture',
            'slug' => 'audit-'.bin2hex(random_bytes(4)),
        ]);

        $this->actorId = Uuid::v7();
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /**
     * @param  array<array-key, mixed>  $payload
     */
    private function record(string $action, array $payload = []): string
    {
        return Audit::record(
            action: $action,
            actorType: ActorType::User,
            organisationId: $this->organisation->id,
            actorId: $this->actorId,
            payload: $payload,
        );
    }

    /**
     * Append a raw row, bypassing Audit::record(), to construct a state the
     * verifier should reject.
     *
     * 🛑 Why tamper by INSERT rather than UPDATE.
     *
     * The application can no longer UPDATE or DELETE an audit row at all — the
     * §8.22.1 triggers refuse it, which is the property
     * {@see AuditAppendOnlyTest} proves. So these tests cannot edit a row the
     * way they did before the triggers existed.
     *
     * A privileged second connection was tried and does not work: the test runs
     * inside an uncommitted transaction, so another connection cannot see the
     * rows, and attempting to lock them waits out the 50-second lock timeout.
     *
     * What matters is that **the verifier cannot tell how a row reached a bad
     * state** — it compares contents against hashes and links. A row whose hash
     * does not match its contents is indistinguishable from an edited one, and
     * a skipped sequence is indistinguishable from a deleted row. So the state
     * is constructed directly, which is faster, needs no credentials, and
     * exercises exactly the same detectors.
     *
     * @param  array<string, mixed>  $overrides
     */
    private function appendRaw(array $overrides = []): string
    {
        $id = Uuid::v7();

        DB::insert(
            'INSERT INTO `audit_events`
                (`id`, `occurred_at`, `organisation_id`, `sequence`, `actor_id`, `actor_type`,
                 `action`, `payload`, `prev_hash`, `hash`)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            array_values(array_merge([
                'id' => $id,
                'occurred_at' => now()->format('Y-m-d H:i:s.v'),
                'organisation_id' => $this->organisation->id,
                'sequence' => 1,
                'actor_id' => $this->actorId,
                'actor_type' => 'user',
                'action' => 'raw.appended',
                'payload' => '[]',
                'prev_hash' => null,
                'hash' => random_bytes(32),
            ], $overrides)),
        );

        return $id;
    }

    /**
     * Run the verifier and capture BOTH its exit code and its output.
     *
     * `Artisan::call()` rather than `$this->artisan()->run()`: the latter
     * returns the exit code but does not populate `Artisan::output()`, so the
     * output assertions silently compared against an empty string. Since the
     * exit code was still correct, the tamper tests passed their first
     * assertion and failed only on the one that checks the row is NAMED —
     * which is the half of the criterion that matters.
     *
     * @return array{0: int, 1: string} exit code and output
     */
    private function verify(): array
    {
        $exit = Artisan::call('docup:audit:verify');

        return [$exit, Artisan::output()];
    }

    public function test_a_chain_of_events_verifies(): void
    {
        $this->record('project.created', ['kind' => 'docs']);
        $this->record('project.updated', ['field' => 'name']);
        $this->record('project.visibility.changed', ['from' => 'restricted', 'to' => 'members']);

        [$exit, $output] = $this->verify();

        $this->assertSame(0, $exit, "verification failed on an untampered chain:\n".$output);
    }

    /**
     * 🛑 **Phase 02 exit criterion.** After a manual row edit,
     * `docup:audit:verify` must fail AND name the offending row.
     *
     * Naming it is the half that matters in practice. "Verification failed" on
     * a 400-day log is not an answer an operator can act on — the next question
     * is always "which row", and a tool that cannot say turns an incident into
     * a weekend of bisecting by hand.
     *
     * The edit targets `action`, a plain visible column rather than the hash
     * itself, because that is the realistic attack: make the log read
     * differently. An earlier draft of this system hashed a stored canonical
     * blob instead of the row's fields, and this exact edit would have passed
     * verification — the visible row would say one thing while the chain
     * vouched for another.
     */
    public function test_a_row_whose_contents_do_not_match_its_hash_is_named(): void
    {
        $this->record('project.created');
        $this->record('project.updated');

        // A third row carrying a hash that does not describe it: exactly the
        // state a hand-edited row leaves behind.
        $planted = $this->appendRaw([
            'sequence' => 3,
            'action' => 'project.destroyed',
            'prev_hash' => DB::selectOne(
                'SELECT `hash` FROM `audit_events` WHERE `chain_key` = ? ORDER BY `sequence` DESC LIMIT 1',
                [$this->organisation->id],
            )->hash,
        ]);

        [$exit, $output] = $this->verify();

        $this->assertSame(1, $exit, 'a row inconsistent with its hash verified clean');
        $this->assertStringContainsString('hash mismatch', $output);
        $this->assertStringContainsString(
            Uuid::toText($planted),
            $output,
            'the failure did not name the offending row, which is the half of the criterion that matters'
        );
    }

    /** A missing row is caught twice over: the gap and the broken link. */
    public function test_a_missing_row_is_detected(): void
    {
        $this->record('a');
        $this->record('b');

        // Sequence 4 where 3 is expected: what a deleted row leaves behind.
        $this->appendRaw(['sequence' => 4, 'prev_hash' => random_bytes(32)]);

        [$exit, $output] = $this->verify();

        $this->assertSame(1, $exit);
        $this->assertStringContainsString('sequence gap', $output);
        $this->assertStringContainsString('broken link', $output);
    }

    /**
     * 🛑 **Phase 02 exit criterion**, and §8.22.5's whole reason for existing:
     * erasing a user's label leaves the chain verifying.
     *
     * This is the single most important data-model consequence of the erasure
     * promise. If a human-readable name were denormalised into the hashed
     * payload, then "erasure removes all personal data" and "the chain still
     * verifies" would be mutually exclusive — you could honour either, never
     * both. The specification calls it a Phase-00 immutable precisely so it is
     * not discovered in Phase 35 with the whole log already written.
     *
     * So the test erases for real: it overwrites the label with a tombstone,
     * exactly as `docup:erase` will, and then requires the chain to verify.
     */
    public function test_erasing_an_actor_label_leaves_the_chain_verifying(): void
    {
        DB::table('actor_labels')->insert([
            'id' => Uuid::v7(),
            'actor_id' => $this->actorId,
            'label' => 'Dana Example <dana@example.com>',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->record('project.created');
        $this->record('project.updated');

        [$exitBefore] = $this->verify();
        $this->assertSame(0, $exitBefore, 'the chain did not verify before erasure');

        // Erasure, as §8.22.5 specifies it: the label is overwritten with a
        // tombstone, not deleted, so the audit log still reads as "a deleted
        // account" rather than a bare identifier.
        DB::table('actor_labels')
            ->where('actor_id', $this->actorId)
            ->update(['label' => '[erased]', 'tombstoned_at' => now(), 'updated_at' => now()]);

        [$exitAfter, $output] = $this->verify();

        $this->assertSame(
            0,
            $exitAfter,
            "🛑 §8.22.5 violated: erasing an actor label broke the audit chain.\n".$output
        );

        $this->assertDatabaseHas('actor_labels', ['actor_id' => $this->actorId, 'label' => '[erased]']);
    }

    /**
     * 🛑 The erasure promise has a second half: the chain must not contain the
     * personal data in the first place.
     *
     * A chain that verifies after erasure is worthless if the name is sitting
     * in the payload — it would mean erasure simply missed it. So this asserts
     * the absence directly.
     */
    public function test_no_event_payload_contains_the_actor_label(): void
    {
        $this->record('project.created', ['subject_kind' => 'project']);

        /** @var list<object{payload: string, action: string}> $rows */
        $rows = DB::select('SELECT `payload`, `action` FROM `audit_events`');

        $this->assertNotEmpty($rows);

        foreach ($rows as $row) {
            $this->assertStringNotContainsString('@', $row->payload, 'an email address reached the hashed payload');
            $this->assertStringNotContainsString('Dana', $row->payload);
        }
    }

    /** Chains are per organisation (§10.6), so one tenant cannot renumber another. */
    public function test_each_organisation_has_an_independent_chain(): void
    {
        $other = Organisation::query()->create([
            'name' => 'Other',
            'slug' => 'other-'.bin2hex(random_bytes(4)),
        ]);

        $this->record('a');
        $this->record('b');

        Audit::record(
            action: 'a',
            actorType: ActorType::User,
            organisationId: $other->id,
            actorId: $this->actorId,
        );

        $mine = DB::selectOne(
            'SELECT MAX(`sequence`) AS top FROM `audit_events` WHERE `organisation_id` = ?',
            [$this->organisation->id],
        );
        $theirs = DB::selectOne(
            'SELECT MAX(`sequence`) AS top FROM `audit_events` WHERE `organisation_id` = ?',
            [$other->id],
        );

        $this->assertSame(2, (int) $mine->top);
        $this->assertSame(1, (int) $theirs->top, 'the second chain continued the first chain’s numbering');

        [$exit] = $this->verify();
        $this->assertSame(0, $exit);
    }

    /**
     * Installation-scope events form their own chain rather than joining an
     * arbitrary tenant's.
     */
    public function test_installation_events_form_their_own_chain(): void
    {
        Audit::record(action: 'installation.booted', actorType: ActorType::System);
        $this->record('project.created');

        $installation = DB::selectOne(
            'SELECT COUNT(*) AS n FROM `audit_events` WHERE `organisation_id` IS NULL AND `chain_key` = ?',
            [str_repeat("\x00", 16)],
        );

        $this->assertSame(1, (int) $installation->n);

        [$exit] = $this->verify();
        $this->assertSame(0, $exit);
    }

    /** §8.22.4: an audit row must not survive its mutation rolling back. */
    public function test_a_rolled_back_transaction_leaves_no_audit_row(): void
    {
        $before = (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_events`')->n;

        try {
            DB::transaction(function (): void {
                $this->record('project.created');

                throw new \RuntimeException('the mutation failed after the audit row was written');
            });
        } catch (\RuntimeException) {
            // expected
        }

        $after = (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_events`')->n;

        $this->assertSame($before, $after, 'an audit row outlived the transaction that wrote it');
    }
}
