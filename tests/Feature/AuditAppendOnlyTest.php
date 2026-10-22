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
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §8.22.1: the audit log is **insert-only for the application**.
 *
 * This is the test that makes that claim true rather than aspirational. Before
 * it, "insert-only" held only because no application code happened to issue an
 * UPDATE — which is not a property, it is a coincidence maintained by review.
 * A SQL-injection bug anywhere in the application could have rewritten the log
 * that exists to detect exactly that.
 *
 * **On the mechanism, stated plainly because it is not what §8.22.1 names.**
 * The specification asks for a grant: "the application's database user holds
 * INSERT and SELECT on `audit_events` and nothing else". MySQL cannot express
 * that beside the schema-level grant the application needs for every other
 * table — a table-level `REVOKE` requires a table-level `GRANT` to subtract
 * from, and `partial_revokes` operates at schema level. `CREATE TRIGGER`
 * likewise needs `SUPER` while binary logging is on, so neither mechanism can
 * be applied by the application itself.
 *
 * The property is therefore enforced by triggers installed by
 * `deploy/mysql/init/10-audit-append-only.sql`, which an administrator applies
 * once. `docup:doctor` fails while it is missing, and this test fails too — so
 * an installation that skipped the step cannot mistake a forgeable log for a
 * protected one. A separate schema for the audit tables is the better long-term
 * answer and is proposed in the build log; it needs an ADR because it touches
 * the §15.2 backup set.
 */
final class AuditAppendOnlyTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Append Only',
            'slug' => 'append-'.bin2hex(random_bytes(4)),
        ]);
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    private function anEvent(): string
    {
        return Audit::record(
            action: 'project.created',
            actorType: ActorType::System,
            organisationId: $this->organisation->id,
        );
    }

    /**
     * A guard on the guard.
     *
     * If the hardening script has not been applied, every assertion below would
     * fail for the right reason but with a confusing message about a missing
     * exception. This says so directly instead.
     */
    public function test_the_hardening_has_been_applied(): void
    {
        /** @var list<object{TRIGGER_NAME: string}> $triggers */
        $triggers = DB::select(
            'SELECT TRIGGER_NAME FROM information_schema.TRIGGERS
              WHERE TRIGGER_SCHEMA = ? AND EVENT_OBJECT_TABLE IN (?, ?)',
            [DB::connection()->getDatabaseName(), 'audit_events', 'audit_anchors'],
        );

        $this->assertCount(
            4,
            $triggers,
            'the §8.22.1 append-only triggers are missing. Apply '
            ."deploy/mysql/init/10-audit-append-only.sql as a database administrator.\n"
            .'Until then the application can rewrite its own audit log.'
        );
    }

    /** 🛑 The headline: an audit row cannot be altered by the application. */
    public function test_the_application_cannot_update_an_audit_event(): void
    {
        $id = $this->anEvent();

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/append-only/');

        DB::update('UPDATE `audit_events` SET `action` = ? WHERE `id` = ?', ['tampered', $id]);
    }

    /** And cannot be removed. Retention uses DROP PARTITION, not DELETE (§20.3). */
    public function test_the_application_cannot_delete_an_audit_event(): void
    {
        $id = $this->anEvent();

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/append-only|DROP PARTITION/');

        DB::delete('DELETE FROM `audit_events` WHERE `id` = ?', [$id]);
    }

    /**
     * Inserting still works, which is the half that is easy to break while
     * hardening the other half. An audit log that cannot be written to would
     * stop every state-changing action, because §8.22.4 puts the audit row in
     * the same transaction as the mutation.
     */
    public function test_the_application_can_still_append(): void
    {
        $before = (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_events`')->n;

        $this->anEvent();

        $after = (int) DB::selectOne('SELECT COUNT(*) AS n FROM `audit_events`')->n;

        $this->assertSame($before + 1, $after);
    }

    /** An anchor may never be re-signed, by anyone. */
    public function test_no_one_can_update_an_anchor(): void
    {
        DB::insert(
            'INSERT INTO `audit_anchors`
                (`id`, `chain_key`, `anchored_on`, `head_hash`, `head_sequence`, `event_count`, `signature`,
                 `created_at`, `updated_at`)
             VALUES (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?, NOW(3), NOW(3))',
            [$this->organisation->id, '2026-10-22', random_bytes(32), 1, 1, random_bytes(32)],
        );

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/re-signed/');

        DB::update('UPDATE `audit_anchors` SET `head_sequence` = ? WHERE `chain_key` = ?', [99, $this->organisation->id]);
    }

    /**
     * Anchors are purged by row under §20.3, but only by the maintenance
     * principal — so the application is refused while retention still works.
     */
    public function test_the_application_cannot_purge_anchors(): void
    {
        DB::insert(
            'INSERT INTO `audit_anchors`
                (`id`, `chain_key`, `anchored_on`, `head_hash`, `head_sequence`, `event_count`, `signature`,
                 `created_at`, `updated_at`)
             VALUES (UUID_TO_BIN(UUID()), ?, ?, ?, ?, ?, ?, NOW(3), NOW(3))',
            [$this->organisation->id, '2026-10-21', random_bytes(32), 1, 1, random_bytes(32)],
        );

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/maintenance principal/');

        DB::delete('DELETE FROM `audit_anchors` WHERE `chain_key` = ?', [$this->organisation->id]);
    }
}
