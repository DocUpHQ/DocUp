<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Support\Uuid;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * Database-level invariants on `role_assignments`.
 *
 * These are asserted against real MySQL because they are not application logic
 * — they are a CHECK constraint and a unique index. A test that went through a
 * model would prove the model validates, which is a different and weaker claim:
 * the point of putting these in the schema is that a hand-written query, a
 * seeder or a future bulk import cannot bypass them.
 */
final class RoleAssignmentConstraintsTest extends TestCase
{
    use DatabaseTransactions;

    private string $organisationId;

    protected function setUp(): void
    {
        parent::setUp();

        $this->organisationId = Uuid::v7();

        DB::table('organisations')->insert([
            'id' => $this->organisationId,
            'name' => 'Constraint Fixture',
            'slug' => 'constraint-fixture-'.bin2hex(random_bytes(4)),
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * @param  array<string, mixed>  $overrides
     */
    private function grant(array $overrides = []): void
    {
        DB::table('role_assignments')->insert(array_merge([
            'id' => Uuid::v7(),
            'subject_type' => 'user',
            'subject_id' => Uuid::v7(),
            'scope_type' => 'installation',
            'scope_id' => null,
            'role' => 'installation_owner',
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ], $overrides));
    }

    /**
     * The installation is a singleton, so an installation-scoped grant naming a
     * particular row is incoherent — and the incoherent row would resolve
     * against nothing, granting silently.
     */
    public function test_an_installation_grant_may_not_name_a_scope_id(): void
    {
        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/role_assignments_scope_id_pairing/');

        $this->grant([
            'scope_type' => 'installation',
            'scope_id' => $this->organisationId,
        ]);
    }

    /**
     * The other direction, which is the dangerous one: a project-scoped grant
     * with no project would be a grant whose scope nobody can check.
     */
    public function test_a_scoped_grant_must_name_its_scope(): void
    {
        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/role_assignments_scope_id_pairing/');

        $this->grant([
            'scope_type' => 'project',
            'scope_id' => null,
            'role' => 'project_admin',
        ]);
    }

    public function test_a_valid_installation_grant_is_accepted(): void
    {
        $this->grant();

        $this->assertSame(1, DB::table('role_assignments')->count());
    }

    /**
     * 🛑 The assertion the `scope_key` generated column exists for.
     *
     * MySQL permits unlimited NULLs in a UNIQUE index, so a unique key over the
     * nullable `scope_id` would have stopped constraining precisely the rows
     * where it is NULL — every installation-scoped grant. The same person could
     * then hold `installation_owner` any number of times, and the duplicate
     * would be invisible rather than rejected.
     *
     * This test would have passed against that broken schema, because it is the
     * *insert* that must fail. That is the point: it fails only if the index is
     * total.
     */
    public function test_the_same_installation_grant_cannot_be_recorded_twice(): void
    {
        $subject = Uuid::v7();

        $this->grant(['subject_id' => $subject]);

        $this->expectException(QueryException::class);
        $this->expectExceptionMessageMatches('/role_assignments_grant_unique/');

        $this->grant(['subject_id' => $subject]);
    }

    /** Two different people may of course hold the same installation role. */
    public function test_two_subjects_may_hold_the_same_installation_role(): void
    {
        $this->grant(['subject_id' => Uuid::v7()]);
        $this->grant(['subject_id' => Uuid::v7()]);

        $this->assertSame(2, DB::table('role_assignments')->count());
    }

    /** The sentinel is what makes the index total, so assert its value. */
    public function test_scope_key_is_the_zero_sentinel_at_installation_scope(): void
    {
        $this->grant();

        /** @var object{scope_key: string}|null $row */
        $row = DB::table('role_assignments')->select('scope_key')->first();

        $this->assertNotNull($row);
        $this->assertSame(str_repeat("\x00", 16), $row->scope_key);
    }

    /** And mirrors scope_id everywhere else, so scoped grants stay distinct. */
    public function test_scope_key_mirrors_scope_id_when_one_is_given(): void
    {
        $project = Uuid::v7();

        $this->grant([
            'scope_type' => 'project',
            'scope_id' => $project,
            'role' => 'project_admin',
            'organisation_id' => $this->organisationId,
        ]);

        /** @var object{scope_key: string}|null $row */
        $row = DB::table('role_assignments')->select('scope_key')->first();

        $this->assertNotNull($row);
        $this->assertSame($project, $row->scope_key);
    }

    /**
     * The database rejects a role the application does not know. Belt and
     * braces with the Role enum, in the direction that matters: a bad value
     * arriving from a seeder or an import fails loudly instead of sitting in
     * the table until something tries to resolve it.
     */
    public function test_an_unknown_role_is_rejected_by_the_column_type(): void
    {
        $this->expectException(QueryException::class);

        $this->grant(['role' => 'superuser']);
    }
}
