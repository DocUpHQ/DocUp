<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\Capability;
use App\Auth\Deletions;
use App\Auth\Invitations;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\RoleResolver;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 Phase 02's exit criteria, demonstrated end to end.
 *
 * §17, Phase 02: "Create an organisation, invite a member, assign a role,
 * create a project. Organisation B's project returns 404 — not 403 — for
 * organisation A through the UI, the API and direct identifier access. After a
 * manual row edit in the database, `docup:audit:verify` fails and names the
 * offending row. 🛑 The audit chain hashes only opaque identifiers: erasing a
 * user's label leaves the chain verifying (§8.22.5)."
 *
 * The cross-tenant and audit criteria have their own dedicated files
 * ({@see CrossTenantAccessTest}, {@see AuditChainTest}) because each needs
 * several cases. This file is the **first** criterion as one continuous
 * journey, plus §8.2.8 deletion semantics, so that "it works" is asserted as a
 * sequence a person could actually follow rather than as four unrelated unit
 * tests that happen to pass.
 */
final class Phase02ExitCriteriaTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 Exit criterion 1: create an organisation, invite a member, assign a
     * role, create a project — in that order, as one story.
     */
    public function test_the_full_journey(): void
    {
        $this->context->spanAllOrganisations();

        // --- create an organisation -------------------------------------
        $organisation = Organisation::query()->create([
            'name' => 'Acme Engineering',
            'slug' => 'acme-'.bin2hex(random_bytes(4)),
        ]);

        $owner = User::query()->create([
            'name' => 'Owner',
            'email' => 'owner-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $organisation->id,
            'subject_type' => 'user',
            'subject_id' => $owner->id,
            'scope_type' => 'organisation',
            'scope_id' => $organisation->id,
            'role' => Role::OrgAdmin->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->for($organisation->id);

        // --- invite a member ---------------------------------------------
        $newcomer = User::query()->create([
            'name' => 'Newcomer',
            'email' => 'newcomer-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        [$invitation, $code] = app(Invitations::class)->issue(
            $organisation,
            $newcomer->email,
            Role::ProjectMaintainer,
            $owner,
        );

        $this->assertTrue($invitation->isOpen());

        // --- assign a role (by accepting) --------------------------------
        $assignment = app(Invitations::class)->accept($code, $newcomer);

        $this->assertSame(Role::ProjectMaintainer, $assignment->role);
        $this->assertTrue(
            app(RoleResolver::class)->allows($newcomer, Capability::ProjectView, null, $organisation->id),
        );

        // --- create a project --------------------------------------------
        $project = Project::query()->create([
            'slug' => 'handbook',
            'name' => 'Engineering Handbook',
        ]);

        $this->assertSame($organisation->id, $project->organisation_id);

        // And the member can reach it through the dashboard.
        $this->actingAs($newcomer)
            ->get("/o/{$organisation->slug}/projects/handbook")
            ->assertOk();

        // --- every step left an audit trail ------------------------------
        /** @var list<object{action: string}> $events */
        $events = DB::select('SELECT `action` FROM `audit_events` WHERE `organisation_id` = ? ORDER BY `sequence`', [$organisation->id]);
        $actions = array_map(static fn (object $e): string => $e->action, $events);

        $this->assertContains('organisation.invitation.issued', $actions);
        $this->assertContains('organisation.invitation.accepted', $actions);

        // --- and the chain still verifies --------------------------------
        $this->assertSame(0, Artisan::call('docup:audit:verify'), Artisan::output());
    }

    /**
     * 🛑 §8.2.8: "Project and version slugs MUST NOT be reusable after
     * deletion", and §8.22.6 hard-purges the row at 30 days — so the
     * reservation has to outlive the purge or the rule quietly expires with it.
     */
    public function test_a_deleted_projects_slug_is_never_reusable(): void
    {
        $this->context->spanAllOrganisations();

        $organisation = Organisation::query()->create([
            'name' => 'Deletions',
            'slug' => 'del-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($organisation->id);

        $project = Project::query()->create(['slug' => 'retired', 'name' => 'Retired']);

        app(Deletions::class)->deleteProject($project);

        $this->assertFalse(app(Deletions::class)->slugIsAvailable($organisation, 'retired'));

        // Now jump past the recovery window and purge for real.
        Carbon::setTestNow(now()->addDays(Deletions::RECOVERY_WINDOW_DAYS + 1));

        $this->assertSame(0, Artisan::call('docup:purge'));

        $this->context->for($organisation->id);

        // 🛑 The row is gone...
        $this->assertSame(0, Project::query()->withTrashed()->where('slug', 'retired')->count());

        // ...and the slug is STILL reserved. This is the assertion that would
        // have failed with soft deletion alone, thirty days after any deletion,
        // silently.
        $this->assertFalse(
            app(Deletions::class)->slugIsAvailable($organisation, 'retired'),
            'the slug became reusable after the hard purge, violating §8.2.8'
        );
    }

    /** §8.22.1: audit events are retained past the data they describe. */
    public function test_audit_events_survive_the_purge_of_their_subject(): void
    {
        $this->context->spanAllOrganisations();

        $organisation = Organisation::query()->create([
            'name' => 'Retention',
            'slug' => 'ret-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($organisation->id);

        $project = Project::query()->create(['slug' => 'short-lived', 'name' => 'Short Lived']);
        $projectId = $project->id;

        app(Deletions::class)->deleteProject($project);

        Carbon::setTestNow(now()->addDays(Deletions::RECOVERY_WINDOW_DAYS + 1));
        Artisan::call('docup:purge');

        /** @var list<object{action: string}> $events */
        $events = DB::select(
            'SELECT `action` FROM `audit_events` WHERE `subject_id` = ? ORDER BY `sequence`',
            [$projectId],
        );

        $actions = array_map(static fn (object $e): string => $e->action, $events);

        // 🛑 The record of the deletion outlives the thing deleted. Free by
        // construction — audit_events carries no foreign keys because it is
        // partitioned (§10.6) — but worth asserting, because the absence of a
        // constraint reads as an oversight until someone "fixes" it.
        $this->assertContains('project.deleted', $actions);
        $this->assertContains('project.purged', $actions);

        $this->assertSame(0, Artisan::call('docup:audit:verify'), Artisan::output());
    }

    /** The purge must not touch anything still inside its recovery window. */
    public function test_the_purge_leaves_the_recovery_window_alone(): void
    {
        $this->context->spanAllOrganisations();

        $organisation = Organisation::query()->create([
            'name' => 'Window',
            'slug' => 'win-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($organisation->id);

        $project = Project::query()->create(['slug' => 'recent', 'name' => 'Recent']);

        app(Deletions::class)->deleteProject($project);

        Artisan::call('docup:purge');

        $this->context->for($organisation->id);

        $this->assertSame(
            1,
            Project::query()->withTrashed()->where('slug', 'recent')->count(),
            'the purge destroyed a row still inside its 30-day recovery window'
        );
    }
}
