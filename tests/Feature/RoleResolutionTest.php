<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\RoleResolver;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Tests\TestCase;

/**
 * Additive union over the scope chain (§12.1, §8.13.1, §8.2.9).
 */
final class RoleResolutionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private RoleResolver $resolver;

    private Organisation $organisation;

    private Project $project;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->resolver = app(RoleResolver::class);

        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Resolver Fixture',
            'slug' => 'resolver-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create(['slug' => 'docs', 'name' => 'Docs']);

        $this->user = User::query()->create([
            'name' => 'Resolver User',
            'email' => 'resolver-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    private function grant(Role $role, string $scopeType, ?string $scopeId): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $scopeType === 'installation' ? null : $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->user->id,
            'scope_type' => $scopeType,
            'scope_id' => $scopeId,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    public function test_a_user_with_no_assignments_holds_nothing(): void
    {
        $this->assertSame([], $this->resolver->rolesFor($this->user, $this->project));
        $this->assertFalse($this->resolver->allows($this->user, Capability::ProjectView, $this->project));
    }

    /**
     * 🛑 The headline property of §12.1: the union, not the nearest scope.
     *
     * An org member who also administers one project must hold both sets. A
     * nearest-wins implementation would give them only the project role and
     * silently strip `project.create` at organisation level — which looks like
     * a permissions bug long after the fact and is why §12.1 states the rule
     * rather than leaving it to the reader.
     */
    public function test_capabilities_from_several_scopes_are_unioned(): void
    {
        $this->grant(Role::OrgMember, 'organisation', $this->organisation->id);
        $this->grant(Role::ProjectAdmin, 'project', $this->project->id);

        $capabilities = $this->resolver->capabilitiesFor($this->user, $this->project);

        // From org_member:
        $this->assertContains(Capability::ProjectCreate, $capabilities);
        // From project_admin:
        $this->assertContains(Capability::ProjectVisibilityUpdate, $capabilities);
        $this->assertContains(Capability::ProjectDelete, $capabilities);
    }

    public function test_installation_roles_apply_everywhere(): void
    {
        $this->grant(Role::InstallationOwner, 'installation', null);

        $this->assertTrue($this->resolver->allows($this->user, Capability::ProjectDelete, $this->project));
        $this->assertTrue($this->resolver->allows($this->user, Capability::OrganisationUpdate, null, $this->organisation->id));
    }

    /**
     * 🛑 §8.13.2 survives resolution.
     *
     * The separation of duty is only real if it holds after the union. An owner
     * must still not reach IdP configuration or audit export — and the obvious
     * `Gate::before()` shortcut for owners would have broken precisely this
     * while leaving the capability matrix looking correct.
     */
    public function test_an_installation_owner_still_cannot_manage_idp_or_export_audit(): void
    {
        $this->grant(Role::InstallationOwner, 'installation', null);

        $this->assertFalse($this->resolver->allows($this->user, Capability::InstallationIdpManage));
        $this->assertFalse($this->resolver->allows($this->user, Capability::InstallationAuditExport));
    }

    /** §8.2.9: the one audited flag that escapes additive inheritance. */
    public function test_a_project_can_opt_out_of_organisation_roles(): void
    {
        $this->grant(Role::OrgAdmin, 'organisation', $this->organisation->id);

        $this->assertTrue($this->resolver->allows($this->user, Capability::ProjectDelete, $this->project));

        // Via the audited setter, not update(): the flag is deliberately not
        // mass-assignable, which is how this test first failed.
        $this->project->setOrganisationRoleInheritance(false);

        $this->assertFalse(
            $this->resolver->allows($this->user, Capability::ProjectDelete, $this->project->fresh()),
            'the §8.2.9 opt-out did not remove the inherited organisation role'
        );
    }

    /**
     * 🛑 But opting out must NOT lock out the installation.
     *
     * Otherwise a project-level flag lets an organisation take a project
     * hostage, with nobody able to reach it — including the person responsible
     * for the installation.
     */
    public function test_opting_out_does_not_escape_installation_roles(): void
    {
        $this->grant(Role::InstallationOwner, 'installation', null);
        $this->project->setOrganisationRoleInheritance(false);

        $this->assertTrue(
            $this->resolver->allows($this->user, Capability::ProjectDelete, $this->project->fresh()),
            'a project opted out of organisation roles also escaped installation roles'
        );
    }

    /** An expired assignment confers nothing (§10.1 `expires_at`). */
    public function test_an_expired_assignment_is_ignored(): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->user->id,
            'scope_type' => 'project',
            'scope_id' => $this->project->id,
            'role' => Role::ProjectAdmin->value,
            'source' => 'manual',
            'expires_at' => now()->subMinute(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->assertFalse($this->resolver->allows($this->user, Capability::ProjectDelete, $this->project));
    }

    /** A role on one project says nothing about another. */
    public function test_a_project_role_does_not_leak_to_a_sibling_project(): void
    {
        $other = Project::query()->create(['slug' => 'other', 'name' => 'Other']);

        $this->grant(Role::ProjectAdmin, 'project', $this->project->id);

        $this->assertTrue($this->resolver->allows($this->user, Capability::ProjectDelete, $this->project));
        $this->assertFalse($this->resolver->allows($this->user, Capability::ProjectDelete, $other));
    }

    /**
     * 🛑 §12.1: "Laravel `Gate` and policies are the only call site." So the
     * matrix must be reachable the normal way, or call sites will grow their own
     * checks.
     */
    public function test_every_capability_is_registered_as_a_gate_ability(): void
    {
        $this->grant(Role::ProjectAdmin, 'project', $this->project->id);

        $this->assertTrue($this->user->can(Capability::ProjectDelete->value, $this->project));
        $this->assertFalse($this->user->can(Capability::InstallationIdpManage->value));

        foreach (Capability::cases() as $capability) {
            $this->assertTrue(
                Gate::has($capability->value),
                "[{$capability->value}] is not registered as a gate ability"
            );
        }
    }

    /**
     * 🛑 Authorisation must see installation-scope rows even inside a tenant
     * context.
     *
     * `role_assignments` holds those with a NULL `organisation_id`, which the
     * §8.2.1 global scope would filter away — so an installation owner would
     * lose every capability the moment a tenant was declared. The resolver uses
     * the query builder for this reason, and this test is what would catch a
     * well-meaning refactor to Eloquent.
     */
    public function test_installation_roles_resolve_inside_a_tenant_context(): void
    {
        $this->grant(Role::InstallationOwner, 'installation', null);

        $this->context->for($this->organisation->id);

        $this->assertTrue(
            $this->resolver->allows($this->user, Capability::ProjectDelete, $this->project),
            'the tenancy scope hid installation-scope role assignments'
        );
    }
}
