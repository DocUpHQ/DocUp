<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 **Phase 02 exit criterion.** "Organisation B's project returns 404 — not
 * 403 — for organisation A through the UI, the API **and** direct identifier
 * access."
 *
 * All three routes, because they fail differently. The UI and API go through
 * route binding; direct identifier access is the one people forget, and it is
 * the one an attacker reaches for after seeing a UUID in a log or a support
 * ticket.
 *
 * Why 404 and not 403 is the whole point: a 403 confirms the row exists. An
 * attacker who can tell "forbidden" from "no such thing" can enumerate another
 * tenant's projects without ever reading one, and that enumeration is itself
 * the leak.
 */
final class CrossTenantAccessTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $alpha;

    private Organisation $beta;

    private Project $betaProject;

    private User $alphaMember;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->alpha = Organisation::query()->create([
            'name' => 'Alpha',
            'slug' => 'alpha-'.bin2hex(random_bytes(4)),
        ]);

        $this->beta = Organisation::query()->create([
            'name' => 'Beta',
            'slug' => 'beta-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->alpha->id);

        Project::query()->create(['slug' => 'alpha-docs', 'name' => 'Alpha Docs']);

        $this->context->for($this->beta->id);

        $this->betaProject = Project::query()->create(['slug' => 'beta-docs', 'name' => 'Beta Docs']);

        $this->context->spanAllOrganisations();

        $this->alphaMember = User::query()->create([
            'name' => 'Alpha Member',
            'email' => 'alpha-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $this->grant($this->alphaMember, $this->alpha, Role::OrgAdmin);

        // 🛑 The context is forgotten before any request runs. The middleware
        // must declare it; a test that left one set could pass while the
        // middleware did nothing.
        $this->context->forget();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    private function grant(User $user, Organisation $organisation, Role $role): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => 'organisation',
            'scope_id' => $organisation->id,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    // ------------------------------------------------------------ the UI route

    public function test_a_member_can_see_their_own_project(): void
    {
        $this->actingAs($this->alphaMember)
            ->get("/o/{$this->alpha->slug}/projects/alpha-docs")
            ->assertOk();
    }

    /** 🛑 Through the UI, by slug, under the member's own organisation. */
    public function test_the_ui_returns_404_for_another_organisations_project(): void
    {
        $this->actingAs($this->alphaMember)
            ->get("/o/{$this->alpha->slug}/projects/beta-docs")
            ->assertNotFound();
    }

    /**
     * 🛑 And under the other organisation's own prefix, which is the attempt
     * that would otherwise reveal that Beta exists.
     */
    public function test_the_ui_returns_404_for_another_organisation_entirely(): void
    {
        $this->actingAs($this->alphaMember)
            ->get("/o/{$this->beta->slug}/projects/beta-docs")
            ->assertNotFound();
    }

    /** Not even the organisation listing may confirm the tenant exists. */
    public function test_the_ui_returns_404_for_another_organisations_index(): void
    {
        $this->actingAs($this->alphaMember)
            ->get("/o/{$this->beta->slug}/projects")
            ->assertNotFound();
    }

    // ----------------------------------------------------------- the API route

    public function test_the_api_serves_a_members_own_project(): void
    {
        $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->alpha->slug}/projects/alpha-docs")
            ->assertOk()
            ->assertJsonPath('data.slug', 'alpha-docs');
    }

    /** 🛑 Through the API. */
    public function test_the_api_returns_404_for_another_organisations_project(): void
    {
        $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->beta->slug}/projects/beta-docs")
            ->assertNotFound();
    }

    /** The API index must not leak another tenant's projects either. */
    public function test_the_api_index_lists_only_the_members_own_projects(): void
    {
        $response = $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->alpha->slug}/projects")
            ->assertOk();

        $slugs = array_column($response->json('data'), 'slug');

        $this->assertSame(['alpha-docs'], $slugs);
    }

    // ------------------------------------------------ direct identifier access

    /**
     * 🛑 The third route §8.2.2 names, and the one most easily missed.
     *
     * The attacker has the UUID — from a log line, a support ticket, a
     * screenshot — and asks for it under an organisation they legitimately
     * belong to. Knowing the key must not help.
     */
    public function test_direct_identifier_access_returns_404_across_tenants(): void
    {
        $this->actingAs($this->alphaMember)
            ->get("/o/{$this->alpha->slug}/projects/".Uuid::toText($this->betaProject->id))
            ->assertNotFound();

        $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->alpha->slug}/projects/".Uuid::toText($this->betaProject->id))
            ->assertNotFound();
    }

    /** The same identifier under Beta's own prefix is still 404, via membership. */
    public function test_direct_identifier_access_under_the_owning_tenant_is_also_404(): void
    {
        $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->beta->slug}/projects/".Uuid::toText($this->betaProject->id))
            ->assertNotFound();
    }

    /** And identifier access to one's own project works, or the test above is vacuous. */
    public function test_direct_identifier_access_works_within_the_tenant(): void
    {
        $this->context->for($this->alpha->id);
        $own = Project::query()->where('slug', 'alpha-docs')->firstOrFail();
        $this->context->forget();

        $this->actingAs($this->alphaMember)
            ->getJson("/api/v1/organisations/{$this->alpha->slug}/projects/".Uuid::toText($own->id))
            ->assertOk()
            ->assertJsonPath('data.slug', 'alpha-docs');
    }

    /**
     * 🛑 An invalid identifier is a 404, never a 500 (ADR 0006).
     *
     * The exit criterion ADR 0006 measured. A 500 here would be an information
     * leak of a different kind — a stack trace — and a denial-of-service lever.
     */
    public function test_a_malformed_identifier_is_404_not_500(): void
    {
        foreach (['not-a-uuid', str_repeat('z', 36), '../../etc/passwd', '1'] as $rubbish) {
            $this->actingAs($this->alphaMember)
                ->getJson("/api/v1/organisations/{$this->alpha->slug}/projects/".urlencode($rubbish))
                ->assertNotFound();
        }
    }

    /** A stranger with no membership anywhere sees nothing at all. */
    public function test_a_non_member_gets_404_rather_than_403(): void
    {
        $this->context->spanAllOrganisations();

        $stranger = User::query()->create([
            'name' => 'Stranger',
            'email' => 'stranger-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $this->context->forget();

        $response = $this->actingAs($stranger)
            ->get("/o/{$this->alpha->slug}/projects/alpha-docs");

        $response->assertNotFound();
        $this->assertNotSame(403, $response->getStatusCode(), '403 confirms the project exists');
    }

    /** An unauthenticated request never reaches the tenancy layer. */
    public function test_an_anonymous_request_is_not_served(): void
    {
        $response = $this->get("/o/{$this->alpha->slug}/projects/alpha-docs");

        $this->assertContains($response->getStatusCode(), [302, 401, 404]);
        $this->assertNotSame(200, $response->getStatusCode());
    }
}
