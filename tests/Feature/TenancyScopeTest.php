<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\Exceptions\TenancyContextMissing;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tests\TestCase;

/**
 * The §8.2.1 global tenancy scope, and the data-layer half of §8.2.2.
 *
 * §8.2.2 requires cross-tenant access to return **404, never 403**, through the
 * UI, the API and direct identifier access alike. The full criterion needs
 * endpoints, which arrive later in Phase 02 — but the mechanism that delivers
 * it is here: if a row in another organisation is simply **not visible**, route
 * binding finds nothing and the framework renders 404 without any code
 * choosing to. A 403 would require code that first found the row, and finding
 * it is already the leak.
 */
final class TenancyScopeTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $alpha;

    private Organisation $beta;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);

        // Creating the organisations themselves is installation-wide work:
        // Organisation is the tenancy root and carries no organisation_id.
        $this->context->spanAllOrganisations();

        $this->alpha = Organisation::query()->create([
            'name' => 'Alpha',
            'slug' => 'alpha-'.bin2hex(random_bytes(4)),
        ]);

        $this->beta = Organisation::query()->create([
            'name' => 'Beta',
            'slug' => 'beta-'.bin2hex(random_bytes(4)),
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The headline isolation property.
     */
    public function test_a_project_is_invisible_from_another_organisation(): void
    {
        $this->context->for($this->alpha->id);
        Project::query()->create(['slug' => 'docs', 'name' => 'Alpha Docs']);

        $this->context->for($this->beta->id);

        $this->assertSame(0, Project::query()->count(), "beta can see alpha's projects");
    }

    /**
     * 🛑 §8.2.2 "direct identifier access". Knowing the key must not help: the
     * lookup returns nothing, so the caller cannot distinguish "exists but
     * forbidden" from "does not exist".
     */
    public function test_finding_another_organisations_project_by_its_key_returns_nothing(): void
    {
        $this->context->for($this->alpha->id);
        $project = Project::query()->create(['slug' => 'private-docs', 'name' => 'Alpha Private']);
        $knownId = $project->id;

        $this->context->for($this->beta->id);

        $this->assertNull(
            Project::query()->find($knownId),
            'a known key from another organisation resolved; this is the 403-instead-of-404 leak'
        );
    }

    /**
     * 🛑 Fail loud, not open.
     *
     * The dangerous alternative is a scope that returns every row when nobody
     * declared a tenant. This asserts the exception rather than an empty set,
     * because "closed" would present as an inexplicably blank page and get
     * debugged for an hour before anyone suspected tenancy.
     */
    public function test_querying_with_no_declared_context_throws_rather_than_leaking(): void
    {
        $this->context->for($this->alpha->id);
        Project::query()->create(['slug' => 'docs', 'name' => 'Alpha Docs']);

        $this->context->forget();

        $this->expectException(TenancyContextMissing::class);

        Project::query()->count();
    }

    public function test_creating_a_project_with_no_context_throws(): void
    {
        $this->context->forget();

        $this->expectException(TenancyContextMissing::class);

        Project::query()->create(['slug' => 'orphan', 'name' => 'Orphan']);
    }

    /** The tenant is filled from the context rather than from the caller. */
    public function test_the_organisation_is_filled_in_on_create(): void
    {
        $this->context->for($this->beta->id);

        $project = Project::query()->create(['slug' => 'beta-docs', 'name' => 'Beta Docs']);

        $this->assertSame($this->beta->id, $project->organisation_id);
    }

    /** Installation-wide work sees every tenant, which is the whole purpose. */
    public function test_spanning_all_organisations_sees_every_project(): void
    {
        $this->context->for($this->alpha->id);
        Project::query()->create(['slug' => 'a', 'name' => 'A']);

        $this->context->for($this->beta->id);
        Project::query()->create(['slug' => 'b', 'name' => 'B']);

        $this->context->spanAllOrganisations();

        $this->assertSame(2, Project::query()->count());
    }

    /**
     * Restoration matters more than it looks: without it one system-wide
     * operation inside a tenant-scoped request would leave the remainder of
     * that request unscoped — a leak introduced by a helper, far from any code
     * that looks like it concerns tenancy.
     */
    public function test_spanning_all_organisations_temporarily_restores_the_previous_tenant(): void
    {
        $this->context->for($this->alpha->id);

        $seen = $this->context->acrossAllOrganisations(function (): bool {
            return app(OrganisationContext::class)->spansAllOrganisations();
        });

        $this->assertTrue($seen, 'the callback did not run with an unscoped context');
        $this->assertSame($this->alpha->id, $this->context->current(), 'the previous tenant was not restored');
        $this->assertFalse($this->context->spansAllOrganisations());
    }

    /**
     * 🛑 §8.2.10: visibility defaults to the strongest level. A project that is
     * public by default leaks on the operator's first mistake, and the default
     * is the setting nobody reviews.
     */
    public function test_a_new_project_is_restricted_until_someone_says_otherwise(): void
    {
        $this->context->for($this->alpha->id);

        $project = Project::query()->create(['slug' => 'fresh', 'name' => 'Fresh']);

        $this->assertSame('restricted', $project->visibility->value);
        $this->assertFalse($project->isPubliclyVisible());
    }

    /** §8.2.9 defaults to inheriting; the surprising state is a project nobody can administer. */
    public function test_a_new_project_inherits_organisation_roles(): void
    {
        $this->context->for($this->alpha->id);

        $project = Project::query()->create(['slug' => 'inherits', 'name' => 'Inherits']);

        $this->assertTrue($project->inherit_organisation_roles);
    }
}
