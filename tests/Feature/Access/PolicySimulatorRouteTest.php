<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

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
 * 🛑 §8.12.25's "a policy simulator MUST exist **in the UI**" — the half of
 * the requirement that is easy to satisfy on paper.
 *
 * `PolicySimulatorTest` proves the answer is right. This proves an operator can
 * get it, and that the wrong operator cannot: §19/40's failure mode is about
 * the person clicking through a dashboard, not the one with a shell, so a
 * simulator reachable only from a console command would satisfy the words and
 * miss the point.
 *
 * ## 🛑 Why the capability is its own, and why that needs a test
 *
 * Answering "as this identity" means naming the organisation's reader
 * identities and their reconciled groups (§8.13.7) — a membership list of
 * everybody who has ever signed in to the documentation, which §8.22.7
 * classifies `pseudonymous`. `project.view` is held by `project_reader`, whose
 * job is to read a project rather than to audit its readership. The two
 * questions have different blast radii and conflating them would make the
 * narrower role the wider one.
 */
final class PolicySimulatorRouteTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);

        $this->organisation = Organisation::query()->create([
            'name' => 'Simulator UI Co',
            'slug' => 'simui-'.bin2hex(random_bytes(3)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'slug' => 'handbook',
            'name' => 'Handbook',
            'visibility' => 'public',
        ]);

        $this->context->forget();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /** An operator reaches the page, and it renders before anything is asked. */
    public function test_an_operator_reaches_the_simulator(): void
    {
        $this->actingAs($this->member(Role::OrgAdmin))
            ->get($this->url())
            ->assertSuccessful()
            ->assertInertia(fn ($page) => $page
                ->component('Projects/PolicySimulator')
                /*
                 * 🛑 The form renders with no answer. A simulator that demanded
                 * inputs to show its own form is a simulator an operator meets
                 * as a validation error.
                 */
                ->where('answer', null)
                ->where('refused', null));
    }

    /**
     * 🛑 §8.12.25's sentence reaches the page: the verdict, the rule and the
     * binding.
     *
     * Asserted on the props rather than on rendered markup, because the props
     * are the contract between the controller and the page — and a markup
     * assertion would pass on a page that received the facts and printed none
     * of them.
     */
    public function test_the_answer_reaches_the_page(): void
    {
        $this->actingAs($this->member(Role::OrgAdmin))
            ->get($this->url(['host' => 'nothing-here.example.test', 'path' => '/en/v1/']))
            ->assertSuccessful()
            ->assertInertia(fn ($page) => $page
                ->component('Projects/PolicySimulator')
                ->has('answer')
                /*
                 * An unknown host resolves to nothing, and that is reported as
                 * unresolved rather than as a denial — see
                 * `PolicySimulatorTest`. The page gets the distinction.
                 */
                ->where('answer.resolved', false)
                ->where('asked.host', 'nothing-here.example.test'));
    }

    /**
     * 🛑 `policy-003`: a `project_reader` may not simulate.
     *
     * 404, never 403 — §8.2.2's rule, and here it costs nothing because
     * `abort_unless` on a project the route already bound is the same shape the
     * rest of the dashboard uses.
     */
    public function test_a_project_reader_may_not_simulate(): void
    {
        $this->actingAs($this->member(Role::ProjectReader, project: true))
            ->get($this->url())
            ->assertNotFound();
    }

    /** And neither may a writer, who can publish but not audit the readership. */
    public function test_a_project_writer_may_not_simulate(): void
    {
        $this->actingAs($this->member(Role::ProjectWriter, project: true))
            ->get($this->url())
            ->assertNotFound();
    }

    /** A maintainer may: §17's "an operator can prove what any identity may read". */
    public function test_a_project_maintainer_may_simulate(): void
    {
        $this->actingAs($this->member(Role::ProjectMaintainer, project: true))
            ->get($this->url())
            ->assertSuccessful();
    }

    /**
     * 🛑 An operator from another organisation gets a 404 from route binding
     * alone.
     *
     * No code does this: `{project}` resolves through §8.2.1's global scope, so
     * another tenant's project is simply not found. A 403 would require first
     * locating the row, and locating it is already the leak.
     */
    public function test_another_organisations_operator_cannot_reach_it(): void
    {
        $other = Organisation::query()->create([
            'name' => 'Globex',
            'slug' => 'globex-'.bin2hex(random_bytes(3)),
        ]);

        $outsider = $this->member(Role::OrgAdmin, organisation: $other);

        $this->actingAs($outsider)->get($this->url())->assertNotFound();
    }

    /**
     * 🛑 A simulation is recorded as an operator action.
     *
     * §8.22.4 asks for an event per state-changing action and this changes
     * nothing — it is audited because the *question* is sensitive. "Who can
     * read this" is what somebody asks before they exfiltrate, and §20.3's
     * chain is the only place that would show it was asked.
     */
    public function test_a_simulation_is_audited(): void
    {
        $before = DB::table('audit_events')->where('action', 'policy.simulated')->count();

        $this->actingAs($this->member(Role::OrgAdmin))
            ->get($this->url(['host' => 'nothing-here.example.test', 'path' => '/en/v1/']))
            ->assertSuccessful();

        $this->assertGreaterThan(
            $before,
            DB::table('audit_events')->where('action', 'policy.simulated')->count(),
        );
    }

    /** Nothing is audited for merely opening the page, which asks nothing. */
    public function test_opening_the_page_is_not_audited(): void
    {
        $before = DB::table('audit_events')->where('action', 'policy.simulated')->count();

        $this->actingAs($this->member(Role::OrgAdmin))->get($this->url())->assertSuccessful();

        $this->assertSame(
            $before,
            DB::table('audit_events')->where('action', 'policy.simulated')->count(),
        );
    }

    /** A malformed question is a validation error, not a wrong answer. */
    public function test_a_malformed_question_is_refused(): void
    {
        $this->actingAs($this->member(Role::OrgAdmin))
            ->get($this->url(['host' => 'docs.example.test', 'identity' => 'somebody-else']))
            ->assertSessionHasErrors('identity');
    }

    // ------------------------------------------------------------- fixtures

    /** @param  array<string, string>  $query */
    private function url(array $query = []): string
    {
        $url = '/o/'.$this->organisation->slug.'/projects/'.$this->project->slug.'/policy/simulate';

        return $query === [] ? $url : $url.'?'.http_build_query($query);
    }

    private function member(Role $role, bool $project = false, ?Organisation $organisation = null): User
    {
        $organisation ??= $this->organisation;

        $this->context->for($organisation->id);

        $user = User::factory()->create();

        $scopeType = $project ? 'project' : 'organisation';
        $scopeId = $project ? $this->project->id : $organisation->id;

        DB::table('role_assignments')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => $scopeType,
            'scope_id' => $scopeId,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->forget();

        return $user;
    }
}
