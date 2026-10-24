<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\OrganisationContext;
use App\Builds\BuildPipeline;
use App\Builds\BuildTrigger;
use App\Builds\FailureCatalogue;
use App\Builds\Runner\Spool;
use App\Models\BuildRequest;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tests\TestCase;

/**
 * §8.1.7's hosting-only mode and §8.5.10's fork policy — the two ways a
 * build is refused before anything runs.
 *
 * > §8.1.7: "The system MUST support a `hosting-only` mode
 * > (`DOCUP_BUILDS_ENABLED=false`) in which no repository code is executed
 * > anywhere … This is the single most important enterprise concession: it
 * > lets a security team adopt DocUp with the RCE surface removed."
 *
 * > §8.5.10: "Fork and pull-request builds MUST receive **no secrets at
 * > all** … Fork-PR builds MUST be **off by default** with an explicit
 * > opt-in and a written threat statement."
 *
 * 🛑 **Refused, never queued.** §17 is explicit that a trigger in
 * hosting-only mode is "refused with a stable identifier rather than queued
 * forever", and the reason is what an author sees: a request sitting in
 * `queued` on an installation that has deliberately removed its runner
 * looks exactly like a busy queue. Nothing distinguishes "we will never
 * build this" from "we have not built it yet" except saying so.
 *
 * No container runs in this file. Every refusal here happens before the
 * plan is resolved, which is the point of testing it.
 */
final class BuildAvailabilityTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private Component $component;

    protected function setUp(): void
    {
        parent::setUp();

        /*
         * 🛑 This file's subject is the two POLICY refusals, so it supplies
         * its own §8.5.12 verdict rather than depending on a runner having
         * written one. Without this the pipeline refuses every build with
         * `infra.sandbox_self_test_failed` before reaching the gate under
         * test — correct behaviour, and a precondition rather than a
         * result. The test that IS about the missing verdict overrides the
         * spool again, below.
         */
        config()->set('builds.spool', sys_get_temp_dir().'/docup-avail-'.bin2hex(random_bytes(6)));
        $spool = Spool::fromConfig();
        $spool->ensure();
        $spool->writeSelfTest(true, 'supplied by '.self::class);
        $this->app->instance(Spool::class, $spool);

        $context = app(OrganisationContext::class);
        $context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Availability Co',
            'slug' => 'avail-'.bin2hex(random_bytes(4)),
        ]);

        $context->for($this->organisation->id);

        $slug = 'avail-'.bin2hex(random_bytes(3));

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Availability',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $this->component = Component::query()->create([
            'key' => $slug,
            'name' => 'Availability',
            'min_access' => 'public',
        ]);

        $mount = new ComponentMount;
        $mount->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $this->version->id,
            'component_id' => $this->component->id,
            'mount_path' => '',
            'is_primary' => true,
            'min_access_snapshot' => 'public',
        ])->save();
    }

    /** 🛑 §8.1.7: builds off means refused, with an identifier an API can read. */
    public function test_a_trigger_is_refused_in_hosting_only_mode(): void
    {
        config()->set('builds.enabled', false);

        $request = $this->trigger();

        $this->assertNull(app(BuildPipeline::class)->run($request));

        $request->refresh();

        $this->assertSame('rejected', $request->state);
        $this->assertSame('rejected.builds_disabled', $request->outcome_identifier);
        $this->assertStringContainsString(
            'hosting-only',
            FailureCatalogue::message('rejected.builds_disabled'),
        );
    }

    /**
     * 🛑 ...and the direction that matters as much: with builds enabled the
     * refusal does not fire.
     *
     * A test that only proved the refusal would pass against an
     * installation that refused every build, which is the same defect
     * wearing a different hat. This one gets past the §8.1.7 gate and
     * stops at the next honest obstacle — no repository is attached — which
     * is a different identifier entirely.
     */
    public function test_the_same_trigger_passes_the_gate_with_builds_enabled(): void
    {
        config()->set('builds.enabled', true);

        $request = $this->trigger();
        app(BuildPipeline::class)->run($request);

        $request->refresh();

        $this->assertNotSame('rejected.builds_disabled', $request->outcome_identifier);
        $this->assertSame('rejected.no_repository_attached', $request->outcome_identifier);
    }

    /** 🛑 §8.5.10: a fork build is refused unless the project opted in. */
    public function test_a_fork_build_is_refused_by_default(): void
    {
        config()->set('builds.enabled', true);

        $request = $this->trigger();
        $request->forceFill(['from_fork' => true])->save();

        $this->assertFalse($this->project->fork_builds_enabled, '§8.5.10: off by default');

        app(BuildPipeline::class)->run($request);
        $request->refresh();

        $this->assertSame('rejected.fork_builds_disabled', $request->outcome_identifier);
    }

    /** ...and is allowed through the gate once the project has opted in. */
    public function test_a_fork_build_passes_the_gate_once_the_project_opts_in(): void
    {
        config()->set('builds.enabled', true);

        $this->project->forceFill(['fork_builds_enabled' => true])->save();

        $request = $this->trigger();
        $request->forceFill(['from_fork' => true])->save();

        app(BuildPipeline::class)->run($request);
        $request->refresh();

        $this->assertNotSame('rejected.fork_builds_disabled', $request->outcome_identifier);
    }

    /**
     * 🛑 §8.5.12's verdict gates the worker too.
     *
     * The runner refuses to *start* on a failed self-test; this is the
     * other half, in the process that has the database. Without it a build
     * triggered while the sandbox was broken would wait out its whole
     * timeout and report `infra.runner_did_not_answer` — true, and useless.
     */
    public function test_a_trigger_is_refused_when_the_sandbox_self_test_has_not_passed(): void
    {
        config()->set('builds.enabled', true);
        config()->set('builds.spool', sys_get_temp_dir().'/docup-no-selftest-'.bin2hex(random_bytes(6)));
        $this->app->instance(Spool::class, Spool::fromConfig());

        $request = $this->trigger();
        app(BuildPipeline::class)->run($request);

        $request->refresh();

        $this->assertSame('infra.sandbox_self_test_failed', $request->outcome_identifier);
    }

    private function trigger(): BuildRequest
    {
        return app(BuildTrigger::class)->record(
            version: $this->version,
            trigger: 'manual',
            componentId: $this->component->id,
        );
    }
}
