<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\OrganisationContext;
use App\Builds\BuildPipeline;
use App\Builds\BuildTrigger;
use App\Builds\Stage;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Source\Provider;
use App\Source\RepositoryConnector;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 Phase 09's fourth exit criterion: "**A second identical build hits the
 * fragment cache and skips the build stage, proven by step rows.**"
 *
 * 🛑 **Two versions, not two triggers of one version**, and the difference
 * is what makes this a test of the fragment cache at all. §8.5.2's
 * short-circuit already catches a repeat trigger of the same version — its
 * `plan_digest` includes the version id — and that path produces no build
 * row and no step rows to prove anything with. The fragment digest excludes
 * the version by design (§8.5.19 keys on source, environment, configuration
 * and public variables), so two *different* versions of the same component
 * at the same commit are exactly the case it exists for: "this is what makes
 * a shared API repository feeding 40 projects affordable".
 *
 * Runs in the `runner` container, because the first of the two builds is
 * real.
 */
final class FragmentReuseTest extends TestCase
{
    use DatabaseTransactions;

    private const REPOSITORY = 'https://github.com/mkdocs/mkdocs';

    private const SOURCE_PATH = 'mkdocs/tests/integration/subpages';

    private Organisation $organisation;

    private Project $project;

    private Component $component;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Fragment Reuse Co',
            'slug' => 'reuse-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'reuse-'.bin2hex(random_bytes(3)),
            'name' => 'Reused',
            'visibility' => 'public',
        ]);

        $this->component = Component::query()->create([
            'key' => 'reuse-'.bin2hex(random_bytes(3)),
            'name' => 'Reused',
            'min_access' => 'public',
        ]);
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    public function test_a_second_version_of_the_same_source_is_served_from_the_fragment_cache(): void
    {
        $this->requireRunner();

        $connector = app(RepositoryConnector::class);

        $repository = $connector->connect(
            organisationId: $this->organisation->id,
            url: self::REPOSITORY,
            provider: Provider::GitHub,
            providerRepoId: '20580498',
        );

        $repository->forceFill(['default_branch' => 'master'])->save();
        $connector->attach($repository, $this->component, self::SOURCE_PATH);

        $first = $this->buildInto($this->versionNamed('one'));

        if (! $first instanceof Build || $first->state !== 'published') {
            $this->reportOrSkip('the first build did not publish, so there is no fragment to reuse');
        }

        $this->assertDatabaseHas('build_fragments', ['build_id' => $first->id, 'was_hit' => false]);

        // -------------------------------------------- the second version

        $started = microtime(true);
        $second = $this->buildInto($this->versionNamed('two'));
        $elapsed = microtime(true) - $started;

        $this->assertInstanceOf(Build::class, $second);
        $this->assertNotSame(bin2hex($first->id), bin2hex($second->id), 'the second build reused the first build row');
        $this->assertContains($second->state, ['published', 'success_unpublished']);

        /*
         * 🛑 "proven by step rows". Both stages skipped, both with the
         * reason that names the cause — a `skipped` with no reason would be
         * indistinguishable from the stage simply having had nothing to do,
         * which is what `skipped.nothing_to_install` means on a cold build.
         */
        $reasons = [];

        foreach ($second->steps()->get() as $step) {
            $reasons[$step->stage->value] = [$step->state, $step->failure_identifier];
        }

        $this->assertSame(
            ['skipped', 'skipped.fragment_cache_hit'],
            $reasons[Stage::Environment->value] ?? null,
            '§8.5.19: a cache hit skips the environment stage',
        );

        $this->assertSame(
            ['skipped', 'skipped.fragment_cache_hit'],
            $reasons[Stage::Build->value] ?? null,
            '🛑 §8.5.19: a cache hit skips the build stage entirely',
        );

        // ...and the second record, which the step rows alone cannot give:
        // the skip was a HIT rather than a stage with nothing to do.
        $this->assertDatabaseHas('build_fragments', ['build_id' => $second->id, 'was_hit' => true]);

        $this->assertSame(
            1,
            (int) DB::table('fragments')->where('repository_id', $repository->id)->value('refcount'),
        );

        // The published output is real: `collect`, `store` and `publish`
        // still ran, because this version needs its own artifacts.
        $this->assertSame('succeeded', $second->steps()->where('stage', Stage::Store->value)->value('state'));
        $this->assertGreaterThan(0, (int) $second->file_count);

        fwrite(STDERR, sprintf("\n  fragment-cache build: %.1fs\n", $elapsed));
    }

    /**
     * 🛑 The application zone, and nowhere else.
     *
     * The same guard {@see EndToEndBuildTest} uses and for the same reason:
     * this test needs BOTH halves of §11.2 — the spool to reach the runner,
     * and the database to record two builds. The runner container has the
     * first and deliberately not the second, so running the suite there
     * must skip this rather than fail on a connection timeout that reads
     * like a broken pipeline.
     */
    private function requireRunner(): void
    {
        $spool = (string) config('builds.spool');

        if (! is_dir($spool) || ! is_writable($spool)) {
            $this->markTestSkipped('no runner spool at '.$spool.'; start the `runner` service');
        }

        if (! is_string(config('app.key')) || config('app.key') === '') {
            $this->markTestSkipped('no APP_KEY: run this in the `app` container, not the runner (§11.2)');
        }
    }

    /** 🛑 A skip is not a pass, and `DOCUP_E2E=1` is what says so. */
    private function reportOrSkip(string $reason): never
    {
        if (getenv('DOCUP_E2E') === '1') {
            $this->fail($reason);
        }

        $this->markTestSkipped($reason);
    }

    private function versionNamed(string $slug): ProjectVersion
    {
        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'release',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        return $version;
    }

    private function buildInto(ProjectVersion $version): ?Build
    {
        $request = app(BuildTrigger::class)->record(
            version: $version,
            trigger: 'manual',
            componentId: $this->component->id,
        );

        return app(BuildPipeline::class)->run($request, waitSeconds: 180);
    }
}
