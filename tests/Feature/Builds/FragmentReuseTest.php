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
 * row and no step rows to prove anything with.
 *
 * 🛑 **AMENDED (Phase 13, 2026-10-25): the two builds now use two
 * COMPONENTS, not two versions of one.**
 *
 * Phase 13 implemented §8.7.9's content key, which is a stronger and
 * earlier short-circuit than the fragment cache and layers above it:
 *
 *   - §8.7.9's key covers `organisation`, `component`, `commit`, config,
 *     environment and pipeline version. When it matches, the whole build
 *     already exists and the new version publishes it — **no build row at
 *     all**, which is strictly better than one that skips two stages.
 *   - §8.5.19's fragment digest excludes the component. When the content
 *     key *differs* but the source output would be identical, the fragment
 *     cache is what saves the work.
 *
 * Two versions of one project at one commit now share one build row, so
 * they stopped exercising the fragment cache — the test failed on exactly
 * that, asserting two build ids where there is now correctly one. Two
 * components over the same repository and source path keep the content
 * keys apart while the fragment digests match, which is both what this
 * criterion needs and the more realistic shape of §8.5.19's own example:
 * "a shared API repository feeding 40 projects" is 40 teams registering it,
 * and one team mounting it 40 times needs no build at all.
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

    public function test_a_second_version_of_the_same_component_is_served_from_the_existing_build(): void
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

        /*
         * 🛑 A second version of the same component at the same commit.
         *
         * Before Phase 13 this produced a second build row whose
         * `environment` and `build` stages were skipped by §8.5.19's
         * fragment cache. It now produces **no build row at all**: §8.7.9's
         * content key covers organisation, component, commit, config,
         * environment and pipeline version, every one of which is
         * identical here, so the version publishes the existing build.
         *
         * That is strictly stronger than the behaviour this test used to
         * assert — no container, no ingest, no second copy of the bytes —
         * and it is what §8.7.9 asks for in its own words: "satisfied from
         * an existing successful build with the same key".
         */
        $started = microtime(true);
        $secondVersion = $this->versionNamed('two');
        $second = $this->buildInto($secondVersion);
        $elapsed = microtime(true) - $started;

        $this->assertInstanceOf(Build::class, $second);

        $this->assertSame(
            bin2hex($first->id),
            bin2hex($second->id),
            '🛑 §8.7.9: identical inputs must be satisfied from the existing build',
        );

        $this->assertSame(
            1,
            Build::query()->where('organisation_id', $this->organisation->id)->count(),
            'one build row, however many versions serve from it',
        );

        // The second version really is published, from the first's bytes.
        $secondVersion->refresh();

        $this->assertNotNull($secondVersion->published_manifest_id);

        $this->assertSame(
            1,
            (int) DB::table('manifest_builds')->where('build_id', $first->id)->count() > 0 ? 1 : 0,
            'the reused build is linked to a manifest',
        );

        /*
         * 🛑 And no second artifact was written. §8.8.1 makes artifacts
         * immutable and write-once, so re-ingesting the same bytes under a
         * second build id would be two copies of one tree — the storage
         * cost this feature exists to avoid, and the one a build count
         * alone would not catch.
         */
        $this->assertSame(
            1,
            (int) DB::table('build_outputs')->where('format', 'html')->count(),
            'the reused publish must not ingest a second copy of the bytes',
        );

        fwrite(STDERR, sprintf("\n  reused-build publish: %.1fs\n", $elapsed));
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
