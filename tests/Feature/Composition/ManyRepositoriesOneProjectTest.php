<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Automation\AutomationEngine;
use App\Builds\Jobs\RunBuild;
use App\Builds\RepositoryFanout;
use App\Composition\Components;
use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;
use App\Composition\MirrorFallback;
use App\Composition\Mounts;
use App\Composition\SelectorKind;
use App\Models\Build;
use App\Models\BuildRequest;
use App\Models\Component;
use App\Models\ComponentSource;
use App\Models\ManifestLinkIssue;
use App\Models\MountResolution;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ProjectVersionManifest;
use App\Models\Repository;
use App\Support\Uuid;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Versions\VersionOperations;
use App\Webhooks\PushEvent;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 Phase 14's exit criteria: many repositories, one project.
 *
 * > "Three repositories (MkDocs, Sphinx, Docusaurus) serve as one navigable
 * > site on one domain with one version selector and one navigation tree
 * > arranged **by topic**, not by repository. Pushing to repository 2
 * > rebuilds only source 2. A deliberate `index.html` collision fails the
 * > build naming **both** sources and the exact path. The manifest answers
 * > which commit of which repository produced any URL. 🛑 A failed
 * > contributor build leaves the live composition **intact and serving**.
 * > 🛑 A cross-component link resolves, and one repository's broken
 * > reference is recorded as a link issue that does **not** fail the other
 * > repository's build. Project `v2.3` takes the glossary repository's
 * > `v2.0` via `mirror_label` + `newest_semver_lte`."
 *
 * 🛑 **"Arranged by topic, not by repository" is the assertion that decides
 * how the first test is written.** A composition that produced three
 * sections named after three repositories would satisfy every other clause
 * — one domain, one version selector, one tree — and would be the thing
 * §8.7.6 says is not a manual. So the test asserts the *order and the
 * labels* of the spliced tree against a layout the project wrote, and
 * asserts that a component's pages appear under a heading that is not the
 * component's name.
 */
final class ManyRepositoriesOneProjectTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Components $components;

    private Mounts $mounts;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-p14-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Three Repos Co',
            'slug' => 'three-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->components = new Components;
        $this->mounts = new Mounts;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    /**
     * 🛑 "Three repositories serve as one navigable site ... with one
     * navigation tree arranged **by topic**, not by repository."
     */
    public function test_three_repositories_serve_as_one_site_arranged_by_topic(): void
    {
        $site = $this->threeRepositorySite();
        $version = $site['version'];

        /** @var ProjectVersionManifest $manifest */
        $manifest = ProjectVersionManifest::query()
            ->whereKey($version->fresh()?->getRawOriginal('published_manifest_id'))
            ->firstOrFail();

        /** @var list<array<string, mixed>> $mounts */
        $mounts = $manifest->mounts_json['mounts'] ?? [];

        $this->assertCount(3, $mounts, 'three repositories, three mounts, one version');

        $paths = array_map(static fn (array $mount): string => (string) $mount['mount_path'], $mounts);
        sort($paths, SORT_STRING);

        $this->assertSame(['', 'glossary', 'reference'], $paths, 'disjoint prefixes, one of them the root');

        /*
         * 🛑 One navigation tree, arranged by the PROJECT's topics. The
         * layout below names "Start here" and "Looking things up"; neither
         * is a component key, and the glossary's own pages sit under the
         * second one. A tree arranged by repository would read
         * "handbook / reference / glossary", which is a directory.
         */
        $nav = $manifest->nav_json['nodes'] ?? [];

        $this->assertIsArray($nav);
        $this->assertCount(2, $nav);
        $this->assertSame('Start here', $nav[0]['label']);
        $this->assertSame('Looking things up', $nav[1]['label']);

        /*
         * 🛑 And every href carries its mount's prefix (§8.7.6: "spliced in
         * with that mount's prefix applied to every href"). Without this
         * the tree renders and every link in two of its three sections
         * 404s — which is the failure a structural assertion on labels
         * alone would miss.
         */
        $lookingUp = $nav[1]['children'] ?? [];

        $this->assertIsArray($lookingUp);
        $this->assertCount(2, $lookingUp, 'two repositories under one topic');

        $hrefs = array_map(static fn (array $child): string => (string) ($child['href'] ?? ''), $lookingUp);
        sort($hrefs, SORT_STRING);

        $this->assertSame(
            ['glossary/terms.html', 'reference/api.html'],
            $hrefs,
            'each spliced href carries ITS OWN mount prefix',
        );

        // One version selector: three components, one project version.
        $this->assertSame(
            1,
            ProjectVersion::query()->where('project_id', $version->project_id)->count(),
        );
    }

    /**
     * 🛑 "Pushing to repository 2 rebuilds only source 2."
     *
     * Three **separate** repositories this time, not one monorepo: Phase
     * 13's fan-out narrowed within a repository, and this is the claim
     * across them. Asserted on the enqueued job list, like Phase 13's,
     * because a build that runs and discards its output still satisfies
     * "the site did not change".
     */
    public function test_pushing_to_one_repository_rebuilds_only_that_source(): void
    {
        Queue::fake();

        $site = $this->threeRepositorySite();

        $outcome = $this->fanout()->dispatch(
            $site['repositories']['reference'],
            $this->push(['docs/api.md']),
        );

        $this->assertCount(1, $outcome->enqueued, 'one repository pushed, one build enqueued');
        Queue::assertPushed(RunBuild::class, 1);

        $this->assertSame(
            1,
            BuildRequest::query()->where('organisation_id', $this->organisation->id)->count(),
            'the other two repositories produce no request at all',
        );
    }

    /**
     * 🛑 "A deliberate `index.html` collision fails the build naming
     * **both** sources and the exact path."
     *
     * The collision is engineered the only way `mount` mode can produce
     * one: the primary at the root already serves `reference/index.html`,
     * and a second component is then mounted at `reference`. §8.7.15
     * refuses that at mount time; the override moves the question to
     * publish, where §8.7.14 sees both file manifests and refuses the
     * overlap — naming both components and the path.
     */
    public function test_a_deliberate_index_collision_names_both_sources_and_the_path(): void
    {
        $handbook = $this->makeComponent('handbook', AccessLevel::Public);
        $reference = $this->makeComponent('reference', AccessLevel::Public);

        $version = $this->publicVersion('manual');

        $this->mounts->attach($version, $handbook, '', isPrimary: true);
        $this->mounts->attach(
            $version,
            $reference,
            'reference',
            isPrimary: false,
            shadowingOverride: true,
        );

        // Both emit `reference/index.html` as the reader would request it:
        // the handbook's own `reference/index.html`, and the mounted
        // component's root `index.html` under the `reference` prefix.
        $this->buildFor($handbook, ['html/index.html', 'html/reference/index.html']);
        $this->buildFor($reference, ['html/index.html']);

        try {
            app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($handbook));
            $this->fail('§8.7.14 refuses an output path collision by default');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::PathCollision, $refused->rejection);

            // 🛑 All three, which is the whole of §8.7.14's sentence.
            $this->assertStringContainsString('reference/index.html', $refused->getMessage());
            $this->assertStringContainsString($handbook->key, $refused->getMessage());
            $this->assertStringContainsString($reference->key, $refused->getMessage());
        }

        $this->assertNull(
            $version->fresh()?->published_manifest_id,
            'a refused composition publishes nothing',
        );
    }

    /**
     * 🛑 "The manifest answers which commit of which repository produced
     * any URL."
     *
     * Answered from the stored manifest alone — no join, no build row —
     * because §10.4 lets a manifest outlive the builds it names and §8.7.21
     * makes this the auditor's answer years later.
     */
    public function test_the_manifest_answers_which_commit_produced_a_url(): void
    {
        $site = $this->threeRepositorySite();

        /** @var ProjectVersionManifest $manifest */
        $manifest = ProjectVersionManifest::query()
            ->whereKey($site['version']->fresh()?->getRawOriginal('published_manifest_id'))
            ->firstOrFail();

        /** @var list<array<string, mixed>> $mounts */
        $mounts = $manifest->mounts_json['mounts'] ?? [];
        $byPath = [];

        foreach ($mounts as $mount) {
            $byPath[(string) $mount['mount_path']] = $mount;
        }

        // A URL under `glossary/` is served by the glossary mount, and the
        // manifest row names its component, its ref and its commit.
        $glossary = $byPath['glossary'] ?? null;

        $this->assertIsArray($glossary);
        $this->assertSame($site['components']['glossary']->key, $glossary['component_key']);
        $this->assertSame('v2.0', $glossary['resolved_ref']);
        $this->assertSame(str_repeat('c', 40), $glossary['commit_sha']);
        $this->assertNotNull($glossary['build_id']);

        // §8.8.8's append-only record agrees with the manifest, which is
        // what makes the two usable as a cross-check rather than as one
        // answer written twice.
        $this->assertSame(
            3,
            MountResolution::query()->where('project_version_id', $site['version']->id)->count(),
            'one resolution row per mount, on every publish',
        );
    }

    /**
     * 🛑 "A failed contributor build leaves the live composition **intact
     * and serving**."
     *
     * The strong form: the glossary's newest build FAILS, the project
     * republishes, and the glossary mount still resolves to its previous
     * success. Asserting only "the old manifest is still pointed at" would
     * pass for an implementation that refused to publish at all, which is
     * not the same promise.
     */
    public function test_a_failed_contributor_build_leaves_the_composition_serving(): void
    {
        $site = $this->threeRepositorySite();
        $version = $site['version'];

        $servingBefore = $this->buildIdFor($version, 'glossary');
        $this->assertNotNull($servingBefore);

        // The glossary's next build fails. A failed build is not a selector
        // candidate, so nothing special has to happen for this to work —
        // which is the point of testing it.
        $failed = new Build;
        $failed->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $site['components']['glossary']->id,
            'content_key' => hash('sha256', 'failed-'.bin2hex(random_bytes(8))),
            'state' => 'failed',
            'failure_class' => 'user',
            'failure_identifier' => 'user.build_command_failed',
            'commit_sha' => str_repeat('f', 40),
            'finished_at' => now(),
        ])->save();

        /*
         * 🛑 Refreshed, so the republication is real. SPEC 8.8.4
         * compares against the pointer the caller captured; publishing from
         * a model loaded before the first publish loses that race and
         * leaves this test asserting that nothing happened.
         */
        $again = app(Publisher::class)->publishExistingBuild(
            $version->refresh(),
            $this->latestBuildOf($site['components']['handbook']),
        );

        $this->assertTrue($again->published, 'the project republished with one contributor failing');

        $this->assertSame(
            $servingBefore,
            $this->buildIdFor($version, 'glossary'),
            'the glossary keeps serving the build that succeeded',
        );

        $this->assertTrue(
            $version->fresh()?->published === true,
            'and the project published, rather than refusing because one contributor failed',
        );
    }

    /**
     * 🛑 "A cross-component link resolves, and one repository's broken
     * reference is recorded as a link issue that does **not** fail the
     * other repository's build."
     */
    public function test_a_cross_component_link_resolves_and_a_broken_one_is_only_recorded(): void
    {
        $site = $this->threeRepositorySite();
        $version = $site['version'];

        /** @var ProjectVersionManifest $manifest */
        $manifest = ProjectVersionManifest::query()
            ->whereKey($version->fresh()?->getRawOriginal('published_manifest_id'))
            ->firstOrFail();

        // The good half: the reference component's link to the glossary is
        // in the cross-reference map, pointing at where the glossary is
        // mounted in this composition.
        $xref = $manifest->xref_json['components'] ?? [];

        $this->assertIsArray($xref);
        $this->assertArrayHasKey($site['components']['glossary']->key, $xref);
        $this->assertSame('glossary', $xref[$site['components']['glossary']->key]['mount_path']);

        // 🛑 The bad half, and the clause that matters: the reference
        // build's broken reference is recorded, and the publish happened
        // anyway.
        $issues = ManifestLinkIssue::query()->where('manifest_id', $manifest->id)->get();

        $this->assertCount(1, $issues, 'one broken reference, one issue');

        $issue = $issues->first();

        $this->assertInstanceOf(ManifestLinkIssue::class, $issue);
        $this->assertSame('path_not_found', $issue->kind);
        $this->assertSame($site['components']['glossary']->key, $issue->target_component_key);
        $this->assertSame('missing-term.html', $issue->target_path);

        $this->assertTrue($version->fresh()?->published === true, 'and the version published');

        // 🛑 And the OTHER repository's build is untouched: not failed, not
        // marked, still the one being served.
        $glossaryBuild = $this->latestBuildOf($site['components']['glossary']);

        $this->assertSame('published', $glossaryBuild->state);
    }

    /**
     * 🛑 "Project `v2.3` takes the glossary repository's `v2.0` via
     * `mirror_label` + `newest_semver_lte`."
     *
     * §8.7.5's worked example, verbatim. The glossary has `v1.0` and
     * `v2.0` and no `v2.3`; the project version is `v2.3`; the answer must
     * be `v2.0` and not `v1.0`, and the resolution row must say it came
     * from the fallback rather than from an exact match.
     */
    public function test_a_version_takes_the_highest_component_label_at_or_below_it(): void
    {
        $glossary = $this->makeComponent('glossary', AccessLevel::Public);
        $this->components->attachSource(
            $glossary,
            $this->repository('https://github.com/docup/glossary.git', '9001'),
            'docs',
        );

        $this->buildFor($glossary, ['html/index.html'], ref: 'v1.0', commit: str_repeat('1', 40));
        $this->buildFor($glossary, ['html/index.html'], ref: 'v2.0', commit: str_repeat('2', 40));

        // A later build of a HIGHER label, so "newest" and
        // "newest_semver_lte" give different answers and the test can tell
        // which one ran.
        $this->buildFor($glossary, ['html/index.html'], ref: 'v3.0', commit: str_repeat('3', 40));

        $version = $this->publicVersion('manual', slug: 'v2.3');
        $this->mounts->attach(
            $version,
            $glossary,
            '',
            isPrimary: true,
            selector: SelectorKind::MirrorLabel,
            mirrorFallback: MirrorFallback::NewestSemverLte,
        );

        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($glossary));

        /** @var MountResolution $resolution */
        $resolution = MountResolution::query()
            ->where('project_version_id', $version->id)
            ->orderByDesc('created_at')
            ->firstOrFail();

        $this->assertSame('v2.0', $resolution->resolved_ref, 'the highest label at or below 2.3');
        $this->assertSame(str_repeat('2', 40), $resolution->resolved_commit_sha);
        $this->assertSame('fallback_semver_lte', $resolution->outcome->value);
    }

    /**
     * 🛑 §8.7.15's refusal, which is what makes the override above explicit.
     */
    public function test_a_mount_path_that_shadows_another_is_refused_by_default(): void
    {
        $handbook = $this->makeComponent('handbook', AccessLevel::Public);
        $deep = $this->makeComponent('deep', AccessLevel::Public);
        $other = $this->makeComponent('other', AccessLevel::Public);

        $version = $this->publicVersion('manual');

        $this->mounts->attach($version, $handbook, '', isPrimary: true);
        $this->mounts->attach($version, $deep, 'guide', isPrimary: false);

        try {
            $this->mounts->attach($version, $other, 'guide/advanced', isPrimary: false);
            $this->fail('§8.7.15 refuses a mount path prefixed by an existing one');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::MountPathShadows, $refused->rejection);
        }

        // 🛑 And the root is NOT a shadow: §8.7.3 requires one mount there
        // and §8.7.12 resolves by longest prefix, so every deeper mount is
        // a deliberate narrowing of it rather than a collision with it.
        // `guide` above was accepted beside the root, which is that rule.
        $this->assertSame(2, $version->mounts()->count());
    }

    // ---------------------------------------------------------------- setup

    /**
     * Three repositories, three components, one project version.
     *
     * The shape the exit criterion describes: a handbook at the root, a
     * reference at `reference`, a glossary at `glossary`, each from its own
     * repository, composed by a layout tree that arranges them by topic.
     *
     * @return array{version: ProjectVersion, components: array<string, Component>, repositories: array<string, Repository>}
     */
    private function threeRepositorySite(): array
    {
        $repositories = [
            'handbook' => $this->repository('https://github.com/docup/handbook.git', '101'),
            'reference' => $this->repository('https://github.com/docup/reference.git', '102'),
            'glossary' => $this->repository('https://github.com/docup/glossary.git', '103'),
        ];

        $components = [];

        foreach ($repositories as $key => $repository) {
            $components[$key] = $this->makeComponent($key, AccessLevel::Public);
            $this->components->attachSource($components[$key], $repository, 'docs');
        }

        $version = $this->publicVersion('manual', tracking: 'main');

        /*
         * 🛑 §8.7.6's layout tree, written by the PROJECT. Neither heading
         * is a component key, and the `{include:}` placeholders are what
         * put a repository's pages under a topic somebody else chose.
         */
        $version->forceFill([
            'layout_json' => [
                [
                    'label' => 'Start here',
                    'children' => [
                        ['include' => $components['handbook']->key],
                    ],
                ],
                [
                    'label' => 'Looking things up',
                    'children' => [
                        ['include' => $components['reference']->key],
                        ['include' => $components['glossary']->key],
                    ],
                ],
            ],
        ])->save();

        $this->mounts->attach($version, $components['handbook'], '', isPrimary: true);
        $this->mounts->attach($version, $components['reference'], 'reference', isPrimary: false);
        $this->mounts->attach($version, $components['glossary'], 'glossary', isPrimary: false);

        $this->buildFor(
            $components['handbook'],
            ['html/index.html', 'html/welcome.html'],
            ref: 'main',
            commit: str_repeat('a', 40),
            nav: [['label' => 'Welcome', 'href' => 'welcome.html']],
        );

        /*
         * 🛑 The reference's build carries TWO cross-references: one that
         * resolves and one that does not. §8.7.16's clause is about the
         * second not breaking the first, so both have to be present in one
         * build.
         */
        $this->buildFor(
            $components['reference'],
            ['html/index.html', 'html/api.html'],
            ref: 'main',
            commit: str_repeat('b', 40),
            nav: [['label' => 'API', 'href' => 'api.html']],
            references: [
                ['component' => $components['glossary']->key, 'path' => 'terms.html', 'source' => 'api.html'],
                ['component' => $components['glossary']->key, 'path' => 'missing-term.html', 'source' => 'api.html'],
            ],
        );

        $this->buildFor(
            $components['glossary'],
            ['html/index.html', 'html/terms.html'],
            ref: 'v2.0',
            commit: str_repeat('c', 40),
            nav: [['label' => 'Terms', 'href' => 'terms.html']],
        );

        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($components['handbook']));

        return ['version' => $version, 'components' => $components, 'repositories' => $repositories];
    }

    private function makeComponent(string $key, AccessLevel $minAccess): Component
    {
        return $this->components->register(
            organisationId: $this->organisation->id,
            key: $key.'-'.bin2hex(random_bytes(3)),
            name: ucfirst($key),
            minAccess: $minAccess,
        );
    }

    /**
     * @param  string|null  $tracking  the ref this version follows, or null.
     *                                 Null is what keeps the throwaway versions
     *                                 {@see self::buildFor()} creates out of the
     *                                 fan-out: they exist to produce a build, not to
     *                                 be rebuilt by a push.
     */
    private function publicVersion(
        string $name,
        string $slug = 'latest',
        ?string $tracking = null,
    ): ProjectVersion {
        $project = Project::query()->create([
            'slug' => $name.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($name),
            'visibility' => 'public',
            'preview_policy' => 'all_dependent_versions',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => $tracking,
            'ref_kind' => $tracking === null ? null : 'branch',
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        return $version;
    }

    /**
     * A real, ingested, successful build of one component.
     *
     * 🛑 Goes through the real {@see Publisher}, on a throwaway version of
     * its own, so the artifact is validated by the one `ArtifactIngestor`
     * and the file manifest the composition reads is the real one. A build
     * row with a hand-written manifest would let the collision and
     * link-issue tests pass against a shape the ingestor would refuse.
     *
     * @param  list<string>  $paths  manifest paths this build serves
     * @param  list<array{label: string, href: string}>  $nav  §8.7.6's fragment
     * @param  list<array{component: string, path: string, source: string}>  $references
     */
    private function buildFor(
        Component $component,
        array $paths,
        string $ref = 'main',
        ?string $commit = null,
        array $nav = [],
        array $references = [],
    ): Build {
        $staging = $this->publicVersion('staging');
        $this->mounts->attach($staging, $component, '', isPrimary: true);

        $writer = new ArchiveWriter;

        foreach ($paths as $path) {
            $writer->add($path, "<!doctype html><html><head></head><body>{$path}</body></html>\n");
        }

        $archive = $writer->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz');

        $outcome = app(Publisher::class)->publishUpload($staging, $archive);
        $build = $outcome->build;

        $this->assertInstanceOf(Build::class, $build);

        $build->forceFill([
            'commit_sha' => $commit ?? str_repeat('0', 40),
            'nav_json' => $nav === [] ? null : $nav,
            'cross_references' => $references === []
                ? null
                : ['schema' => 'docup.cross-references/1', 'dropped' => 0, 'references' => $references],
        ])->save();

        DB::table('build_sources')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'build_id' => $build->id,
            'repository_id' => $this->repositoryIdFor($component),
            'component_source_id' => $this->sourceIdFor($component),
            'ref' => $ref,
            'commit_sha' => $commit ?? str_repeat('0', 40),
            'source_path' => 'docs',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $build;
    }

    private function latestBuildOf(Component $component): Build
    {
        /** @var Build */
        return Build::query()
            ->where('component_id', $component->id)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->orderByDesc('finished_at')
            ->orderByDesc('id')
            ->firstOrFail();
    }

    /** The build a published manifest names for one mount path. */
    private function buildIdFor(ProjectVersion $version, string $mountPath): ?string
    {
        $manifestId = $version->fresh()?->getRawOriginal('published_manifest_id');

        if (! is_string($manifestId)) {
            return null;
        }

        /** @var ProjectVersionManifest|null $manifest */
        $manifest = ProjectVersionManifest::query()->whereKey($manifestId)->first();

        return $manifest?->buildIdForMount($mountPath);
    }

    /** @return string raw 16 bytes */
    private function repositoryIdFor(Component $component): string
    {
        $source = $component->sources()->first();

        if ($source instanceof ComponentSource) {
            return $source->repository_id;
        }

        return $this->repository(
            'https://github.com/docup/x-'.bin2hex(random_bytes(3)).'.git',
            (string) random_int(1000, 9999),
        )->id;
    }

    /** @return string|null raw 16 bytes */
    private function sourceIdFor(Component $component): ?string
    {
        return $component->sources()->first()?->id;
    }

    private function repository(string $cloneUrl, string $providerRepoId): Repository
    {
        $repository = new Repository;

        $repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => $cloneUrl,
            'normalised_url' => str_replace('.git', '', $cloneUrl),
            'default_branch' => 'main',
            'provider_repo_id' => $providerRepoId.'-'.bin2hex(random_bytes(3)),
        ])->save();

        return $repository;
    }

    private function fanout(): RepositoryFanout
    {
        return new RepositoryFanout(
            app(RefSync::class),
            new AutomationEngine(app(VersionOperations::class)),
        );
    }

    /** @param  list<string>  $paths */
    private function push(array $paths): PushEvent
    {
        return new PushEvent(
            deliveryId: 'd-'.bin2hex(random_bytes(4)),
            event: 'push',
            repositoryIdentifier: null,
            refName: 'main',
            refKind: RefKind::Branch,
            commitSha: str_repeat('b', 40),
            changedPaths: $paths,
            commitMessages: ['docs: update'],
            payloadTruncated: false,
        );
    }
}
