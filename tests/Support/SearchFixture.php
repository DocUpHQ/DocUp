<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Models\Build;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\RoutingSnapshotLoader;
use App\Serving\SnapshotMount;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;

/**
 * The project, version, domain and published artifact a §8.16 test needs.
 *
 * Extracted because six test files need the same seven-step setup and because
 * one of §8.16's exit criteria — a **reused build**, mounted by two projects —
 * cannot be built without a helper that can mount an existing build somewhere
 * else. Hiding that in each test would have hidden the interesting part.
 *
 * 🛑 This helper publishes through the real {@see Publisher}. It does not insert
 * a `builds` row or a manifest by hand, because the thing under test is partly
 * "what does the published manifest say" — and a fixture that wrote its own
 * manifest would agree with the indexer even when both were wrong. Phase 28's
 * `ExitCriteriaTest` makes the same choice and says so about the build id.
 */
final class SearchFixture
{
    public Organisation $organisation;

    public Project $project;

    public string $host;

    /** @var array<string, ProjectVersion> */
    public array $versions = [];

    private string $fixtures;

    public function __construct(
        private readonly OrganisationContext $context,
        private readonly string $label = 'search',
    ) {
        $this->fixtures = sys_get_temp_dir().'/docup-'.$this->label.'-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $slug = $this->label.'-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.self::docsApex();

        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Search Co',
            'slug' => $this->label.'-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Search Demo',
            'visibility' => 'public',
        ]);

        $this->domain($slug);
    }

    public function cleanUp(): void
    {
        $this->context->forget();

        foreach ((array) glob($this->fixtures.'/*') as $file) {
            if (is_string($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->fixtures);
    }

    /** A version, published or not, with the visibility the caller asks for. */
    public function version(string $slug, string $visibility = 'public', bool $listed = true, bool $active = true): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'release',
            'language' => 'en',
            'visibility' => $visibility,
            'listed' => $listed,
            'active' => $active,
            'ref_name' => $slug,
            'ref_kind' => 'tag',
        ])->save();

        $this->versions[$slug] = $version;

        return $version;
    }

    /**
     * Point §8.16.9's three channels at these versions.
     *
     * 🛑 The pointers, not "the newest version". §8.16.9 indexes `default`,
     * `stable` and `latest`, and §8.6.4 makes these columns what those words
     * mean — a test that relied on recency would pass against an indexer that
     * had the rule wrong.
     */
    public function channels(?ProjectVersion $default = null, ?ProjectVersion $stable = null, ?ProjectVersion $latest = null): void
    {
        $this->project->forceFill([
            'default_version_id' => $default?->id,
            'resolved_stable_version_id' => $stable?->id,
            'resolved_latest_version_id' => $latest?->id,
        ])->save();
    }

    /**
     * Publish a tree into a version, through the real publisher.
     *
     * @param  array<string, string>  $files  manifest paths to contents, e.g.
     *                                        `html/guide/index.html`
     */
    public function publish(ProjectVersion $version, array $files): void
    {
        $writer = new ArchiveWriter;

        foreach ($files as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz(
            $this->fixtures.'/'.$version->slug.'-'.bin2hex(random_bytes(3)).'.tar.gz',
        );

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($version, $archive);

        /*
         * Refreshed inside the context, for the reason Phase 28's fixture
         * records: `refresh()` reloads loaded relations and `project` is one,
         * which is a tenant-scoped query §8.2.1 refuses with nothing declared.
         */
        $version->refresh();
    }

    /**
     * Give a build §8.16.3's `search:` configuration, as the pipeline would.
     *
     * @param  array<string, mixed>  $search
     */
    public function searchConfig(ProjectVersion $version, array $search): void
    {
        DB::table('builds')
            ->where('id', Uuid::toBytes($this->buildIdOf($version)))
            ->update(['search_config' => json_encode($search)]);
    }

    /**
     * 🛑 Mount an **existing build** into another project's version — exit
     * criterion 5's whole subject.
     *
     * > "A reused build is indexed **once** and is searchable from every project
     * > that mounts it, with correct per-project URLs."
     *
     * Written against the published manifest's `mounts_json`, because that is
     * what §8.8.3 makes the authority for "which build does this version
     * publish" and what the indexer reads. A fixture that created a second
     * build would be testing something else entirely: two builds of identical
     * bytes are two document sets, and the criterion is about one.
     *
     * The `component_mounts` row is written too, because §8.16.6 reads
     * `min_access` from it — without one the scope has no component ceiling and
     * the test would pass for the wrong reason.
     */
    public function mountExistingBuild(
        ProjectVersion $version,
        string $buildIdText,
        string $mountPath = '',
        ?string $minAccess = null,
    ): void {
        $manifestId = Uuid::v7();
        $componentId = $this->degenerateComponentId();

        /*
         * 🛑 Replace the version's mounts rather than adding to them.
         * `component_mounts` is unique on `(project_version_id, component_id)`
         * and on `(project_version_id, primary_marker)`, so a version that has
         * already published its own build cannot also mount a second build of
         * the same component — correctly, because §8.7 mounts a component once
         * per version. This method says "this version now publishes exactly
         * this build", so the previous mount goes.
         */
        DB::table('component_mounts')->where('project_version_id', $version->id)->delete();

        DB::table('component_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $componentId,
            'mount_path' => $mountPath,
            'selector_kind' => 'pinned_build',
            'selector_value' => $buildIdText,
            'is_required' => true,
            'is_primary' => true,
            'min_access_snapshot' => $minAccess ?? 'public',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('project_version_manifests')->insert([
            'id' => $manifestId,
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            /*
             * 🛑 One past the highest. `project_version_manifests` is unique on
             * `(project_version_id, revision)` and §10.4 forbids updating a
             * manifest — "a change is a new revision" — so a version that has
             * already published cannot be given a second revision 1.
             */
            'revision' => $this->nextRevisionFor($version),
            'mounts_json' => json_encode([
                'mounts' => [[
                    'mount_path' => $mountPath,
                    'build_id' => $buildIdText,
                    'is_primary' => true,
                ]],
                'shadow_redirects' => [],
            ]),
            'created_at' => now(),
        ]);

        $version->forceFill([
            'published_manifest_id' => $manifestId,
            'published' => true,
        ])->save();
    }

    /**
     * 🛑 Compose several already-published builds into one version — exit
     * criterion 1's "three-source project".
     *
     * Written straight into the published manifest's `mounts_json`, because
     * §8.8.3 makes that the authority for what a version publishes and it is
     * what the indexer reads. Driving three real component builds through
     * Phase 13's composition planner would exercise Phase 13 rather than
     * §8.16, and the manifest it produced would be this same shape.
     *
     * @param  list<array{build: string, path: string, min_access?: string}>  $mounts
     */
    public function compose(ProjectVersion $version, array $mounts): void
    {
        $manifestId = Uuid::v7();
        $entries = [];

        /* The same replacement, and the same reason, as `mountExistingBuild()`. */
        DB::table('component_mounts')->where('project_version_id', $version->id)->delete();

        foreach ($mounts as $index => $mount) {
            $entries[] = [
                'mount_path' => $mount['path'],
                'build_id' => $mount['build'],
                'is_primary' => $index === 0,
            ];

            DB::table('component_mounts')->insert([
                'id' => Uuid::v7(),
                'organisation_id' => $this->organisation->id,
                'project_version_id' => $version->id,
                'component_id' => $this->componentFor($index),
                'mount_path' => $mount['path'],
                'selector_kind' => 'pinned_build',
                'selector_value' => $mount['build'],
                'is_required' => true,
                /*
                 * §8.7.19 allows one primary per version and the schema has a
                 * unique index on it, so only the first mount is primary — the
                 * same rule `Publisher` applies.
                 */
                'is_primary' => $index === 0,
                'min_access_snapshot' => $mount['min_access'] ?? 'public',
                'created_at' => now(),
                'updated_at' => now(),
            ]);
        }

        DB::table('project_version_manifests')->insert([
            'id' => $manifestId,
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            /*
             * 🛑 One past the highest. `project_version_manifests` is unique on
             * `(project_version_id, revision)` and §10.4 forbids updating a
             * manifest — "a change is a new revision" — so a version that has
             * already published cannot be given a second revision 1.
             */
            'revision' => $this->nextRevisionFor($version),
            'mounts_json' => json_encode(['mounts' => $entries, 'shadow_redirects' => []]),
            'created_at' => now(),
        ]);

        $version->forceFill([
            'published_manifest_id' => $manifestId,
            'published' => true,
        ])->save();
    }

    /**
     * A distinct component per mount.
     *
     * 🛑 `component_mounts` is unique on `(project_version_id, component_id)`,
     * so three mounts of one component cannot coexist in a version — correctly,
     * because §8.7 mounts a component once per version. A composed version is
     * three **components**, so the fixture creates three.
     */
    private function componentFor(int $index): string
    {
        if ($index === 0) {
            return $this->degenerateComponentId();
        }

        $id = Uuid::v7();

        DB::table('components')->insert([
            'id' => $id,
            'organisation_id' => $this->organisation->id,
            'key' => 'fixture-'.$index.'-'.bin2hex(random_bytes(3)),
            'name' => 'Fixture component '.$index,
            'min_access' => 'public',
            'state' => 'active',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    /** §10.4: a manifest is never updated, so each one is a new revision. */
    private function nextRevisionFor(ProjectVersion $version): int
    {
        $highest = DB::table('project_version_manifests')
            ->where('project_version_id', $version->id)
            ->max('revision');

        return is_numeric($highest) ? ((int) $highest) + 1 : 1;
    }

    /** The component every single-source publish creates (§8.7.1's degenerate one). */
    public function degenerateComponentId(): string
    {
        $id = DB::table('components')
            ->where('organisation_id', $this->organisation->id)
            ->value('id');

        Assert::assertIsString(
            $id,
            'the degenerate component does not exist until the first publish — publish before mounting',
        );

        return $id;
    }

    /**
     * The newest build of a version, as text.
     *
     * 🛑 Read from the `builds` row and not from the manifest, deliberately:
     * the indexer reads the manifest, so a fixture that read the manifest would
     * agree with the code under test even when both were wrong. Phase 28's
     * fixture makes and records the same choice.
     *
     * 🛑 Ordered by **`id`**, not by `created_at`, and that is Phase 28's
     * finding arriving here: two builds of one version created in the same
     * millisecond tie on `created_at`, so `orderByDesc('created_at')` returns
     * whichever the database felt like. A republish inside one test does
     * exactly that, and the symptom was this fixture reporting the same build
     * id before and after. `id` is a UUIDv7 and ADR 0006's whole premise is
     * that those are lexicographically time-ordered, so it breaks the tie.
     *
     * 🛑 And this is still not "which build does this version **publish**" —
     * that is `App\Addons\PublishedBuild`, through the manifest, and it differs
     * after a rollback (§8.8.5 flips the pointer to an older build and creates
     * no row). These tests never roll back; one that did would have to ask that
     * class, and the distinction is the one Phase 28 recorded.
     */
    public function buildIdOf(ProjectVersion $version): string
    {
        $build = Build::withoutGlobalScopes()
            ->where('project_version_id', $version->id)
            ->orderByDesc('id')
            ->firstOrFail();

        return Uuid::toText($build->id);
    }

    /** The resolved mount for this fixture's host, which is what a search takes. */
    public function mount(string $path = '/'): SnapshotMount
    {
        /** @var RoutingSnapshotLoader $loader */
        $loader = app(RoutingSnapshotLoader::class);

        $snapshot = $loader->load($this->host);
        $match = $snapshot->servable ? $snapshot->matchFor($path) : null;

        Assert::assertNotNull($match, 'the fixture host resolves to a mount');

        return $match->mount;
    }

    public static function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    /** A default subdomain and a canonical mount for the project. */
    private function domain(string $slug): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $slug.'.'.self::docsApex(),
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
