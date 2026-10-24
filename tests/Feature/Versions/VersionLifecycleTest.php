<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Versions;

use App\Artifacts\ArtifactStore;
use App\Artifacts\FileManifest;
use App\Auth\OrganisationContext;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use App\Versions\ChannelResolver;
use App\Versions\PageExistence;
use App\Versions\TranslationGroup;
use App\Versions\VersionOperations;
use App\Versions\VersionRefused;
use App\Versions\VersionRejection;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * §8.6.7's bulk operations and wipe, §8.6.12's translations, and §8.6.14's
 * pointer — the §17 deliverables that are neither an exit criterion nor a
 * routing question.
 */
final class VersionLifecycleTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private Component $component;

    private VersionOperations $operations;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Lifecycle Co',
            'slug' => 'life-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'life-'.bin2hex(random_bytes(3)),
            'name' => 'Lifecycle',
            'visibility' => 'public',
        ]);

        $this->component = Component::query()->create([
            'key' => 'life-'.bin2hex(random_bytes(3)),
            'name' => 'Lifecycle',
            'min_access' => 'public',
        ]);

        $this->operations = app(VersionOperations::class);
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    // ------------------------------------------------------------- §8.6.7

    public function test_bulk_deactivation_changes_only_what_was_active(): void
    {
        $one = $this->version('v1', active: true);
        $two = $this->version('v2', active: true);
        $already = $this->version('v3', active: false);

        $changed = $this->operations->setActive([$one, $two, $already], false);

        $this->assertSame(2, $changed, 'the already-inactive version is not a change');
        $this->assertFalse($one->fresh()?->active);
        $this->assertFalse($two->fresh()?->active);
    }

    /**
     * 🛑 One audit event per version, not one for the batch.
     *
     * An operator deactivating forty versions has made forty decisions a
     * reader will notice; a single `bulk_deactivate (40)` answers "how
     * many" and not "which".
     */
    public function test_each_version_in_a_bulk_operation_is_audited_separately(): void
    {
        $versions = [$this->version('v1'), $this->version('v2'), $this->version('v3')];

        $before = DB::table('audit_events')->where('action', 'version.deactivated')->count();

        $this->operations->setActive($versions, false);

        $this->assertSame(
            $before + 3,
            DB::table('audit_events')->where('action', 'version.deactivated')->count(),
        );
    }

    /**
     * §8.6.7's wipe: "discards artifacts while **retaining the version
     * row**".
     *
     * 🛑 The row is the difference from a delete, and it is a reader's
     * difference: a deleted version's URLs resolve to nothing, a wiped
     * version's to a 404 that §8.11.5's chain can answer with the default
     * version's own `404.html`.
     */
    public function test_a_wipe_discards_the_artifacts_and_keeps_the_row(): void
    {
        $version = $this->version('v1');
        $build = $this->publishedBuild($version);

        $store = app(ArtifactStore::class);
        $store->put($store->keyFor($build->id, 'html/index.html'), '<!doctype html>');

        $this->assertNotSame([], $store->list($store->prefixFor($build->id)));

        $discarded = $this->operations->wipe($version);

        $this->assertSame(1, $discarded);
        $this->assertSame([], $store->list($store->prefixFor($build->id)), 'the bytes are gone');

        $kept = $version->fresh();

        $this->assertInstanceOf(ProjectVersion::class, $kept, '🛑 and the row is not');
        $this->assertNotNull($kept->wiped_at);
        $this->assertFalse($kept->published, 'the pointer is cleared before the bytes go');
        $this->assertNull($kept->published_manifest_id);
    }

    // ------------------------------------------------------------ §8.6.14

    /**
     * 🛑 "The pointer ... MUST be re-pointed automatically with an audit
     * event when its target is deleted or deactivated."
     */
    public function test_deactivating_the_default_version_repoints_it_and_audits(): void
    {
        $main = $this->version('main', refName: 'main', refKind: 'branch');
        $release = $this->version('v2.0.0', refName: 'v2.0.0', refKind: 'tag');

        $this->project->forceFill(['default_version_id' => $release->id])->save();

        app(ChannelResolver::class)->reconcile($this->project, [$main, $release], 'main');

        $before = DB::table('audit_events')->where('action', 'version.default_repointed')->count();

        $this->operations->setActive([$release], false);

        $project = $this->project->fresh();

        $this->assertInstanceOf(Project::class, $project);
        $this->assertNotSame($release->id, $project->default_version_id, 'the pointer moved');
        $this->assertSame($main->id, $project->default_version_id, '§8.6.14 falls back to latest');

        $this->assertSame(
            $before + 1,
            DB::table('audit_events')->where('action', 'version.default_repointed')->count(),
            '🛑 §8.6.14 asks for the audit event by name',
        );
    }

    /**
     * 🛑 The fallback order does NOT end in "the first row".
     *
     * A project with no servable channel has no default, and `/` 404s
     * rather than redirecting somewhere arbitrary — an arbitrary redirect
     * is a URL readers bookmark that changes meaning next time a version is
     * created.
     */
    public function test_a_project_with_no_channel_has_no_default(): void
    {
        $only = $this->version('feature-login', refName: 'feature-login', refKind: 'branch');

        $this->project->forceFill(['default_version_id' => $only->id])->save();

        $channels = app(ChannelResolver::class)->reconcile($this->project, [$only], 'main');

        $this->assertNull($channels->stable);
        $this->assertNull($channels->latest, 'the default branch has no version');

        $this->operations->setActive([$only], false);

        $this->assertNull($this->project->fresh()?->default_version_id);
    }

    /** A default that is still active is left alone. */
    public function test_a_live_default_is_not_repointed(): void
    {
        $main = $this->version('main', refName: 'main', refKind: 'branch');
        $other = $this->version('v1.0.0', refName: 'v1.0.0', refKind: 'tag');

        $this->project->forceFill(['default_version_id' => $main->id])->save();

        $this->operations->setActive([$other], false);

        $this->assertSame($main->id, $this->project->fresh()?->default_version_id);
    }

    // ------------------------------------------------------------ §8.6.12

    /**
     * 🛑 "Language MUST be a property of a project version with a
     * `translation_group_id`, **not** a sibling project."
     */
    public function test_translations_are_versions_of_one_project(): void
    {
        $english = $this->version('v2', language: 'en');
        $japanese = $this->version('v2', language: 'ja');

        $groups = app(TranslationGroup::class);
        $group = $groups->group([$english, $japanese]);

        $this->assertSame($group, $english->fresh()?->translation_group_id);
        $this->assertSame($group, $japanese->fresh()?->translation_group_id);

        // 🛑 Two rows sharing a slug, which §10.4's unique key permits by
        // design: `UNIQUE (project_id, language, slug)`.
        $this->assertSame('v2', $english->slug);
        $this->assertSame('v2', $japanese->slug);

        $this->assertSame(
            'ja',
            $groups->inLanguage($this->reload($english), 'ja')?->language,
        );

        $this->assertSame(['en', 'ja'], $groups->languagesOf($this->project->id));
    }

    /** A third language joins the existing group rather than renumbering it. */
    public function test_adding_a_language_keeps_the_existing_group(): void
    {
        $english = $this->version('v2', language: 'en');
        $japanese = $this->version('v2', language: 'ja');

        $groups = app(TranslationGroup::class);
        $group = $groups->group([$english, $japanese]);

        $french = $this->version('v2', language: 'fr');

        $this->assertSame($group, $groups->group([$english->fresh() ?? $english, $french]));
        $this->assertSame($group, $french->fresh()?->translation_group_id);
    }

    /** 🛑 One version per language, or the switcher is ambiguous. */
    public function test_two_versions_in_one_language_cannot_be_translations(): void
    {
        $one = $this->version('v1', language: 'en');
        $two = $this->version('v2', language: 'en');

        try {
            app(TranslationGroup::class)->group([$one, $two]);
            $this->fail('two English versions were grouped as translations');
        } catch (VersionRefused $refused) {
            $this->assertSame(VersionRejection::DuplicateLanguageInGroup, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.6.13: "never a silent fallback to another language."
     *
     * `inLanguage()` returns null for a language the group does not hold,
     * so a caller cannot accidentally serve French to somebody who asked
     * for Japanese.
     */
    public function test_a_language_the_group_does_not_hold_is_null_rather_than_a_fallback(): void
    {
        $english = $this->version('v2', language: 'en');
        $french = $this->version('v2', language: 'fr');

        $groups = app(TranslationGroup::class);
        $groups->group([$english, $french]);

        $this->assertNull($groups->inLanguage($english->fresh() ?? $english, 'ja'));
    }

    // ------------------------------------------------------------ §8.6.11

    /**
     * 🛑 §8.6.11: "when a reader switches version and the page is absent,
     * the flyout MUST say so **from the per-build file manifest** rather
     * than delivering a bare 404."
     *
     * Answered without fetching anything: the manifest is already loaded
     * for the version being served, and the value of the answer is that it
     * is available before the reader clicks. A flyout that probed each
     * version would cost one request per version, on every page load, for
     * a question nobody has asked yet.
     */
    public function test_cross_version_page_existence_is_answered_from_the_manifest(): void
    {
        $withPage = $this->version('v2');
        $withoutPage = $this->version('v1');

        $this->publishWithFiles($withPage, ['html/index.html', 'html/guide/auth.html']);
        $this->publishWithFiles($withoutPage, ['html/index.html']);

        $existence = app(PageExistence::class);

        $this->assertTrue($existence->inVersion($withPage->fresh() ?? $withPage, 'html/guide/auth.html'));
        $this->assertFalse($existence->inVersion($withoutPage->fresh() ?? $withoutPage, 'html/guide/auth.html'));

        $answers = $existence->across(
            [$withPage->fresh() ?? $withPage, $withoutPage->fresh() ?? $withoutPage],
            'html/guide/auth.html',
        );

        $this->assertTrue($answers[bin2hex($withPage->id)]);
        $this->assertFalse($answers[bin2hex($withoutPage->id)]);
    }

    /**
     * 🛑 A version with nothing published answers `false`, not "unknown".
     *
     * The three-state answer is tempting and useless: a flyout saying "may
     * or may not exist" has told the reader nothing, and the honest
     * statement about a version with no manifest is that the page is not
     * there — because it is not.
     */
    public function test_a_version_with_nothing_published_does_not_hold_the_page(): void
    {
        $unpublished = $this->version('v3');

        $this->assertFalse(
            app(PageExistence::class)->inVersion($unpublished, 'html/index.html'),
        );
    }

    /** The nearest surviving ancestor, for a reader switching version. */
    public function test_the_nearest_page_walks_up_the_path(): void
    {
        $version = $this->version('v1');

        $this->publishWithFiles($version, ['html/index.html', 'html/guide/index.html']);

        $fresh = $version->fresh() ?? $version;
        $existence = app(PageExistence::class);

        $this->assertSame(
            'html/guide/index.html',
            $existence->nearestIn($fresh, 'html/guide/auth/tokens/index.html'),
        );

        // ...and null rather than a guess when even the root is absent.
        $this->assertNull($existence->nearestIn($this->version('v9'), 'html/index.html'));
    }

    /**
     * Publish a version with a real file manifest behind it.
     *
     * @param  list<string>  $paths
     */
    private function publishWithFiles(ProjectVersion $version, array $paths): void
    {
        $build = $this->publishedBuild($version);
        $store = app(ArtifactStore::class);

        $manifest = new FileManifest;

        foreach ($paths as $path) {
            $manifest->add($path, hash('sha256', $path), 10);
            $store->put($store->keyFor($build->id, $path), 'x');
        }

        // Where `ManifestReader::loadFiles()` looks: the `manifest` media
        // type's own prefix, not the build root.
        $store->put($store->keyFor($build->id, 'manifest').'/manifest.json', $manifest->encode());

        /*
         * 🛑 `mounts_json` is what `ManifestReader::mounts()` reads, and
         * `manifest_builds` is the relational mirror of it. The reader
         * takes the JSON — one read of one row on the serving path rather
         * than a join — so a fixture that wrote only the table would be
         * testing nothing.
         */
        DB::table('project_version_manifests')
            ->where('id', $version->fresh()?->published_manifest_id)
            ->update([
                'mounts_json' => json_encode([
                    'mounts' => [[
                        'mount_path' => '',
                        'build_id' => $build->uuid,
                    ]],
                ]),
            ]);

        Cache::flush();
    }
    // ----------------------------------------------------------- helpers

    private function version(
        string $slug,
        string $language = 'en',
        bool $active = true,
        ?string $refName = null,
        ?string $refKind = null,
    ): ProjectVersion {
        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'language' => $language,
            'kind' => $refKind === 'tag' ? 'release' : 'channel',
            'active' => $active,
            'listed' => true,
            'published' => false,
            'visibility' => 'public',
            'ref_name' => $refName,
            'ref_kind' => $refKind,
        ])->save();

        return $version;
    }

    private function publishedBuild(ProjectVersion $version): Build
    {
        $build = new Build;
        $build->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $this->component->id,
            'content_key' => hash('sha256', 'life:'.bin2hex(random_bytes(8))),
            'state' => 'published',
        ])->save();

        $manifestId = Uuid::v7();

        DB::table('project_version_manifests')->insert([
            'id' => $manifestId,
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'revision' => 1,
            'mounts_json' => json_encode([]),
            'created_at' => now(),
        ]);

        $version->forceFill(['published' => true, 'published_manifest_id' => $manifestId])->save();

        return $build;
    }

    /**
     * `fresh()` with the nullability resolved once.
     *
     * Eloquent types `fresh()` as `?Model` and the row is always there, so
     * every call site would otherwise carry a `?? $original` that reads as
     * if the row might have vanished. Carried from Phase 08's handover
     * note, which named this exact friction.
     */
    private function reload(ProjectVersion $version): ProjectVersion
    {
        $fresh = $version->fresh();

        $this->assertInstanceOf(ProjectVersion::class, $fresh);

        return $fresh;
    }
}
