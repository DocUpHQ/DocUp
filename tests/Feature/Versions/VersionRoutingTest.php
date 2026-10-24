<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Versions;

use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\Resolver;
use App\Serving\RouteKind;
use App\Serving\RouteOutcome;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Uuid;
use App\Versions\VersionOperations;
use App\Versions\VersionRefused;
use App\Versions\VersionRejection;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * §8.6's serving half: what a URL does once a version exists.
 *
 * Three of Phase 10's exit criteria land here rather than in
 * {@see VersionSyncTest}, because each is a statement about a request:
 *
 *  - "A version with `listed=false` **still returns 200 by direct URL**";
 *  - "A renamed slug leaves a **working 301**";
 *  - §8.6.10's `/page/<filename>`, which §17 lists as a deliverable.
 *
 * 🛑 **Through the resolver, with a real routing snapshot.** The resolver is
 * what §8.9.1 makes the single answer to "what does this URL mean", and a
 * test that asked the database instead would prove something about the
 * database.
 */
final class VersionRoutingTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private string $host;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Routing Co',
            'slug' => 'routing-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $slug = 'routed-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.config('docup.origins.docs');

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Routed',
            'visibility' => 'public',
        ]);

        $this->project->forceFill(['versioning_scheme' => 'multi_version'])->save();

        $this->giveTheProjectADefaultSubdomain($slug);
    }

    /**
     * A default subdomain and a canonical mount, by raw insert.
     *
     * The same shape `DocumentServingTest` uses and for the same reason:
     * §17 puts domain management in Phase 18, so a factory here would be
     * inventing the write side early. An installation-owned apex needs no
     * proof of control (§8.10.4), which is why it serves immediately.
     */
    private function giveTheProjectADefaultSubdomain(string $slug): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $this->host,
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

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The exit criterion: "A version with `listed=false` still returns
     * 200 by direct URL."
     *
     * §8.6.2 distinguishes `hidden` from `private` precisely here, and the
     * failure mode is one line of code: a resolver that read `listed` would
     * 404 every link anybody had been given to a hidden version.
     */
    public function test_an_unlisted_version_still_resolves_by_direct_url(): void
    {
        $listed = $this->publishedVersion('v1.0.0');
        $hidden = $this->publishedVersion('v2.0.0-secret');

        $hidden->forceFill(['listed' => false])->save();

        $this->assertResolves('/v1.0.0/index.html', $listed);

        // 🛑 The whole criterion, in one assertion.
        $this->assertResolves('/v2.0.0-secret/index.html', $hidden);
    }

    /** 🛑 "A renamed slug leaves a working 301." */
    public function test_a_renamed_slug_leaves_a_working_redirect(): void
    {
        $version = $this->publishedVersion('v2');

        app(VersionOperations::class)->rename($version, 'v2.0');

        $this->assertSame('v2.0', $version->fresh()?->slug);

        $outcome = $this->resolve('/v2/guide/index.html');

        $this->assertTrue(($outcome->kind === RouteKind::Redirect), 'a former slug must redirect, not 404');
        $this->assertSame('/v2.0/guide/index.html', $outcome->redirectTo);

        // ...and the new slug is served directly rather than through its
        // own redirect, which would be a loop.
        $this->assertResolves('/v2.0/guide/index.html', $version->fresh());
    }

    /**
     * 🛑 A version that reclaims a slug it once had is reached directly.
     *
     * The history row for the reclaimed slug is removed by the rename, so
     * the live version shadows nothing. Without that, `/v2/` would 301 to
     * `/v2/` — a loop that §8.11.3's hop cap would catch, which is still a
     * redirect nobody should have served.
     */
    public function test_reclaiming_a_former_slug_does_not_create_a_loop(): void
    {
        $version = $this->publishedVersion('v2');
        $operations = app(VersionOperations::class);

        $operations->rename($version, 'v2.0');
        $operations->rename($version->fresh() ?? $version, 'v2');

        $outcome = $this->resolve('/v2/index.html');

        $this->assertFalse(($outcome->kind === RouteKind::Redirect), 'the live slug must be served, not redirected');
        $this->assertSame('v2', $outcome->version?->slug);
    }

    /** A 301 to a version that is no longer servable is not offered. */
    public function test_a_former_slug_pointing_at_a_dead_version_is_a_404(): void
    {
        $version = $this->publishedVersion('v3');

        app(VersionOperations::class)->rename($version, 'v3.0');
        $version->fresh()?->forceFill(['active' => false])->save();

        $outcome = $this->resolve('/v3/index.html');

        $this->assertFalse(($outcome->kind === RouteKind::Redirect), 'a 301 to a 404 is worse than the 404');
        $this->assertFalse(($outcome->kind === RouteKind::Resolved));
    }

    // ------------------------------------------------------------ §8.6.10

    /** §8.6.10: `/page/<filename>` resolves in the default version. */
    public function test_a_version_agnostic_page_link_redirects_to_the_default_version(): void
    {
        $this->publishedVersion('v1.0.0');
        $default = $this->publishedVersion('v2.0.0');

        $this->project->forceFill(['default_version_id' => $default->id])->save();

        $outcome = $this->resolve('/page/guide/auth.html');

        $this->assertTrue(($outcome->kind === RouteKind::Redirect));
        $this->assertSame('/v2.0.0/guide/auth.html', $outcome->redirectTo);
    }

    /** `/page/` alone names no page, and a guess would invent a URL. */
    public function test_a_page_link_with_no_filename_is_rejected(): void
    {
        $default = $this->publishedVersion('v1.0.0');
        $this->project->forceFill(['default_version_id' => $default->id])->save();

        $outcome = $this->resolve('/page/');

        $this->assertFalse(($outcome->kind === RouteKind::Resolved));
        $this->assertFalse(($outcome->kind === RouteKind::Redirect));
    }

    // ------------------------------------------------------------- §8.6.6

    /** 🛑 A slug may not be a reserved segment or anything shaped like a language. */
    public function test_a_reserved_slug_is_refused(): void
    {
        $version = $this->publishedVersion('v1.0.0');
        $operations = app(VersionOperations::class);

        foreach (['_', 'page', 'en', 'pt-br'] as $reserved) {
            try {
                $operations->rename($version, $reserved);
                $this->fail('"'.$reserved.'" was accepted as a version slug');
            } catch (VersionRefused $refused) {
                $this->assertSame(VersionRejection::SlugReserved, $refused->rejection);
            }
        }
    }

    /** An operator's input is refused rather than silently normalised. */
    public function test_a_slug_that_is_not_already_normalised_is_refused(): void
    {
        $version = $this->publishedVersion('v1.0.0');

        try {
            app(VersionOperations::class)->rename($version, 'Release 2.0');
            $this->fail('an unnormalised slug was accepted');
        } catch (VersionRefused $refused) {
            $this->assertSame(VersionRejection::SlugNotNormalised, $refused->rejection);
            $this->assertStringContainsString('release-2.0', $refused->getMessage());
        }
    }

    public function test_a_slug_another_version_already_uses_is_refused(): void
    {
        $this->publishedVersion('v1.0.0');
        $second = $this->publishedVersion('v2.0.0');

        $this->expectException(VersionRefused::class);

        app(VersionOperations::class)->rename($second, 'v1.0.0');
    }

    // ----------------------------------------------------------- helpers

    private function assertResolves(string $path, ?ProjectVersion $expected): void
    {
        $outcome = $this->resolve($path);

        $this->assertTrue(($outcome->kind === RouteKind::Resolved), $path.' did not resolve');
        $this->assertSame($expected?->slug, $outcome->version?->slug);
    }

    private function resolve(string $path): RouteOutcome
    {
        // 🛑 The snapshot is memoised per routing epoch, and these tests
        // change the things that bump it inside one process. Flushing is
        // what makes each assertion a statement about the state it just
        // created rather than about the state two tests ago.
        Cache::flush();

        return app(Resolver::class)->resolveRoute(
            app(RoutingSnapshotLoader::class)->load($this->host),
            $path,
        );
    }

    /**
     * A version with something published, so `isServable()` is true.
     *
     * The manifest is the degenerate single-component one Phase 03 ships;
     * what matters here is that the pointer is not null, because
     * `SnapshotVersion::isServable()` reads it.
     */
    private function publishedVersion(string $slug): ProjectVersion
    {
        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'language' => 'en',
            'kind' => 'release',
            'active' => true,
            'listed' => true,
            'published' => true,
            'visibility' => 'public',
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

        $version->forceFill(['published_manifest_id' => $manifestId])->save();

        if ($this->project->default_version_id === null) {
            $this->project->forceFill(['default_version_id' => $version->id])->save();
        }

        return $version;
    }
}
