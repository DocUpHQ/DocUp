<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Seo;

use App\Auth\OrganisationContext;
use App\Http\Middleware\RejectNonCanonicalPath;
use App\Models\Domain;
use App\Models\DomainMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Seo\GeneratedArtifacts;
use App\Seo\GeneratedStore;
use App\Seo\LlmsTxt;
use App\Seo\RobotsTxt;
use App\Seo\Sitemap;
use App\Seo\SitemapEntry;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * 🛑 §8.11.6's four files and §17's exit criteria for them.
 *
 * > "`sitemap.xml` omits hidden versions and serving aliases carry
 * > `Disallow: /`. `llms.txt` lists the navigation tree."
 */
final class GeneratedArtifactsTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hosted Co',
            'slug' => 'hosted-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'manual-'.bin2hex(random_bytes(3)),
            'name' => 'The Manual',
            'visibility' => 'public',
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The exit criterion: a hidden version is absent from the sitemap
     * while still being reachable.
     *
     * P10 made `listed` an axis of its own precisely so a version can be
     * "200 by direct URL and absent from the version list". A sitemap that
     * listed it would undo the second half; a `Disallow` would undo the
     * first.
     */
    public function test_the_sitemap_omits_hidden_and_non_public_versions(): void
    {
        $this->version('v1', listed: true);
        $this->version('v2-unlisted', listed: false);
        $this->version('v3-private', listed: true, visibility: 'members');
        $this->version('v4-unpublished', listed: true, published: false);
        $this->version('v5-retired', listed: true, active: false);

        $mount = $this->mount('docs.example.test', indexable: true);

        app(GeneratedArtifacts::class)->regenerate($this->project);

        $sitemap = $this->read($mount, 'sitemap.xml');

        $this->assertStringContainsString('/en/v1/', $sitemap, 'the listed, published, public version is present');

        foreach (['v2-unlisted', 'v3-private', 'v4-unpublished', 'v5-retired'] as $absent) {
            $this->assertStringNotContainsString(
                $absent,
                $sitemap,
                $absent.' must not be advertised to a crawler',
            );
        }
    }

    /**
     * 🛑 The other half of the exit criterion: "serving aliases carry
     * `Disallow: /`".
     *
     * §8.10.2 has every verified domain answering 200, so the same
     * documentation really is reachable at several hostnames. That is right
     * for readers and duplicate content for a crawler.
     */
    public function test_a_serving_alias_disallows_everything_and_is_noindex(): void
    {
        $this->version('v1');

        $canonical = $this->mount('canonical.example.test', indexable: true);
        $alias = $this->mount('alias.example.test', indexable: false);

        app(GeneratedArtifacts::class)->regenerate($this->project);

        $this->assertStringContainsString('Allow: /', $this->read($canonical, 'robots.txt'));
        $this->assertStringContainsString('Sitemap:', $this->read($canonical, 'robots.txt'));

        $aliasRobots = $this->read($alias, 'robots.txt');

        $this->assertStringContainsString('Disallow: /', $aliasRobots);
        $this->assertStringNotContainsString('Allow: /', $aliasRobots);

        /*
         * 🛑 And no `Sitemap:` line, because offering one would invite a
         * crawler to the very URLs the line above asked it to leave alone
         * — and some crawlers read `Sitemap:` even when they honour
         * `Disallow`.
         */
        $this->assertStringNotContainsString('Sitemap:', $aliasRobots);

        /*
         * The alias still gets a sitemap **file**, and it is empty: writing
         * three of the four would make the fourth a 404, which an operator
         * cannot distinguish from a misconfiguration.
         */
        $aliasSitemap = $this->read($alias, 'sitemap.xml');

        $this->assertStringContainsString('<urlset', $aliasSitemap);
        $this->assertStringNotContainsString('<loc>', $aliasSitemap);
    }

    /** 🛑 The exit criterion: "`llms.txt` lists the navigation tree." */
    public function test_llms_txt_lists_the_navigation_tree(): void
    {
        $version = $this->version('v1');
        $this->navigationFor($version, [
            ['title' => 'Getting started', 'href' => 'start/'],
            ['title' => 'Guides', 'children' => [
                ['title' => 'Installing', 'href' => 'guides/install/'],
                ['title' => 'Upgrading', 'href' => 'guides/upgrade/'],
            ]],
        ]);

        $mount = $this->mount('docs.example.test', indexable: true);

        app(GeneratedArtifacts::class)->regenerate($this->project);

        $llms = $this->read($mount, 'llms.txt');

        $this->assertStringContainsString('# The Manual', $llms);

        foreach (['Getting started', 'Installing', 'Upgrading'] as $title) {
            $this->assertStringContainsString($title, $llms, $title.' is in the tree and must be listed');
        }

        /*
         * Nested entries are flattened with their own URLs rather than
         * dropped: an agent reading the index needs every page, not every
         * top-level heading.
         */
        $this->assertStringContainsString('guides/install/', $llms);
        $this->assertStringContainsString('guides/upgrade/', $llms);
    }

    /**
     * 🛑 §8.11.6: the revision is in the path, and the old one is swept
     * **after** the mount moves on.
     *
     * Reversed, a reader arriving between the delete and the update gets a
     * 404 for `robots.txt` — which a crawler reads as "crawl everything".
     */
    public function test_regenerating_advances_the_revision_and_sweeps_the_previous(): void
    {
        $this->version('v1');
        $mount = $this->mount('docs.example.test', indexable: true);

        app(GeneratedArtifacts::class)->regenerate($this->project);
        $first = (int) $this->refreshed($mount)->generated_revision;

        app(GeneratedArtifacts::class)->regenerate($this->project);
        $second = (int) $this->refreshed($mount)->generated_revision;

        $this->assertSame($first + 1, $second);

        $store = app(GeneratedStore::class);

        $this->assertNotNull($store->get((string) $mount->id, $second, 'robots.txt'));
        $this->assertNull(
            $store->get((string) $mount->id, $first, 'robots.txt'),
            'the superseded revision is swept once nothing points at it',
        );
    }

    /**
     * 🛑 §8.11.6's store is separate from the build tree, so §8.8.1's
     * write-once rule is untouched — asserted by the prefix, because that
     * is the whole mechanism.
     */
    public function test_the_generated_files_live_outside_the_build_tree(): void
    {
        $this->version('v1');
        $mount = $this->mount('docs.example.test', indexable: true);

        app(GeneratedArtifacts::class)->regenerate($this->project);

        $prefix = app(GeneratedStore::class)->prefixFor(
            (string) $mount->id,
            (int) $this->refreshed($mount)->generated_revision,
        );

        $this->assertStringStartsWith('generated/', $prefix);
        $this->assertStringNotContainsString('builds/', $prefix);
    }

    /** §8.11.6's `hreflang`, "across versions, mounts **and** domains". */
    public function test_the_sitemap_carries_reciprocal_hreflang_alternates(): void
    {
        $group = Uuid::v7();

        $this->version('v1', language: 'en', translationGroup: $group);
        $this->version('v1', language: 'ja', translationGroup: $group);

        $mount = $this->mount('docs.example.test', indexable: true);

        app(GeneratedArtifacts::class)->regenerate($this->project);

        $sitemap = $this->read($mount, 'sitemap.xml');

        $this->assertStringContainsString('xmlns:xhtml', $sitemap);
        $this->assertStringContainsString('hreflang="en"', $sitemap);
        $this->assertStringContainsString('hreflang="ja"', $sitemap);

        /*
         * 🛑 Reciprocal: every alternate lists every other, including
         * itself. A non-reciprocal set is silently ignored by the crawler
         * that reads these most.
         */
        $this->assertSame(
            2,
            substr_count($sitemap, 'hreflang="en"'),
            'the English page must be listed as an alternate of both',
        );
    }

    /** A URL with an ampersand does not make the sitemap unparseable. */
    public function test_the_sitemap_escapes_its_urls(): void
    {
        $xml = Sitemap::render([
            new SitemapEntry('https://docs.example.test/a?x=1&y=2'),
        ]);

        $this->assertStringContainsString('&amp;', $xml);
        $this->assertStringNotContainsString('&y', $xml);
        $this->assertInstanceOf(\DOMDocument::class, $this->parse($xml));
    }

    /** A title containing Markdown syntax cannot restructure `llms.txt`. */
    public function test_llms_txt_escapes_a_hostile_title(): void
    {
        $out = LlmsTxt::index('Manual', null, [[
            'heading' => 'Pages',
            'links' => [['title' => 'Evil](https://evil.test) [x', 'url' => '/a/']],
        ]]);

        $this->assertStringNotContainsString('](https://evil.test)', $out);
        $this->assertStringContainsString('\]', $out);
    }

    /** `robots.txt` keeps `/_/` out of a crawler's way (§7.3). */
    public function test_robots_disallows_the_reserved_namespace(): void
    {
        $this->assertStringContainsString('Disallow: /_/', RobotsTxt::render(true, null));
    }

    private function parse(string $xml): \DOMDocument
    {
        $document = new \DOMDocument;

        $this->assertTrue($document->loadXML($xml), 'the sitemap must be well-formed XML');

        return $document;
    }

    private function read(DomainMount $mount, string $file): string
    {
        $contents = app(GeneratedStore::class)->get(
            (string) $mount->id,
            (int) $this->refreshed($mount)->generated_revision,
            $file,
        );

        $this->assertNotNull($contents, $file.' was not written');

        return $contents;
    }

    private function refreshed(DomainMount $mount): DomainMount
    {
        $fresh = $mount->fresh();

        $this->assertInstanceOf(DomainMount::class, $fresh);

        return $fresh;
    }

    private function version(
        string $slug,
        bool $listed = true,
        string $visibility = 'public',
        bool $published = true,
        bool $active = true,
        string $language = 'en',
        ?string $translationGroup = null,
    ): ProjectVersion {
        $version = new ProjectVersion;

        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => $language,
            'visibility' => $visibility,
            'active' => $active,
            'listed' => $listed,
            'published' => $published,
            'translation_group_id' => $translationGroup,
        ])->save();

        /*
         * The manifest is created second and the pointer set third, because
         * §8.8.3's foreign key runs both ways: a manifest belongs to a
         * version, and a version points at a manifest. A manifest written
         * first has nothing to belong to.
         */
        if ($published) {
            $version->forceFill(['published_manifest_id' => $this->manifestFor($version)])->save();
        }

        return $version;
    }

    /** A manifest row with no mounts: enough for the sitemap's purposes. */
    private function manifestFor(ProjectVersion $version): string
    {
        $id = Uuid::v7();

        /*
         * No `updated_at`: §10.4 makes a manifest **immutable**, so the
         * table has no such column. Nothing updates a manifest row — a new
         * revision is a new row.
         */
        DB::table('project_version_manifests')->insert([
            'id' => $id,
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'revision' => 1,
            'mounts_json' => json_encode([], JSON_THROW_ON_ERROR),
            'nav_json' => null,
            'xref_json' => null,
            'created_at' => Carbon::now()->format('Y-m-d H:i:s.v'),
        ]);

        return $id;
    }

    /** @param  list<array<string, mixed>>  $nodes */
    private function navigationFor(ProjectVersion $version, array $nodes): void
    {
        /*
         * `{"nodes": …}`, which is the shape §8.7.6's spliced navigation is
         * stored in and the one `ManifestReader::navigation()` reads. Not
         * a bare array: the column carries a document with room for the
         * splice's own metadata.
         */
        DB::table('project_version_manifests')
            ->where('id', $version->published_manifest_id)
            ->update(['nav_json' => json_encode(['nodes' => $nodes], JSON_THROW_ON_ERROR)]);
    }

    private function mount(string $host, bool $indexable): DomainMount
    {
        $domain = new Domain;
        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        $mount = new DomainMount;
        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domain->id,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            /*
             * 🛑 `is_indexable` is **not** set: §8.10.2 derives it from the
             * mode and §10.5 makes it a generated column, so MySQL refuses
             * a value for it. Choosing the mode is choosing indexability,
             * which is the requirement's own design — "Only the canonical
             * mount is indexable".
             */
            'mode' => $indexable ? 'canonical' : 'serve',
        ])->save();

        return $mount;
    }

    /**
     * 🛑 All four generated files, over **HTTP**, on both host shapes.
     *
     * Added in Phase 21, which is the phase that found what its absence cost:
     * `GeneratedFileController` declared the filename as a positional
     * parameter, Laravel passes a route's **domain** parameters before its path
     * parameters, and both groups registering these routes are domain-scoped —
     * so every request for `robots.txt`, `sitemap.xml`, `llms.txt` or
     * `llms-full.txt` received the hostname in `$docupGeneratedFile` and
     * answered `generated.unknown_file`. On every host there had ever been.
     *
     * 🛑 **Phase 20's tests were all correct and none of them could have
     * caught it**: they drove `GeneratedArtifacts` and the store directly and
     * asserted the written bytes, which were right. §8.11.6 is a requirement
     * about four *URLs*, and the only test that can check a URL is one that
     * asks for it. The same gap, in the same shape, as Phase 19's finding that
     * the ACME challenge path was swallowed by a domain route.
     */
    public function test_every_generated_file_is_served_over_http(): void
    {
        $custom = 'manual-'.bin2hex(random_bytes(3)).'.example.test';
        $mount = $this->mount($custom, indexable: true);

        $this->version('v2', listed: true, visibility: 'public');

        app(GeneratedArtifacts::class)->regenerate($this->project);

        foreach (GeneratedStore::FILES as $file) {
            $response = $this->getExactly('http://'.$custom.'/'.$file);

            $response->assertOk();
            $response->assertHeader(RejectNonCanonicalPath::RESOLVER_HEADER, 'generated.store');
        }

        /*
         * And on the default subdomain, which is the **other** domain-scoped
         * group and the one whose extra `{docupHostLabel}` parameter made the
         * positional read wrong. Two groups, two chances to get it wrong, so
         * both are asserted.
         */
        $label = 'sub-'.bin2hex(random_bytes(3));
        $apex = config('docup.origins.docs');
        $subdomain = $label.'.'.(is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test');

        $default = new Domain;
        $default->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $subdomain,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        $second = new DomainMount;
        $second->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $default->id,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'serve',
        ])->save();

        app(GeneratedArtifacts::class)->regenerate($this->project);

        Cache::flush();

        foreach (GeneratedStore::FILES as $file) {
            $this->getExactly('http://'.$subdomain.'/'.$file)->assertOk();
        }

        $this->assertNotSame((string) $mount->id, (string) $second->id);
    }

    /**
     * 🛑 And a documentation path that merely ends in one of the four names is
     * still served from the build.
     *
     * §8.11.6's route pattern cannot be constrained to mount prefixes, because
     * those are rows — so `/en/v2/sitemap.xml` matches the prefixed generated
     * route and the controller has to delegate it. A 404 here would make those
     * four filenames unservable from any build, for every project, for ever.
     */
    public function test_a_build_path_ending_in_a_generated_name_is_not_swallowed(): void
    {
        $custom = 'manual-'.bin2hex(random_bytes(3)).'.example.test';
        $this->mount($custom, indexable: true);

        $response = $this->getExactly('http://'.$custom.'/en/v2/sitemap.xml');

        /*
         * 404 because this fixture publishes no such file — but a 404 from the
         * **document** path, not `generated.unknown_file`. The resolver header
         * is what distinguishes "the build does not have it" from "the route
         * never reached the right controller", which is exactly the confusion
         * that hid the parameter defect.
         */
        $this->assertNotSame(
            'generated.unknown_file',
            $response->headers->get(RejectNonCanonicalPath::RESOLVER_HEADER),
            'a documentation path must be delegated, not treated as a generated file',
        );
    }

    /**
     * A GET that preserves the path exactly, as the serving tests use.
     *
     * @return TestResponse<Response>
     */
    private function getExactly(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse(
            $this->app->handle(Request::create($url, 'GET')),
        );
    }
}
