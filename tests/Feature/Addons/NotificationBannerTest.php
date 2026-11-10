<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Addons\BannerKind;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\HostKind;
use App\Serving\HostMatcher;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §8.15.6's three notification banners, each in both directions.
 *
 * > "Addons MUST provide: […] three **notification banners** (you are reading
 * > an old version / this is the development version / this is a pull-request
 * > build) with **stated trigger conditions** and **per-project toggles**."
 *
 * The conditions are stated on {@see BannerKind}'s cases. This asserts each one
 * fires when it should, does **not** fire when it should not, and is silenced
 * by its toggle — and the negative half is the half worth having: a banner that
 * fires on every page is a banner readers stop seeing, which is ADR 0002's
 * finding about injection warnings arrived at from the reader's side.
 */
final class NotificationBannerTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    /** @var array<string, ProjectVersion> */
    private array $versions = [];

    private string $slug;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Storage::fake('branding');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-banners-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->slug = 'banner-'.bin2hex(random_bytes(3));

        $this->organisation = Organisation::query()->create([
            'name' => 'Banner Co',
            'slug' => 'banner-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $this->slug,
            'name' => 'Banner Demo',
            'visibility' => 'public',
        ]);

        // `v1.9` and `v1.10` on purpose: §8.6.5 names `v1.10` sorting below
        // `v1.9` as "the first bug report every new installation receives", and
        // the old-version banner's trigger is the same comparator.
        $this->versions['v1.9'] = $this->makeVersion('v1.9', 'tag');
        $this->versions['v1.10'] = $this->makeVersion('v1.10', 'tag');
        $this->versions['main'] = $this->makeVersion('main', 'branch');

        $this->project->forceFill([
            'default_version_id' => $this->versions['v1.10']->id,
            'resolved_stable_version_id' => $this->versions['v1.10']->id,
            'resolved_latest_version_id' => $this->versions['main']->id,
        ])->save();

        foreach ($this->versions as $version) {
            $this->publish($version);
        }

        $this->giveTheProjectADomain($this->slug.'.'.$this->docsApex(), 'default_subdomain');
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
     * 🛑 "You are reading an old version", and 🛑 the comparator in its trigger.
     *
     * `v1.9` is older than the default `v1.10` under `semver`, so the banner
     * fires — and it fires because of the comparator rather than because of a
     * string comparison, which `v1.9` vs `v1.10` is exactly the pair to prove:
     * `'v1.9' > 'v1.10'` as strings.
     */
    public function test_an_older_version_warns_and_links_to_the_default(): void
    {
        $banner = $this->bannerOn('/en/v1.9/', BannerKind::OldVersion);

        $this->assertNotNull($banner, 'v1.9 is older than the default v1.10');
        $this->assertSame('warning', $banner['tone']);
        $this->assertSame('/en/v1.10/', $banner['href'], 'the link goes to the default version');
        $this->assertSame('v1.9', $banner['values']['version']);
        $this->assertSame('v1.10', $banner['values']['default']);
    }

    /** 🛑 And it does NOT fire on the default version itself. */
    public function test_the_default_version_does_not_warn(): void
    {
        $this->assertNull($this->bannerOn('/en/v1.10/', BannerKind::OldVersion));
    }

    /**
     * 🛑 Nor on a version NEWER than the default.
     *
     * One direction only, deliberately: a reader on a release candidate is not
     * reading an old version, and telling them so would send them backwards.
     * `main` sorts above `v1.10` under `semver`'s handling of a non-version ref.
     */
    public function test_a_newer_version_does_not_warn_that_it_is_old(): void
    {
        $this->project->forceFill(['default_version_id' => $this->versions['v1.9']->id])->save();
        Cache::flush();

        $this->assertNull(
            $this->bannerOn('/en/v1.10/', BannerKind::OldVersion),
            'v1.10 is newer than the default v1.9 and must not be called old',
        );
    }

    /** 🛑 "This is the development version" — all three clauses. */
    public function test_the_latest_branch_warns_that_it_is_the_development_version(): void
    {
        $banner = $this->bannerOn('/en/main/', BannerKind::DevelopmentVersion);

        $this->assertNotNull($banner);
        $this->assertSame('notice', $banner['tone']);
        $this->assertSame('main', $banner['values']['version']);
    }

    /**
     * 🛑 The third clause: with no `stable` to send the reader to, no banner.
     *
     * A warning a reader cannot act on is one they learn to ignore, and a
     * single-version project would otherwise carry this banner on every page
     * forever — which is ADR 0002's injection-warning failure in another guise.
     */
    public function test_the_development_banner_is_silent_with_no_stable(): void
    {
        $this->project->forceFill(['resolved_stable_version_id' => null])->save();
        Cache::flush();

        $this->assertNull($this->bannerOn('/en/main/', BannerKind::DevelopmentVersion));
    }

    /**
     * 🛑 The branch clause: a `latest` that resolves to a **tag** is a release.
     */
    public function test_the_development_banner_is_silent_when_latest_is_a_tag(): void
    {
        $this->project->forceFill([
            'resolved_latest_version_id' => $this->versions['v1.10']->id,
            'resolved_stable_version_id' => $this->versions['v1.9']->id,
        ])->save();
        Cache::flush();

        $this->assertNull(
            $this->bannerOn('/en/v1.10/', BannerKind::DevelopmentVersion),
            'a tag is a release, not a development stream',
        );
    }

    /**
     * 🛑 "This is a pull-request build", triggered by the **preview host**.
     *
     * §8.1.4 requires previews to occupy a third distinct registrable domain
     * and §8.20.1 repeats it, so the host IS the definition of a preview. That
     * is why the trigger needs no column and will need no re-wiring when Phase
     * 32 creates its first ephemeral version.
     */
    public function test_the_preview_host_warns_that_it_is_a_pull_request_build(): void
    {
        $previewHost = $this->previewHost();

        $this->giveTheProjectADomain($previewHost, 'preview');
        Cache::flush();

        $banner = $this->bannerOn('/en/v1.10/', BannerKind::PullRequest, $previewHost);

        $this->assertNotNull($banner, 'a preview host is a pull-request build');
        $this->assertSame('notice', $banner['tone']);
    }

    /** 🛑 And it is silent on the documentation host. */
    public function test_the_documentation_host_does_not_warn_about_a_pull_request(): void
    {
        $this->assertNull($this->bannerOn('/en/v1.10/', BannerKind::PullRequest));
    }

    /**
     * 🛑 §8.15.6's per-project toggles, all three.
     *
     * Asserted as a loop over {@see BannerKind::toggleable()} rather than three
     * hand-written cases, so a fourth toggleable banner cannot be added without
     * either a column or a failing test.
     */
    public function test_each_banner_has_a_working_per_project_toggle(): void
    {
        $previewHost = $this->previewHost();
        $this->giveTheProjectADomain($previewHost, 'preview');

        /*
         * A list of triples rather than a map keyed by the enum: PHP array keys
         * are int|string and an enum cannot be one, which is a language fact
         * rather than a design choice and is worth the shape it forces.
         */
        $cases = [
            [BannerKind::OldVersion, 'notify_old_version', '/en/v1.9/', $this->slug.'.'.$this->docsApex()],
            [BannerKind::DevelopmentVersion, 'notify_development_version', '/en/main/', $this->slug.'.'.$this->docsApex()],
            [BannerKind::PullRequest, 'notify_pull_request', '/en/v1.10/', $previewHost],
        ];

        $this->assertSame(
            array_map(static fn (BannerKind $kind): string => $kind->value, BannerKind::toggleable()),
            array_map(static fn (array $case): string => $case[0]->value, $cases),
            'every toggleable banner is covered here',
        );

        foreach ($cases as [$kind, $column, $path, $host]) {
            Cache::flush();
            $this->assertNotNull($this->bannerOn($path, $kind, $host), $kind->value.' fires by default');

            $this->project->forceFill([$column => false])->save();
            Cache::flush();

            $this->assertNull($this->bannerOn($path, $kind, $host), $kind->value.' is silenced by '.$column);

            $this->project->forceFill([$column => true])->save();
        }
    }

    /**
     * 🛑 §8.6.13's banner has **no** toggle, and that is the requirement.
     *
     * "A missing page in a non-default language MUST return 404 plus a
     * notification banner, never a silent fallback." A toggle would be a switch
     * for turning a MUST off.
     */
    public function test_the_translation_banner_has_no_toggle(): void
    {
        $this->project->forceFill([
            'notify_old_version' => false,
            'notify_development_version' => false,
            'notify_pull_request' => false,
        ])->save();
        Cache::flush();

        $this->assertTrue(
            BannerKind::PageUntranslated->enabledFor(
                Project::withoutGlobalScopes()->whereKey($this->project->id)->firstOrFail(),
            ),
        );

        $this->assertNotContains(
            BannerKind::PageUntranslated,
            BannerKind::toggleable(),
            '§8.6.13 is not one of §8.15.6\'s three and must not get a toggle',
        );
    }

    /**
     * 🛑 No banner carries a sentence, and that is §8.14.3.
     *
     * "Chrome content MUST be structured data … never free HTML." So every
     * banner in the payload is a key, a tone and substitutions — which is also
     * what lets an `api_only` consumer localise it, since §8.15.2 makes this
     * endpoint the only source of the fact.
     */
    public function test_a_banner_carries_a_key_and_never_a_sentence(): void
    {
        $banner = $this->bannerOn('/en/v1.9/', BannerKind::OldVersion);

        $this->assertNotNull($banner);
        $this->assertSame(BannerKind::OldVersion->translationKey(), $banner['key']);

        foreach ($banner['values'] as $value) {
            $this->assertDoesNotMatchRegularExpression('/\s/', (string) $value, 'a value is a token, not prose');
        }

        $this->assertStringNotContainsString('<', json_encode($banner, JSON_THROW_ON_ERROR));
    }

    // ------------------------------------------------------------- helpers

    /**
     * The banner of this kind in the payload for a path, or null.
     *
     * @return array{kind: string, key: string, tone: string, href: string|null, values: array<string, string>}|null
     */
    private function bannerOn(string $path, BannerKind $kind, ?string $host = null): ?array
    {
        $host ??= $this->slug.'.'.$this->docsApex();

        $response = TestResponse::fromBaseResponse($this->app->handle(Request::create(
            'http://'.$host.'/_/addons?path='.urlencode($path),
            'GET',
        )));

        $response->assertOk();

        /** @var array{notifications: list<array<string, mixed>>} $payload */
        $payload = json_decode((string) $response->getContent(), true, 64, JSON_THROW_ON_ERROR);

        foreach ($payload['notifications'] as $banner) {
            if ($banner['kind'] === $kind->value) {
                /** @var array{kind: string, key: string, tone: string, href: string|null, values: array<string, string>} $banner */
                return $banner;
            }
        }

        return null;
    }

    private function makeVersion(string $slug, string $refKind): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => $refKind === 'branch' ? 'channel' : 'release',
            'language' => 'en',
            'visibility' => 'public',
            'ref_name' => $slug,
            'ref_kind' => $refKind,
        ])->save();

        return $version;
    }

    private function publish(ProjectVersion $version): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<!doctype html><html><head></head><body>doc</body></html>')
            ->toTarGz($this->fixtures.'/'.bin2hex(random_bytes(4)).'.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($version, $archive);
        $version->refresh();

        $this->context->forget();
        $this->context->for($this->organisation->id);
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    private function previewApex(): string
    {
        $apex = config('docup.origins.preview');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-previews.test';
    }

    /**
     * A preview host, in the shape §8.20's host grammar requires.
     *
     * 🛑 `<project>--<version>` under the preview apex, and the `--` is not
     * decoration: {@see HostMatcher} offers a
     * {@see HostKind::Preview} candidate only for a label that
     * splits on it, so a host without one resolves as a custom domain and the
     * pull-request banner never fires. Found exactly that way.
     */
    private function previewHost(): string
    {
        return $this->slug.'--v1-10.'.$this->previewApex();
    }

    private function giveTheProjectADomain(string $host, string $kind): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => $kind,
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
            /*
             * 🛑 The preview mount is `serve`, not a second `canonical`.
             * §8.10.2 allows one canonical mount per project — `is_indexable`
             * is GENERATED from this column — and a preview that claimed to be
             * canonical would put the preview host in every `rel=canonical`,
             * which is what §8.20.1's `noindex` exists to prevent.
             */
            'mode' => $kind === 'preview' ? 'serve' : 'canonical',
            'mount_exposure' => 'inherit',
            'position' => $kind === 'preview' ? 1 : 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
