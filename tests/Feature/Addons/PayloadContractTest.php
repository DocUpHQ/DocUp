<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Addons\AddonsContract;
use App\Addons\CrossReferenceMap;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Branding\ApiOnlyChrome;
use App\Http\Controllers\Serving\CrossReferenceController;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §8.15.2's payload contract: the field set, and the two agreements.
 *
 * ## The field set
 *
 * §8.15.2 names what the payload carries, and the sentence is the field list:
 * "branding tokens, version list and sort, flyout configuration, notifications,
 * search configuration, merged navigation, cross-reference map, canonical URL
 * and analytics opt-in." §8.15.11 adds the offline formats. Asserted as a set
 * rather than field by field, so a refactor that **drops** one fails — which is
 * the direction that matters: a missing field is a feature with no data, and
 * the runtime would simply render nothing and say nothing.
 *
 * ## 🛑 The two agreements
 *
 * Two facts are computed in two places by design, and in each case the second
 * place exists for a reason that forbids merging them. So the agreement is
 * asserted instead:
 *
 * 1. **The cross-reference base.** {@see CrossReferenceMap} builds
 *    a base URL for the client to concatenate; the server answers the same
 *    reference with a 302 whose `Location` is the whole URL
 *    ({@see CrossReferenceController}). §8.7.17
 *    requires both — the 302 is "the no-JavaScript and AI-agent path" — so a
 *    divergence would be invisible to whichever one nobody tested.
 *
 * 2. **§8.6.13's translation notice.** The document response carries it as a
 *    header and the payload carries it as a banner, because a document's own
 *    JavaScript cannot read its response headers and nothing rewrites
 *    documentation on the serving path (§4.3/2, §8.9.8).
 */
final class PayloadContractTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $english;

    private ProjectVersion $japanese;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Storage::fake('branding');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-contract-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'contract-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Contract Co',
            'slug' => 'contract-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Contract Demo',
            'visibility' => 'public',
        ]);

        // 🛑 One translation group, two languages. §8.6.12: language is a
        // property of a version with a `translation_group_id`, never a sibling
        // project — so the notice below is about two rows, not two projects.
        $group = Uuid::v7();

        $this->english = $this->makeVersion('v1', 'en', $group);
        $this->japanese = $this->makeVersion('v1', 'ja', $group);

        $this->project->forceFill(['default_version_id' => $this->english->id])->save();

        $this->giveTheProjectADefaultSubdomain($slug);
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

    /** §8.15.2's field set, plus §8.15.11's. */
    public function test_the_payload_carries_every_field_the_requirement_names(): void
    {
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $payload = $this->addons('/en/v1/');

        $this->assertSame(
            [
                'analytics',          // §8.15.2 "analytics opt-in"
                'branding',           // §8.15.2 "branding tokens" — §8.14.14's contract
                'branding_contract',
                'build',
                'canonical',          // §8.15.2 "canonical URL"
                'chrome_mode',        // §8.15.7
                'contract',
                'cross_references',   // §8.15.2 "cross-reference map" — §8.7.17
                'downloads',          // §8.15.11
                'flyout',             // §8.15.2 "version list and sort", "flyout configuration"
                'injector_version',   // §8.15.4
                'navigation',         // §8.15.2 "merged navigation"
                'notifications',      // §8.15.2 "notifications" — §8.15.6
                'project',
                'search',             // §8.15.2 "search configuration"
                'version',
            ],
            self::sortedKeys($payload),
            '§8.15.2 names the fields; this is the set',
        );

        // The two version numbers are independent, which is what
        // {@see AddonsContract} promises and why they are two.
        $this->assertSame(AddonsContract::VERSION, $payload['contract']);
        $this->assertSame(ApiOnlyChrome::VERSION, $payload['branding_contract']);
        $this->assertSame(ApiOnlyChrome::VERSION, $payload['branding']['contract']);

        // §8.14.14's contract is nested VERBATIM, so the committed reference
        // example stays a document rather than becoming a fragment.
        $this->assertSame(
            ['assets', 'banner', 'chrome', 'contract', 'scheme', 'theme'],
            self::sortedKeys($payload['branding']),
        );
    }

    /**
     * 🛑 §8.15.2's "search configuration" is honest about Phase 29.
     *
     * `enabled: false` until the index exists, and the runtime says "search is
     * not configured" rather than querying nothing. Asserted because the
     * tempting alternative — a truthy flag and an endpoint that 404s — is the
     * failure Phase 26b named: "a config key nothing reads is a key an operator
     * believes is doing something."
     */
    public function test_the_search_configuration_states_that_no_engine_exists_yet(): void
    {
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $search = $this->addons('/en/v1/')['search'];

        $this->assertFalse($search['enabled']);
        $this->assertNull($search['endpoint']);

        // §8.15.12's own default, stated in the requirement and emitted here.
        $this->assertSame("input[type='search'], [role='search'] input", $search['selector']);
        $this->assertTrue($search['takeover']);
    }

    /** §8.15.2's "analytics opt-in", off with no toggle (Phase 31 owns it). */
    public function test_analytics_is_off_and_has_no_endpoint(): void
    {
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $this->assertSame(
            ['enabled' => false, 'endpoint' => null],
            $this->addons('/en/v1/')['analytics'],
        );
    }

    /**
     * 🛑 §8.15.11's offline formats, with their `/_/downloads/...` URLs.
     *
     * "so the flyout can offer downloads without a second resolution round
     * trip" — and the URL carries the language and the version whatever the
     * project's §8.6.9 scheme is, which is what the downloads endpoint answers
     * on.
     */
    public function test_the_payload_carries_the_offline_formats_it_actually_has(): void
    {
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $this->assertSame([], $this->addons('/en/v1/')['downloads'], 'an HTML-only build offers none');

        $this->publish($this->english, [
            'html/index.html' => self::page(),
            'pdf/document.pdf' => '%PDF-1.4 fake',
        ]);

        Cache::flush();

        $downloads = $this->addons('/en/v1/')['downloads'];

        $this->assertCount(1, $downloads);
        $this->assertSame('pdf', $downloads[0]['format']);
        $this->assertSame('/_/downloads/en/v1/pdf', $downloads[0]['href']);
        $this->assertSame('application/pdf', $downloads[0]['content_type']);

        // 🛑 And the URL actually serves, which is the whole point of carrying
        // it: a flyout offering a download the endpoint would 404 is worse than
        // one offering none.
        $this->getExactly('http://'.$this->host.$downloads[0]['href'])->assertOk();
    }

    /**
     * 🛑 Agreement one: the client's rewrite target equals the server's 302.
     *
     * The payload gives a base to concatenate and the controller gives a whole
     * `Location`. §8.7.17 needs both, so this asserts they are the same URL.
     */
    public function test_the_cross_reference_base_agrees_with_the_servers_302(): void
    {
        /*
         * A document that refers to another component, which is what makes the
         * ingest record a cross-reference at all (§8.7.16). The component is
         * this version's own single mount, which is the degenerate composition
         * Phase 03 creates — so `/_/x/<key>/page.html` resolves to this
         * version's own tree.
         */
        /*
         * Published twice, and the first publish is what creates the component:
         * §17 gives Phase 03 "exactly one degenerate component per project with
         * a single primary mount at `mount_path=''`", created BY publishing. So
         * the key cannot be known before there is a build — which is also true
         * of a real generator writing a cross-reference, and is why §8.7.16
         * records an unresolved reference as a link issue rather than a failure.
         */
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $component = $this->componentKey();

        $this->publish($this->english, [
            'html/index.html' => '<!doctype html><html><head></head><body>'
                .'<a href="/_/x/'.$component.'/guide.html">see the guide</a>'
                .'</body></html>',
            'html/guide.html' => self::page(),
        ]);

        Cache::flush();

        $map = $this->addons('/en/v1/')['cross_references'];

        $this->assertArrayHasKey($component, $map, 'the payload carries the component the build referenced');

        $clientTarget = $map[$component].'guide.html';

        $redirect = $this->getExactly('http://'.$this->host.'/_/x/'.$component.'/guide.html');

        $redirect->assertStatus(302);

        $this->assertSame(
            $redirect->headers->get('Location'),
            $clientTarget,
            'the client rewrite and the server 302 must name the same URL (§8.7.17)',
        );

        // And it is a real page rather than a plausible one.
        $this->getExactly('http://'.$this->host.$clientTarget)->assertOk();
    }

    /**
     * 🛑 An unknown component is absent from the map, so the client leaves the
     * link alone and the server still 404s it.
     *
     * §8.7.16: "sending every typo to the home page is how a broken link
     * becomes invisible." A rewriter that guessed would do exactly that on the
     * client, where nobody would see the 404 at all.
     */
    public function test_an_unknown_component_is_absent_from_the_map(): void
    {
        $this->publish($this->english, ['html/index.html' => self::page()]);

        $this->assertArrayNotHasKey('no-such-component', $this->addons('/en/v1/')['cross_references']);
        $this->getExactly('http://'.$this->host.'/_/x/no-such-component/page.html')->assertNotFound();
    }

    /**
     * 🛑 Agreement two: §8.6.13's notice in the payload matches the header.
     *
     * Phase 27 recorded the banner as owed ("§8.6.13's banner inside P28's
     * closed shadow root"). This is it, and the assertion is that both answers
     * come from the same facts: the document response's `X-DocUp-Notice` and the
     * payload's banner must describe one event.
     */
    public function test_the_translation_notice_matches_the_document_header(): void
    {
        // English has the page; Japanese does not.
        $this->publish($this->english, ['html/index.html' => self::page(), 'html/guide.html' => self::page()]);
        $this->publish($this->japanese, ['html/index.html' => self::page()]);

        Cache::flush();

        $document = $this->getExactly('http://'.$this->host.'/ja/v1/guide.html');

        $document->assertNotFound();

        $header = (string) $document->headers->get('X-DocUp-Notice');

        $this->assertStringContainsString('translation.page_untranslated', $header);

        $banners = $this->addons('/ja/v1/guide.html')['notifications'];
        $untranslated = null;

        foreach ($banners as $banner) {
            if ($banner['kind'] === 'addons.page_untranslated') {
                $untranslated = $banner;
            }
        }

        $this->assertNotNull($untranslated, 'the payload carries §8.6.13\'s banner');
        $this->assertSame('translation.page_untranslated', $untranslated['values']['code']);
        $this->assertSame('ja', $untranslated['values']['requested']);
        $this->assertStringContainsString('en', $untranslated['values']['available']);

        // 🛑 Both halves name the same languages, which is the agreement.
        $this->assertStringContainsString('available=en', $header);
        $this->assertNotNull($untranslated['href'], 'the banner offers somewhere to go');
    }

    // ------------------------------------------------------------- helpers

    /**
     * @param  array<string, mixed>  $payload
     * @return list<string>
     */
    private static function sortedKeys(array $payload): array
    {
        $keys = array_keys($payload);
        sort($keys, SORT_STRING);

        /** @var list<string> */
        return $keys;
    }

    private static function page(): string
    {
        return '<!doctype html><html lang="en"><head></head><body><h1>Page</h1></body></html>';
    }

    /** The degenerate component Phase 03 creates for an uncomposed version. */
    private function componentKey(): string
    {
        /*
         * 🛑 By organisation and by the mount, not by `components.project_id` —
         * there is no such column. §8.7.1 makes a component a thing an
         * organisation owns and a project MOUNTS, which is the whole of
         * one-repository-to-many-projects (§8.7.9): a component belongs to no
         * single project by design.
         */
        $key = DB::table('component_mounts')
            ->join('components', 'components.id', '=', 'component_mounts.component_id')
            ->join('project_versions', 'project_versions.id', '=', 'component_mounts.project_version_id')
            ->where('project_versions.project_id', $this->project->id)
            ->value('components.key');

        $this->assertIsString($key, 'the project has its degenerate component');

        return $key;
    }

    /** @return array<string, mixed> */
    private function addons(string $path): array
    {
        $response = $this->getExactly('http://'.$this->host.'/_/addons?path='.urlencode($path));

        $response->assertOk();

        /** @var array<string, mixed> $decoded */
        $decoded = json_decode((string) $response->getContent(), true, 64, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }

    private function makeVersion(string $slug, string $language, string $group): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'release',
            'language' => $language,
            'visibility' => 'public',
            'translation_group_id' => $group,
            'ref_name' => $slug,
            'ref_kind' => 'tag',
        ])->save();

        return $version;
    }

    /** @param array<string, string> $files */
    private function publish(ProjectVersion $version, array $files): void
    {
        $writer = new ArchiveWriter;

        foreach ($files as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz($this->fixtures.'/'.bin2hex(random_bytes(4)).'.tar.gz');

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

    private function giveTheProjectADefaultSubdomain(string $slug): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $slug.'.'.$this->docsApex(),
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
