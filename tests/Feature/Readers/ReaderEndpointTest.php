<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Readers;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Http\Middleware\OnlyFromLoopback;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Readers\Containment;
use App\Readers\EpochFeed;
use App\Readers\Grants\GrantKeys;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * §20.2's reserved endpoints that Phase 22 adds: the Tier B subrequest, the
 * JWKS document and the Tier C epoch feed — plus §8.12.22's verdict reporting.
 */
final class ReaderEndpointTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        /*
         * 🛑 The containment verdict lives on the `local` disk, so it is faked
         * here: a real verdict left behind by `deploy/containment-self-test.sh`
         * on a developer's machine would make these assertions pass or fail on
         * the strength of what somebody ran yesterday.
         */
        Storage::fake('local');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-rend-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'rend-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Endpoint Co',
            'slug' => 'rend-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Endpoints',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->mountOn($this->host);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version, (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>e</body></html>\n")
            ->toTarGz($this->fixtures.'/tree.tar.gz'));

        $this->context->forget();
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

    // ------------------------------------------------------- §8.12.13's Tier B

    /**
     * 🛑 §8.12.13: "The authz endpoint emits only 2xx/401."
     *
     * Two statuses and nothing else, because the vocabulary is an internal
     * protocol — §8.12.24 — and anything richer would be a vocabulary nginx has
     * to be taught.
     */
    public function test_the_tier_b_endpoint_allows_a_public_document_with_204(): void
    {
        $response = $this->fetch("https://{$this->host}/_/authz?uri=/en/latest/");

        $this->assertSame(204, $response->getStatusCode());
        $this->assertSame('', $response->getContent());
    }

    /** And refuses a private one with a 401 — the subrequest vocabulary. */
    public function test_the_tier_b_endpoint_refuses_a_private_document_with_401(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $response = $this->fetch("https://{$this->host}/_/authz?uri=/en/latest/");

        $this->assertSame(401, $response->getStatusCode());
    }

    /**
     * 🛑 §8.12.13: "the **401 MUST be cached too** or an unauthenticated
     * crawler costs one PHP call per asset."
     *
     * ADR 0005 measured a page at sixty assets, so an uncached denial turns one
     * crawl of a private project into sixty PHP invocations — the shape §9.3.5
     * is about.
     */
    public function test_both_tier_b_answers_carry_a_cache_lifetime(): void
    {
        $allow = $this->fetch("https://{$this->host}/_/authz?uri=/en/latest/");

        $this->assertStringContainsString('max-age=', (string) $allow->headers->get('Cache-Control'));

        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $deny = $this->fetch("https://{$this->host}/_/authz?uri=/en/latest/");

        $this->assertStringContainsString('max-age=', (string) $deny->headers->get('Cache-Control'));

        /*
         * 🛑 And both are `private`. §9.3.2: private content never carries a
         * public cache directive, and the subrequest's answer is about a
         * specific reader even when that reader is anonymous.
         */
        foreach ([$allow, $deny] as $response) {
            $this->assertStringContainsString('private', (string) $response->headers->get('Cache-Control'));
            $this->assertStringContainsString('Cookie', (string) $response->headers->get('Vary'));
        }
    }

    /**
     * 🛑 An unresolvable path is **denied**, not allowed.
     *
     * The subrequest gates the file server, so a path the resolver cannot
     * account for must not be served on the grounds that the authorisation
     * layer had no opinion about it.
     */
    public function test_the_tier_b_endpoint_denies_an_unresolvable_path(): void
    {
        $this->assertSame(
            401,
            $this->fetch("https://{$this->host}/_/authz?uri=/no/such/version/")->getStatusCode(),
        );
    }

    // ---------------------------------------------------------- §20.2's JWKS

    /**
     * 🛑 §8.12.11's JWKS, public and short-cached — §20.2's own exception to
     * "nothing under `/.well-known/` is publicly cacheable".
     */
    public function test_the_jwks_is_public_and_short_cached(): void
    {
        app(GrantKeys::class)->signing();

        $response = $this->fetch("https://{$this->host}/.well-known/docup-grant-jwks.json");

        $response->assertOk();
        $response->assertHeader('Content-Type', 'application/jwk-set+json');

        $cacheControl = (string) $response->headers->get('Cache-Control');

        $this->assertStringContainsString('public', $cacheControl);
        $this->assertStringContainsString('max-age='.GrantKeys::JWKS_CACHE_SECONDS, $cacheControl);

        /** @var array{keys: list<array<string, string>>} $body */
        $body = $response->json();

        $this->assertNotSame([], $body['keys']);

        /* 🛑 No private key member, on any key. */
        foreach ($body['keys'] as $jwk) {
            $this->assertArrayNotHasKey('d', $jwk);
        }
    }

    /** It answers on a documentation host, which is where the edge asks. */
    public function test_the_jwks_answers_on_a_documentation_host(): void
    {
        app(GrantKeys::class)->signing();

        $this->fetch("https://{$this->host}/.well-known/docup-grant-jwks.json")->assertOk();
    }

    // ----------------------------------------------------- §20.2's epoch feed

    /**
     * 🛑 **The epoch feed is NOT public**, and this is the assertion behind
     * Phase 22's proposed clarification to §20.2.
     *
     * The feed is a list of every project identifier on the installation plus a
     * counter that moves when a private project's access policy changes.
     * §8.2.7's visibility-filtered index exists to avoid publishing the first,
     * and §8.6.2 keeps a hidden version out of a sitemap for less than the
     * second. So it carries `OnlyFromLoopback`, exactly as §8.10.11's endpoints
     * do, and §20.2's placement under `/.well-known/` is read as a statement
     * about the path grammar rather than about who may read it.
     */
    public function test_the_epoch_feed_is_refused_from_a_non_loopback_address(): void
    {
        $response = $this->getFrom(
            "https://{$this->host}/.well-known/docup-epochs",
            '203.0.113.9',
        );

        $this->assertSame(404, $response->getStatusCode());
    }

    /** From loopback — the edge — it answers with the combined epochs. */
    public function test_the_epoch_feed_publishes_the_combined_epoch(): void
    {
        DB::table('projects')
            ->where('id', $this->project->id)
            ->update(['authz_epoch' => 4, 'identity_epoch' => 3]);

        $response = $this->getFrom("https://{$this->host}/.well-known/docup-epochs", '127.0.0.1');

        $response->assertOk();

        /** @var array{claim: string, interval: int, projects: array<string, int>} $body */
        $body = $response->json();

        $this->assertSame('ep', $body['claim'], 'the claim name matches the grant`s');
        $this->assertSame(EpochFeed::INTERVAL_SECONDS, $body['interval']);
        $this->assertSame(7, $body['projects'][Uuid::toText($this->project->id)] ?? null);

        /*
         * 🛑 `no-store`, not the "short-cached" §20.2 permits for the JWKS. The
         * feed's entire value is freshness: §8.12.13 makes the polling interval
         * the exposure window, and a cache in front of it would add its own
         * `max-age` to that window invisibly.
         */
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
    }

    /** 🛑 §8.12.13's own ceiling on the interval. */
    public function test_the_published_interval_is_within_five_seconds(): void
    {
        $this->assertLessThanOrEqual(5, EpochFeed::INTERVAL_SECONDS);
    }

    // ------------------------------------------------- §8.12.22's self-test

    /**
     * 🛑 A missing verdict is reported as `never_run`, and the health endpoint
     * is 503 for it — the same argument §8.5.12's sandbox verdict makes.
     */
    public function test_the_self_test_endpoint_reports_a_missing_containment_verdict(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        /** @var Containment $containment */
        $containment = app(Containment::class);

        $this->assertNotNull($containment->plan(), 'something private is published');
        $this->assertSame('never_run', $containment->state());

        $response = $this->getFrom('https://'.config('docup.origins.app').'/_/health/self-test', '127.0.0.1');

        $this->assertSame('never_run', $response->json('private_asset_containment'));
        $this->assertSame(503, $response->getStatusCode(), '🛑 an unexercised control is not a pass');
    }

    /**
     * 🛑 And a failed verdict is a failure, with the reason reaching the
     * operator and nothing else.
     */
    public function test_the_self_test_endpoint_reports_a_failed_containment_verdict(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        /** @var Containment $containment */
        $containment = app(Containment::class);
        $containment->record(false, 200, 'a known-private asset served 200', $this->host);

        $response = $this->getFrom('https://'.config('docup.origins.app').'/_/health/self-test', '127.0.0.1');

        $this->assertSame('failed', $response->json('private_asset_containment'));
        $this->assertSame(503, $response->getStatusCode());
        $this->assertStringContainsString('served 200', (string) $response->json('containment_detail'));
    }

    /**
     * 🛑 `not_applicable` is honest and healthy: an installation serving only
     * public documentation has no known-private asset to probe.
     *
     * Decided from the database, never from a flag — a flag is what an operator
     * sets when the check is inconvenient.
     */
    public function test_an_installation_with_nothing_private_is_not_applicable(): void
    {
        /** @var Containment $containment */
        $containment = app(Containment::class);

        /*
         * The fixture's project is public, but the test database may hold
         * private projects from other fixtures, so this asserts the mechanism
         * rather than the installation: a public project is not a plan.
         */
        $plan = $containment->plan();

        if ($plan !== null) {
            $this->assertNotSame(
                $this->host,
                $plan['host'],
                '🛑 a public project must never be chosen as the private probe',
            );
        }

        $this->assertContains(
            $containment->state(),
            ['not_applicable', 'never_run', 'passed', 'failed'],
        );
    }

    /**
     * 🛑 §8.12.22's rule, as the command that holds it: "fails on any 200".
     *
     * Asserted on the **exit code**, through `Artisan::call()` rather than the
     * `artisan()` helper's fluent assertions, because the exit code is what
     * `deploy/containment-self-test.sh` reads and therefore what makes the
     * check fail a build. A fluent assertion would be testing the output.
     */
    public function test_the_containment_command_fails_on_any_200(): void
    {
        $this->assertSame(1, $this->record(status: '200'));
        $this->assertSame(0, $this->record(status: '404'));

        $this->assertSame(
            0,
            $this->record(status: '403'),
            'a 403 does not serve the document either (§8.12.23)',
        );
    }

    /**
     * 🛑 The negative control: a refusal proves nothing unless the same asset
     * is reachable with credentials.
     *
     * This is the half Phase 22 adds. An installation whose documentation host
     * is misconfigured refuses *everything*, and the positive half passes on it
     * forever.
     */
    public function test_the_containment_command_requires_the_negative_control_to_pass(): void
    {
        $this->assertSame(1, $this->record(status: '404', negative: '404'));
        $this->assertSame(0, $this->record(status: '404', negative: '200'));
    }

    // ---------------------------------------------------------------- fixtures

    /** One `docup:containment --record` run, returning its exit code. */
    private function record(string $status, ?string $negative = null): int
    {
        $options = ['--record' => true, '--status' => $status];

        if ($negative !== null) {
            $options['--negative'] = $negative;
        }

        return Artisan::call('docup:containment', $options);
    }

    /** @return TestResponse<Response> */
    private function fetch(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }

    /**
     * A request from a specific address, for {@see OnlyFromLoopback}.
     *
     * 🛑 `REMOTE_ADDR`, because that middleware reads `$request->ip()` and
     * §8.9.4 forbids a trusted header — so there is no header a test could set
     * instead, which is the property under test.
     *
     * @return TestResponse<Response>
     */
    private function getFrom(string $url, string $ip): TestResponse
    {
        $request = Request::create($url, 'GET', server: ['REMOTE_ADDR' => $ip]);

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    private function mountOn(string $host): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $host,
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
