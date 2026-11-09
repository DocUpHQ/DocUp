<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Branding\CascadeLevel;
use App\Branding\ResolvedFrameAncestors;
use App\Branding\ThemeRevisions;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\ArtifactHandoff;
use App\Serving\DocumentationPolicy;
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
 * 🛑 §8.14.15's documentation CSP and §8.14.16's `frame-ancestors`.
 *
 * Phase 27 built the token, validated it, emitted nothing, and recorded the
 * omission in the token's own `purpose` text: "Stored and validated; not yet
 * enforced … Until then this value protects nothing." The reason given was that
 * emitting it needs the resolved value in the routing snapshot, because a theme
 * resolution per document request is unavailable under §9.2.
 *
 * This file is the other half. It asserts the chain end to end: a project
 * publishes a theme that sets the token, the resolved value lands on the
 * project row, the routing snapshot carries it, and a documentation response
 * carries a CSP built from it.
 *
 * 🛑 It also asserts the two things that must **not** happen: no `sandbox`
 * directive at any setting (§8.14.15 forbids it, because an opaque origin
 * cannot read §8.12.10's `__Host-` reader cookie), and no `*` reaching the
 * header even if one reached the column.
 */
final class DocumentationPolicyTest extends TestCase
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
        Storage::fake('branding');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-csp-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'csp-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'CSP Co',
            'slug' => 'csp-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'CSP Demo',
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

    /** The default policy: §8.14.15's three directives and nothing else. */
    public function test_a_documentation_response_carries_the_default_policy(): void
    {
        $this->publish();

        $policy = $this->policyFor('/en/latest/');

        $this->assertStringContainsString("frame-ancestors 'self'", $policy);
        $this->assertStringContainsString("base-uri 'self'", $policy);
        $this->assertStringContainsString("object-src 'none'", $policy);

        /*
         * 🛑 And nothing else. §8.14.15 limits the default policy to those three
         * by name, with its own reason: a `script-src` here breaks Sphinx's
         * inline scripts, MathJax and Mermaid, and the bug reports that follow
         * produce "operators who disable CSP entirely".
         */
        $this->assertSame(3, substr_count($policy, ';') + 1, 'the default policy is exactly three directives');
        $this->assertStringNotContainsString('script-src', $policy);
        $this->assertStringNotContainsString('style-src', $policy);
        $this->assertStringNotContainsString('default-src', $policy);
    }

    /** 🛑 §8.14.15: `sandbox` is never emitted, at any setting. */
    public function test_sandbox_is_never_emitted(): void
    {
        $this->publish();

        foreach ([false, true] as $strict) {
            config(['docup.csp.documentation_strict' => $strict]);

            $this->assertStringNotContainsString(
                DocumentationPolicy::FORBIDDEN_DIRECTIVE,
                $this->policyFor('/en/latest/'),
                '§8.14.15 forbids CSP sandbox on documentation: an opaque origin '
                .'cannot read §8.12.10\'s __Host- reader cookie',
            );
        }
    }

    /**
     * 🛑 The whole chain: a token edit reaches the header with no rebuild.
     *
     * This is §8.14.16 doing something for the first time, and it is also the
     * §8.14 goal applied to a security header rather than to a colour: the
     * artifact is untouched, the build id does not move, and the response
     * changes.
     */
    public function test_a_published_token_reaches_the_header(): void
    {
        $this->publish();

        $this->assertStringContainsString("frame-ancestors 'self'", $this->policyFor('/en/latest/'));

        $this->publishProjectTheme([
            'security.frame-ancestors' => "'self' https://partner.example.com",
        ]);

        // The resolved value is on the row, written by the publish.
        $project = Project::withoutGlobalScopes()->whereKey($this->project->id)->firstOrFail();

        $this->assertSame(
            "'self' https://partner.example.com",
            $project->resolved_frame_ancestors,
            'the theme publish reconciles the resolved column',
        );

        Cache::flush();

        $this->assertStringContainsString(
            "frame-ancestors 'self' https://partner.example.com",
            $this->policyFor('/en/latest/'),
        );
    }

    /**
     * 🛑 §8.14.16: "never `*`", enforced at emission as well as at authoring.
     *
     * The grammar refuses a wildcard when a token is written. This asserts the
     * second half: a value that reached the column by some other route — a
     * hand-written UPDATE, a backup restored from before the grammar existed —
     * is replaced by the default rather than emitted. `frame-ancestors *` is
     * indistinguishable from no policy, so the failure would be silent.
     */
    public function test_a_wildcard_in_the_column_never_reaches_the_header(): void
    {
        $this->publish();

        foreach (['*', "'self' *", "'self'; script-src *"] as $hostile) {
            DB::table('projects')
                ->where('id', $this->project->id)
                ->update(['resolved_frame_ancestors' => $hostile]);

            Cache::flush();

            $policy = $this->policyFor('/en/latest/');

            $this->assertStringContainsString("frame-ancestors 'self'", $policy);
            $this->assertStringNotContainsString('*', $policy, 'stored: '.$hostile);
            $this->assertStringNotContainsString('script-src', $policy, 'stored: '.$hostile);
        }
    }

    /** §8.14.10's strict set, behind the opt-in. */
    public function test_strict_mode_adds_the_exfiltration_set(): void
    {
        $this->publish();

        $permissive = $this->policyFor('/en/latest/');

        $this->assertStringNotContainsString('img-src', $permissive, '§8.14.15: permissive by default');

        config(['docup.csp.documentation_strict' => true]);

        $strict = $this->policyFor('/en/latest/');

        $this->assertStringContainsString("img-src 'self' data:", $strict);
        $this->assertStringContainsString("font-src 'self'", $strict);
        $this->assertStringContainsString("connect-src 'self'", $strict);

        // §8.14.10 names the asset host explicitly, so an uploaded logo still
        // renders under the strict policy.
        $this->assertStringContainsString('img-src', $strict);
        $this->assertMatchesRegularExpression("/img-src 'self' data: https?:\\/\\//", $strict);
    }

    /**
     * 🛑 The header is on every served file, not only on HTML.
     *
     * An asset reachable in a frame is a reader's session reachable in a frame,
     * and a reader cannot tell which URL an attacker chose to embed.
     */
    public function test_the_policy_is_on_an_asset_as_well_as_a_document(): void
    {
        $this->publish(['html/assets/site.css' => "body{color:#222}\n"]);

        $this->assertStringContainsString(
            'frame-ancestors',
            $this->policyFor('/en/latest/assets/site.css'),
        );
    }

    /**
     * 🛑 The edge must re-emit it, and Phase 04 already arranged that.
     *
     * `Content-Security-Policy` has been in {@see ArtifactHandoff}'s preserved
     * and nginx-re-emitted lists since Phase 04 — carried for a header nothing
     * yet sent. Asserted here because that is the only reason this phase
     * changes no edge configuration, and §18.18's finding is that nginx
     * "replaces the entire response header set" on an internal redirect: a CSP
     * that was not re-emitted would be absent in exactly the deployment this
     * header matters for.
     */
    public function test_the_edge_contract_already_carries_the_header(): void
    {
        $this->assertContains(DocumentationPolicy::HEADER, ArtifactHandoff::PRESERVED_HEADERS);
        $this->assertContains(DocumentationPolicy::HEADER, ArtifactHandoff::NGINX_REEMITTED_HEADERS);
    }

    /** A project that never published a theme still gets §8.14.16's default. */
    public function test_an_unreconciled_project_reads_as_the_default(): void
    {
        $this->publish();

        $project = Project::withoutGlobalScopes()->whereKey($this->project->id)->firstOrFail();

        $this->assertNull($project->resolved_frame_ancestors, 'nothing has reconciled it');
        $this->assertStringContainsString(
            'frame-ancestors '.ResolvedFrameAncestors::DEFAULT,
            $this->policyFor('/en/latest/'),
        );
    }

    // ------------------------------------------------------------- helpers

    private function policyFor(string $path): string
    {
        $response = $this->getExactly('http://'.$this->host.$path);

        $response->assertOk();

        $policy = $response->headers->get(DocumentationPolicy::HEADER);

        $this->assertIsString($policy, 'every documentation response carries a CSP');

        return $policy;
    }

    /** @return TestResponse<Response> */
    private function getExactly(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse($this->app->handle(Request::create($url, 'GET')));
    }

    /** @param array<string, string> $extra */
    private function publish(array $extra = []): void
    {
        $writer = (new ArchiveWriter)->add(
            'html/index.html',
            '<!doctype html><html><head></head><body>doc</body></html>',
        );

        foreach ($extra as $path => $contents) {
            $writer->add($path, $contents);
        }

        $archive = $writer->toTarGz($this->fixtures.'/tree-'.bin2hex(random_bytes(3)).'.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version, $archive);
        $this->version->refresh();

        $this->context->forget();
    }

    /** @param array<string, mixed> $tokens */
    private function publishProjectTheme(array $tokens): void
    {
        $this->context->for($this->organisation->id);

        $revisions = ThemeRevisions::make((string) $this->organisation->id, (string) $this->project->id);

        $revisions->publish($revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: $tokens,
        ));

        $this->context->forget();
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

        $this->context->forget();
    }
}
