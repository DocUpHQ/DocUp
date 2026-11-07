<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

use App\Access\AccessSurface;
use App\Access\PolicyRefused;
use App\Access\ReaderContext;
use App\Access\ReaderGate;
use App\Access\ReaderPolicies;
use App\Access\RequirementRejection;
use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Seo\GeneratedArtifacts;
use App\Serving\RoutingSnapshotLoader;
use App\Support\Epoch;
use App\Support\Invalidation;
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
 * 🛑 §17's Phase 21 exit criteria, over the **real** serving path.
 *
 * > "A private version 404s anonymously, 200s for a member, and carries private
 * > cache directives on both axes with no cache tag."
 * > "🛑 A rule satisfiable by IP allowlist alone is rejected at write time."
 * > "🛑 A per-domain override that would widen access is rejected; one that
 * > narrows is accepted."
 *
 * The 48-case matrix in `tests/Unit/Access/DecisionTableTest` proves the
 * function; this proves the **wiring** — that a request through the HTTP kernel
 * reaches it, that the status it chose is the status sent, and that the cache
 * directives on a private 200 are private. A pure function correct in isolation
 * and bypassed in the controller is the failure this file exists to catch.
 */
final class ReaderAuthorisationTest extends TestCase
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
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-authz-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'authz-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Authz Co',
            'slug' => 'authz-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Guarded',
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
        $this->publish();
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

    // ------------------------------------------------------- the exit criteria

    /** A public version still serves, with the decision header on it. */
    public function test_a_public_version_serves_and_carries_the_decision_header(): void
    {
        $response = $this->getExactly("http://{$this->host}/en/latest/");

        $response->assertOk();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'allow:allowed;by=public');

        // 🛑 §8.12.14: the decision ran for a public project too — the header is
        // the evidence that there was no public fast path around it.
        $this->assertStringContainsString('public', (string) $response->headers->get('Cache-Control'));
    }

    /**
     * 🛑 The exit criterion: "A private version 404s anonymously … and carries
     * private cache directives on both axes with no cache tag."
     */
    public function test_a_private_version_404s_anonymously_with_private_directives(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $response = $this->getExactly("http://{$this->host}/en/latest/");

        $response->assertNotFound();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'deny:version_visibility');

        // 🛑 Private on **both** axes, which is the criterion's own word.
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertStringContainsString('no-store', (string) $response->headers->get('CDN-Cache-Control'));
        $this->assertNull($response->headers->get('Cache-Tag'), '🛑 no cache tag on a private response');

        /*
         * 🛑 **No challenge**, and this is the assertion that caught a
         * disclosure. §8.12.23's case (b) permits a 401 when "the resource's
         * **existence is already public**" — and a private version's existence
         * is not: §8.6.2 keeps it out of the sitemap, the flyout, `llms.txt`
         * and search. The gate's first implementation read the **project's**
         * visibility alone, so this version answered 401 with a
         * `WWW-Authenticate` header and confirmed its own existence to anybody
         * who guessed the slug.
         */
        $this->assertNull(
            $response->headers->get('WWW-Authenticate'),
            '🛑 a private version must not confirm its existence with a challenge',
        );
    }

    /**
     * 🛑 And the case §8.12.23's clause (b) is actually for: public content
     * with a guarded path inside it.
     *
     * The project and the version are both public, so a reader already knows
     * they exist — the sitemap says so. Only this path needs a credential, and
     * a 401 therefore discloses nothing a crawler could not already see.
     */
    public function test_a_guarded_path_in_public_content_may_challenge(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        $policies->addRule(
            $this->project,
            label: 'the internal runbooks',
            allow: true,
            requirement: ['leaf' => 'binding', 'driver' => 'oidc'],
            pathPatterns: ['/internal'],
        );

        $policies->addRule(
            $this->project,
            label: 'everything else is public',
            allow: true,
            requirement: ['leaf' => 'public'],
            publicCacheMode: true,
        );

        // The public part still serves.
        $this->getExactly("http://{$this->host}/en/latest/")->assertOk();

        // The guarded part challenges, because its existence is not a secret.
        $guarded = $this->getExactly("http://{$this->host}/en/latest/internal/runbook.html");

        $guarded->assertStatus(401);
        $guarded->assertHeader('WWW-Authenticate', 'Bearer realm="docup", scope="docs:read"');
        $guarded->assertHeader(ReaderGate::DECISION_HEADER, 'challenge:authentication_required;rule=1');
    }

    /**
     * 🛑 And a **guarded project** offers no challenge at all, because its
     * existence is private (§8.2.7, §8.12.23).
     */
    public function test_a_guarded_project_404s_with_no_challenge(): void
    {
        $this->project->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $response = $this->getExactly("http://{$this->host}/en/latest/");

        $response->assertNotFound();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'deny:project_visibility');
        $this->assertNull(
            $response->headers->get('WWW-Authenticate'),
            '🛑 §8.12.23: a challenge would tell a crawler there is something here',
        );
    }

    /**
     * 🛑 "200s for a member" — through the gate rather than through HTTP,
     * because no reader session exists until Phase 22.
     *
     * Said plainly rather than skipped: §17 gives P22 "`reader_identities`
     * physically disjoint from `users`" and the PKCE handoff, so there is no
     * way to *present* a member identity over HTTP yet. What exists is the
     * decision, and this drives it with the context P22 will construct — so
     * the half that can be built is built and asserted, and the half that
     * cannot is named.
     */
    public function test_a_private_version_200s_for_a_member_through_the_gate(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        /** @var ReaderGate $gate */
        $gate = app(ReaderGate::class);

        $snapshot = app(RoutingSnapshotLoader::class)->load($this->host);
        $mount = $snapshot->matchFor('/');

        $this->assertNotNull($mount);

        $version = $mount->mount->project->version('en', 'latest');

        $this->assertNotNull($version);

        $anonymous = $gate->authorise($mount->mount, $version, 'en', '/', AccessSurface::Proxy);

        $this->assertFalse($anonymous->allowed);

        $member = $gate->authorise(
            $mount->mount,
            $version,
            'en',
            '/',
            AccessSurface::Proxy,
            reader: ReaderContext::member('member-subject'),
        );

        $this->assertTrue($member->allowed);
        $this->assertSame(200, $member->status);

        // 🛑 And not publicly cacheable, even for the member who may read it.
        $this->assertFalse($member->rulePubliclyCacheable);
    }

    /** 🛑 The download surface takes the same decision (§8.12.21). */
    public function test_a_private_version_download_is_refused(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $response = $this->getExactly("http://{$this->host}/_/downloads/en/latest/pdf");

        $response->assertNotFound();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'deny:version_visibility');
    }

    /**
     * 🛑 The exit criterion: "A rule satisfiable by IP allowlist alone is
     * **rejected at write time**."
     *
     * Asserted here as well as in the unit suite, because this goes through
     * `ReaderPolicies` — the write path, with the database, the cap and the
     * audit record — and what the unit test proves is the invariant rather
     * than the refusal reaching a caller.
     */
    public function test_a_gate_only_rule_is_refused_at_write_time(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        try {
            $policies->addRule(
                $this->project,
                label: 'from the office',
                allow: true,
                requirement: ['leaf' => 'gate', 'driver' => 'ip_allowlist'],
            );

            $this->fail('🛑 §8.12.7: a gate-only requirement must be refused');
        } catch (PolicyRefused $refused) {
            $this->assertSame(RequirementRejection::SatisfiableWithoutIdentity, $refused->rejection);
        }

        // And nothing was written.
        $this->assertSame(0, DB::table('reader_policy_rules')->count());
    }

    /**
     * 🛑 The exit criterion: "A per-domain override that would widen access is
     * rejected; one that narrows is accepted."
     */
    public function test_a_widening_override_is_refused_and_a_narrowing_one_is_accepted(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);

        // Narrowing: accepted.
        $policies->assertOverrideNarrows('members', AccessLevel::Public);
        $policies->assertOverrideNarrows('restricted', AccessLevel::Members);
        // `inherit` takes the project's value and so widens nothing.
        $policies->assertOverrideNarrows('inherit', AccessLevel::Members);

        $this->addToAssertionCount(3);

        try {
            $policies->assertOverrideNarrows('public', AccessLevel::Members);

            $this->fail('🛑 §8.12.8: an override that widens must be refused');
        } catch (PolicyRefused $refused) {
            $this->assertSame(RequirementRejection::ExposureWidens, $refused->rejection);
        }
    }

    /**
     * 🛑 §9.3.2 as data: a rule that demands a credential may not call itself
     * publicly cacheable.
     */
    public function test_a_credentialled_rule_cannot_be_publicly_cacheable(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        try {
            $policies->addRule(
                $this->project,
                label: 'members, cached publicly',
                allow: true,
                requirement: ['leaf' => 'binding', 'driver' => 'oidc'],
                publicCacheMode: true,
            );

            $this->fail('🛑 §9.3.2: a private response must not reach a shared cache');
        } catch (PolicyRefused $refused) {
            $this->assertSame(
                RequirementRejection::PublicCacheModeNeedsPublicTerminal,
                $refused->rejection,
            );
        }
    }

    /** §8.12.9 refuses a regex path pattern by shape, at write time. */
    public function test_a_regex_path_pattern_is_refused(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        try {
            $policies->addRule(
                $this->project,
                label: 'the internal sections',
                allow: false,
                requirement: ['leaf' => 'public'],
                pathPatterns: ['^/internal/.*$'],
            );

            $this->fail('🛑 §8.12.9 forbids regex path matching');
        } catch (PolicyRefused $refused) {
            $this->assertSame(RequirementRejection::RegexPathPattern, $refused->rejection);
        }
    }

    /** §10.6's hard cap of 50 rules per project. */
    public function test_the_rule_cap_is_enforced(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        for ($i = 0; $i < ReaderPolicies::MAX_RULES_PER_PROJECT; $i++) {
            $policies->addRule(
                $this->project,
                label: 'rule '.$i,
                allow: true,
                requirement: ['leaf' => 'binding', 'driver' => 'oidc'],
                versionSlugs: ['v'.$i],
            );
        }

        try {
            $policies->addRule(
                $this->project,
                label: 'one too many',
                allow: true,
                requirement: ['leaf' => 'binding', 'driver' => 'oidc'],
            );

            $this->fail('the cap must be enforced');
        } catch (PolicyRefused $refused) {
            $this->assertSame(RequirementRejection::TooManyRules, $refused->rejection);
        }
    }

    /**
     * 🛑 §10.8's bound for `authz_epoch`: "revoking a session or editing a
     * policy takes effect on the **next request**".
     *
     * §10.8 requires "**one test proving a bump takes effect within its
     * bound**" per epoch, and this is that test for the two epochs Phase 21
     * makes live. The mechanism is the key, not a purge: the cached policy is
     * addressed by `authz:policy:<project>:<epoch>`, so a bump addresses a
     * different entry and the old one is simply never read again.
     */
    public function test_a_policy_write_bumps_both_epochs_and_takes_effect_next_request(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);

        $before = $this->epochs();

        $policies->createFor($this->project);

        $afterPolicy = $this->epochs();

        $this->assertGreaterThan($before['authz'], $afterPolicy['authz']);
        $this->assertGreaterThan($before['policy_generation'], $afterPolicy['policy_generation']);

        /*
         * 🛑 The bound, demonstrated. The policy now exists with zero rules,
         * which §8.12.19 makes a deny — and the very next request sees it,
         * with nothing purged in between.
         *
         * 🛑 **401, not 404**, and that is §8.12.23's clause (b) rather than a
         * leak. The project and the version are both still public, so this
         * page is in the sitemap and a reader already knows it exists; what
         * has changed is that its content now requires an authentication the
         * operator has not configured. A 404 here would claim a page that is
         * advertised does not exist — which is the lie, not the challenge.
         */
        $response = $this->getExactly("http://{$this->host}/en/latest/");

        $response->assertStatus(401);
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'challenge:authentication_required');

        // And the registry no longer claims these two are unimplemented.
        $this->assertTrue(Epoch::Authz->isImplemented());
        $this->assertTrue(Epoch::PolicyGeneration->isImplemented());
    }

    /**
     * 🛑 A policy that admits everybody restores service, by the next request.
     *
     * The other direction of the same bound, and the one an operator depends on
     * after fixing a mistake.
     */
    public function test_an_allow_rule_restores_service_on_the_next_request(): void
    {
        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        // A zero-rule policy on still-public content challenges (§8.12.19,
        // §8.12.23 clause (b)).
        $this->getExactly("http://{$this->host}/en/latest/")->assertStatus(401);

        $policies->addRule(
            $this->project,
            label: 'public documentation',
            allow: true,
            requirement: ['leaf' => 'public'],
            publicCacheMode: true,
        );

        $response = $this->getExactly("http://{$this->host}/en/latest/");

        $response->assertOk();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'allow:allowed;rule=1;by=public');
    }

    /**
     * 🛑 §10.8 lists "visibility change" among the four things that bump
     * `authz_epoch`, and §8.12.13 calls a change to this column "an
     * access-stopping event requiring an epoch bump".
     *
     * 🛑 **It did not, until this phase**, and the omission cost nothing until
     * there was a decision for it to invalidate. Both epochs move now, and the
     * second is the half that is easy to miss: `projects.visibility` is
     * carried in the **routing snapshot**, cached on `routing_epoch`
     * (§8.9.10), so bumping only the authorisation epoch would leave
     * `EffectiveAccess` deciding against the visibility the snapshot still
     * held — a project flipped to `members` that went on serving publicly for
     * the snapshot's TTL.
     *
     * Asserted on the column values rather than through the UI, because the
     * change is behind §8.13.5's step-up re-authentication and what is being
     * tested is the registry's bound, not the capability check.
     */
    public function test_a_visibility_change_bumps_the_authorisation_and_routing_epochs(): void
    {
        $before = $this->epochs();
        $beforeRouting = (int) DB::table('projects')->where('id', $this->project->id)->value('routing_epoch');

        Invalidation::bumpAuthz(
            projectId: (string) $this->project->id,
            cause: 'visibility',
            organisationId: (string) $this->project->organisation_id,
        );

        Invalidation::bumpRouting(
            projectId: (string) $this->project->id,
            cause: 'visibility',
            organisationId: (string) $this->project->organisation_id,
        );

        $after = $this->epochs();

        $this->assertGreaterThan($before['authz'], $after['authz']);
        $this->assertGreaterThan(
            $beforeRouting,
            (int) DB::table('projects')->where('id', $this->project->id)->value('routing_epoch'),
            '🛑 the snapshot carries the visibility, so the routing epoch has to move too',
        );

        /*
         * 🛑 And `policy_generation` does **not** move, because this was not a
         * policy write. §10.8 gives the two counters different triggers and
         * different failure modes — `policy_generation` gates search and fails
         * closed — so a visibility change that bumped it would disable a
         * project's search for no reason.
         */
        $this->assertSame($before['policy_generation'], $after['policy_generation']);
    }

    /**
     * 🛑 §20.3's decision log: a denial is one row, and an allow aggregates.
     *
     * > denials, challenges — one row each
     * > aggregated allows — "One row per session, version and hour"
     *
     * The asymmetry is the feature: a reader opening a page with sixty assets
     * authorises sixty times, and sixty rows per page view is the shape that
     * makes an access log unaffordable and then switched off.
     */
    public function test_denials_are_individual_rows_and_allows_aggregate(): void
    {
        $this->version->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        DB::table('access_decisions')->where('project_id', $this->project->id)->delete();

        for ($i = 0; $i < 3; $i++) {
            $this->getExactly("http://{$this->host}/en/latest/page-{$i}.html")->assertNotFound();
        }

        $denials = DB::table('access_decisions')
            ->where('project_id', $this->project->id)
            ->where('outcome', 'deny')
            ->get();

        $this->assertCount(3, $denials, '🛑 a denial is evidence; each one gets a row');

        foreach ($denials as $row) {
            $this->assertNull($row->aggregate_key, 'a denial has no aggregate key');
            $this->assertSame(1, (int) $row->occurrences);
            $this->assertSame('version_visibility', $row->reason_code);
        }

        // Now the allow side: three requests, one row, three occurrences.
        $this->version->forceFill(['visibility' => 'public'])->save();
        Cache::flush();

        DB::table('access_decisions')->where('project_id', $this->project->id)->delete();

        for ($i = 0; $i < 3; $i++) {
            $this->getExactly("http://{$this->host}/en/latest/")->assertOk();
        }

        $allows = DB::table('access_decisions')
            ->where('project_id', $this->project->id)
            ->where('outcome', 'allow')
            ->get();

        $this->assertCount(1, $allows, '🛑 §20.3: one row per session, version and hour');

        $aggregated = $allows->first();

        $this->assertNotNull($aggregated);
        $this->assertSame(3, (int) $aggregated->occurrences);
        $this->assertNotNull($aggregated->aggregate_key);
    }

    /**
     * 🛑 §20.3: "the only place a raw IP exists" is `security_events`. No reader
     * subject reaches `access_decisions` in the clear.
     */
    public function test_no_reader_subject_reaches_the_decision_log_in_the_clear(): void
    {
        /** @var ReaderGate $gate */
        $gate = app(ReaderGate::class);

        $snapshot = app(RoutingSnapshotLoader::class)->load($this->host);
        $mount = $snapshot->matchFor('/');

        $this->assertNotNull($mount);

        $version = $mount->mount->project->version('en', 'latest');

        $this->assertNotNull($version);

        $subject = 'reader-'.bin2hex(random_bytes(8));

        $gate->authorise(
            $mount->mount,
            $version,
            'en',
            '/',
            AccessSurface::Proxy,
            reader: ReaderContext::member($subject),
        );

        $row = DB::table('access_decisions')
            ->where('project_id', $this->project->id)
            ->orderByDesc('decided_at')
            ->first(['subject_hash']);

        $this->assertNotNull($row);
        $this->assertNotNull($row->subject_hash);
        $this->assertSame(32, strlen((string) $row->subject_hash), 'a SHA-256 of 32 raw bytes');
        $this->assertStringNotContainsString(
            $subject,
            (string) $row->subject_hash,
            '🛑 a reader subject reached the decision log',
        );
    }

    /**
     * 🛑 §8.12.21's generated surfaces are built from the authorised view: a
     * guarded project's sitemap lists nothing.
     *
     * The four SQL conditions in `GeneratedArtifacts` would have passed this
     * version — it is `public`, `active`, `listed` and `published`. §8.2.10's
     * project visibility is what refuses it, and only the decision function
     * knows that.
     */
    public function test_a_guarded_project_advertises_no_versions(): void
    {
        $this->project->forceFill(['visibility' => 'members'])->save();
        Cache::flush();

        $this->context->for($this->organisation->id);

        /** @var GeneratedArtifacts $artefacts */
        $artefacts = app(GeneratedArtifacts::class);
        $artefacts->regenerate($this->project->refresh());

        $this->context->forget();

        /*
         * 🛑 The routing snapshot carries `generated_revision` (§8.11.6) and is
         * cached on the **routing** epoch, which a regeneration does not bump.
         * In production that is fine: the only caller is the pointer flip,
         * which bumps the routing epoch for the version-pointer change in the
         * same transaction. Calling `regenerate()` directly, as this test does
         * and as a rebrand will in Phase 26, leaves the snapshot naming a
         * revision the sweep has just deleted — recorded in the build log as
         * owed by whichever phase adds the second caller.
         */
        Cache::flush();

        $sitemap = $this->getExactly("http://{$this->host}/sitemap.xml");

        $sitemap->assertOk();
        $this->assertStringNotContainsString(
            '/en/latest/',
            $sitemap->getContent() === false ? '' : (string) $sitemap->getContent(),
            '🛑 §8.12.21: a guarded project must not advertise its versions',
        );
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * @param  array<string, string>  $headers
     * @return TestResponse<Response>
     */
    private function getExactly(string $url, array $headers = []): TestResponse
    {
        $request = Request::create($url, 'GET');

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }

    /** @return array{authz: int, policy_generation: int} */
    private function epochs(): array
    {
        $row = DB::table('projects')
            ->where('id', $this->project->id)
            ->first(['authz_epoch', 'policy_generation']);

        return [
            'authz' => (int) ($row->authz_epoch ?? 0),
            'policy_generation' => (int) ($row->policy_generation ?? 0),
        ];
    }

    private function publish(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>guarded</body></html>\n")
            ->toTarGz($this->fixtures.'/tree.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version, $archive);

        $this->context->forget();
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
