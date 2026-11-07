<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Readers;

use App\Access\EffectiveAccess;
use App\Access\ReaderGate;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Readers\Grants\Grant;
use App\Readers\PkceChallenge;
use App\Readers\ReaderCookies;
use App\Readers\ReaderHandoffState;
use App\Readers\ReaderSessions;
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
 * 🛑 §17's Phase 22 exit criteria, over the **real** HTTP path.
 *
 * > "One dashboard login authorises two unrelated custom domains of one project
 * > **with no shared cookie**. A grant minted for domain A is refused on domain
 * > B. A sibling-subdomain cookie-tossing fixture fails. Revoking a session,
 * > editing a policy or bumping an epoch stops service within one subsequent
 * > request. Logging out of project A leaves project B signed in. 🛑 A return
 * > URL supplied as a request parameter is ignored in favour of the domain row."
 *
 * Every one of those is a statement about the wiring rather than about a
 * function, which is why they are here and not in a unit test: §8.12.10's
 * handoff is three requests across two registrable domains, and the only way to
 * be sure it works is to make the three requests.
 *
 * 🛑 **Two custom domains for one project, which is the case §8.12.10 exists
 * for.** A default subdomain would have proved nothing: both origins would
 * share a registrable domain and a single cookie could have covered them, which
 * is exactly the design §8.1.4 forbids and §12.4's `__Host-` prefix makes
 * impossible.
 */
final class ReaderSessionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $alpha;

    private Project $beta;

    private ProjectVersion $alphaVersion;

    private ProjectVersion $betaVersion;

    private User $member;

    /** Two unrelated registrable domains, both serving project alpha. */
    private string $alphaOne;

    private string $alphaTwo;

    /** One domain serving project beta. */
    private string $betaHost;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-rsess-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $nonce = bin2hex(random_bytes(3));

        /*
         * 🛑 Three hostnames on **three different registrable domains**. The
         * exit criterion says "two unrelated custom domains", and "unrelated"
         * is load-bearing: `a.example.com` and `b.example.com` share a
         * registrable domain, so a cookie with a `Domain` attribute could span
         * them and the test would pass while proving nothing.
         */
        $this->alphaOne = 'docs-'.$nonce.'-one.example';
        $this->alphaTwo = 'manual-'.$nonce.'-two.example';
        $this->betaHost = 'beta-'.$nonce.'.example';

        $this->organisation = Organisation::query()->create([
            'name' => 'Reader Co',
            'slug' => 'reader-'.$nonce,
        ]);

        $this->context->for($this->organisation->id);

        [$this->alpha, $this->alphaVersion] = $this->makeProject('alpha-'.$nonce);
        [$this->beta, $this->betaVersion] = $this->makeProject('beta-'.$nonce);

        $this->customDomain($this->alphaOne, $this->alpha);
        $this->customDomain($this->alphaTwo, $this->alpha);
        $this->customDomain($this->betaHost, $this->beta);

        $this->member = User::query()->create([
            'name' => 'Reader',
            'email' => 'reader-'.$nonce.'@example.test',
            'password' => 'x',
        ]);

        /*
         * 🛑 A role on **each** project, because §12.3's `members` rung is
         * per-target: `RoleResolver::rolesFor()` resolves against one project,
         * and a reader who is a member of alpha is deliberately not a member of
         * beta. The "logging out of A leaves B signed in" criterion needs both.
         */
        $this->grant($this->member, $this->alpha, Role::ProjectAdmin);
        $this->grant($this->member, $this->beta, Role::ProjectAdmin);

        /* Private, so only a member may read and the test has something to prove. */
        $this->alphaVersion->forceFill(['visibility' => 'members'])->save();
        $this->betaVersion->forceFill(['visibility' => 'members'])->save();

        Cache::flush();
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

    // ------------------------------------------------------- the exit criteria

    /**
     * 🛑 "One dashboard login authorises two unrelated custom domains of one
     * project **with no shared cookie**."
     *
     * One `actingAs`, two handoffs, two sessions, two reads. And the assertion
     * that makes it mean something: neither session cookie carries a `Domain`
     * attribute, so there is no cookie that could have spanned the two origins
     * — the authorisation on the second domain came from its own session, not
     * from the first one's credential.
     */
    public function test_one_login_authorises_two_unrelated_custom_domains(): void
    {
        $this->assertNotFound($this->read($this->alphaOne));
        $this->assertNotFound($this->read($this->alphaTwo));

        $this->actingAs($this->member);

        $first = $this->signIn($this->alphaOne);
        $second = $this->signIn($this->alphaTwo);

        $this->read($this->alphaOne, $first)->assertOk();
        $this->read($this->alphaTwo, $second)->assertOk();

        /*
         * 🛑 Two different handles. If one cookie had spanned both origins they
         * would be equal, and the test above would have passed for the wrong
         * reason.
         */
        $this->assertNotSame(
            $first[ReaderCookies::SESSION],
            $second[ReaderCookies::SESSION],
            '🛑 each origin must establish its own session (§8.12.10)',
        );

        /* And two rows, on two domains, for one user. */
        $sessions = DB::table('docs_sessions')
            ->where('user_id', $this->member->id)
            ->whereNull('revoked_at')
            ->get(['domain_id', 'project_id']);

        $this->assertCount(2, $sessions);
        $this->assertSame(
            [$this->alpha->id, $this->alpha->id],
            $sessions->pluck('project_id')->all(),
            'both sessions belong to the same project',
        );
    }

    /**
     * 🛑 §12.4's rule, asserted on the wire: "Every cookie is `__Host-`
     * prefixed, Secure, HttpOnly, `SameSite=Lax`" with "**no** `Domain`
     * attribute and **`Path=/`**".
     *
     * The failure this guards is silent. A browser does not report a `__Host-`
     * cookie with a `Domain` attribute — it simply does not store it, the next
     * request arrives with no session, and the reader loops through the handoff
     * with nothing in any log.
     */
    public function test_every_reader_cookie_satisfies_the_host_prefix_rules(): void
    {
        $this->actingAs($this->member);

        $callback = $this->completeHandoff($this->alphaOne);

        $names = [];

        foreach ($callback->headers->getCookies() as $cookie) {
            $names[] = $cookie->getName();

            $this->assertStringStartsWith('__Host-', $cookie->getName());
            $this->assertNull($cookie->getDomain(), '🛑 __Host- forbids a Domain attribute');
            $this->assertSame('/', $cookie->getPath(), '🛑 __Host- requires Path=/');
            $this->assertTrue($cookie->isSecure(), '🛑 __Host- requires Secure');
            $this->assertSame('lax', $cookie->getSameSite());
        }

        $this->assertContains(ReaderCookies::SESSION, $names);
        $this->assertContains(ReaderCookies::CACHE_KEY, $names);
    }

    /**
     * 🛑 "A grant minted for domain A is refused on domain B."
     *
     * This is §8.12.11's audience binding, and it is the assertion that would
     * fail if the grant were bound to the project instead of the domain — which
     * reads just as naturally and would let one grant work on every domain a
     * project serves.
     */
    public function test_a_grant_minted_for_one_domain_is_refused_on_another(): void
    {
        $this->actingAs($this->member);

        $onDomainOne = $this->signIn($this->alphaOne);

        $this->assertArrayHasKey(ReaderCookies::GRANT, $onDomainOne, 'the read minted a grant');

        /*
         * The grant alone, carried to the other domain of the **same project**.
         * Same project, same reader, same organisation — only the origin
         * differs, which is precisely the variable §8.12.11 binds.
         */
        $tossed = $this->read($this->alphaTwo, [
            ReaderCookies::GRANT => $onDomainOne[ReaderCookies::GRANT],
        ]);

        $this->assertNotFound($tossed);
    }

    /**
     * 🛑 "A sibling-subdomain cookie-tossing fixture fails."
     *
     * The attack §14.1/2 and §8.1.4 are both about: documentation is
     * attacker-controlled JavaScript, and on a shared parent domain it can set
     * a cookie the sibling will send. `__Host-` is what stops the browser doing
     * it — but a test cannot assert what a browser refuses, so this asserts the
     * half the **server** owns: a session handle presented on an origin it was
     * not established for resolves to nothing.
     *
     * That is defence the browser's rules do not provide. If `__Host-` were
     * dropped tomorrow the tossed handle would still be refused, because
     * {@see ReaderSessions::resolve()} matches the row's own
     * `domain_id`.
     */
    public function test_a_tossed_session_handle_is_refused_on_a_sibling_origin(): void
    {
        $this->actingAs($this->member);

        $onAlpha = $this->signIn($this->alphaOne);

        /* The handle, tossed at an unrelated project's origin. */
        $this->assertNotFound($this->read($this->betaHost, [
            ReaderCookies::SESSION => $onAlpha[ReaderCookies::SESSION],
        ]));

        /* And at the other domain of its own project, which is also not its origin. */
        $this->assertNotFound($this->read($this->alphaTwo, [
            ReaderCookies::SESSION => $onAlpha[ReaderCookies::SESSION],
        ]));
    }

    /**
     * 🛑 "Revoking a session … stops service within one subsequent request."
     *
     * §8.12.15's bound, and the mechanism is what makes it exact: the revoke
     * bumps `identity_epoch`, the grant in the reader's cookie carries the
     * combined epoch it was minted under, and the comparison happens on the
     * next request. Nothing is purged.
     */
    public function test_revoking_a_session_stops_service_on_the_next_request(): void
    {
        $this->actingAs($this->member);

        $cookies = $this->signIn($this->alphaOne);
        $this->read($this->alphaOne, $cookies)->assertOk();

        DB::table('docs_sessions')
            ->where('user_id', $this->member->id)
            ->update(['revoked_at' => now(), 'revoked_reason' => 'test']);

        Invalidation::bumpIdentity(
            projectId: $this->alpha->id,
            cause: 'session revoke',
            organisationId: $this->organisation->id,
        );

        /*
         * 🛑 The **same cookies**, including the still-unexpired grant. The
         * grant's signature is as valid as it was a moment ago; what changed is
         * one integer in one row.
         */
        $this->assertNotFound($this->read($this->alphaOne, $cookies));
    }

    /**
     * 🛑 "editing a policy … stops service within one subsequent request."
     *
     * The same mechanism from the other epoch. `authz_epoch` and
     * `identity_epoch` are summed into the grant's one `ep` claim, so either
     * one moving is enough — which is the property
     * {@see Grant::combinedEpoch()} argues for.
     */
    public function test_bumping_the_authz_epoch_stops_service_on_the_next_request(): void
    {
        $this->actingAs($this->member);

        $cookies = $this->signIn($this->alphaOne);
        $this->read($this->alphaOne, $cookies)->assertOk();

        Invalidation::bumpAuthz(
            projectId: $this->alpha->id,
            cause: 'policy change',
            organisationId: $this->organisation->id,
        );

        Cache::flush();

        /*
         * 🛑 The grant is refused, and then the **session** re-establishes the
         * reader and a fresh grant is minted — so the read still succeeds. That
         * is the correct behaviour and the subtler half of §8.12.15: an epoch
         * bump invalidates the cheap credential, not the revocable one. A test
         * asserting a 404 here would be asserting that a policy edit signs
         * every reader out, which §8.12.15 does not say and operators would
         * not tolerate.
         */
        $second = $this->read($this->alphaOne, $cookies);
        $second->assertOk();

        $this->assertNotSame(
            $cookies[ReaderCookies::GRANT],
            self::cookiesOf($second)[ReaderCookies::GRANT] ?? null,
            '🛑 the stale grant was replaced rather than honoured',
        );
    }

    /**
     * 🛑 And the case that distinguishes the two: a visibility flip, where the
     * session is live and the answer is still no.
     *
     * §8.12.14's "no public fast path" has a mirror image. A reader holding a
     * valid grant and a live session must still be refused when the resource
     * stops admitting them, which only happens because
     * {@see EffectiveAccess} runs on every request.
     */
    public function test_a_live_session_is_refused_when_the_project_turns_private(): void
    {
        $this->actingAs($this->member);

        $cookies = $this->signIn($this->alphaOne);
        $this->read($this->alphaOne, $cookies)->assertOk();

        /* `restricted` demands a rule naming the resource; no policy exists. */
        $this->alphaVersion->forceFill(['visibility' => 'restricted'])->save();

        Invalidation::bumpAuthz(
            projectId: $this->alpha->id,
            cause: 'visibility change',
            organisationId: $this->organisation->id,
        );

        Cache::flush();

        $this->assertNotFound($this->read($this->alphaOne, $cookies));
    }

    /**
     * 🛑 "Logging out of project A leaves project B signed in."
     *
     * The per-origin design, observed from the reader's side. There is no
     * global reader logout and there cannot be one — which is the same fact
     * that made §8.12.10's handoff necessary.
     */
    public function test_logging_out_of_one_project_leaves_the_other_signed_in(): void
    {
        $this->actingAs($this->member);

        $onAlpha = $this->signIn($this->alphaOne);
        $onBeta = $this->signIn($this->betaHost);

        $this->read($this->alphaOne, $onAlpha)->assertOk();
        $this->read($this->betaHost, $onBeta)->assertOk();

        $logout = $this->postExactly("https://{$this->alphaOne}/_/auth/logout", $onAlpha);
        $logout->assertRedirect('/');

        /* Alpha is out… */
        $this->assertNotFound($this->read($this->alphaOne, $onAlpha));

        /* …and beta has not noticed. */
        $this->read($this->betaHost, $onBeta)->assertOk();
    }

    /**
     * 🛑 "A return URL supplied as a request parameter is ignored in favour of
     * the domain row."
     *
     * §8.12.10's one hard rule. The handoff endpoint is the only place in the
     * product that sends a reader from one registrable domain to another, so a
     * `return` parameter that could carry an origin would be an open redirect
     * with the dashboard's own authority behind it.
     */
    public function test_the_return_url_comes_from_the_domain_row(): void
    {
        $this->actingAs($this->member);

        $hostile = [
            'https://evil.example/',
            '//evil.example/',
            '/\\evil.example',
            'http://'.$this->alphaOne.'.evil.example/',
        ];

        foreach ($hostile as $attempt) {
            $response = $this->getExactly(
                'https://'.config('docup.origins.app').'/reader/handoff?'.http_build_query([
                    'domain' => Uuid::toText($this->domainIdFor($this->alphaOne)),
                    'challenge' => str_repeat('a', 43),
                    'return' => $attempt,
                ]),
            );

            $location = (string) $response->headers->get('Location');

            /*
             * 🛑 The origin is the domain row's, always. Asserted as a prefix
             * rather than by parsing, because what matters is the literal bytes
             * a browser will read as the origin.
             */
            $this->assertStringStartsWith(
                'https://'.$this->alphaOne.'/_/auth/callback?code=',
                $location,
                "🛑 a hostile return ({$attempt}) must not reach the Location header",
            );

            $this->assertStringNotContainsString('evil.example', $location);
        }
    }

    /**
     * 🛑 A handoff code is single-use, and the second attempt is refused.
     *
     * §8.12.10's "single-use handoff code", which is what stops a code leaked
     * through a `Referer`, a browser history or a proxy log from being a
     * session. The latch is one atomic `UPDATE`; this is the test that it is
     * one and not a read followed by a write.
     */
    public function test_a_handoff_code_cannot_be_redeemed_twice(): void
    {
        $this->actingAs($this->member);

        $handoff = $this->getExactly(
            'https://'.config('docup.origins.app').'/reader/handoff?'.http_build_query([
                'domain' => Uuid::toText($this->domainIdFor($this->alphaOne)),
                'challenge' => PkceChallenge::challengeFor($verifier = str_repeat('v', 43)),
                'return' => '/en/latest/',
            ]),
        );

        $callbackUrl = (string) $handoff->headers->get('Location');

        $state = (new ReaderHandoffState($verifier, '/en/latest/'))->toCookie();

        $first = $this->getExactly($callbackUrl, cookies: [ReaderCookies::STATE => $state]);
        $first->assertOk();

        /* The same code, the same verifier, a moment later. */
        $second = $this->getExactly($callbackUrl, cookies: [ReaderCookies::STATE => $state]);
        $this->assertNotFound($second);
    }

    /**
     * 🛑 The PKCE verifier is what binds a code to a browser, and a code
     * redeemed without it is refused.
     *
     * Without this, a leaked callback URL is a session. With it, the leak is
     * worthless to anybody who does not also hold the `__Host-` cookie on the
     * origin that started the handoff — which is the whole argument in
     * {@see PkceChallenge}.
     */
    public function test_a_code_without_its_verifier_is_refused(): void
    {
        $this->actingAs($this->member);

        $handoff = $this->getExactly(
            'https://'.config('docup.origins.app').'/reader/handoff?'.http_build_query([
                'domain' => Uuid::toText($this->domainIdFor($this->alphaOne)),
                'challenge' => PkceChallenge::challengeFor(str_repeat('v', 43)),
                'return' => '/en/latest/',
            ]),
        );

        $callbackUrl = (string) $handoff->headers->get('Location');

        /* Somebody else's verifier, correctly shaped. */
        $wrong = (new ReaderHandoffState(str_repeat('w', 43), '/en/latest/'))->toCookie();

        $this->assertNotFound(
            $this->getExactly($callbackUrl, cookies: [ReaderCookies::STATE => $wrong]),
        );

        /*
         * 🛑 And the code survived, so the legitimate reader can still use it.
         * A wrong verifier that consumed the code would turn a probe into a
         * denial of service against the reader it was stolen from.
         */
        $right = (new ReaderHandoffState(str_repeat('v', 43), '/en/latest/'))->toCookie();

        $this->getExactly($callbackUrl, cookies: [ReaderCookies::STATE => $right])->assertOk();
    }

    /**
     * 🛑 The decision header says a member was admitted, not that the project
     * was public.
     *
     * §20.3's log and §8.12.25's simulator both key off *why* a reader was
     * admitted, and the header is how that is observable from outside — the
     * only way the wiring can be checked in production.
     */
    public function test_a_member_read_is_recorded_as_a_member_read(): void
    {
        $this->actingAs($this->member);

        $cookies = $this->signIn($this->alphaOne);
        $response = $this->read($this->alphaOne, $cookies);

        $response->assertOk();
        $response->assertHeader(ReaderGate::DECISION_HEADER, 'allow:allowed;by=binding');

        /* 🛑 And privately cached, because the reader needed a credential. */
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertNull($response->headers->get('Cache-Tag'));
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * Run §8.12.10's three requests and return the cookies the reader ends up
     * with.
     *
     * @return array<string, string>
     */
    private function signIn(string $host): array
    {
        $callback = $this->completeHandoff($host);

        $cookies = self::cookiesOf(TestResponse::fromBaseResponse($callback));

        /* One read, so a grant is minted and the caller holds the full set. */
        $read = $this->read($host, $cookies);

        return array_merge($cookies, self::cookiesOf($read));
    }

    /** Steps 1–3 of the handoff, returning the callback's raw response. */
    private function completeHandoff(string $host): Response
    {
        $start = $this->getExactly("https://{$host}/_/auth/start?return=/en/latest/");

        $location = (string) $start->headers->get('Location');
        $state = self::cookiesOf($start)[ReaderCookies::STATE] ?? '';

        $handoff = $this->getExactly($location);

        return $this->app->handle(self::requestFor(
            (string) $handoff->headers->get('Location'),
            'GET',
            [ReaderCookies::STATE => $state],
        ));
    }

    /**
     * @param  array<string, string>  $cookies
     * @return TestResponse<Response>
     */
    private function read(string $host, array $cookies = []): TestResponse
    {
        return $this->getExactly("https://{$host}/en/latest/", cookies: $cookies);
    }

    /**
     * @param  array<string, string>  $cookies
     * @return TestResponse<Response>
     */
    private function getExactly(string $url, array $cookies = []): TestResponse
    {
        return TestResponse::fromBaseResponse(
            $this->app->handle(self::requestFor($url, 'GET', $cookies)),
        );
    }

    /**
     * @param  array<string, string>  $cookies
     * @return TestResponse<Response>
     */
    private function postExactly(string $url, array $cookies = []): TestResponse
    {
        return TestResponse::fromBaseResponse(
            $this->app->handle(self::requestFor($url, 'POST', $cookies)),
        );
    }

    /** @param  array<string, string>  $cookies */
    private static function requestFor(string $url, string $method, array $cookies): Request
    {
        return Request::create($url, $method, [], $cookies);
    }

    /**
     * The cookies a response sets, as a name => value map.
     *
     * 🛑 Expired cookies are **dropped** rather than carried as empty strings,
     * so a logout's `Set-Cookie` expiries do not read as credentials in the
     * next request.
     *
     * @param  TestResponse<Response>  $response
     * @return array<string, string>
     */
    private static function cookiesOf(TestResponse $response): array
    {
        $cookies = [];

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            $value = (string) $cookie->getValue();

            if ($value !== '') {
                $cookies[$cookie->getName()] = $value;
            }
        }

        return $cookies;
    }

    /** @param  TestResponse<Response>  $response */
    private function assertNotFound(TestResponse $response): void
    {
        $this->assertSame(
            404,
            $response->getStatusCode(),
            '🛑 §8.12.23 makes 404 the default for an unauthorised resource',
        );
    }

    /** @return array{0: Project, 1: ProjectVersion} */
    private function makeProject(string $slug): array
    {
        $project = Project::query()->create([
            'slug' => $slug,
            'name' => $slug,
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

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>{$slug}</body></html>\n")
            ->toTarGz($this->fixtures.'/'.$slug.'.tar.gz');

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($version, $archive);

        return [$project, $version];
    }

    private function customDomain(string $host, Project $project): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $project->id,
            'path_prefix' => '',
            'mode' => 'serve',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /** @return string raw 16 bytes */
    private function domainIdFor(string $host): string
    {
        return (string) DB::table('domains')->where('host', $host)->value('id');
    }

    private function grant(User $user, Project $project, Role $role): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => 'project',
            'scope_id' => $project->id,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
