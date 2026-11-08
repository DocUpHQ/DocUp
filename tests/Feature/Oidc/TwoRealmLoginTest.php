<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Oidc;

use App\Access\ReaderPolicies;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Oidc\GroupMappings;
use App\Auth\Providers\Oidc\OidcRejection;
use App\Egress\DnsResolver;
use App\Egress\Transport;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\Support\FakeDnsResolver;
use Tests\Support\FakeTransport;
use Tests\Support\OidcTokens;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 24 exit criterion, over the **real** HTTP path.
 *
 * > "Two projects on one installation authenticate readers against two
 * > different Keycloak realms in one browser session."
 *
 * ## What this proves, and what it does not
 *
 * **Proves:** everything that is DocUp's. Two projects, two bindings, two
 * issuers, two key sets, two exchanges, two per-origin sessions — and no
 * cross-talk between any of those pairs. A reader admitted to project A does
 * not read project B, project B's rule is not satisfied by project A's
 * binding, and the two flows' `state` and `nonce` rows do not interfere.
 * Driven through the actual routes and the actual cookie jar, so §8.12.10's
 * handoff, §8.12.11's grant and §12.3's decision all run.
 *
 * 🛑 **Does not prove:** interoperability with Keycloak itself. The provider
 * here is a fixture, so what is asserted is that DocUp speaks the protocol it
 * believes it speaks. ADR 0008 measured the one question that could not be
 * answered from a fixture — whether a real provider tolerates one fixed
 * `redirect_uri` for readers arriving from two custom domains — on Keycloak
 * 26.0.8, with an unregistered URI refused as a control. The build log records
 * what remains owed.
 *
 * ## "One browser session" is the part that needs the real path
 *
 * Two realms in two *requests* would prove little. The criterion says one
 * browser session because that is where the interesting failures live: a
 * `__Host-` cookie set by one flow and read by the other, a verifier cookie
 * clobbered by the second sign-in, a session on origin A honoured on origin B.
 * So the two flows share one cookie jar here, as they would in a browser.
 */
final class TwoRealmLoginTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $operator;

    private FakeTransport $transport;

    private string $fixtures;

    /** @var array<string, array{project: Project, host: string, binding: string, provider: OidcTokens, issuer: string}> */
    private array $realms = [];

    /**
     * The cookie jar, **keyed by host**.
     *
     * 🛑 Per-origin because that is what a `__Host-` cookie is: §12.4
     * gives every reader cookie the prefix and no `Domain`, so a browser scopes
     * each to the exact origin that set it, and two documentation hosts each
     * holding their own `__Host-docup_rsess` is the ordinary case rather than a
     * collision.
     *
     * The first version was host-blind, on the theory that sharing everything
     * is stricter. It is stricter and it was wrong: realm B's sign-in
     * overwrote realm A's session cookie and the cross-talk assertion failed
     * against a product behaving correctly.
     *
     * @var array<string, array<string, string>>
     */
    private array $cookies = [];

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-tworealm-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Two Realm Co',
            'slug' => 'twor-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'twor-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        /*
         * 🛑 The real `HardenedEgressClient`, with only the transport and the
         * resolver swapped. §8.3.9's scheme allowlist, resolve-then-pin, port
         * policy and redirect refusal all still run — which is the half of this
         * phase that an HTTP-level mock would skip entirely.
         */
        $this->transport = new FakeTransport;

        $this->app->instance(Transport::class, $this->transport);
        $this->app->instance(DnsResolver::class, (new FakeDnsResolver)
            ->stable('acme.idp.example.test', ['93.184.216.34'])
            ->stable('globex.idp.example.test', ['93.184.216.34']));

        $this->realms['acme'] = $this->realm('acme');
        $this->realms['globex'] = $this->realm('globex');

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

    // ------------------------------------------------- the exit criterion

    /**
     * 🛑 §17: two projects, two realms, one browser session.
     *
     * Both readers sign in and read their own project. The assertions that
     * matter are the negative ones after: neither reader reaches the other's
     * project, which is what "two different realms" has to mean to be worth
     * requiring.
     */
    public function test_two_projects_authenticate_against_two_realms_in_one_session(): void
    {
        /* Realm A's reader signs in and reads project A. */
        $this->signIn('acme', 'reader-at-acme');

        $this->read('acme')->assertOk();

        /*
         * 🛑 And cannot read project B. The session is per origin (§8.12.10's
         * whole premise) and the binding is per project, so there are two
         * independent reasons this must fail — which is the point: a reader
         * admitted by one realm must not be admitted by the other's rule.
         */
        $this->assertNotFound($this->read('globex'));

        /* Realm B's reader signs in **in the same jar** and reads project B. */
        $this->signIn('globex', 'reader-at-globex');

        $this->read('globex')->assertOk();

        /*
         * 🛑 Project A still reads, which is the cross-talk assertion. A
         * verifier cookie or a session cookie clobbered by the second sign-in
         * would show up exactly here, and only here — a test that signed in
         * twice and checked only the second would pass with the first broken.
         */
        $this->read('acme')->assertOk();
    }

    /**
     * 🛑 A token from realm A is refused by realm B's binding.
     *
     * The same assertion one layer down, and it is the one that would catch a
     * verifier that compared `iss` against anything shared. Both providers are
     * well-formed and both tokens are correctly signed; only the audience and
     * the issuer differ.
     */
    public function test_a_token_from_the_other_realm_is_refused(): void
    {
        $acme = $this->realms['acme'];
        $globex = $this->realms['globex'];

        /* Start a flow for globex, then answer it with an acme-signed token. */
        $started = $this->start('globex');

        $this->stubTokenEndpoint(
            $globex,
            $acme['provider']->idToken(
                $acme['issuer'],
                'client-acme',
                $started['nonce'],
            ),
        );

        $response = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'code' => 'the-code',
            'state' => $started['state'],
        ]);

        $this->assertSame(404, $response->getStatusCode());

        /*
         * 🛑 And the audit chain says **which** check refused it, because §17
         * requires distinct events. Either the signature or the issuer is a
         * legitimate answer here — the token was signed by another key *and*
         * names another issuer — so both are accepted, and nothing else is.
         */
        $this->assertAudited([
            OidcRejection::KeyNotPinned,
            OidcRejection::SignatureInvalid,
            OidcRejection::IssuerMismatch,
        ]);
    }

    /**
     * 🛑 A `state` from realm A's flow cannot complete realm B's.
     *
     * The stored row carries the binding, the domain and the project, so a
     * `state` is only ever usable for the exchange that opened it — §8.12.10's
     * "an index into verified state, never the URL itself", applied to the
     * other direction.
     */
    public function test_a_state_from_one_realm_cannot_complete_the_other(): void
    {
        $acme = $this->start('acme');
        $this->start('globex');

        /*
         * Answer with a token that is perfectly valid for acme. The exchange
         * resolves acme's binding from the row, so the flow completes for
         * acme's project — and the reader lands on acme's host, not globex's.
         */
        $this->stubTokenEndpoint(
            $this->realms['acme'],
            $this->realms['acme']['provider']->idToken(
                $this->realms['acme']['issuer'],
                'client-acme',
                $acme['nonce'],
            ),
        );

        $response = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'code' => 'the-code',
            'state' => $acme['state'],
        ]);

        $this->assertSame(302, $response->getStatusCode());

        $location = (string) $response->headers->get('Location');

        $this->assertStringContainsString($this->realms['acme']['host'], $location);
        $this->assertStringNotContainsString($this->realms['globex']['host'], $location);
    }

    /**
     * 🛑 An implicit-flow response is refused **without** spending the state.
     *
     * §8.12.18: "no implicit flow". Refusing before the latch is deliberate —
     * a forged redirect carrying a token must not be able to consume a real
     * reader's in-flight exchange, which would turn a refusal into a denial of
     * service against the reader it was aimed at.
     */
    public function test_an_implicit_flow_response_is_refused_without_spending_the_state(): void
    {
        $started = $this->start('acme');

        $response = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'state' => $started['state'],
            'id_token' => 'a.token.in-the-query',
        ]);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([OidcRejection::ImplicitFlowRefused]);

        /* 🛑 The row is untouched, so the reader's own flow still completes. */
        $this->assertNull(
            DB::table('oidc_authorisation_requests')->value('consumed_at'),
            '🛑 §8.12.18: refusing an implicit response must not spend a live exchange',
        );
    }

    /**
     * 🛑 §8.13.7: a group removed at the identity provider is removed here.
     *
     * §17's own words: "not merely not added". The reader signs in twice — once
     * asserting the group, once not — and the second login must take it away.
     */
    public function test_a_group_removed_at_the_idp_is_removed_on_next_login(): void
    {
        $realm = $this->realms['acme'];

        DB::table('auth_provider_bindings')
            ->where('id', $realm['binding'])
            ->update(['config' => (string) json_encode([
                'issuer' => $realm['issuer'],
                'client_id' => 'client-acme',
                'provisioning' => 'create_reader_and_map_groups',
                'groups_claim' => 'groups',
            ])]);

        app(GroupMappings::class)->add(
            bindingId: $realm['binding'],
            bindingScopeType: 'project',
            organisationId: (string) $this->organisation->id,
            providerGroup: 'engineering',
            target: 'group',
            targetValue: 'engineers',
        );

        Cache::flush();

        /* First login: the provider asserts the group. */
        $this->signIn('acme', 'reader-at-acme', ['groups' => ['engineering']]);

        $this->assertSame(
            '["engineers"]',
            (string) DB::table('reader_identities')->value('reader_groups'),
            'the mapped group is applied on first login',
        );

        /*
         * 🛑 Second login, the same subject, and the provider no longer asserts
         * the group. §8.13.7's reconciliation has to **remove** it.
         */
        $this->cookies = [];

        $this->signIn('acme', 'reader-at-acme', ['groups' => []]);

        $this->assertSame(
            '[]',
            (string) DB::table('reader_identities')->value('reader_groups'),
            '🛑 §8.13.7 / §17: a group removed at the IdP is removed, not merely not added',
        );
    }

    /**
     * 🛑 §8.13.7's `disabled` mode admits nobody new, and says so.
     *
     * Not a failure to provision: an operator choosing `disabled` means "only
     * readers I created". The audited refusal is how they find out they have
     * missed somebody.
     */
    public function test_provisioning_disabled_refuses_an_unknown_subject(): void
    {
        $realm = $this->realms['globex'];

        DB::table('auth_provider_bindings')
            ->where('id', $realm['binding'])
            ->update(['config' => (string) json_encode([
                'issuer' => $realm['issuer'],
                'client_id' => 'client-globex',
                'provisioning' => 'disabled',
            ])]);

        Cache::flush();

        $started = $this->start('globex');

        $this->stubTokenEndpoint(
            $realm,
            $realm['provider']->idToken($realm['issuer'], 'client-globex', $started['nonce']),
        );

        $response = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'code' => 'the-code',
            'state' => $started['state'],
        ]);

        $this->assertSame(404, $response->getStatusCode());
        $this->assertAudited([OidcRejection::ProvisioningDisabled]);
        $this->assertSame(0, DB::table('reader_identities')->count());
    }

    // ------------------------------------------------------------ the flow

    /**
     * Drive a whole sign-in, from the documentation origin and back.
     *
     * @param  array<string, mixed>  $extraClaims
     */
    private function signIn(string $realm, string $subject, array $extraClaims = []): void
    {
        $started = $this->start($realm);

        $this->stubTokenEndpoint(
            $this->realms[$realm],
            $this->realms[$realm]['provider']->idToken(
                $this->realms[$realm]['issuer'],
                'client-'.$realm,
                $started['nonce'],
                overrides: array_merge(['sub' => $subject], $extraClaims),
            ),
        );

        $callback = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'code' => 'the-code-for-'.$realm,
            'state' => $started['state'],
        ]);

        $this->assertSame(
            302,
            $callback->getStatusCode(),
            'the callback should redirect to the documentation origin',
        );

        $location = (string) $callback->headers->get('Location');

        /* The final hop: the documentation origin redeems the handoff code. */
        $parts = parse_url($location);

        $this->assertIsArray($parts);
        $this->assertSame($this->realms[$realm]['host'], $parts['host'] ?? null);

        /*
         * `parse_url`'s array shape types `path` as a string, so there is
         * nothing to narrow — the `?? '/'` is for a URL that carries none.
         */
        $path = $parts['path'] ?? '/';

        $final = $this->visit(
            $this->realms[$realm]['host'],
            $path,
            ['code' => self::queryOf($location)['code'] ?? ''],
        );

        $this->assertSame(200, $final->getStatusCode(), 'the handoff should establish a session');
    }

    /**
     * The documentation origin's `/_/auth/start`, followed to the dashboard.
     *
     * @return array{state: string, nonce: string}
     */
    private function start(string $realm): array
    {
        $begin = $this->visit($this->realms[$realm]['host'], '/_/auth/start', ['return' => '/en/v1/']);

        $this->assertSame(302, $begin->getStatusCode());

        $oidcStart = (string) $begin->headers->get('Location');

        $this->assertStringContainsString('/_/auth/oidc/start', $oidcStart, '🛑 a guarded project goes to the OIDC leg');

        $redirect = $this->visit(
            $this->dashboard(),
            '/_/auth/oidc/start',
            self::queryOf($oidcStart),
        );

        $this->assertSame(302, $redirect->getStatusCode(), 'the start leg should redirect to the provider');

        $authorise = (string) $redirect->headers->get('Location');

        $this->assertStringContainsString($this->realms[$realm]['issuer'], $authorise);

        $sent = self::queryOf($authorise);

        return [
            'state' => $sent['state'] ?? '',
            'nonce' => $sent['nonce'] ?? '',
        ];
    }

    /** @param  array{issuer: string, ...}  $realm */
    private function stubTokenEndpoint(array $realm, string $idToken): void
    {
        $this->transport->json($realm['issuer'].'/protocol/openid-connect/token', [
            'access_token' => 'test-access-token',
            'token_type' => 'Bearer',
            'id_token' => $idToken,
        ]);
    }

    // ---------------------------------------------------------- fixtures

    /**
     * One realm: a provider, a project, a host and an active binding.
     *
     * @return array{project: Project, host: string, binding: string, provider: OidcTokens, issuer: string}
     */
    private function realm(string $name): array
    {
        $this->context->for($this->organisation->id);

        $provider = new OidcTokens(kid: $name.'-key');
        $issuer = 'https://'.$name.'.idp.example.test/realms/'.$name;

        /*
         * The provider's own three documents, served through the real egress
         * client by {@see FakeTransport}.
         */
        $this->transport->json($issuer.'/.well-known/openid-configuration', [
            'issuer' => $issuer,
            'authorization_endpoint' => $issuer.'/protocol/openid-connect/auth',
            'token_endpoint' => $issuer.'/protocol/openid-connect/token',
            'jwks_uri' => $issuer.'/protocol/openid-connect/certs',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ]);

        $this->transport->json($issuer.'/protocol/openid-connect/certs', $provider->jwks());

        $slug = $name.'-'.bin2hex(random_bytes(3));
        $host = $slug.'.'.$this->docsApex();

        $project = Project::query()->create([
            'slug' => $slug,
            'name' => ucfirst($name),
            /*
             * Public project, private version — the shape a credential is
             * actually for, and it makes a refusal a refusal of the version
             * rather than of the project.
             */
            'visibility' => 'public',
        ]);

        $version = $this->publishVersion($project, 'v1');

        $project->forceFill(['default_version_id' => $version->id])->save();

        $this->mountOn($project, $host);

        $bindings = app(Bindings::class);

        $bindingId = $bindings->create(
            scopeType: 'project',
            scopeId: $project->id,
            type: 'oidc',
            name: $name.' realm',
            config: [
                'issuer' => $issuer,
                'client_id' => 'client-'.$name,
                'provisioning' => 'create_reader',
            ],
            secrets: ['client_secret' => 'secret-for-'.$name],
            organisationId: $this->organisation->id,
        );

        $bindings->transition($bindingId, BindingState::Verifying);
        $bindings->probe($bindingId);
        $bindings->recordTestLogin($bindingId, $this->operator->id);
        $bindings->transition($bindingId, BindingState::Active);

        $this->ruleFor($project, $bindingId);

        return [
            'project' => $project,
            'host' => $host,
            'binding' => $bindingId,
            'provider' => $provider,
            'issuer' => $issuer,
        ];
    }

    private function publishVersion(Project $project, string $slug): ProjectVersion
    {
        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'members',
        ])->save();

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>{$project->slug}</body></html>\n")
            ->toTarGz($this->fixtures.'/'.$project->slug.'.tar.gz');

        app(Publisher::class)->publishUpload($version, $archive);

        return $version;
    }

    private function mountOn(Project $project, string $host): void
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
            'project_id' => $project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /** A rule admitting exactly this binding, on the private version. */
    private function ruleFor(Project $project, string $bindingId): void
    {
        $policies = app(ReaderPolicies::class);

        $policies->createFor($project, actorId: $this->operator->id);

        $policies->addRule(
            project: $project,
            label: 'admit the realm',
            allow: true,
            requirement: ['leaf' => 'binding', 'binding_id' => Uuid::toText($bindingId)],
            versionSlugs: ['v1'],
            actorId: $this->operator->id,
        );
    }

    // ------------------------------------------------- the shared cookie jar

    /**
     * One request, carrying and collecting cookies like a browser.
     *
     * Named `visit` rather than `get` because the framework's own
     * `TestCase::get()` is public, so a private override is a fatal error —
     * and because this is not that method: it drives the kernel directly with
     * an absolute URL, so the host is the one under test.
     *
     * 🛑 Cookies are sent to and collected from **one origin**, which is
     * §12.4's own design showing through: every reader cookie is `__Host-`
     * prefixed with no `Domain`, so there is no cookie in this product that a
     * browser would send to a second host.
     *
     * The first version of this jar was host-blind, on the theory that sharing
     * everything is "stricter than reality". It is stricter, and it was also
     * wrong: realm B's sign-in overwrote realm A's `__Host-docup_rsess` and the
     * cross-talk assertion failed against a product behaving correctly. A test
     * that models something a browser cannot do tests nothing.
     *
     * So "one browser session" means one jar holding several origins' cookies
     * side by side — which is still exactly where cross-talk would appear.
     *
     * @param  array<string, string>  $query
     * @return TestResponse<Response>
     */
    private function visit(string $host, string $path, array $query = []): TestResponse
    {
        $url = 'https://'.$host.$path.($query === [] ? '' : '?'.http_build_query($query));

        $request = Request::create(
            $url,
            'GET',
            [],
            $this->cookies[$host] ?? [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        );

        $response = TestResponse::fromBaseResponse($this->app->handle($request));

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            $value = (string) $cookie->getValue();

            /*
             * An empty value is a deletion, which is how §12.4's cookies are
             * cleared — so the jar honours it, or a revoked session would
             * appear to survive.
             */
            if ($value === '') {
                unset($this->cookies[$host][$cookie->getName()]);

                continue;
            }

            $this->cookies[$host][$cookie->getName()] = $value;
        }

        return $response;
    }

    /** @return TestResponse<Response> */
    private function read(string $realm): TestResponse
    {
        return $this->visit($this->realms[$realm]['host'], '/en/v1/');
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

    /**
     * 🛑 §17's "distinct audit events": one of these actions was recorded.
     *
     * @param  list<OidcRejection>  $expected
     */
    private function assertAudited(array $expected): void
    {
        $actions = [];

        foreach (DB::table('audit_events')->orderByDesc('occurred_at')->limit(20)->get(['action']) as $row) {
            $actions[] = (string) $row->action;
        }

        $wanted = array_map(static fn (OidcRejection $case): string => $case->auditAction(), $expected);

        $this->assertNotEmpty(
            array_intersect($wanted, $actions),
            '🛑 §17: the refusal must raise its own audit event; wanted one of '
                .implode(', ', $wanted).' and the chain holds '.implode(', ', $actions),
        );
    }

    /**
     * A URL's query string as a flat map of strings.
     *
     * 🛑 One place, because `parse_str` writes `string|array<mixed>` into
     * its out-parameter — a repeated parameter becomes an array — so every
     * read needs narrowing. Four casts at four call sites is four chances to
     * cast an array to `"Array"` and compare it to something; one helper that
     * drops non-strings is none.
     *
     * Dropping rather than failing is right here: a repeated parameter in a URL
     * DocUp built would be a bug this returns nothing for, and the assertion
     * that wanted the value is what reports it.
     *
     * @return array<string, string>
     */
    private static function queryOf(string $url): array
    {
        $raw = parse_url($url, PHP_URL_QUERY);

        if (! is_string($raw)) {
            return [];
        }

        parse_str($raw, $parsed);

        $out = [];

        foreach ($parsed as $name => $value) {
            if (is_string($value)) {
                $out[(string) $name] = $value;
            }
        }

        return $out;
    }

    /**
     * 🛑 The configured dashboard host, not a constant.
     *
     * `routes/web.php` is loaded at boot, so a host constraint on it is fixed
     * before a test's `setUp` runs — overriding `docup.origins.app` afterwards
     * moves the URLs the application *builds* and not the ones it *matches*.
     * The first version of this test did exactly that and every request to the
     * dashboard 404'd. Reading the real value keeps the two in step.
     */
    private function dashboard(): string
    {
        $host = config('docup.origins.app');

        return is_string($host) && $host !== '' ? $host : 'docup.localhost';
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docs.docup.localhost';
    }
}
