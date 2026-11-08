<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Providers;

use App\Access\AccessLeaf;
use App\Access\ReaderPolicies;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\ReaderCredentials;
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
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\Support\FakeDnsResolver;
use Tests\Support\FakeTransport;
use Tests\Support\HostileSamlResponses;
use Tests\Support\OidcTokens;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 25 exit criterion, in full.
 *
 * > "Five projects on one installation — public, password, OIDC, SAML,
 * > token-only — demonstrated in one browser session."
 *
 * `TwoRealmLoginTest` proved two OIDC realms coexist. This is the harder
 * version of the same claim: five projects, five **different** driver types,
 * one installation, one jar.
 *
 * ## 🛑 Why the negative assertions are the test
 *
 * Five projects each admitting their own reader would pass with an
 * `EffectiveAccess` that said yes to everybody. What makes this criterion worth
 * requiring is that each credential reaches **exactly one** project: the OIDC
 * reader's session does not open the SAML project, the reader token does not
 * open the password project, and none of them is needed for the public one.
 *
 * Two independent mechanisms produce that, and the test does not distinguish
 * them because an operator does not care which held:
 *
 * 1. §8.12.10's session is **per origin** — every reader cookie is `__Host-`
 *    prefixed with no `Domain` (§12.4), so a browser physically cannot send
 *    one host's session to another.
 * 2. §8.12.7's rules name a **binding**, so a reader vouched for by one
 *    provider does not satisfy a rule naming a different one even on the same
 *    origin.
 *
 * ## 🛑 What "one browser session" means here
 *
 * One jar, holding several origins' cookies side by side — which is what a
 * browser has. A jar that shared cookies across hosts would be modelling
 * something no browser does, and `TwoRealmLoginTest` records what happened when
 * an earlier version tried it: the cross-talk assertion failed against a
 * product that was behaving correctly.
 */
final class FiveProviderSessionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $operator;

    private FakeTransport $transport;

    private HostileSamlResponses $idp;

    private OidcTokens $oidcProvider;

    private string $fixtures;

    private string $oidcIssuer;

    /**
     * The five projects, keyed by the driver that guards each.
     *
     * @var array<string, array{project: Project, host: string, binding: ?string, type: ?string}>
     */
    private array $sites = [];

    /** The reader token for the `reader_token` project. */
    private string $readerToken = '';

    /** @var array<string, array<string, string>> per-origin, as a browser is */
    private array $cookies = [];

    private const string PASSWORD = 'correct horse battery staple';

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-fiveprov-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->idp = new HostileSamlResponses;
        $this->oidcProvider = new OidcTokens(kid: 'five-key');
        $this->oidcIssuer = 'https://five.idp.example.test/realms/five';

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Five Provider Co',
            'slug' => 'five-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'five-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        /*
         * 🛑 The real `HardenedEgressClient` with only the transport and the
         * resolver swapped, as `TwoRealmLoginTest` does: §8.3.9's scheme
         * allowlist, resolve-then-pin, port policy and redirect refusal all
         * still run. The SAML project needs none of this — its trust anchor is
         * a configured certificate, so there is nothing to fetch — which is
         * itself one of the differences this test exercises.
         */
        $this->transport = new FakeTransport;

        $this->transport->json($this->oidcIssuer.'/.well-known/openid-configuration', [
            'issuer' => $this->oidcIssuer,
            'authorization_endpoint' => $this->oidcIssuer.'/protocol/openid-connect/auth',
            'token_endpoint' => $this->oidcIssuer.'/protocol/openid-connect/token',
            'jwks_uri' => $this->oidcIssuer.'/protocol/openid-connect/certs',
            'id_token_signing_alg_values_supported' => ['RS256'],
            'code_challenge_methods_supported' => ['S256'],
        ]);

        $this->transport->json(
            $this->oidcIssuer.'/protocol/openid-connect/certs',
            $this->oidcProvider->jwks(),
        );

        $this->app->instance(Transport::class, $this->transport);
        $this->app->instance(DnsResolver::class, (new FakeDnsResolver)
            ->stable('five.idp.example.test', ['93.184.216.34']));

        $this->sites['public'] = $this->publicSite();
        $this->sites['password'] = $this->guardedSite('password', 'the client portal', [], [
            'password_hash' => Hash::make(self::PASSWORD),
        ]);
        $this->sites['oidc'] = $this->guardedSite('oidc', 'the realm', [
            'issuer' => $this->oidcIssuer,
            'client_id' => 'client-five',
            'provisioning' => 'create_reader',
        ], ['client_secret' => 'secret-for-five']);
        $this->sites['saml'] = $this->guardedSite('saml', 'the idp', [
            'idp_entity_id' => HostileSamlResponses::ISSUER,
            'sso_url' => 'https://idp.example.test/realms/acme/protocol/saml',
            'certificate' => $this->idp->certificate(),
            'provisioning' => 'create_reader',
        ]);
        $this->sites['token'] = $this->guardedSite('reader_token', 'the CI token');

        $this->readerToken = $this->issueToken(
            $this->sites['token']['project'],
            (string) $this->sites['token']['binding'],
        );

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
     * 🛑 Five projects, five driver types, one browser session.
     *
     * Walked in order, and each step asserts the project is **shut** before the
     * credential arrives. A project that was open all along would satisfy every
     * positive assertion in this test, which is exactly the failure §8.12.23's
     * "404, never 403" default exists to make loud.
     */
    public function test_five_providers_serve_five_projects_in_one_session(): void
    {
        /*
         * 1. 🛑 **Public.** No credential, no cookie, no rule — and it serves.
         *
         * First deliberately: it is the control for everything below. If the
         * harness cannot read a project that is genuinely open, the four 404s
         * that follow prove nothing about authentication.
         */
        $this->read('public')->assertOk();

        /* 2. **Password.** Shut, then open with the credential, and only `v1`. */
        $this->assertNotFound($this->read('password'));
        $this->read('password', password: self::PASSWORD)->assertOk();

        /*
         * 🛑 And a wrong password is §8.12.23's case (a) — "a credential was
         * presented and rejected" — which is the one place a challenge is
         * permitted, so this is a 401 rather than the 404 everything else
         * returns.
         */
        $this->assertSame(401, $this->read('password', password: 'wrong')->getStatusCode());

        /* 3. **OIDC.** Shut, then the full exchange, then open. */
        $this->assertNotFound($this->read('oidc'));
        $this->signInWithOidc('reader-at-five');
        $this->read('oidc')->assertOk();

        /* 4. **SAML.** Shut, then the full assertion flow, then open. */
        $this->assertNotFound($this->read('saml'));
        $this->signInWithSaml();
        $this->read('saml')->assertOk();

        /* 5. **Token-only.** Shut, then open with the bearer token. */
        $this->assertNotFound($this->read('token'));
        $this->read('token', bearer: $this->readerToken)->assertOk();

        /*
         * 🛑 And the state established along the way is still good. Walking
         * forwards could pass while each step quietly invalidated the last —
         * one `Cache::flush()` in the wrong place, a shared cookie name, an
         * epoch bumped installation-wide — so the two sessions are re-read
         * after everything else has happened.
         */
        $this->read('public')->assertOk();
        $this->read('oidc')->assertOk();
        $this->read('saml')->assertOk();
    }

    /**
     * 🛑 And no credential reaches a project it was not issued for.
     *
     * The half of the criterion that is not about five logins succeeding. Run as
     * its own test so a failure names the leak rather than the walkthrough.
     */
    public function test_no_credential_reaches_another_project(): void
    {
        /*
         * 🛑 The stateless credentials first, while **no** session exists.
         *
         * Asserted here rather than after the sign-ins, because a session on an
         * origin legitimately opens that origin's project — so presenting a
         * useless token alongside a valid session proves nothing about the
         * token. The claim is "this credential admits nobody anywhere else",
         * and the only place it can be made is where nothing else admits them.
         */
        $this->assertNotFound(
            $this->read('password', bearer: $this->readerToken),
            'a reader token opened a password-guarded project',
        );
        $this->assertNotFound(
            $this->read('oidc', bearer: $this->readerToken),
            'a reader token opened an IdP-guarded project',
        );
        $this->assertNotFound(
            $this->read('saml', bearer: $this->readerToken),
            'a reader token opened a SAML-guarded project',
        );

        /* And one project's password opens no other. */
        $this->assertNotFound(
            $this->read('token', password: self::PASSWORD),
            "a password opened a different project's version",
        );

        /*
         * 🛑 One sign-in at a time, and the leak is asserted **before** the
         * second one. Checking after both would assert nothing: once a reader
         * has signed in at both providers, both projects are legitimately open
         * — which is the whole point of "one browser session" — so the only
         * moment that can catch cross-talk is while exactly one credential
         * exists.
         */
        $this->signInWithOidc('reader-at-five');

        $this->read('oidc')->assertOk();
        $this->assertNotFound($this->read('saml'), 'the OIDC session opened the SAML project');

        /*
         * 🛑 And it is not merely "no session for that host": the password
         * project is on a third origin and the OIDC reader does not reach it
         * either, which is the rule naming a binding rather than the cookie
         * being per origin.
         */
        $this->assertNotFound($this->read('password'), 'the OIDC session opened the password project');

        /* Now the SAML reader signs in, in the same jar, and both are open. */
        $this->signInWithSaml();

        $this->read('saml')->assertOk();
        $this->read('oidc')->assertOk();

    }

    /**
     * 🛑 Each project's own rule names its own binding, and nothing wider.
     *
     * Asserted on the configuration rather than through a request, because it
     * is the premise the two tests above rest on: if two projects shared a
     * binding, their mutual refusal would be proving only the per-origin
     * session and the criterion's "five providers" would be four.
     */
    public function test_each_project_is_guarded_by_its_own_binding(): void
    {
        $bindings = [];

        foreach ($this->sites as $key => $site) {
            if ($site['binding'] === null || $site['type'] === null) {
                continue;
            }

            $this->assertNotContains(
                $site['binding'],
                $bindings,
                'the '.$key.' project shares a binding with another',
            );

            $bindings[] = $site['binding'];

            /*
             * 🛑 The stored type, read back. A fixture that *said* `saml` and
             * created `password` would make every assertion in this file pass
             * while testing four drivers.
             */
            $this->assertSame(
                $site['type'],
                (string) DB::table('auth_provider_bindings')
                    ->where('id', $site['binding'])
                    ->value('type'),
            );
        }

        $this->assertSame(
            ['password', 'oidc', 'saml', 'reader_token'],
            array_values(array_filter(array_column($this->sites, 'type'))),
            '🛑 §17: the five are public, password, OIDC, SAML and token-only',
        );

        $this->assertCount(4, $bindings, 'four guarded projects plus one public one');
    }

    // ------------------------------------------------------- the two logins

    /** The whole OIDC flow, through the jar, as a browser would walk it. */
    private function signInWithOidc(string $subject): void
    {
        $host = $this->sites['oidc']['host'];

        $begin = $this->visit($host, '/_/auth/start', ['return' => '/en/v1/']);

        $this->assertSame(302, $begin->getStatusCode());

        $startUrl = (string) $begin->headers->get('Location');

        $this->assertStringContainsString('/_/auth/oidc/start', $startUrl);

        $redirect = $this->visit($this->dashboard(), '/_/auth/oidc/start', self::queryOf($startUrl));

        $this->assertSame(302, $redirect->getStatusCode());

        $sent = self::queryOf((string) $redirect->headers->get('Location'));

        /*
         * 🛑 `test-access-token`, which is `OidcTokens::idToken()`'s default
         * and therefore the value its `at_hash` is computed over. Any other
         * string here makes §8.12.18's `at_hash` check refuse a token that is
         * otherwise perfect — which presents as a 404 naming nothing, because
         * §8.12.23 gives the reader no detail.
         */
        $this->transport->json($this->oidcIssuer.'/protocol/openid-connect/token', [
            'access_token' => 'test-access-token',
            'token_type' => 'Bearer',
            'id_token' => $this->oidcProvider->idToken(
                $this->oidcIssuer,
                'client-five',
                $sent['nonce'] ?? '',
                overrides: ['sub' => $subject],
            ),
        ]);

        $callback = $this->visit($this->dashboard(), '/_/auth/oidc/callback', [
            'code' => 'the-code',
            'state' => $sent['state'] ?? '',
        ]);

        $this->assertSame(302, $callback->getStatusCode());

        $this->redeem($host, (string) $callback->headers->get('Location'));
    }

    /**
     * The whole SAML flow, through the jar.
     *
     * 🛑 The identity provider's half is the one thing simulated: instead of a
     * real Keycloak POSTing its auto-submitted form, the fixture mints the
     * assertion and the test POSTs it. ADR 0013 measured the real provider —
     * `RelayState` round-tripped, `Destination` and the registered ACS enforced
     * — so what is left to prove here is DocUp's own two halves, and those are
     * driven through the real routes.
     *
     * The request id is read from the exchange row because only DocUp knows it;
     * a real identity provider learns it from the `SAMLRequest` DocUp just
     * sent, which is the same fact arriving by a route a test cannot take.
     */
    private function signInWithSaml(): void
    {
        $host = $this->sites['saml']['host'];

        $begin = $this->visit($host, '/_/auth/start', ['return' => '/en/v1/']);

        $this->assertSame(302, $begin->getStatusCode());

        $startUrl = (string) $begin->headers->get('Location');

        $this->assertStringContainsString(
            '/_/auth/saml/start',
            $startUrl,
            '🛑 §8.12.18: a SAML-guarded project goes to the SAML leg',
        );

        $redirect = $this->visit($this->dashboard(), '/_/auth/saml/start', self::queryOf($startUrl));

        $this->assertSame(302, $redirect->getStatusCode());

        $toProvider = (string) $redirect->headers->get('Location');

        $this->assertStringContainsString('SAMLRequest=', $toProvider);

        $relayState = self::queryOf($toProvider)['RelayState'] ?? '';

        $this->assertNotSame('', $relayState, 'the start leg should send a RelayState');

        $requestId = $this->context->acrossAllOrganisations(
            fn (): string => (string) DB::table('saml_auth_requests')
                ->where('binding_id', $this->sites['saml']['binding'])
                ->whereNull('consumed_at')
                ->orderByDesc('created_at')
                ->value('request_id'),
        );

        $this->assertNotSame('', $requestId);

        /*
         * 🛑 A unique assertion id per sign-in, because the replay cache is
         * real and shared across this test's logins. Two sign-ins reusing one
         * id would have the second refused as `AssertionReplayed` — correctly,
         * which would make this helper look broken.
         */
        $assertion = $this->idp->valid(
            $requestId,
            assertionId: 'five-'.bin2hex(random_bytes(6)),
        );

        $acs = $this->submit($this->dashboard(), '/_/auth/saml/acs', [
            'SAMLResponse' => base64_encode($assertion),
            'RelayState' => $relayState,
        ]);

        $this->assertSame(302, $acs->getStatusCode(), 'the ACS should redirect to the documentation origin');

        $this->redeem($host, (string) $acs->headers->get('Location'));
    }

    /**
     * §8.12.10's last hop: the documentation origin redeems the handoff code.
     *
     * Shared by both providers, which is the design holding: each leg ends by
     * minting the same handoff code this origin was already waiting for, so
     * adding SAML was a choice of URL rather than a second session mechanism.
     */
    private function redeem(string $host, string $location): void
    {
        $parts = parse_url($location);

        $this->assertIsArray($parts);
        $this->assertSame($host, $parts['host'] ?? null, 'the handoff must return to the originating host');

        $final = $this->visit(
            $host,
            $parts['path'] ?? '/',
            ['code' => self::queryOf($location)['code'] ?? ''],
        );

        $this->assertSame(200, $final->getStatusCode(), 'the handoff should establish a session');
    }

    // ---------------------------------------------------------- fixtures

    /**
     * A project with a public version and no policy at all.
     *
     * 🛑 No rule rather than an allow-everybody rule, which is the honest shape
     * of "public": §12.3 reaches `public` without consulting a binding, so a
     * rule here would be testing the rule engine instead of the default.
     *
     * @return array{project: Project, host: string, binding: ?string, type: ?string}
     */
    private function publicSite(): array
    {
        $slug = 'public-'.bin2hex(random_bytes(3));
        $host = $slug.'.'.$this->docsApex();

        $project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Public',
            'visibility' => 'public',
        ]);

        $version = $this->publishVersion($project, 'public');

        $project->forceFill(['default_version_id' => $version->id])->save();

        $this->mountOn($project, $host);

        return ['project' => $project, 'host' => $host, 'binding' => null, 'type' => null];
    }

    /**
     * A project whose `v1` is private, guarded by one binding of one type.
     *
     * @param  array<string, mixed>  $config
     * @param  array<string, string>  $secrets
     * @return array{project: Project, host: string, binding: ?string, type: ?string}
     */
    private function guardedSite(string $type, string $name, array $config = [], array $secrets = []): array
    {
        /*
         * 🛑 The slug is **derived** from the type, not the type itself.
         *
         * `reader_token` carries an underscore, which is legal in
         * `auth_provider_bindings.type` and illegal in a hostname — so a site
         * named after the driver produced `reader_token-abc.docs.…`, which the
         * routing snapshot never matched. The request 404'd before reaching
         * `EffectiveAccess` at all, and the decision log was empty: an
         * authorisation test that silently stops testing authorisation.
         */
        $slug = str_replace('_', '-', $type).'-'.bin2hex(random_bytes(3));
        $host = $slug.'.'.$this->docsApex();

        $project = Project::query()->create([
            'slug' => $slug,
            'name' => ucfirst($type),
            /*
             * 🛑 A **public project with a private version**, which is the
             * shape a reader credential is actually for: it makes every refusal
             * below a refusal of the *version* rather than of the project, so a
             * 404 cannot be the §8.2.2 tenancy default passing for an
             * authentication decision.
             */
            'visibility' => 'public',
        ]);

        $version = $this->publishVersion($project, 'members');

        $project->forceFill(['default_version_id' => $version->id])->save();

        $this->mountOn($project, $host);

        $bindings = app(Bindings::class);

        $bindingId = $bindings->create(
            scopeType: 'project',
            scopeId: $project->id,
            type: $type,
            name: $name,
            config: $config,
            secrets: $secrets,
            organisationId: $this->organisation->id,
        );

        $bindings->transition($bindingId, BindingState::Verifying);
        $bindings->probe($bindingId);
        $bindings->recordTestLogin($bindingId, $this->operator->id);
        $bindings->transition($bindingId, BindingState::Active);

        $policies = app(ReaderPolicies::class);

        $policies->createFor($project, actorId: $this->operator->id);

        /*
         * 🛑 The leaf comes from §8.12.17's table, not from this fixture.
         *
         * `AccessLeaf::forDriver()` **is** that table as a function, and
         * §8.12.7's satisfiability invariant is defined over the
         * classification — so a rule naming `reader_token` as `binding` is
         * refused at write time, which is how the first version of this fixture
         * failed. Reading the classification rather than restating it means the
         * rule cannot disagree with the driver: `password`, `oidc` and `saml`
         * are `{binding}`, `reader_token` is `{bearer}`.
         */
        $leaf = AccessLeaf::forDriver($type);

        $this->assertInstanceOf(AccessLeaf::class, $leaf, '§8.12.17 classifies every registered driver');

        /*
         * 🛑 One rule, naming this binding and this version slug.
         *
         * `versionSlugs` is not decoration: §12.3 only reaches the
         * `restricted` rung for a rule that names the resource explicitly, so a
         * rule with an empty slug list would leave the reader at
         * `authenticated` — which a `members` version refuses, and the whole
         * test would be five 404s that look like a working product.
         */
        $policies->addRule(
            project: $project,
            label: 'admit '.$name,
            allow: true,
            requirement: ['leaf' => $leaf->value, 'binding_id' => Uuid::toText($bindingId)],
            versionSlugs: ['v1'],
            actorId: $this->operator->id,
        );

        return ['project' => $project, 'host' => $host, 'binding' => $bindingId, 'type' => $type];
    }

    private function publishVersion(Project $project, string $visibility): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'v1',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => $visibility,
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

    private function issueToken(Project $project, string $bindingId): string
    {
        $this->context->for($this->organisation->id);

        $issued = app(ReaderCredentials::class)->issue(
            project: $project,
            bindingId: $bindingId,
            kind: 'reader_token',
            label: 'a token',
            versionSlugs: ['v1'],
            actorId: $this->operator->id,
        );

        $this->context->forget();

        return $issued['secret'];
    }

    // ------------------------------------------------- the shared cookie jar

    /**
     * One GET, carrying and collecting cookies like a browser.
     *
     * 🛑 Per **origin**, which is §12.4's design showing through: every reader
     * cookie is `__Host-` prefixed with no `Domain`, so there is no cookie in
     * this product a browser would send to a second host. A host-blind jar
     * would be stricter than reality and would also be wrong — one host's
     * sign-in would overwrite another's session and the cross-talk assertions
     * would fail against a correct product.
     *
     * @param  array<string, string>  $query
     * @return TestResponse<Response>
     */
    private function visit(string $host, string $path, array $query = []): TestResponse
    {
        $url = 'https://'.$host.$path.($query === [] ? '' : '?'.http_build_query($query));

        return $this->send(Request::create(
            $url,
            'GET',
            [],
            $this->cookies[$host] ?? [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        ), $host);
    }

    /**
     * One POST, for the ACS — the only cross-origin form in either flow.
     *
     * 🛑 Named `submit` rather than `post` for the reason `visit` is not
     * `get`: the framework's own `TestCase::post()` is public, so a private
     * override is a fatal error rather than a failing test.
     *
     * @param  array<string, string>  $fields
     * @return TestResponse<Response>
     */
    private function submit(string $host, string $path, array $fields): TestResponse
    {
        return $this->send(Request::create(
            'https://'.$host.$path,
            'POST',
            $fields,
            $this->cookies[$host] ?? [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        ), $host);
    }

    /** @return TestResponse<Response> */
    private function send(Request $request, string $host): TestResponse
    {
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

    /**
     * Read one site's `v1`, optionally presenting a credential.
     *
     * 🛑 A password arrives as a request parameter because §8.12.16's
     * credential **page** is still owed — there is no dashboard form yet — and
     * that is what the transport reads either way.
     *
     * @return TestResponse<Response>
     */
    private function read(string $site, ?string $password = null, ?string $bearer = null): TestResponse
    {
        $host = $this->sites[$site]['host'];

        $request = Request::create(
            'https://'.$host.'/en/v1/',
            'GET',
            $password === null ? [] : ['docup_password' => $password],
            $this->cookies[$host] ?? [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        );

        if ($bearer !== null) {
            $request->headers->set('Authorization', 'Bearer '.$bearer);
        }

        return $this->send($request, $host);
    }

    /** @param  TestResponse<Response>  $response */
    private function assertNotFound(TestResponse $response, string $message = ''): void
    {
        $this->assertSame(
            404,
            $response->getStatusCode(),
            $message === ''
                ? '🛑 §8.12.23 makes 404 the default for an unauthorised resource'
                : '🛑 '.$message,
        );
    }

    /**
     * A URL's query string as a flat map of strings.
     *
     * `parse_str` writes `string|array<mixed>` into its out-parameter, so every
     * read needs narrowing; dropping a repeated parameter is right here,
     * because one in a URL DocUp built would be a bug the assertion that wanted
     * the value reports.
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
     * 🛑 Read, never set. Route host constraints are compiled before `setUp`
     * runs, so overriding `docup.origins.app` would move the URLs the
     * application *builds* and not the ones it *matches*.
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
