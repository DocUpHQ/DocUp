<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Providers;

use App\Access\ReaderPolicies;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Drivers\HeaderTrustDriver;
use App\Auth\Providers\Drivers\LdapDriver;
use App\Auth\Providers\Drivers\MtlsDriver;
use App\Auth\Providers\Drivers\PasswordDriver;
use App\Auth\Providers\ReaderCredentials;
use App\Credentials\SecretRedactor;
use App\Http\Middleware\ConvertShareLink;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Readers\ReaderCookies;
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
use Tests\TestCase;

/**
 * 🛑 §17's Phase 23 exit criteria, over the **real** HTTP path.
 *
 * > "Password, secret link (with expiry) and `Authorization: Bearer` each grant
 * > **exactly** their scope and nothing wider. A share link in a query string
 * > converts to a cookie and 302s to a clean URL, and the query value appears
 * > in no log. An expired link 404s. 🛑 A degraded binding returns a branded
 * > 503 naming the binding, and offers **no** path to public. 🛑 A zero-rule
 * > policy denies everything with a red banner. A referenced binding cannot be
 * > deleted. Argon2 parameters are asserted at or above the OWASP floor by
 * > test."
 *
 * "Exactly their scope and nothing wider" is the phrase that shapes this file:
 * every credential test asserts a 200 on what it should reach **and** a refusal
 * on what it should not, because a credential that works is not evidence of a
 * credential that is bounded.
 */
final class ReaderProviderTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private User $operator;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-prov-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'prov-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Provider Co',
            'slug' => 'prov-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Guarded',
            /*
             * 🛑 The project stays **public** and the versions are private, so
             * §8.12.23's case (b) is available and a refusal is a refusal of
             * the version rather than of the project. That is the shape a
             * credential is actually for: a mostly-public site with a guarded
             * version.
             */
            'visibility' => 'public',
        ]);

        $this->version = $this->publishVersion('v1');
        /*
         * 🛑 Published and deliberately not kept. Every test here reaches a
         * version by slug through the real HTTP path, so holding the model
         * would be holding a handle nothing uses — but the version has to
         * exist, because "nothing wider" is asserted against it.
         */
        $this->publishVersion('v2');

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'op-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        $this->mountOn($this->host);

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

    // -------------------------------------------------- "exactly their scope"

    /**
     * 🛑 A password grants the rule's scope and nothing wider.
     *
     * The `password` driver carries no scope of its own — one password admits
     * everybody a rule admits — so "exactly their scope" here means the
     * **rule's** version selector, and the assertion that matters is the second
     * one: `v2` is refused with the same password.
     */
    public function test_a_password_grants_exactly_the_rule_s_scope(): void
    {
        $binding = $this->activeBinding('password', 'the client portal', secrets: [
            'password_hash' => Hash::make('correct horse'),
        ]);

        $this->ruleFor($binding, versionSlugs: ['v1'], leaf: 'binding');

        /* No password: refused, and **not** challenged — nothing was presented. */
        $anonymous = $this->read('v1');
        $this->assertNotFound($anonymous);

        /* The password, submitted: admitted to v1. */
        $admitted = $this->read('v1', password: 'correct horse');
        $admitted->assertOk();

        /* 🛑 And nothing wider: v2 is outside the rule. */
        $this->assertNotFound($this->read('v2', password: 'correct horse'));

        /*
         * 🛑 A wrong password is §8.12.23's case (a) — "a credential was
         * presented and rejected" — so it is one of the exactly two cases a
         * challenge is permitted in, and §8.12.24 makes the answer to this
         * non-interactive client a `401` carrying the header. Asserting a 404
         * here would have been asserting the opposite of the requirement: the
         * reader already knows the resource exists, because they just tried to
         * open it with a credential for it, so withholding the challenge
         * protects nothing and strands them.
         */
        $wrong = $this->read('v1', password: 'wrong');
        $wrong->assertStatus(401);
        $this->assertSame(
            'Bearer realm="docup", scope="docs:read"',
            $wrong->headers->get('WWW-Authenticate'),
        );
    }

    /**
     * 🛑 A share link grants its own scope and nothing wider — "with expiry",
     * which §8.12.16 makes mandatory.
     *
     * Two bounds are asserted, because a link has two: the **rule's** and the
     * **credential's**. A link issued for `/guide/` inside a rule that admits
     * every path must still be refused on `/internal/`, because §12.3's last
     * conjunct narrows to the satisfying leaf's scope.
     */
    public function test_a_share_link_grants_exactly_its_own_scope(): void
    {
        $binding = $this->activeBinding('shared_link', 'the engagement link', shareable: true);
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'share');

        $link = $this->issueLink($binding, pathPrefixes: ['/guide'], expiresIn: 3600);

        /* The link reaches what it is scoped to. */
        $this->read('v1', share: $link, path: '/guide/index.html')->assertOk();

        /*
         * 🛑 And **nothing wider**, even though the rule admits every path.
         * This is §12.3's last conjunct: the credential narrows the reader.
         */
        $this->assertNotFound($this->read('v1', share: $link, path: '/internal/index.html'));
    }

    /** 🛑 §17: "An expired link 404s." */
    public function test_an_expired_link_404s(): void
    {
        $binding = $this->activeBinding('shared_link', 'the stale link', shareable: true);
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'share');

        $link = $this->issueLink($binding, expiresIn: 3600);

        $this->read('v1', share: $link)->assertOk();

        /* Move the expiry into the past, which is what time does. */
        DB::table('reader_credentials')->update([
            'expires_at' => now()->subMinute()->format('Y-m-d H:i:s.v'),
        ]);

        $this->assertNotFound($this->read('v1', share: $link));
    }

    /** And a revoked link stops working on its next use, with nothing purged. */
    public function test_a_revoked_link_stops_working_immediately(): void
    {
        $binding = $this->activeBinding('shared_link', 'the revoked link', shareable: true);
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'share');

        $link = $this->issueLink($binding, expiresIn: 3600);
        $this->read('v1', share: $link)->assertOk();

        $id = (string) DB::table('reader_credentials')->value('id');
        app(ReaderCredentials::class)->revoke($id, 'operator');

        /*
         * 🛑 No cache flush and no epoch bump between these two reads. A
         * credential is checked against the database on the request that
         * presents it, which is why §8.12.16's revocation needs no
         * invalidation machinery at all.
         */
        $this->assertNotFound($this->read('v1', share: $link));
    }

    /**
     * 🛑 A single-use link admits one reader, and the count is atomic.
     *
     * `max_uses` is enforced by the `UPDATE`'s own `WHERE`, so two concurrent
     * requests cannot both see the last use available — which for a
     * single-use link is the whole of its value.
     */
    public function test_a_single_use_link_admits_one_reader(): void
    {
        $binding = $this->activeBinding('shared_link', 'one use only', shareable: true);
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'share');

        $link = $this->issueLink($binding, expiresIn: 3600, maxUses: 1);

        $this->read('v1', share: $link)->assertOk();
        $this->assertNotFound($this->read('v1', share: $link));
    }

    /**
     * 🛑 A bearer token grants exactly its scope — §8.12.16's "version and path
     * scope".
     *
     * And it establishes **no session**, which is the point of a non-interactive
     * reader: a CI job has nowhere to keep a cookie, so the token is presented
     * on every request.
     */
    public function test_a_bearer_token_grants_exactly_its_scope(): void
    {
        $binding = $this->activeBinding('reader_token', 'the CI token');
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'bearer');

        $token = $this->issueToken($binding, versionSlugs: ['v1']);

        $this->read('v1', bearer: $token)->assertOk();

        /* 🛑 Nothing wider: the token names v1 and the rule admits both. */
        $this->assertNotFound($this->read('v2', bearer: $token));

        /* And no session cookie was set — a token reader keeps none. */
        $response = $this->read('v1', bearer: $token);

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            $this->assertNotSame(
                ReaderCookies::SESSION,
                $cookie->getName(),
                '🛑 a bearer reader establishes no session (§8.12.24)',
            );
        }
    }

    /** 🛑 A malformed `Authorization` header is nothing, not an error. */
    public function test_a_malformed_authorization_header_is_ignored(): void
    {
        $binding = $this->activeBinding('reader_token', 'the strict token');
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'bearer');

        foreach (['Bearer', 'Basic abcdefghijklmnop', 'Bearer a b', 'Bearerxyz', ''] as $header) {
            $this->assertNotFound(
                $this->read('v1', authorization: $header),
                'malformed header must not authorise: "'.$header.'"',
            );
        }
    }

    // ------------------------------------------- §8.12.16's query-to-cookie

    /**
     * 🛑 §17: "A share link in a query string converts to a cookie and 302s to
     * a clean URL, and the query value appears in no log."
     *
     * Three assertions in one, because the requirement is three things and
     * passing two of them is the failure mode: a conversion that sets the
     * cookie but leaves the parameter, or redirects but drops the reader's own
     * query.
     */
    public function test_a_share_link_in_a_query_string_converts_to_a_cookie(): void
    {
        $binding = $this->activeBinding('shared_link', 'the emailed link', shareable: true);
        $this->ruleFor($binding, versionSlugs: ['v1', 'v2'], leaf: 'share');

        $link = $this->issueLink($binding, expiresIn: 3600);

        $response = $this->fetch(
            "https://{$this->host}/en/v1/?highlight=foo&".ConvertShareLink::PARAMETER.'='.$link,
        );

        /* 1. A 302 to a clean URL. */
        $response->assertStatus(302);

        $location = (string) $response->headers->get('Location');

        $this->assertStringNotContainsString(ConvertShareLink::PARAMETER, $location);
        $this->assertStringNotContainsString($link, $location);

        /*
         * 🛑 2. The reader's **own** query survives. Dropping the whole query
         * string would silently change the page they were sent to — a
         * `?highlight=` is how a documentation link points at a passage.
         */
        $this->assertStringContainsString('highlight=foo', $location);

        /* 3. The cookie carries the secret. */
        $cookies = [];

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = (string) $cookie->getValue();
        }

        $this->assertSame($link, $cookies[ReaderCookies::SHARE] ?? null);

        /* And the cookie then works on the clean URL. */
        $this->read('v1', share: $link)->assertOk();
    }

    /**
     * 🛑 "the query value appears in no log", and the reason it already does
     * not is a **Phase 05** decision.
     *
     * {@see SecretRedactor}'s `docup(?:_[a-z]+)?_…` pattern matches a link
     * secret because §9.1.4 mints every token with a `docup_` prefix. Asserted
     * rather than assumed, because the thing that would break it is somebody
     * minting a credential without that prefix — and this is the test that
     * would fail.
     */
    public function test_a_link_secret_is_redacted_from_logs(): void
    {
        $binding = $this->activeBinding('shared_link', 'the logged link', shareable: true);
        $link = $this->issueLink($binding, expiresIn: 3600);

        $redactor = new SecretRedactor;

        $line = 'GET /en/v1/?'.ConvertShareLink::PARAMETER.'='.$link.' HTTP/1.1';

        $this->assertStringNotContainsString(
            $link,
            $redactor->scrub($line),
            '🛑 §9.1.4\'s docup_ prefix is what makes §8.12.16\'s log requirement hold',
        );
    }

    /**
     * 🛑 An invalid secret still leaves the URL.
     *
     * Leaving it because the link was wrong is the worst of both outcomes: no
     * access **and** a leaked credential in the history, the `Referer` and
     * every proxy log. And no cookie is set, so a reader who clicked a typo'd
     * link is not challenged on every subsequent page.
     */
    public function test_an_invalid_share_secret_still_leaves_the_url(): void
    {
        $response = $this->fetch(
            "https://{$this->host}/en/v1/?".ConvertShareLink::PARAMETER.'=docup_link_notarealsecretatall',
        );

        $response->assertStatus(302);
        $this->assertStringNotContainsString('docup_link_', (string) $response->headers->get('Location'));

        foreach ($response->baseResponse->headers->getCookies() as $cookie) {
            $this->assertNotSame(
                ReaderCookies::SHARE,
                $cookie->getName(),
                '🛑 a junk secret must not become a junk cookie',
            );
        }
    }

    /**
     * 🛑 The conversion response is never cacheable.
     *
     * It carries a `Set-Cookie` holding a live credential; a shared cache that
     * stored it would hand the next reader somebody else's share link —
     * §9.3.2's failure behind a 302 that looks like routing.
     */
    public function test_the_conversion_is_never_cacheable(): void
    {
        $binding = $this->activeBinding('shared_link', 'the uncached link', shareable: true);
        $link = $this->issueLink($binding, expiresIn: 3600);

        $response = $this->fetch(
            "https://{$this->host}/en/v1/?".ConvertShareLink::PARAMETER.'='.$link,
        );

        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        $this->assertSame('no-referrer', $response->headers->get('Referrer-Policy'));
    }

    // ----------------------------------------------- §8.12.19's degraded 503

    /**
     * 🛑 §17: "A degraded binding returns a branded 503 naming the binding, and
     * offers **no** path to public."
     *
     * Four assertions, and the last is the one the requirement is really about:
     * §8.12.19 says the UI "MUST NOT offer a 'make public' button there", and
     * the reader's page must not offer a way round either.
     */
    public function test_a_degraded_binding_returns_a_branded_503(): void
    {
        $binding = $this->activeBinding('password', 'the broken portal', secrets: [
            'password_hash' => Hash::make('irrelevant'),
        ]);

        $this->ruleFor($binding, versionSlugs: [], leaf: 'binding');

        DB::table('auth_provider_bindings')
            ->where('id', $binding)
            ->update(['state' => BindingState::Degraded->value, 'epoch' => 99]);

        Cache::flush();

        $response = $this->read('v1');

        /* 1. 503, not 404 — the reader may be fine and we cannot tell. */
        $response->assertStatus(503);

        $body = (string) $response->baseResponse->getContent();

        /* 2. Naming the binding, so the reader can tell somebody which. */
        $this->assertStringContainsString('the broken portal', $body);

        /* 3. Never cacheable: the outage must not outlive itself. */
        $this->assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));

        /*
         * 🛑 4. **No path to public.** No "continue as guest", no "view public
         * version", and no `WWW-Authenticate` inviting a credential the
         * installation cannot check.
         */
        foreach (['continue as', 'as a guest', 'public version', 'make public', 'skip sign'] as $escape) {
            $this->assertStringNotContainsStringIgnoringCase(
                $escape,
                $body,
                '🛑 §8.12.19: a degraded binding offers no path to public',
            );
        }

        $this->assertNull($response->headers->get('WWW-Authenticate'));
    }

    /**
     * 🛑 And a degraded binding does not fall back to a **healthy** one.
     *
     * The requirement's own words: "never fall back to another provider". This
     * is the case that a naive merge gets wrong — a project with a working
     * allowlist and a broken portal would quietly keep serving the office
     * network, which is a privacy posture nobody chose.
     */
    public function test_a_degraded_binding_does_not_fall_back_to_a_healthy_one(): void
    {
        $healthy = $this->activeBinding('ip_allowlist', 'the office', config: [
            'ranges' => ['127.0.0.0/8'],
        ]);

        $broken = $this->activeBinding('password', 'the broken idp', secrets: [
            'password_hash' => Hash::make('irrelevant'),
        ]);

        $this->ruleFor($healthy, versionSlugs: [], leaf: 'gate');

        DB::table('auth_provider_bindings')
            ->where('id', $broken)
            ->update(['state' => BindingState::Degraded->value]);

        Cache::flush();

        /*
         * The allowlist would admit this request on its own — the test client's
         * address is in `127.0.0.0/8`. It must still get the 503.
         */
        $this->read('v1')->assertStatus(503);
    }

    // ------------------------------------------- lifecycle and referential rules

    /** 🛑 §17: "A referenced binding cannot be deleted." */
    public function test_a_referenced_binding_cannot_be_deleted(): void
    {
        $binding = $this->activeBinding('shared_link', 'the referenced one', shareable: true);
        $this->issueLink($binding, expiresIn: 3600);

        try {
            app(Bindings::class)->delete($binding);
            $this->fail('a referenced binding was deleted');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::StillReferenced, $refused->rejection);
        }

        /* And once the credential is revoked it is still referenced — revocation is not deletion. */
        $id = (string) DB::table('reader_credentials')->value('id');
        app(ReaderCredentials::class)->revoke($id, 'operator');

        try {
            app(Bindings::class)->delete($binding);
            $this->fail('🛑 a revoked credential still references its binding');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::StillReferenced, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.12.4: "`ldap`, `mtls` and `header_trust` MUST be installation-scope
     * only."
     *
     * None of the three shipped in Phase 23, so what this asserted was the
     * **mechanism** that would refuse them: a driver whose
     * `allowsProjectScope()` is false is refused at project scope, and the
     * registry refuses a type it does not know at all.
     *
     * 🛑 All three ship now, so this test is down to its last case — and that
     * is the test narrowing correctly rather than weakening.
     * {@see self::test_the_three_edge_drivers_are_refused_at_project_scope()}
     * makes the assertion Phase 23 said it could not.
     */
    public function test_an_unknown_driver_type_is_refused_at_write_time(): void
    {
        $bindings = app(Bindings::class);

        /*
         * 🛑 This list shrinks as phases land, and each departure is the phase
         * boundary moving rather than the gate weakening. `oidc` left in P24,
         * `saml` in P25, `ldap` in P26b — §8.12.17 names the driver and §17
         * names the phase, so a registry that still refused one after its phase
         * would be the thing to fix.
         *
         * `mtls` and `header_trust` left in P26b as well, which empties the
         * list of real drivers entirely. What remains is a name that will never
         * be registered — and it stays, because "the registry refuses a type it
         * does not know" is still a rule and this is the only thing left
         * asserting it.
         */
        foreach (['made_up', 'ldap_v2', 'kerberos'] as $type) {
            try {
                $bindings->create('project', $this->project->id, $type, 'nope-'.$type);
                $this->fail('"'.$type.'" was accepted and no driver is registered for it');
            } catch (BindingRefused $refused) {
                $this->assertSame(
                    BindingRejection::UnknownDriver,
                    $refused->rejection,
                    '"'.$type.'" must be refused by the registry (§8.12.2)',
                );
            }
        }
    }

    /**
     * 🛑 §8.12.4's installation-scope-only rule, now that a driver exists to
     * test it with.
     *
     * Phase 23's note on the test above said what it could not yet assert:
     * "None of the three ships in Phase 23, so what is asserted is the
     * **mechanism**." `ldap` ships in Phase 26b, so the rule itself is
     * assertable for all three — and the refusal is now `ScopeNotPermitted`
     * rather than `UnknownDriver`, which is a **stronger** refusal from a more
     * specific check.
     *
     * > "`ldap`, `mtls` and `header_trust` MUST be **installation-scope only**
     * > — they reach into the operator's internal network or depend on facts
     * > only the TLS terminator can establish, so project-scope configuration
     * > would convert tenant self-service into an SSRF or header-spoofing
     * > primitive."
     *
     * A project administrator who could configure this would be a tenant who
     * could point DocUp's own server at any host on the operator's network.
     */
    public function test_the_three_edge_drivers_are_refused_at_project_scope(): void
    {
        $bindings = app(Bindings::class);

        /*
         * 🛑 All three, not just `ldap`. The requirement names three drivers
         * and the reason differs between them — `ldap` reaches into the
         * operator's network, the other two depend on the terminator — so a
         * test covering one would leave the other two resting on a capability
         * method nobody asserted.
         */
        foreach (['ldap', 'mtls', 'header_trust'] as $type) {
            try {
                $bindings->create('project', $this->project->id, $type, 'tenant '.$type);
                $this->fail('🛑 §8.12.4: a project-scoped `'.$type.'` binding is a tenant primitive');
            } catch (BindingRefused $refused) {
                $this->assertSame(
                    BindingRejection::ScopeNotPermitted,
                    $refused->rejection,
                    '`'.$type.'` must be refused for its SCOPE, not for being unknown',
                );
            }
        }

        /* The capability is what `permittedAt()` reads, so assert it directly too. */
        foreach ([LdapDriver::class, MtlsDriver::class, HeaderTrustDriver::class] as $driver) {
            $this->assertFalse(
                $driver::allowsProjectScope(),
                $driver.' would be configurable by a tenant',
            );
        }
    }

    /** 🛑 §8.12.16's mandatory expiry, refused at write time. */
    public function test_a_share_link_without_an_expiry_is_refused(): void
    {
        $binding = $this->activeBinding('shared_link', 'the unexpiring link', shareable: true);

        try {
            app(ReaderCredentials::class)->issue(
                $this->project,
                $binding,
                'shared_link',
                'forever',
            );
            $this->fail('a share link with no expiry was issued');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::ShareLinkNeedsExpiry, $refused->rejection);
        }
    }

    /** 🛑 And a link against a binding that is not marked shareable. */
    public function test_a_link_against_a_non_shareable_binding_is_refused(): void
    {
        /*
         * 🛑 **Not** an `active` binding, and it cannot be one: a
         * `shared_link` that is not shareable fails its own probe
         * ({@see \App\Auth\Providers\Drivers\SharedLinkDriver::probe()}), so
         * §8.12.19 refuses the transition to `active`. That is the lifecycle
         * working, and the refusal under test here is a different one —
         * `issue()` does not require an active binding, so this asserts the
         * `shareable` flag and nothing else.
         */
        $binding = $this->binding('shared_link', 'not shareable', shareable: false);

        try {
            app(ReaderCredentials::class)->issue(
                $this->project,
                $binding,
                'shared_link',
                'nope',
                expiresAt: time() + 3600,
            );
            $this->fail('a link was issued against a non-shareable binding');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::BindingNotShareable, $refused->rejection);
        }
    }

    // --------------------------------------- §17's Argon2 floor, by test

    /**
     * 🛑 §17: "Argon2 parameters are asserted at or above the OWASP floor by
     * test."
     *
     * Four assertions, because the floor can be breached in four places and
     * `BedrockTest` only guards the first:
     *
     * 1. the **configuration**, which is where an operator lowers it;
     * 2. {@see PasswordDriver::owaspFloor()}, a second copy of the same three
     *    numbers that can drift from the first — the driver refuses a hash
     *    below it, so a drift downwards would make the refusal cosmetic;
     * 3. a **real hash's own encoded parameters**, which is the only one of the
     *    four that proves the configuration is actually reaching PHP rather
     *    than being read and ignored;
     * 4. the **probe's refusal** of a hash below the floor, which is what
     *    §8.12.19 relies on to keep such a binding out of `active`.
     */
    public function test_argon2id_is_at_or_above_the_owasp_floor(): void
    {
        $floor = PasswordDriver::owaspFloor();

        /* 1. OWASP's own published minimum for Argon2id, m=19456 t=2 p=1. */
        $this->assertSame(['memory' => 19456, 'time' => 2, 'threads' => 1], $floor);

        /* 2. The configuration is at or above it. */
        foreach ($floor as $parameter => $minimum) {
            $this->assertGreaterThanOrEqual(
                $minimum,
                (int) config('hashing.argon.'.$parameter),
                '🛑 §8.12.16: hashing.argon.'.$parameter.' is below the OWASP floor',
            );
        }

        /*
         * 3. 🛑 And the hash PHP actually produces says so itself. Read from
         * the encoded hash rather than from config, because this is the
         * assertion a misconfigured driver cannot pass: `$argon2id$v=19$m=…`
         * is what the verifier will use, whatever the configuration claims.
         */
        $hash = Hash::make('correct horse battery staple');

        $this->assertStringStartsWith('$argon2id$', $hash);

        $encoded = [];

        $this->assertSame(1, preg_match('/\$m=(\d+),t=(\d+),p=(\d+)\$/', $hash, $encoded));

        /*
         * The three groups exist because the match succeeded, which the
         * assertion above has established — but the analyser types
         * `preg_match`'s output as "the groups or nothing", so the narrowing is
         * written out. Asserting the count is also the honest check: a future
         * PHP that spelled the parameters differently would reach the
         * comparisons with a short array rather than with silent nulls.
         */
        $this->assertCount(4, $encoded);

        $this->assertGreaterThanOrEqual($floor['memory'], (int) ($encoded[1] ?? 0));
        $this->assertGreaterThanOrEqual($floor['time'], (int) ($encoded[2] ?? 0));
        $this->assertGreaterThanOrEqual($floor['threads'], (int) ($encoded[3] ?? 0));

        /*
         * 4. 🛑 A binding holding a hash below the floor fails its probe, so
         * §8.12.19 cannot promote it to `active`. Written with a deliberately
         * weak hash rather than by lowering the configuration, because §9.4
         * forbids lowering a gate to make a test pass — and a weak *stored*
         * hash is the real case anyway: one written before the operator raised
         * `ARGON_MEMORY`.
         */
        $weak = password_hash('correct horse battery staple', PASSWORD_ARGON2ID, [
            'memory_cost' => 1024,
            'time_cost' => 1,
            'threads' => 1,
        ]);

        $this->assertStringContainsString('m=1024', $weak);

        $binding = $this->binding('password', 'the stale hash', secrets: [
            'password_hash' => $weak,
        ]);

        $this->context->spanAllOrganisations();
        $result = app(Bindings::class)->probe($binding);
        $this->context->forget();

        $this->assertFalse(
            $result->passed,
            '🛑 §8.12.16: a stored hash below the Argon2id floor must fail its probe',
        );
        $this->assertStringContainsString('below the configured', $result->summary);
    }

    /**
     * 🛑 And a binding whose hash is below the floor cannot become `active`.
     *
     * The probe failing is only half of §8.12.19; the half that protects
     * readers is the transition refusing. Asserted separately because the two
     * are separate code paths and a probe whose verdict nothing reads would
     * pass the test above.
     */
    public function test_a_weak_hash_keeps_a_binding_out_of_active(): void
    {
        $weak = password_hash('whatever', PASSWORD_ARGON2ID, [
            'memory_cost' => 1024,
            'time_cost' => 1,
            'threads' => 1,
        ]);

        $this->assertStringContainsString('m=1024', $weak);

        $this->expectException(BindingRefused::class);

        $this->activeBinding('password', 'the weak portal', secrets: [
            'password_hash' => $weak,
        ]);
    }

    // ---------------------------------------------------------------- fixtures

    /**
     * An `active` binding, through the real lifecycle.
     *
     * 🛑 Goes through {@see Bindings::transition()} rather than writing
     * `state = 'active'`, so every test here is also a test that §8.12.19's
     * progression can be completed — and so a change that broke it would fail
     * this whole file rather than passing it on a hand-written row.
     *
     * @param  array<string, mixed>  $config
     * @param  array<string, string>  $secrets
     * @return string raw 16 bytes
     */
    private function activeBinding(
        string $type,
        string $name,
        array $config = [],
        array $secrets = [],
        bool $shareable = false,
    ): string {
        $id = $this->binding($type, $name, $config, $secrets, $shareable);

        $this->context->spanAllOrganisations();

        $bindings = app(Bindings::class);

        $bindings->transition($id, BindingState::Verifying);
        $bindings->probe($id);
        $bindings->recordTestLogin($id, $this->operator->id);
        $bindings->transition($id, BindingState::Active);

        Cache::flush();
        $this->context->forget();

        return $id;
    }

    /**
     * A `draft` binding, created and left there.
     *
     * 🛑 Separate from {@see activeBinding()} because some bindings
     * **cannot** become active and that is correct: a non-shareable
     * `shared_link` fails its own probe, so §8.12.19 refuses the transition.
     * A test about such a binding needs the row without the lifecycle, and the
     * two helpers keep that distinction visible rather than hiding it behind a
     * boolean on one.
     *
     * @param  array<string, mixed>  $config
     * @param  array<string, string>  $secrets
     * @return string raw 16 bytes
     */
    private function binding(
        string $type,
        string $name,
        array $config = [],
        array $secrets = [],
        bool $shareable = false,
    ): string {
        $this->context->spanAllOrganisations();

        $id = app(Bindings::class)->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: $type,
            name: $name,
            config: $config,
            secrets: $secrets,
            organisationId: $this->organisation->id,
            shareable: $shareable,
        );

        Cache::flush();
        $this->context->forget();

        return $id;
    }

    /**
     * A policy rule admitting one leaf, optionally scoped to versions.
     *
     * @param  list<string>  $versionSlugs
     */
    private function ruleFor(string $bindingId, array $versionSlugs, string $leaf): void
    {
        $this->context->for($this->organisation->id);

        /** @var ReaderPolicies $policies */
        $policies = app(ReaderPolicies::class);

        if (DB::table('reader_policies')->where('project_id', $this->project->id)->doesntExist()) {
            /*
             * 🛑 `allowNetworkOnlyAccess` for the gate case, because §8.12.7
             * **refuses** a requirement satisfiable without an identity at write
             * time — and a gate bears none. That is the invariant working: a
             * gate-only rule is reachable only through the escape §8.12.7 names
             * ("the project has explicitly enabled network-only access,
             * UI-flagged weak, audited"), and a test that wrote the row by hand
             * would have bypassed the very check Phase 21 exists for.
             */
            $policies->createFor($this->project, allowNetworkOnlyAccess: $leaf === 'gate');
        }

        /*
         * 🛑 Through `addRule()`, the **real** write path, not an INSERT.
         *
         * Writing the row by hand is how the first version of this fixture got
         * `version_selector` wrong: §8.12.6's selector is
         * `{"slugs": [...], "languages": [...]}` and a bare array parses to no
         * slugs at all — so `namesResourceExplicitly()` was false, the reader
         * never reached §12.3's `restricted` rung, and every credential test
         * failed on `version_visibility` with a rule that had matched. Using
         * the API that stores it means the fixture cannot disagree with the
         * reader.
         */
        $policies->addRule(
            project: $this->project,
            label: 'admit '.$leaf,
            allow: true,
            /*
             * 🛑 The requirement names the **binding** for an identity leaf, so
             * §12.3's per-binding check is exercised rather than bypassed by a
             * bare leaf kind.
             */
            requirement: $leaf === 'gate'
                ? ['leaf' => 'gate', 'driver' => 'ip_allowlist']
                : ['leaf' => $leaf, 'binding_id' => Uuid::toText($bindingId)],
            versionSlugs: $versionSlugs,
            actorId: $this->operator->id,
        );

        Cache::flush();
        $this->context->forget();
    }

    /** @param  list<string>  $pathPrefixes */
    private function issueLink(
        string $bindingId,
        array $pathPrefixes = [],
        int $expiresIn = 3600,
        ?int $maxUses = null,
        ?string $password = null,
    ): string {
        $this->context->for($this->organisation->id);

        $issued = app(ReaderCredentials::class)->issue(
            project: $this->project,
            bindingId: $bindingId,
            kind: 'shared_link',
            label: 'a link',
            pathPrefixes: $pathPrefixes,
            expiresAt: time() + $expiresIn,
            maxUses: $maxUses,
            password: $password,
            actorId: $this->operator->id,
        );

        $this->context->forget();

        return $issued['secret'];
    }

    /** @param  list<string>  $versionSlugs */
    private function issueToken(string $bindingId, array $versionSlugs = []): string
    {
        $this->context->for($this->organisation->id);

        $issued = app(ReaderCredentials::class)->issue(
            project: $this->project,
            bindingId: $bindingId,
            kind: 'reader_token',
            label: 'a token',
            versionSlugs: $versionSlugs,
            actorId: $this->operator->id,
        );

        $this->context->forget();

        return $issued['secret'];
    }

    /**
     * One read, with whatever credential the test is exercising.
     *
     * @return TestResponse<Response>
     */
    private function read(
        string $version,
        string $path = '/',
        ?string $share = null,
        ?string $bearer = null,
        ?string $password = null,
        ?string $authorization = null,
    ): TestResponse {
        $cookies = [];

        if ($share !== null) {
            $cookies[ReaderCookies::SHARE] = $share;
        }

        $headers = [];

        if ($bearer !== null) {
            $headers['Authorization'] = 'Bearer '.$bearer;
        }

        if ($authorization !== null) {
            $headers['Authorization'] = $authorization;
        }

        $url = "https://{$this->host}/en/{$version}".($path === '/' ? '/' : $path);

        /*
         * 🛑 A password arrives as a POST field in the real credential flow,
         * which P23 does not build a page for — no dashboard exists. So it is
         * passed as a request parameter here, which is the same thing the
         * transport reads, and the credential **page** is recorded as owed.
         */
        $request = Request::create(
            $url,
            'GET',
            $password === null ? [] : ['docup_password' => $password],
            $cookies,
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        );

        foreach ($headers as $name => $value) {
            $request->headers->set($name, $value);
        }

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    /** @return TestResponse<Response> */
    private function fetch(string $url): TestResponse
    {
        return TestResponse::fromBaseResponse($this->app->handle(
            Request::create($url, 'GET', [], [], [], ['REMOTE_ADDR' => '127.0.0.1']),
        ));
    }

    /** @param  TestResponse<Response>  $response */
    private function assertNotFound(TestResponse $response, string $message = ''): void
    {
        $this->assertSame(
            404,
            $response->getStatusCode(),
            $message !== '' ? $message : '🛑 §8.12.23 makes 404 the default for an unauthorised resource',
        );
    }

    private function publishVersion(string $slug): ProjectVersion
    {
        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => 'en',
            /* 🛑 Private, so a credential has something to prove. */
            'visibility' => 'members',
        ])->save();

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>{$slug}</body></html>\n")
            ->add('html/guide/index.html', "<!doctype html><html><head></head><body>guide</body></html>\n")
            ->add('html/internal/index.html', "<!doctype html><html><head></head><body>internal</body></html>\n")
            ->toTarGz($this->fixtures.'/'.$slug.'.tar.gz');

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($version, $archive);

        return $version;
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
