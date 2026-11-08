<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Ldap;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Http\Controllers\Readers\SamlAcsController;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Middleware\PreventRequestForgery;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Storage;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * §8.12.16's credential page, and what it refuses to tell anybody.
 *
 * 🛑 **No directory is needed for any of this**, which is the point. Every
 * assertion here is about the endpoint rather than about LDAP: what it serves,
 * to whom, on what evidence, and what a failure looks like.
 * {@see LdapDirectoryTest} drives the other half against a real directory.
 *
 * ## 🛑 The question this file exists to answer
 *
 * A credential form is a page that takes a password, on the dashboard origin,
 * reachable without a session. So the interesting assertions are all
 * negative:
 *
 * - it does not render for somebody who has not come from a documentation
 *   origin, because a form that rendered for anybody would confirm that this
 *   installation has LDAP configured at all;
 * - it does not render for a project with no `ldap` binding, for the same
 *   reason one rung down;
 * - it carries **no project or organisation branding** (§8.14.12), so a
 *   tenant-controlled domain can never be the thing that looks like it
 *   collected the password;
 * - it carries no handoff challenge in its own URL;
 * - and the POST is CSRF-protected, unlike the SAML ACS beside it, because
 *   this form is served by DocUp to the origin it posts back to.
 */
final class LdapSignInTest extends TestCase
{
    use DatabaseTransactions;

    /** 43 base64url characters, the shape `reader_handoff_codes` stores. */
    private const string CHALLENGE = 'Cq8rTQ8h-0VYjJm3tZ9xN2pL7wKdG5sRfBvHcUyAeI4';

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $domainId;

    private string $host;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-ldapui-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $slug = 'ldapui-'.bin2hex(random_bytes(3));
        $this->host = $slug.'.'.$this->docsApex();

        $this->organisation = Organisation::query()->create([
            'name' => 'Directory Co',
            'slug' => 'dir-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => $slug,
            'name' => 'Guarded',
            'visibility' => 'members',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'members',
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->mountTheProject($slug);

        /*
         * 🛑 A PUBLISHED revision, because the routing snapshot is not
         * servable without one -- and the controller resolves the project
         * through `$snapshot->matchFor($returnPath)` exactly as §8.9.4
         * requires. Without this the positive case is a 404 and every negative
         * case passes for the wrong reason, which is how this file first ran.
         */
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

    // ------------------------------------------------------- the ordinary case

    /**
     * 🛑 The positive case first, because every refusal below is only
     * meaningful if the page renders at all.
     */
    public function test_the_form_renders_for_a_reader_arriving_from_a_guarded_project(): void
    {
        $this->bindAnLdapProvider();

        $this->get($this->startUrl())
            ->assertOk()
            ->assertInertia(fn ($page) => $page
                ->component('Auth/ReaderSignIn')
                ->where('label', 'Corporate directory'));
    }

    /**
     * 🛑 §8.14.12: "Pages that accept credentials MUST carry **no project or
     * organisation branding**."
     *
     * Asserted over the whole response rather than over the props, because the
     * requirement is about what reaches the reader's browser — a project name
     * in a shared Inertia prop, a page title or a layout would all satisfy a
     * props-only check and violate the requirement.
     *
     * Phase 27 owns the enforcement of this rule across every credential page
     * (§17's "the credential-page branding refusal"); this page is written to
     * it now so it is not one that has to be fixed then.
     */
    public function test_the_form_carries_no_project_or_organisation_branding(): void
    {
        $this->bindAnLdapProvider();

        $body = $this->get($this->startUrl())->assertOk()->getContent();

        $this->assertIsString($body);
        $this->assertStringNotContainsString($this->project->name, $body, 'the project name reached a credential page');
        $this->assertStringNotContainsString((string) $this->project->slug, $body, 'the project slug reached a credential page');
        $this->assertStringNotContainsString($this->organisation->name, $body, 'the organisation name reached a credential page');
        $this->assertStringNotContainsString($this->host, $body, 'the documentation host reached a credential page');
    }

    // ------------------------------------------------------------- the refusals

    /**
     * 🛑 A bare GET is a 404, not an empty form.
     *
     * A form that rendered for anybody would confirm that this installation
     * has an `ldap` binding, which is a fact about the operator's internal
     * network. §8.9.4 resolves a project from the host precisely so that
     * reader-visible surfaces do not answer questions about the
     * installation's shape.
     */
    public function test_a_bare_get_is_not_a_form(): void
    {
        $this->bindAnLdapProvider();

        $this->get('/_/auth/ldap')->assertNotFound();
    }

    /** A challenge of the wrong shape is refused before anything is stored. */
    public function test_a_malformed_challenge_is_refused(): void
    {
        $this->bindAnLdapProvider();

        $this->get($this->startUrl(challenge: 'too-short'))->assertNotFound();
    }

    /** A domain that is not a domain is refused. */
    public function test_an_unknown_domain_is_refused(): void
    {
        $this->bindAnLdapProvider();

        $this->get($this->startUrl(domainId: Uuid::toText(Uuid::v7())))->assertNotFound();
    }

    /**
     * 🛑 And a project with **no** `ldap` binding is a 404 rather than an
     * empty form or an error.
     *
     * The reader learns nothing about which provider guards this project —
     * §8.12.3 resolves that server-side exactly so that they cannot name one,
     * and the absence of one is the same class of fact.
     */
    public function test_a_project_with_no_ldap_binding_is_refused(): void
    {
        $this->get($this->startUrl())->assertNotFound();
    }

    /**
     * 🛑 A binding that is not `active` is refused — §8.12.19's progression,
     * which `BindingContext::isUsable()` is the whole of.
     *
     * `verifying` specifically, because that is the state a binding sits in
     * before an operator has completed a test login: a form served from it
     * would collect real passwords for a directory nobody had proven DocUp
     * can reach.
     */
    public function test_a_binding_that_is_not_active_is_refused(): void
    {
        $this->bindAnLdapProvider(state: 'verifying');

        $this->get($this->startUrl())->assertNotFound();
    }

    // ---------------------------------------------------------------- the POST

    /** A POST with no pending sign-in is a 404, whatever it carries. */
    public function test_a_post_without_a_pending_sign_in_is_refused(): void
    {
        $this->bindAnLdapProvider();

        $this->post('/_/auth/ldap', ['username' => 'dana', 'password' => 'anything'])
            ->assertNotFound();
    }

    /**
     * 🛑 The POST keeps CSRF, unlike the SAML ACS beside it.
     *
     * That exemption exists because an assertion arrives as a cross-origin form
     * an identity provider auto-submits, with no DocUp token to present. This
     * form is served by DocUp to the same origin it posts back to, so the token
     * is both available and load-bearing: without it a third-party page could
     * post a reader's cached credentials into a flow whose handoff challenge
     * the attacker chose.
     *
     * 🛑 **Asserted over the route table, not over a status code**, and that
     * is not a weaker test -- it is the only honest one.
     * `ValidateCsrfToken::handle()` skips validation outright when
     * `runningUnitTests()` is true, which it is for the whole suite, so a 419
     * can never be produced here and `withMiddleware()` cannot bring it back. A
     * test asserting the status would pass whether the route were protected or
     * not, which is the shape of defect this phase keeps finding.
     *
     * So both halves are asserted together: this route carries the middleware
     * and the ACS beside it does not. The contrast is the requirement -- an
     * 🛑 **This test found the exemption was naming the wrong class.** The ACS
     * read `withoutMiddleware(ValidateCsrfToken::class)` while the `web` group
     * runs `PreventRequestForgery`, and `ValidateCsrfToken` EXTENDS it -- so the
     * exclusion named the subclass, the gathered list kept the parent, and the
     * ACS would have refused every genuine identity provider's POST in
     * production. Which is why the assertion is on `PreventRequestForgery`: the
     * class the group actually runs, not the one an exemption happens to name.
     *
     * An exemption that silently spread to a credential form is exactly what
     * {@see SamlAcsController}'s route comment
     * warns about when it says an `except` list "is a pattern list that grows".
     */
    public function test_the_post_keeps_csrf_and_the_saml_acs_does_not(): void
    {
        $this->assertContains(
            PreventRequestForgery::class,
            $this->middlewareFor('reader.ldap.store'),
            'the credential POST is exempt from CSRF',
        );

        $this->assertNotContains(
            PreventRequestForgery::class,
            $this->middlewareFor('reader.saml.acs'),
            'the SAML ACS is no longer exempt, which would refuse every genuine login',
        );
    }

    /**
     * 🛑 A failed attempt goes back to a URL carrying **no challenge**.
     *
     * The pending sign-in holds the domain, the challenge and the return path
     * server-side, so a retry needs none of them in a URL — which keeps a
     * handoff challenge out of the reader's history and out of any proxy log
     * on the dashboard origin.
     */
    public function test_a_failed_attempt_retries_without_the_challenge_in_the_url(): void
    {
        $this->bindAnLdapProvider();
        $this->get($this->startUrl())->assertOk();

        /*
         * An empty username, which is refused before the directory is reached
         * — so this test needs no directory and still exercises the refusal
         * path the form uses.
         */
        $response = $this->post('/_/auth/ldap', ['username' => '', 'password' => '']);

        $response->assertRedirect();
        $location = (string) $response->headers->get('Location');

        $this->assertStringNotContainsString(self::CHALLENGE, $location);
        $this->assertStringNotContainsString('challenge', $location);
        $this->assertStringEndsWith('/_/auth/ldap', $location);
    }

    /** And the retry renders the form again, with the failure said once. */
    public function test_the_retry_renders_the_form_with_a_single_message(): void
    {
        $this->bindAnLdapProvider();
        $this->get($this->startUrl())->assertOk();
        $this->post('/_/auth/ldap', ['username' => '', 'password' => ''])->assertRedirect();

        $this->get('/_/auth/ldap')
            ->assertOk()
            ->assertInertia(fn ($page) => $page
                ->component('Auth/ReaderSignIn')
                ->where('failed', true));
    }

    /**
     * 🛑 An over-long username is refused without reaching the directory.
     *
     * A megabyte of username is a megabyte the directory parses, and
     * `LdapFilter::build()` would escape it faithfully all the way there.
     */
    public function test_an_over_long_username_is_refused(): void
    {
        $this->bindAnLdapProvider();
        $this->get($this->startUrl())->assertOk();

        $this->post('/_/auth/ldap', [
            'username' => str_repeat('a', 257),
            'password' => 'anything',
        ])->assertRedirect();
    }

    // ------------------------------------------------------------- the plumbing

    /**
     * The middleware a named route actually runs, as the router gathers it.
     *
     * @return list<string>
     */
    private function middlewareFor(string $name): array
    {
        /*
         * 🛑 The HTTP kernel, made explicitly, because it is what
         * registers the `web` group from `bootstrap/app.php`. Without it the
         * group is EMPTY and `gatherRouteMiddleware()` returns only the
         * route's own middleware -- so every assertion here would be about
         * nothing, and the two halves of this test would both pass on a
         * route table that ran no middleware at all. Measured: two probes
         * of the same route disagreed until this line existed.
         */
        $this->app->make(HttpKernel::class);

        $route = Route::getRoutes()->getByName($name);

        $this->assertNotNull($route, 'no route named '.$name);

        return array_values(app('router')->gatherRouteMiddleware($route));
    }

    private function startUrl(?string $domainId = null, ?string $challenge = null): string
    {
        return '/_/auth/ldap?'.http_build_query([
            'domain' => $domainId ?? Uuid::toText($this->domainId),
            'challenge' => $challenge ?? self::CHALLENGE,
            'return' => '/en/latest/',
        ]);
    }

    /**
     * An installation-scoped `ldap` binding, which is the only scope §8.12.4
     * permits for this driver.
     */
    private function bindAnLdapProvider(string $state = 'active'): void
    {
        DB::table('auth_provider_bindings')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => null,
            'scope_type' => 'installation',
            'scope_id' => null,
            'type' => 'ldap',
            'name' => 'Corporate directory',
            'config' => json_encode([
                'uri' => 'ldaps://directory.invalid:636',
                'base_dn' => 'dc=example,dc=test',
                'user_filter' => '(&(objectClass=inetOrgPerson)(uid={username}))',
                'bind_dn' => 'cn=svc,dc=example,dc=test',
                'subject_attribute' => 'uid',
                'groups_attribute' => 'memberOf',
                'display_attribute' => 'cn',
                'provisioning' => 'create_reader_and_map_groups',
            ], JSON_THROW_ON_ERROR),
            'state' => $state,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        /*
         * The snapshot is cached per host and was built before the binding
         * existed. Flushed rather than waited out, because §8.12.3's
         * resolution reads bindings live and only the ROUTING snapshot is
         * cached — a stale one here would make the binding look absent.
         */
        Cache::flush();
    }

    private function mountTheProject(string $slug): void
    {
        $this->domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $this->domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $this->host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $this->domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    private function publish(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', '<!doctype html><html><head></head><body>guarded</body></html>')
            ->toTarGz($this->fixtures.'/tree.tar.gz');

        $this->context->for($this->organisation->id);

        app(Publisher::class)->publishUpload($this->version, $archive);

        $this->context->forget();
    }

    /**
     * 🛑 `docup.origins.docs`, which is the key the snapshot loader reads.
     *
     * A `docup.docs_apex` here resolved to null, so the fallback applied and
     * the fixture built a host under `docup-docs.test` while the loader was
     * deriving candidates from `docup-docs.localhost`. The domain row then
     * matched no candidate kind, the snapshot came back `servable: false`,
     * and the positive case was a 404 while every refusal passed -- for the
     * wrong reason.
     */
    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docup-docs.test';
    }
}
