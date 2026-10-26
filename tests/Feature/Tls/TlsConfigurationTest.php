<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Models\Domain;
use App\Models\DomainMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Support\Uuid;
use App\Tls\CertificateRefused;
use App\Tls\CertificateRejection;
use App\Tls\IssuanceBudgets;
use App\Tls\PassthroughPolicy;
use App\Tls\PermissionEndpoint;
use App\Tls\RegisteredDomain;
use App\Tls\WildcardZones;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * 🛑 The configuration half of Phase 19: §8.10.12's deadlock, §8.10.14's
 * disabled admin API, §8.10.10's own zones, §8.10.13's budget and
 * §8.10.21's passthrough boundary.
 *
 * Every assertion here is against something **shipped** rather than against
 * a value the test invented. That is Phase 05's lesson, recorded in
 * `EgressOptions`: a control asserted only against configurations the tests
 * made up is a control nobody has run.
 */
final class TlsConfigurationTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hosted Co',
            'slug' => 'hosted-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 §8.10.12, and §19's exit criterion: "Configuring the permission
     * endpoint as HTTPS on a served hostname is **refused at validation**,
     * not discovered at first handshake."
     *
     * Discovering it at first handshake means discovering it never: the
     * proxy cannot reach the endpoint without a certificate and cannot get
     * a certificate without the endpoint, so the installation comes up with
     * no TLS anywhere and the request that would have been logged never
     * arrives.
     */
    public function test_https_on_a_served_hostname_is_a_validation_error(): void
    {
        $apex = (string) config('docup.origins.docs');

        foreach (['https://'.$apex.'/_/edge/tls-permission', 'https://ask.'.$apex.'/x'] as $url) {
            try {
                PermissionEndpoint::assertUsable($url);
                $this->fail($url.' was accepted and is an unrecoverable startup deadlock');
            } catch (CertificateRefused $refused) {
                $this->assertSame(CertificateRejection::PermissionEndpointDeadlock, $refused->rejection);
            }
        }
    }

    /** The configurations that are not a deadlock are accepted. */
    public function test_the_usable_endpoint_shapes_are_accepted(): void
    {
        $accepted = [
            'http://127.0.0.1/_/edge/tls-permission',       // what ships
            'http://localhost:8080/_/edge/tls-permission',
            'https://127.0.0.1/_/edge/tls-permission',      // pointless, but reachable
            'https://ask.internal.example/_/edge/tls-permission', // a host we do not serve
        ];

        foreach ($accepted as $url) {
            $this->assertTrue(PermissionEndpoint::usable($url), $url.' was refused and should not be');
        }
    }

    /**
     * 🛑 The **shipped** endpoint is usable.
     *
     * `config/tls.php`'s default is the one an installation runs with, and
     * a default that tripped its own validator would mean every deployment
     * refused to boot. This is the assertion that `EgressConfigurationTest`
     * makes about `config/egress.php`, for the same reason.
     */
    public function test_the_shipped_permission_endpoint_is_usable(): void
    {
        $configured = config('tls.permission_endpoint');

        $this->assertIsString($configured);
        $this->assertStringStartsWith('http://', $configured, '§8.10.11 asks for plaintext');
        $this->assertTrue(PermissionEndpoint::usable($configured));
    }

    /**
     * 🛑 §8.10.14: "The proxy admin API MUST stay **disabled** — it is
     * root-equivalent on the edge."
     *
     * Asserted against the Caddyfile that ships, in the spirit of §8.10.22's
     * byte-identical header allowlist: a constant declaring the API is off
     * while the configuration leaves it on would be a comment, and the
     * whole point of the requirement is that nothing can push a certificate
     * or an upstream into the edge out of band.
     */
    public function test_the_proxy_admin_api_is_disabled_in_the_shipped_configuration(): void
    {
        $caddyfile = (string) file_get_contents(base_path('deploy/Caddyfile'));

        $this->assertFalse(config('tls.admin_api_enabled'), 'config/tls.php must declare the admin API off');

        $this->assertMatchesRegularExpression(
            '/^\s*admin\s+off\s*$/m',
            $caddyfile,
            '🛑 §8.10.14: whoever reaches Caddy\'s admin socket can load a new TLS policy for any name',
        );

        $this->assertDoesNotMatchRegularExpression(
            '/^\s*admin\s+(?!off)\S/m',
            $caddyfile,
            'no other admin directive may re-enable it',
        );
    }

    /**
     * 🛑 §8.10.11's permission endpoint is wired into the shipped
     * Caddyfile, and it is the one `config/tls.php` names.
     *
     * On-demand TLS without `ask` is an unauthenticated path from a TLS
     * handshake to a certificate authority — Caddy's own documentation
     * calls it unsafe in production — so the two must agree, and a test
     * that only checked the constant would pass against a Caddyfile that
     * had never been given it.
     */
    public function test_the_caddyfile_asks_the_endpoint_config_names(): void
    {
        $caddyfile = (string) file_get_contents(base_path('deploy/Caddyfile'));

        $ask = (string) config('tls.permission_endpoint');
        $certificate = (string) config('tls.certificate_endpoint');

        $this->assertStringContainsString('ask '.$ask, $caddyfile);
        $this->assertStringContainsString('get_certificate http '.$certificate, $caddyfile);
        $this->assertStringContainsString('on_demand', $caddyfile);
    }

    /**
     * 🛑 §8.10.18: the challenge path is reachable, and reachable **before**
     * the documentation catch-all.
     *
     * Laravel has no route priority, only registration order, so this is an
     * assertion about `bootstrap/app.php` requiring `routes/edge.php` first.
     * A challenge registered after the documentation routes is answered by
     * §8.9.3's hard 404 and the CA's validation fails with nothing logged
     * on this side.
     */
    public function test_the_acme_challenge_path_is_registered_before_the_catch_all(): void
    {
        $bootstrap = (string) file_get_contents(base_path('bootstrap/app.php'));

        /*
         * The `require` lines, not the first mention: the comment above
         * them names both files, and matching that would assert the order
         * of the prose rather than of the registration.
         */
        $edge = strpos($bootstrap, "require __DIR__.'/../routes/edge.php';");
        $docs = strpos($bootstrap, "require __DIR__.'/../routes/docs.php';");

        $this->assertIsInt($edge, 'routes/edge.php is not required at all');
        $this->assertIsInt($docs);
        $this->assertLessThan($docs, $edge, '🛑 §8.10.18: before the documentation catch-all');

        $response = $this->get('/.well-known/acme-challenge/'.str_repeat('a', 43));

        $this->assertSame(404, $response->getStatusCode(), 'an unpublished token is absent, not misrouted');
        $this->assertSame('', $response->getContent(), 'a body a CA could mistake for an answer costs authorization budget');
    }

    /** §8.10.10's own zones, matched one label deep like a real wildcard. */
    public function test_the_wildcard_zone_test_matches_one_label(): void
    {
        $apex = (string) config('docup.origins.docs');

        $this->assertTrue(WildcardZones::covers($apex));
        $this->assertTrue(WildcardZones::covers('project.'.$apex));
        $this->assertFalse(WildcardZones::covers('a.project.'.$apex), 'two labels is not one');
        $this->assertFalse(WildcardZones::covers('docs.example.test'));
    }

    /**
     * 🛑 §8.10.13's budget is the CA's token bucket, not a fixed window.
     *
     * §18.20 required the limits to be re-read before these numbers were
     * frozen. The 2026-10-26 re-read (page last updated 2026-08-05) states
     * 50 per registered domain with a refill of one per 202 minutes — the
     * totals agree with "50 per 7 days" to within an hour, and the
     * behaviour differs at exactly the moments that matter.
     */
    public function test_the_budget_refills_rather_than_resetting(): void
    {
        $registered = 'budget-'.bin2hex(random_bytes(4)).'.example';
        $now = Carbon::parse('2026-11-01 00:00:00');

        $budgets = new IssuanceBudgets($now);

        for ($i = 0; $i < IssuanceBudgets::CAPACITY; $i++) {
            $budgets->consume($registered);
        }

        $this->assertFalse($budgets->permits($registered), 'the fiftieth issuance empties the bucket');

        try {
            $budgets->consume($registered);
            $this->fail('an empty bucket must refuse');
        } catch (CertificateRefused $refused) {
            $this->assertSame(CertificateRejection::BudgetExhausted, $refused->rejection);
        }

        /*
         * 🛑 A fixed seven-day window would still refuse here. The CA would
         * not: 202 minutes is one token, and seven hours is two.
         */
        $later = new IssuanceBudgets($now->copy()->addMinutes(IssuanceBudgets::REFILL_MINUTES * 2 + 1));

        $this->assertTrue($later->permits($registered), 'the bucket refills; a window does not');
        $this->assertEqualsWithDelta(2.0, $later->remaining($registered), 0.05);
    }

    /** §8.10.13's "warning at 40" is recorded once, not on every issuance after it. */
    public function test_the_budget_warns_at_forty(): void
    {
        $registered = 'warned-'.bin2hex(random_bytes(4)).'.example';
        $budgets = new IssuanceBudgets(Carbon::parse('2026-11-01 00:00:00'));

        for ($i = 0; $i < 39; $i++) {
            $budgets->consume($registered);
        }

        $this->assertFalse($budgets->hasWarned($registered), '39 issuances is not yet the warning');

        $budgets->consume($registered);

        $this->assertTrue($budgets->hasWarned($registered), '§8.10.13: a warning at 40');
    }

    /**
     * 🛑 The registrable domain is wrong only in the safe direction.
     *
     * Without the Public Suffix List the last two labels are used, which
     * over-groups a multi-label suffix: every `.co.uk` host shares one
     * bucket, so the installation stops issuing **earlier** than the CA
     * would. A budget may only be wrong in that direction, and this records
     * which way round it is.
     */
    public function test_the_registered_domain_over_groups_rather_than_under_groups(): void
    {
        $this->assertSame('example.com', RegisteredDomain::of('docs.example.com'));
        $this->assertSame('example.com', RegisteredDomain::of('a.b.c.example.com'));

        // Over-grouped: the CA would say `example.co.uk`.
        $this->assertSame('co.uk', RegisteredDomain::of('docs.example.co.uk'));

        // And the operator can get the CA's own bucketing back.
        $this->assertSame('example.co.uk', RegisteredDomain::of('docs.example.co.uk', ['co.uk']));
    }

    /**
     * 🛑 §8.10.21: `passthrough` is refused on any non-public project.
     *
     * "A caching CDN outside the installation bypasses authorisation
     * entirely" — the first authorised reader's response is cached by a
     * device that has never heard of a reader policy, and the second reader
     * gets it without one.
     */
    public function test_passthrough_is_refused_on_a_non_public_project(): void
    {
        $domain = $this->domain('lb.'.bin2hex(random_bytes(4)).'.example');

        $public = $this->project(AccessLevel::Public);
        $this->mount($domain, $public);

        $this->assertTrue(PassthroughPolicy::usable($domain), 'a public project may terminate elsewhere');

        $private = $this->project(AccessLevel::Members);
        $this->mount($domain, $private, '/private');

        try {
            PassthroughPolicy::assertUsable($domain);
            $this->fail('passthrough was permitted on a hostname serving a members-only project');
        } catch (CertificateRefused $refused) {
            $this->assertSame(CertificateRejection::PassthroughNotPublic, $refused->rejection);
            $this->assertStringContainsString($private->slug, $refused->getMessage());
        }
    }

    private function domain(string $host): Domain
    {
        $domain = new Domain;

        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        return $domain;
    }

    private function project(AccessLevel $visibility): Project
    {
        return Project::query()->create([
            'slug' => 'manual-'.bin2hex(random_bytes(4)),
            'name' => 'Manual',
            'visibility' => $visibility->value,
        ]);
    }

    private function mount(Domain $domain, Project $project, string $prefix = ''): void
    {
        $mount = new DomainMount;

        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domain->id,
            'project_id' => $project->id,
            'path_prefix' => $prefix,
            'mode' => 'serve',
        ])->save();
    }
}
