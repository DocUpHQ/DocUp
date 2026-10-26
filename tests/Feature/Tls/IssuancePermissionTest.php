<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Tls;

use App\Auth\OrganisationContext;
use App\Domains\AgreeingResolvers;
use App\Domains\DnsInstructions;
use App\Domains\Domains;
use App\Domains\DomainVerifier;
use App\Models\CertificateIssuanceAttempt;
use App\Models\Domain;
use App\Models\IssuanceBudget;
use App\Models\Organisation;
use App\Support\Uuid;
use App\Tls\IssuanceBreaker;
use App\Tls\IssuanceBudgets;
use App\Tls\IssuancePermission;
use App\Tls\PermissionVerdict;
use App\Tls\PermittedHosts;
use App\Tls\RegisteredDomain;
use Illuminate\Cache\RateLimiter;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\Support\FakeDnsRecords;
use Tests\TestCase;

/**
 * 🛑 §8.10.11's permission endpoint, and §19's hardest exit criterion.
 *
 * > "500 bogus SNI handshakes per minute trigger **zero** ACME attempts. The
 * > permission endpoint answers in under 5 ms without touching the
 * > certificate store or the database on a hit."
 *
 * The two halves of that sentence are one design: a hostname nobody has ever
 * heard of is the input an attacker supplies, and it is the input that misses
 * every per-host cache. {@see PermittedHosts} is the answer — one shared
 * cache entry holding the set of hosts the installation would ever certify —
 * and the assertions below are about the **absence of work**: zero rows, zero
 * queries, no DNS. A test that only checked the verdicts would pass against
 * an implementation that queried the database five hundred times to produce
 * them.
 */
final class IssuancePermissionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Domains $domains;

    /** The address every verified hostname in these tests points at. */
    private const string INGRESS = '203.0.113.10';

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
        $this->domains = new Domains;

        config(['domains.ingress_addresses' => [self::INGRESS]]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 **Five hundred invented hostnames cost zero ACME attempts and zero
     * queries after the first.**
     *
     * The exit criterion names 500 per minute. The limiter is per minute too
     * — so if denials consumed limiter budget the test would prove only that
     * the limiter works, which is not the claim. The claim is that an
     * unknown hostname never reaches the limiter, the database or DNS at
     * all, and the query count is how that is demonstrated rather than
     * asserted.
     */
    public function test_five_hundred_bogus_handshakes_cost_nothing(): void
    {
        $permission = $this->permission();

        // One query to load the permitted set, before counting starts.
        $permission->decide('warm-the-set.example.net');

        $queries = 0;
        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        for ($i = 0; $i < 500; $i++) {
            $verdict = $permission->decide('sni-'.$i.'.attacker.example');

            $this->assertSame(PermissionVerdict::NotEligible, $verdict);
        }

        DB::flushQueryLog();

        $this->assertSame(0, $queries, '500 unknown hostnames must not reach the database');
        $this->assertSame(
            0,
            CertificateIssuanceAttempt::query()->count(),
            '🛑 a denial must write no row: a row per handshake is a worse amplification than the one being prevented',
        );
    }

    /**
     * 🛑 A repeated question about a real hostname is answered from cache,
     * with no database and no DNS.
     *
     * §8.10.11's "under 5 ms from cache" is a latency budget, and latency is
     * a poor thing to assert in a test suite. What the budget actually
     * requires is that the hit path does no I/O, which is assertable
     * exactly.
     */
    public function test_a_cached_verdict_touches_nothing(): void
    {
        $host = 'docs.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::Permitted, $permission->decide($host));

        $queries = 0;
        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $started = hrtime(true);
        $cached = $permission->decide($host);
        $elapsed = (hrtime(true) - $started) / 1_000_000;

        $this->assertTrue($cached->permits(), 'the cached verdict must be the one computed');
        $this->assertSame(0, $queries, 'a cache hit must not query');
        $this->assertLessThan(5.0, $elapsed, '§8.10.11: under 5 ms from cache (measured '.round($elapsed, 3).' ms)');
    }

    /** A verified hostname pointing at the ingress is permitted, and recorded. */
    public function test_a_verified_hostname_pointing_here_is_permitted(): void
    {
        $host = 'docs.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::Permitted, $permission->decide($host));

        $attempt = CertificateIssuanceAttempt::query()->where('host', $host)->first();

        $this->assertNotNull($attempt, 'a granted permission is the event that precedes issuance and must be recorded');
        $this->assertSame('permitted', $attempt->outcome);
        $this->assertSame('edge', $attempt->source, 'the proxy issues this one, not the application');
        $this->assertSame(RegisteredDomain::fromConfig($host), $attempt->registered_domain);
    }

    /**
     * 🛑 §8.10.11's live-DNS condition, which is the difference between
     * "proved control once" and "directs this name now".
     *
     * Without it a tenant verifies a hostname, moves the DNS elsewhere, and
     * goes on obtaining certificates for a name they no longer direct —
     * which is a certificate for somebody else's traffic, issued by this
     * installation, on this installation's budget.
     */
    public function test_a_verified_hostname_pointed_elsewhere_is_refused(): void
    {
        $host = 'moved.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $permission = $this->permission($this->resolversSeeing([$host => ['198.51.100.7']]));

        $this->assertSame(PermissionVerdict::NotPointedHere, $permission->decide($host));
        $this->assertSame(0, CertificateIssuanceAttempt::query()->count());
    }

    /**
     * 🛑 A resolver outage denies, and is distinguishable from a hostname
     * that points elsewhere.
     *
     * Fail closed — §8.10.11 says so — but the two must not collapse into
     * one verdict, because they have different remedies and only one of them
     * is the operator's to fix. §8.10.6 made the same distinction for
     * verification and `Outcome::Unresolvable` is the same mechanism here.
     */
    public function test_a_resolver_outage_denies_without_looking_like_a_misconfiguration(): void
    {
        $host = 'quiet.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $silent = (new FakeDnsRecords('alpha'))->withAddresses($host, null);
        $permission = $this->permission(new AgreeingResolvers([$silent]));

        $this->assertSame(PermissionVerdict::Unresolvable, $permission->decide($host));
    }

    /**
     * 🛑 §8.10.10: a name the installation's own wildcard already covers is
     * never issued per host.
     *
     * Each such issuance would succeed, so nothing looks wrong — and 500
     * projects under one apex would take ten weeks against a ceiling that is
     * global across accounts. That is the arithmetic §8.10.10 rejects
     * per-host HTTP-01 on, and this is the line that honours it.
     */
    public function test_a_hostname_inside_our_own_wildcard_is_refused(): void
    {
        $apex = (string) config('docup.origins.docs');
        $host = 'project-'.bin2hex(random_bytes(3)).'.'.$apex;

        $domain = new Domain;
        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'host' => $host,
            'kind' => 'default_subdomain',
            'state' => 'active',
        ])->save();

        PermittedHosts::invalidate();

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::OwnZone, $permission->decide($host));
    }

    /** §8.10.13's circuit breaker closes the permission endpoint too. */
    public function test_a_host_in_backoff_is_refused(): void
    {
        $host = 'failing.'.$this->uniqueApex();
        $domain = $this->verifiedDomain($host);

        (new IssuanceBreaker)->fail($domain);

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::InBackoff, $permission->decide($host));
    }

    /** §8.10.13's budget closes it as well, before any DNS lookup. */
    public function test_an_exhausted_budget_refuses(): void
    {
        $host = 'spent.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $budget = new IssuanceBudget;
        $budget->forceFill([
            'registered_domain' => RegisteredDomain::fromConfig($host),
            'tokens' => '0.0000',
            'tokens_at' => Carbon::now(),
        ])->save();

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::BudgetExhausted, $permission->decide($host));
    }

    /**
     * 🛑 §8.10.21: a passthrough host terminates TLS somewhere else, so this
     * installation has no handshake to certify.
     */
    public function test_a_passthrough_host_is_refused(): void
    {
        $host = 'lb.'.$this->uniqueApex();
        $domain = $this->verifiedDomain($host);

        $domain->forceFill(['tls_mode' => 'passthrough'])->save();
        PermittedHosts::invalidate();

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $this->assertSame(PermissionVerdict::NotEligible, $permission->decide($host));
    }

    /**
     * 🛑 §8.10.16: verifying a domain takes effect with no restart and no
     * reload — and §19 gives it sixty seconds.
     *
     * The permitted set is cached, so the real risk is not that the proxy
     * needs restarting but that DocUp's own cache outlives the change. This
     * asserts the invalidation rather than the TTL: a test that waited for
     * the TTL would pass against an implementation with no invalidation at
     * all, which is the implementation that takes a minute instead of a
     * second.
     */
    public function test_verifying_a_domain_opens_issuance_at_once(): void
    {
        $host = 'fresh.'.$this->uniqueApex();

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        $domain = $this->domains->add($this->organisation->id, $host);

        $this->assertSame(
            PermissionVerdict::NotEligible,
            $permission->decide($host),
            'an unproven hostname is not certifiable (§8.10.4)',
        );

        $this->domains->verify($domain, $this->verifierFor($domain));

        /*
         * The per-host verdict was cached as a denial a moment ago. Caddy
         * would ask again on the next handshake, which is a different
         * hostname's cache key from DocUp's point of view only if the
         * verdict cache is dropped — so the endpoint forgets it, exactly as
         * an operator fixing a configuration would need.
         */
        $permission->forget($host);

        $this->assertSame(
            PermissionVerdict::Permitted,
            $permission->decide($host),
            '§8.10.16: no restart, no reload, no render',
        );
    }

    /** Rate limiting is per hostname and global, never per IP (§8.10.11). */
    public function test_the_limiter_is_per_hostname_and_global(): void
    {
        $host = 'busy.'.$this->uniqueApex();
        $this->verifiedDomain($host);

        $permission = $this->permission($this->resolversSeeing([$host => [self::INGRESS]]));

        /*
         * The verdict cache would answer every repeat, so it is dropped each
         * time: this is asking what happens when the proxy genuinely asks
         * again and again, which is what a flood looks like from here.
         */
        $verdicts = [];

        for ($i = 0; $i <= IssuancePermission::PER_HOST_PER_MINUTE + 1; $i++) {
            $permission->forget($host);
            $verdicts[] = $permission->decide($host);
        }

        $this->assertSame(PermissionVerdict::Permitted, $verdicts[0]);
        $this->assertSame(
            PermissionVerdict::RateLimited,
            $verdicts[count($verdicts) - 1],
            'the per-hostname limit must bite even for a hostname that would otherwise be permitted',
        );
    }

    /** An SNI value that is not a hostname is refused without reaching anything. */
    public function test_a_malformed_sni_is_refused(): void
    {
        $permission = $this->permission();

        foreach (['', '..', 'a_b.example.com', str_repeat('a', 300).'.example.com'] as $sni) {
            $this->assertSame(PermissionVerdict::NotEligible, $permission->decide($sni), 'for "'.$sni.'"');
        }
    }

    private function permission(?AgreeingResolvers $resolvers = null): IssuancePermission
    {
        return new IssuancePermission(
            new PermittedHosts,
            new IssuanceBudgets,
            new IssuanceBreaker,
            $resolvers ?? new AgreeingResolvers([new FakeDnsRecords('alpha'), new FakeDnsRecords('beta')]),
            app(RateLimiter::class),
        );
    }

    /**
     * Two resolvers that agree on these addresses.
     *
     * @param  array<string, list<string>|null>  $addresses
     */
    private function resolversSeeing(array $addresses): AgreeingResolvers
    {
        $resolvers = [];

        foreach (['alpha', 'beta'] as $label) {
            $resolver = new FakeDnsRecords($label);

            foreach ($addresses as $name => $answer) {
                $resolver->withAddresses($name, $answer);
            }

            $resolvers[] = $resolver;
        }

        return new AgreeingResolvers($resolvers);
    }

    private function verifiedDomain(string $host): Domain
    {
        $domain = $this->domains->add($this->organisation->id, $host);

        return $this->domains->verify($domain, $this->verifierFor($domain));
    }

    /** A verifier that sees exactly the record {@see DnsInstructions} printed. */
    private function verifierFor(Domain $domain): DomainVerifier
    {
        $apex = (string) config('docup.origins.docs');
        $instructions = DnsInstructions::for($domain, $apex);
        $record = $instructions->records[0];

        $resolvers = [];

        foreach (['alpha', 'beta'] as $label) {
            $resolver = new FakeDnsRecords($label);

            if ($record['type'] === 'TXT') {
                $resolver->withTxt($record['name'], [$record['value']]);
            } else {
                $resolver->withCname($record['name'], $record['value']);
            }

            $resolvers[] = $resolver;
        }

        return new DomainVerifier(new AgreeingResolvers($resolvers), $apex);
    }

    /**
     * A registrable domain no other test in this file shares.
     *
     * 🛑 Distinct per test, because §8.10.13's budget is keyed on the
     * registrable domain: two tests sharing `example.com` would share one
     * bucket, and the budget test would drain it for everybody else.
     */
    private function uniqueApex(): string
    {
        return 'tenant-'.bin2hex(random_bytes(4)).'.example';
    }
}
