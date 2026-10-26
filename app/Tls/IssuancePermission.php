<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Domains\AgreeingResolvers;
use App\Domains\Hostname;
use App\Domains\Outcome;
use App\Models\CertificateIssuanceAttempt;
use App\Models\Domain;
use Illuminate\Cache\RateLimiter;
use Illuminate\Support\Facades\Cache;

/**
 * 🛑 §8.10.11's permission endpoint, which is the only thing standing between
 * a TLS handshake and a certificate authority.
 *
 * > "On-demand issuance for custom domains MUST be gated by an internal,
 * > session-free, plaintext permission endpoint answering in under 5 ms from
 * > cache and failing closed. It MUST allow issuance only when the hostname
 * > has an active proven claim, is not in backoff, is not inside the
 * > installation's own wildcard zones, **currently resolves in live DNS to
 * > an advertised ingress target** (60-second cache), and is within all rate
 * > budgets. Rate limiting MUST be per-hostname and global — per-IP is
 * > meaningless because the proxy calls from localhost."
 *
 * **The order of the checks is load-bearing**, and it is cheapest-first for
 * a reason that is about abuse rather than performance. An attacker opens
 * TLS handshakes with invented SNI values; every one of those reaches this
 * code. So:
 *
 *   1. the cached verdict, if there is one — one cache read, no database;
 *   2. {@see PermittedHosts}, one shared cache entry — still no database,
 *      and this is where every invented hostname stops;
 *   3. the two rate limits, per hostname and global;
 *   4. §8.10.10's own zones, from configuration;
 *   5. the domain row, the breaker and the budget — the first database read;
 *   6. live DNS, the only network call, reached only by a hostname that has
 *      passed everything above.
 *
 * Reversing any two of those turns an unauthenticated handshake into a
 * database query or a DNS lookup, which is the amplification this endpoint
 * exists to prevent.
 *
 * 🛑 **Fail closed, everywhere.** Every unexpected condition — an
 * unparseable hostname, a resolver that will not answer, a cache that
 * returns nonsense — denies. A permission endpoint that failed open would
 * hand the budget to whoever found the failure.
 */
final readonly class IssuancePermission
{
    /** §8.10.11's own number: "60-second cache". */
    public const int CACHE_SECONDS = 60;

    /**
     * Per-hostname: a handful of questions a minute is more than any honest
     * proxy asks, since it caches a certificate for its whole lifetime.
     */
    public const int PER_HOST_PER_MINUTE = 10;

    /**
     * Global: enough to bootstrap an installation, far below what a
     * handshake flood produces. Both limits are per minute because the
     * attack is measured per minute — §19's criterion is "500 bogus SNI
     * handshakes per minute".
     */
    public const int GLOBAL_PER_MINUTE = 120;

    public function __construct(
        private PermittedHosts $permitted,
        private IssuanceBudgets $budgets,
        private IssuanceBreaker $breaker,
        private AgreeingResolvers $resolvers,
        private RateLimiter $limiter,
    ) {}

    /**
     * May the proxy obtain a certificate for this hostname?
     *
     * 🛑 Returns a verdict rather than throwing. This runs on the handshake
     * path, where every outcome including "no" is ordinary, and an exception
     * per bogus SNI would be a stack trace per handshake.
     */
    public function decide(string $rawHost): PermissionVerdict
    {
        $host = $this->normalise($rawHost);

        if ($host === null) {
            return PermissionVerdict::NotEligible;
        }

        $cached = Cache::get($this->key($host));

        if (is_string($cached)) {
            $verdict = PermissionVerdict::tryFrom($cached);

            if ($verdict !== null) {
                return $verdict;
            }
        }

        /*
         * 🛑 Nothing escapes as an exception. This runs during a TLS
         * handshake, Caddy reads a status code, and a 500 is a denial it
         * cannot distinguish from a considered one — so an unhandled error
         * would show up not as an error page but as every custom domain
         * quietly failing to get a certificate.
         *
         * Found by running a real handshake: a tenancy scope raised on the
         * permitted-set query, the endpoint answered 500, and the only
         * visible symptom was no issuance. Fail closed, and loudly in the
         * log rather than in the response.
         */
        try {
            $verdict = $this->evaluate($host);
        } catch (\Throwable $failure) {
            report($failure);

            $verdict = PermissionVerdict::NotEligible;
        }

        /*
         * Both answers are cached, for the same 60 seconds. Caching only the
         * denials would leave the permitted path paying for DNS on every
         * handshake; caching only the grants would leave the denial path
         * — the one under attack — recomputing every time.
         */
        Cache::put($this->key($host), $verdict->value, self::CACHE_SECONDS);

        if ($verdict->permits()) {
            $this->record($host);
        }

        return $verdict;
    }

    /** Drop a cached verdict, so a fixed configuration takes effect at once. */
    public function forget(string $host): void
    {
        $normalised = $this->normalise($host);

        if ($normalised !== null) {
            Cache::forget($this->key($normalised));
        }
    }

    private function evaluate(string $host): PermissionVerdict
    {
        /*
         * 🛑 Step 2, and the one that matters most. An invented hostname is
         * not in the set, so it is refused here — before the limiter, before
         * the database, before DNS. This is the line that makes §19's "500
         * bogus SNI handshakes per minute trigger zero ACME attempts" true,
         * and it costs one cache read shared across all of them.
         */
        $domainId = $this->permitted->idFor($host);

        if ($domainId === null) {
            return PermissionVerdict::NotEligible;
        }

        /*
         * 🛑 Per-hostname and global, never per-IP: §8.10.11 says so, and the
         * reason is that the proxy calls from localhost, so every request
         * this endpoint ever sees has the same source address. A per-IP limit
         * would either be a global limit wearing a misleading name or no
         * limit at all.
         */
        if ($this->limiter->tooManyAttempts('tls-ask:'.$host, self::PER_HOST_PER_MINUTE)
            || $this->limiter->tooManyAttempts('tls-ask', self::GLOBAL_PER_MINUTE)) {
            return PermissionVerdict::RateLimited;
        }

        $this->limiter->hit('tls-ask:'.$host, 60);
        $this->limiter->hit('tls-ask', 60);

        /*
         * 🛑 §8.10.10. A name the installation's own wildcard already covers
         * must never be issued per host: each such issuance succeeds, so
         * nothing looks wrong, and 500 projects under one apex consume ten
         * weeks of a ceiling that is global across accounts.
         */
        if (WildcardZones::covers($host)) {
            return PermissionVerdict::OwnZone;
        }

        $domain = Domain::query()->find($domainId);

        if ($domain === null || ! $domain->canServe()) {
            return PermissionVerdict::NotEligible;
        }

        if ($domain->tls_mode === 'passthrough') {
            return PermissionVerdict::Passthrough;
        }

        if (! $this->breaker->closed($domain)) {
            return PermissionVerdict::InBackoff;
        }

        if (! $this->budgets->permits(RegisteredDomain::fromConfig($host))) {
            return PermissionVerdict::BudgetExhausted;
        }

        return $this->pointedHere($host);
    }

    /**
     * 🛑 §8.10.11's live-DNS condition, and the only network call on this
     * path.
     *
     * Proof of control is a thing that was true once; this is the check that
     * it is still true now. Without it a tenant could verify a hostname,
     * point it somewhere else, and keep obtaining certificates for a name
     * they no longer direct — which is a certificate for somebody else's
     * traffic, issued by this installation, on this installation's budget.
     *
     * It is reached only by a hostname that is already in the permitted set
     * and inside the rate budget, so the number of DNS lookups is bounded by
     * the installation's own domain count rather than by request volume.
     */
    private function pointedHere(string $host): PermissionVerdict
    {
        $targets = $this->ingressAddresses();

        if ($targets === []) {
            /*
             * Fail closed. An installation that cannot say where its ingress
             * is cannot check that a hostname points at it, and the safe
             * reading of "cannot check" is "do not issue" — §8.10.11 says
             * "failing closed" in as many words.
             */
            return PermissionVerdict::NotPointedHere;
        }

        $answer = $this->resolvers->addresses($host);

        if ($answer->outcome === Outcome::Unresolvable) {
            return PermissionVerdict::Unresolvable;
        }

        if ($answer->outcome !== Outcome::Answered) {
            return PermissionVerdict::NotPointedHere;
        }

        foreach ($answer->values as $address) {
            if (in_array($address, $targets, true)) {
                return PermissionVerdict::Permitted;
            }
        }

        return PermissionVerdict::NotPointedHere;
    }

    /**
     * Where this installation says its ingress is.
     *
     * 🛑 Two sources, in order. `DOCUP_INGRESS_ADDRESSES` is the operator's
     * declaration and wins. Where it is unset — Phase 18 shipped it empty on
     * purpose, because "DocUp cannot discover its own public address and
     * guessing it from a request would print the last proxy hop" — the
     * documentation apex is resolved instead, which is the target every
     * §8.10.8 CNAME points at anyway. Resolving our own apex is a fact about
     * this installation, not a guess about the request.
     *
     * @return list<string>
     */
    private function ingressAddresses(): array
    {
        $configured = config('domains.ingress_addresses');
        $addresses = [];

        foreach (is_array($configured) ? $configured : [] as $address) {
            $packed = is_string($address) ? @inet_pton(trim($address)) : false;
            $printable = $packed === false ? false : @inet_ntop($packed);

            if (is_string($printable)) {
                $addresses[] = $printable;
            }
        }

        if ($addresses !== []) {
            return $addresses;
        }

        $apex = WildcardZones::all()[0] ?? null;

        if ($apex === null) {
            return [];
        }

        /** @var list<string> $cached */
        $cached = Cache::remember(
            'tls:ingress-addresses:'.$apex,
            self::CACHE_SECONDS,
            function () use ($apex): array {
                $answer = $this->resolvers->addresses($apex);

                return $answer->outcome === Outcome::Answered ? $answer->values : [];
            },
        );

        return $cached;
    }

    /**
     * §8.10.13's attempts table, written **only** for a permission that was
     * granted.
     *
     * 🛑 A denial writes nothing. §19's criterion is 500 bogus handshakes a
     * minute; a row per denial would turn an unauthenticated handshake into
     * an unauthenticated INSERT, which is a worse amplification than the one
     * being prevented. The grant is rare — the proxy caches a certificate
     * for its lifetime — and it is the event that precedes an issuance, so
     * it is the one worth keeping.
     */
    private function record(string $host): void
    {
        CertificateIssuanceAttempt::query()->create([
            'host' => $host,
            'registered_domain' => RegisteredDomain::fromConfig($host),
            'source' => 'edge',
            'outcome' => 'permitted',
            'reason' => null,
            'detail' => null,
            'attempted_at' => now(),
        ]);
    }

    /**
     * 🛑 The SNI value is attacker-controlled and becomes a cache key, so it
     * is normalised through the same function that governs what may be
     * stored in `domains.host` (§8.10.7) and refused outright where it does
     * not normalise. A raw SNI reaching `Cache::get` is a key-injection, and
     * a differently-spelled one reaching the permitted set is a lookup that
     * misses a host that is really there.
     */
    private function normalise(string $host): ?string
    {
        try {
            return Hostname::normalise($host);
        } catch (\Throwable) {
            return null;
        }
    }

    private function key(string $host): string
    {
        return 'tls:permit:'.hash('sha256', $host);
    }
}
