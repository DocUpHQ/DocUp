<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Auth\OrganisationContext;
use App\Models\Domain;
use Illuminate\Support\Facades\Cache;

/**
 * The set of hostnames this installation would ever certify, in one cache
 * entry.
 *
 * 🛑 **This class is why 500 bogus SNI handshakes a minute cost zero.**
 *
 * §8.10.11 asks for a permission endpoint "answering in under 5 ms from
 * cache and failing closed", and §19's exit criterion is blunter: 500 bogus
 * handshakes per minute must trigger **zero** ACME attempts. The obvious
 * implementation — look the hostname up in `domains` and decide — meets
 * neither, because a hostname nobody has ever heard of is exactly the input
 * an attacker supplies, and it is the input that misses every per-host cache
 * and reaches the database every time. A thousand unknown names is a
 * thousand queries, from an unauthenticated TLS handshake.
 *
 * So the first question asked is not "what do we know about this host?" but
 * "is this host in the set we know about at all?" — and that set is one
 * cache entry, loaded once, shared by every worker. A name outside it is
 * refused with no query, no DNS lookup, and no row written.
 *
 * The set is small by construction: it holds only domains that are serving
 * and proven, which is bounded by the installation's own domain count
 * (§18.20 documents a ceiling of 2,000) rather than by request volume.
 *
 * 🛑 Invalidated explicitly on every domain write **and** carrying a short
 * TTL. The TTL is not redundancy — it is what makes a missed invalidation
 * self-heal within a minute instead of persisting until a deploy, which
 * matters because the failure mode is a newly verified domain that cannot
 * get a certificate and an operator with nothing to look at.
 */
final class PermittedHosts
{
    public const string KEY = 'tls:permitted-hosts';

    /** Short enough that a missed invalidation is a blip, not an outage. */
    public const int TTL_SECONDS = 60;

    /**
     * Hostname to domain id, for every host that may hold a certificate.
     *
     * 🛑 The id is the **raw 16 bytes**, as `HasUuidKey` stores it, not its
     * text form. `Domain::find()` takes bytes, so converting here and back
     * at the one call site would be two conversions whose only effect would
     * be a chance to get one of them wrong — and a text id handed to
     * `find()` matches nothing and reports it as "no such domain".
     *
     * @return array<string, string>
     */
    public function all(): array
    {
        $cached = Cache::get(self::KEY);

        if (is_array($cached)) {
            /** @var array<string, string> $cached */
            return $cached;
        }

        $hosts = $this->load();

        Cache::put(self::KEY, $hosts, self::TTL_SECONDS);

        return $hosts;
    }

    /** The domain id for a host in the set, or null when it is not in it. */
    public function idFor(string $host): ?string
    {
        return $this->all()[$host] ?? null;
    }

    /**
     * 🛑 §8.10.16: "Adding, verifying, activating, suspending or removing a
     * domain MUST take effect with **no proxy restart, config render or
     * reload**."
     *
     * This is the whole mechanism on the TLS side. Nothing is rendered and
     * nothing is signalled: the next permission query recomputes a set that
     * includes — or no longer includes — the hostname, and the proxy's very
     * next handshake sees the new answer.
     */
    public static function invalidate(): void
    {
        Cache::forget(self::KEY);
    }

    /**
     * @return array<string, string>
     */
    private function load(): array
    {
        $hosts = [];

        /*
         * 🛑 Across tenants, and this is not optional: `Domain` is
         * `#[Tenancy(OrganisationScoped)]`, and this query runs during a TLS
         * handshake, where **no organisation is known and none can be**. SNI
         * is a hostname; the whole point of the lookup is to discover whose
         * it is.
         *
         * Without this the scope raises "No organisation context declared
         * (§8.2.1)" and the permission endpoint answers 500 — which Caddy
         * reads as a denial, so the symptom is not an error page but every
         * custom domain silently failing to get a certificate. Found by
         * running a real handshake against the real endpoint.
         */
        return app(OrganisationContext::class)->acrossAllOrganisations(
            fn (): array => $this->query($hosts),
        );
    }

    /**
     * @param  array<string, string>  $hosts
     * @return array<string, string>
     */
    private function query(array $hosts): array
    {

        /*
         * 🛑 The filter is `canServe()`'s, restated as SQL rather than
         * reimplemented: suspended never, and a custom or apex host only
         * once proven. Phase 18 made `Domain::canServe()` delegate to the
         * resolver's own predicate so the dashboard and the serving path
         * could not disagree; this query is the third reader, so it is
         * asserted against that predicate by a test rather than trusted to
         * stay in step.
         *
         * `passthrough` hosts are excluded here rather than refused later:
         * §8.10.21 has them terminating TLS at a corporate load balancer, so
         * this installation has no handshake to present a certificate for.
         */
        $rows = Domain::query()
            ->where('state', '!=', 'suspended')
            ->where('tls_mode', 'managed')
            ->where(function ($query): void {
                $query->whereNotIn('kind', ['custom', 'apex'])
                    ->orWhere(function ($proven): void {
                        $proven->whereIn('kind', ['custom', 'apex'])
                            ->whereNotNull('verified_at')
                            ->where('state', '!=', 'pending');
                    });
            })
            ->get(['id', 'host']);

        foreach ($rows as $row) {
            $hosts[(string) $row->host] = (string) $row->id;
        }

        return $hosts;
    }
}
