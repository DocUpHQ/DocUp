<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\Providers\Drivers\IpAllowlistDriver;
use App\Readers\ReaderResolver;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 Which addresses in front of the application are DocUp's own, so that
 * `$request->ip()` is the **reader's** address rather than the edge's.
 *
 * ## 🛑 What Phase 26b found, and what it cost
 *
 * Nothing configured trusted proxies at all. `$request->ip()` therefore
 * returned `REMOTE_ADDR` — the edge container — while
 * {@see IpAllowlistDriver} and
 * {@see OnlyFromLoopback} both read it believing it to be the client's. The
 * comment in {@see ReaderResolver} said so in as many words: "this
 * is the `TrustProxies`-resolved address". There was no such resolution.
 *
 * So §8.12.17's `ip_allowlist` gate was comparing the **edge's** address
 * against the operator's allowlist. Two outcomes, and the second is the
 * dangerous one:
 *
 * 1. The allowlist holds real reader ranges, matches nothing, and the gate
 *    never satisfies. Visible, annoying, safe.
 * 2. The operator debugs it, reads the address out of their logs, allowlists
 *    *that* — and the gate is now satisfied for every reader on the internet.
 *    §8.12.7 keeps a requirement from resting on a gate alone, so the blast
 *    radius is a narrowing that does not narrow rather than public access.
 *    Silently, which is worse.
 *
 * ## 🛑 Why this is a middleware and not `trustProxies()`
 *
 * Laravel's `Middleware::trustProxies(at:)` takes `array|string|null` and not a
 * closure, so the value has to exist while `bootstrap/app.php` is still being
 * assembled — before `.env` is read. An installation that configured this in
 * `.env` rather than in its real environment would have found the setting
 * silently ignored, which is the class of bug this file exists to fix. Reading
 * `config()` per request costs nothing measurable and cannot be wrong.
 *
 * ## 🛑 The header that is NOT trusted is the point
 *
 * `X-Forwarded-Host` is **excluded**, and excluding it is a requirement rather
 * than a preference. §8.9.4:
 *
 * > "The project MUST be resolved **solely** from the TLS server name or `Host`
 * > header plus the path. No request header MUST act as a project, version or
 * > tenant selector, in any environment. This is the GHSA-mp38-vprc-7hf5
 * > class."
 *
 * The project is resolved from `$request->getHost()`. Trusting
 * `X-Forwarded-Host` would let that header select the project — exactly the
 * vulnerability class the requirement names. 🛑 Laravel's and Symfony's default
 * header sets **include** it, so the set here is written out in full rather
 * than defaulted: the safe thing is not the framework's default, and a future
 * `HEADER_X_FORWARDED_ALL` would silently reintroduce it.
 *
 * An architecture test asserts `HEADER_X_FORWARDED_HOST` appears nowhere.
 */
final class TrustEdgeProxies
{
    /**
     * 🛑 The three headers trusted, and no others.
     *
     * `FOR` is what this exists for. `PROTO` is needed because the edge
     * terminates TLS, so without it every generated URL would be `http://` and
     * §9.3.4's cookie `secure` attribute would be dropped. `PORT` travels with
     * `PROTO` and is meaningless without it.
     */
    private const int TRUSTED_HEADERS = Request::HEADER_X_FORWARDED_FOR
        | Request::HEADER_X_FORWARDED_PORT
        | Request::HEADER_X_FORWARDED_PROTO;

    public function handle(Request $request, \Closure $next): Response
    {
        $proxies = self::configured($request);

        /*
         * 🛑 An empty list is set **explicitly** rather than skipped, and it
         * matters: `setTrustedProxies([])` with a header set still records that
         * nothing is trusted, so a stale value from an earlier request in a
         * worker process cannot survive. Returning early would leave whatever
         * the last request configured — which under FrankenPHP worker mode is a
         * cross-request leak of trust.
         */
        Request::setTrustedProxies($proxies, self::TRUSTED_HEADERS);

        return $next($request);
    }

    /**
     * The configured proxies, in the spelling Symfony actually honours.
     *
     * 🛑 **`*` is Laravel's convention, not Symfony's, and passing it straight
     * through is a silent no-op.** Measured rather than assumed, and the first
     * version of this method got it wrong: `setTrustedProxies(['*'], …)` trusts
     * **nothing** — the header is ignored and `ip()` stays the peer. So does
     * `['REMOTE_ADDR']`, which the documentation for older versions suggests.
     * Laravel's own `TrustProxies` middleware is where the translation lives,
     * which is why the shape worked there and not here.
     *
     * A setting that silently does nothing is worse than one that is absent:
     * the operator reads the name, believes it, and the gate they configured
     * compares the wrong address. So the three spellings an operator might
     * reach for are each mapped to something that works:
     *
     * | Configured | Trusts | Why an operator would pick it |
     * |---|---|---|
     * | empty | nothing | no `ip_allowlist` binding; the safe default |
     * | `*` | the address directly in front | the shipped compose topology |
     * | `private` | any RFC1918 / private address | several hops, all internal |
     * | a CIDR list | exactly those | a known, pinned load balancer |
     *
     * 🛑 `*` is correct **only** where the application is unreachable except
     * through that proxy — the shipped compose topology, where the application
     * port is not published. On a host where the port is reachable, any client
     * becomes "the address directly in front" and can then set its own: name
     * the CIDR instead. `config/docup.php` says so where an operator will read
     * it.
     *
     * @return list<string>
     */
    private static function configured(Request $request): array
    {
        $configured = config('docup.edge.trusted_proxies');

        if (! is_string($configured)) {
            return [];
        }

        $configured = trim($configured);

        if ($configured === '') {
            /* Trust nothing: `ip()` is the direct peer and the header is ignored. */
            return [];
        }

        if ($configured === '*') {
            /*
             * 🛑 Resolved to the actual peer, which is what Laravel's own
             * middleware does with `*`. `$request->server->get('REMOTE_ADDR')`
             * rather than `$request->ip()`, because `ip()` consults the trusted
             * proxies this call is in the middle of setting.
             */
            $peer = $request->server->get('REMOTE_ADDR');

            return is_string($peer) && $peer !== '' ? [$peer] : [];
        }

        if ($configured === 'private') {
            /*
             * Symfony's own magic value for "any private address", which suits
             * a topology with several internal hops: a public client cannot
             * have a private source address, so trusting the range cannot
             * trust a client.
             */
            /*
             * 🛑 The literal string, which is Symfony's documented interface
             * rather than a constant to import. `setTrustedProxies()`'s own
             * docblock: "'private_ranges' or 'PRIVATE_SUBNETS' [is replaced] by
             * IpUtils::PRIVATE_RANGES". `IpUtils::PRIVATE_SUBNETS` exists as an
             * array constant, but passing the array would skip the replacement
             * and tie this file to that list's contents.
             */
            return ['PRIVATE_SUBNETS'];
        }

        return array_values(array_filter(array_map(
            'trim',
            explode(',', $configured),
        ), static fn (string $cidr): bool => $cidr !== ''));
    }
}
