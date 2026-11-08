<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Auth\Providers\Drivers\HeaderTrustDriver;
use App\Auth\Providers\Drivers\MtlsDriver;
use App\Http\Middleware\TrustEdgeProxies;
use Illuminate\Http\Request;

/**
 * 🛑 §8.12.4's exact words — "facts only the TLS terminator can establish" —
 * as the only channel by which such a fact reaches a driver.
 *
 * `mtls` and `header_trust` are the two drivers whose identity is established
 * somewhere else and *told* to DocUp. This object is that telling, and three
 * properties make it safe:
 *
 * 1. 🛑 **An untrusted peer can assert nothing.** {@see self::from()} returns
 *    {@see self::none()} unless the request arrived from an address the
 *    installation declared its own, so a forged assertion is not refused — it
 *    is *unrepresentable*. There is no constructor that takes an assertion
 *    without the hop that carried it.
 * 2. 🛑 **The headers read are fixed by installation configuration**, never by
 *    a binding. A project cannot cause a new header to be read, which is what
 *    keeps `header_trust` from becoming "name any header and I will believe
 *    it"; and the names are themselves constrained by {@see self::READABLE}
 *    and {@see self::NEVER_READ}.
 * 3. 🛑 **Nothing here resolves a project.** §8.9.4: "The project MUST be
 *    resolved **solely** from the TLS server name or `Host` header plus the
 *    path. No request header MUST act as a project, version or tenant
 *    selector, in any environment. This is the GHSA-mp38-vprc-7hf5 class."
 *    These headers name a *reader*. The distinction is the whole safety of
 *    both drivers and it is asserted by name, not by intention: the denylist
 *    below refuses every spelling of the host, an architecture test asserts the
 *    denylist is there, and a feature test configures the hostile name and
 *    proves the resolved project is still the `Host`'s.
 *
 * ## 🛑 Why `*` is not good enough for these two drivers
 *
 * {@see TrustEdgeProxies} accepts `*` — "trust the address directly in front"
 * — and for §8.12.17's `ip_allowlist` that is a reasonable convenience: the
 * worst outcome is a gate that narrows nothing. Here the worst outcome is
 * *anybody asserting any identity*, because with `*` every peer is the address
 * directly in front. So {@see self::terminatorIsPinned()} requires an explicit
 * address or CIDR list, and both drivers' probes fail without one. `private` is
 * refused for the same reason at a smaller scale: on a container network every
 * sidecar has a private address.
 */
final readonly class EdgeAssertion
{
    /**
     * 🛑 Only `X-…` names may be read, which excludes every standard header by
     * construction rather than by enumeration.
     *
     * No HTTP header that routes, names a host, or carries a credential uses
     * this prefix — `Host`, `Forwarded`, `Authorization`, `Cookie` and HTTP/2's
     * `:authority` are all outside it. A denylist alone would have to
     * anticipate the next dangerous header; this anticipates none and admits
     * none.
     */
    private const string READABLE = '/^x-[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i';

    /**
     * 🛑 And within `X-…`, the names that must never be read for identity.
     *
     * The first four are §8.9.4's class: a header that names a host, read as a
     * subject, would put an attacker-chosen hostname where a reader's name
     * belongs — and an operator debugging that would be one step from trusting
     * it for routing. The next two are the same mistake about a path. The last
     * two are here because an address is a `{gate}` input and never an identity
     * (§8.12.17), and reading one as a subject would smuggle §20.3's seven-day
     * raw-IP rule into the decision log.
     */
    private const array NEVER_READ = [
        'x-forwarded-host',
        'x-original-host',
        'x-forwarded-server',
        'x-host',
        'x-original-url',
        'x-rewrite-url',
        'x-forwarded-for',
        'x-real-ip',
    ];

    /**
     * @param  bool  $fromTrustedProxy  🛑 whether the request arrived from an
     *                                  address the installation declared its
     *                                  own. False nulls everything else.
     * @param  string|null  $assertedSubject  what the terminator says the
     *                                        reader is called, for
     *                                        {@see HeaderTrustDriver}
     * @param  string|null  $clientCertificate  the forwarded client
     *                                          certificate, still in the
     *                                          terminator's wire format, for
     *                                          {@see MtlsDriver}
     * @param  string|null  $certificateVerdict  the terminator's own verdict on
     *                                           the handshake — nginx's
     *                                           `$ssl_client_verify`, which is
     *                                           `SUCCESS`, `NONE` or
     *                                           `FAILED:<reason>`
     * @param  string|null  $assertionSecret  🛑 a secret only the terminator's
     *                                        own configuration holds, which is
     *                                        what makes an asserted identity
     *                                        more than a header. See
     *                                        {@see HeaderTrustDriver}'s class
     *                                        note on the pass-through attack it
     *                                        closes.
     */
    private function __construct(
        public bool $fromTrustedProxy = false,
        public ?string $assertedSubject = null,
        public ?string $clientCertificate = null,
        public ?string $certificateVerdict = null,
        public ?string $assertionSecret = null,
    ) {}

    /**
     * 🛑 The terminator asserted nothing, which is what every driver sees on an
     * installation that configured none of this — and what a forged assertion
     * from an untrusted peer collapses to.
     */
    public static function none(): self
    {
        return new self;
    }

    /**
     * Read what the terminator asserted, or nothing at all.
     *
     * 🛑 `isFromTrustedProxy()` is Symfony's own test of `REMOTE_ADDR` against
     * the list {@see TrustEdgeProxies} set earlier in the same request, so this
     * cannot disagree with the address `$request->ip()` resolved. Before Phase
     * 26b nothing set that list, which is the finding the middleware records.
     */
    public static function from(Request $request): self
    {
        /*
         * 🛑 The single load-bearing line of this class. An assertion from an
         * untrusted peer is not refused later by a driver — it never becomes an
         * assertion, because there is no constructor that would hold it.
         */
        if (! $request->isFromTrustedProxy()) {
            return self::none();
        }

        return new self(
            fromTrustedProxy: true,
            assertedSubject: self::header($request, 'docup.auth.asserted_identity.subject_header'),
            clientCertificate: self::header($request, 'docup.auth.client_certificate.header'),
            certificateVerdict: self::header($request, 'docup.auth.client_certificate.verdict_header'),
            assertionSecret: self::header($request, 'docup.auth.asserted_identity.secret_header'),
        );
    }

    /**
     * 🛑 Whether the installation named its terminator precisely enough for an
     * asserted identity to mean anything.
     *
     * `''` asserts nothing at all; `*` and `private` trust a *shape* of peer
     * rather than a peer, and an identity assertion trusted by shape is an
     * identity assertion anybody of that shape can make. See the class note.
     *
     * Read by both drivers' probes, so §8.12.19 refuses to activate a binding
     * on an installation that has not done this — rather than activating one
     * that would believe anybody.
     */
    public static function terminatorIsPinned(): bool
    {
        $configured = config('docup.edge.trusted_proxies');

        if (! is_string($configured)) {
            return false;
        }

        $configured = strtolower(trim($configured));

        return $configured !== '' && $configured !== '*' && $configured !== 'private';
    }

    /**
     * Whether a header name may be read for an asserted identity.
     *
     * Public because both drivers' probes report it, and because a rule an
     * operator can be shown is a rule they can satisfy.
     */
    public static function mayRead(string $header): bool
    {
        $header = strtolower(trim($header));

        return $header !== ''
            && preg_match(self::READABLE, $header) === 1
            && ! in_array($header, self::NEVER_READ, true);
    }

    /**
     * One configured header's value, or null.
     *
     * 🛑 A configured name that {@see self::mayRead()} refuses yields **null
     * rather than an exception**, and the probe is what tells the operator.
     * Throwing here would turn a configuration mistake into a 500 on the
     * serving path — for every reader, including the public ones — where
     * failing closed costs only the drivers that depend on it.
     */
    private static function header(Request $request, string $key): ?string
    {
        $name = config($key);

        if (! is_string($name) || ! self::mayRead($name)) {
            return null;
        }

        $values = $request->headers->all($name);

        /*
         * 🛑 **A header that arrived twice is refused outright**, and this is
         * the most easily-missed defence in the class.
         *
         * `proxy_set_header` in nginx and `header_up X-Foo bar` in Caddy both
         * *replace* every value — but `header_up +X-Foo` appends, and a
         * terminator that sets the header only when the reader is
         * authenticated passes a client's own value straight through
         * untouched. In either case DocUp would see two values: the
         * operator's and an attacker's.
         *
         * Taking the first is choosing between them on the strength of
         * whichever proxy happened to order them, so neither is taken. The
         * operator's remedy is to set the header unconditionally — including
         * to an empty value for an unauthenticated reader — which the operator
         * documentation says in as many words.
         */
        if (count($values) !== 1) {
            return null;
        }

        $value = $values[0] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
