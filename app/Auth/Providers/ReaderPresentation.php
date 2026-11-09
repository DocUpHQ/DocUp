<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\ReaderContext;
use App\Readers\ReaderSessions;

/**
 * What a reader presented, as the only thing a driver may look at.
 *
 * 🛑 **This holds no request**, for the reason {@see ReaderContext}
 * holds none: §8.12.23 says the outcome "is decided by the request's
 * **authorisation state**, never by its `Accept` or `Sec-Fetch-*` headers". A
 * driver handed a `Request` could branch on anything, and the first thing one
 * would branch on is a header that an attacker sets.
 *
 * So the transport extracts the four things a v1 driver can legitimately use,
 * and a driver that wants a fifth has to add it here — in front of a reviewer,
 * with a reason, rather than by reaching into a request object.
 *
 * 🛑 `remoteAddress` is the one field that is **not** a credential, and it is
 * typed as what it is. §8.12.17 classifies `ip_allowlist` as a `{gate}`, never
 * an identity; keeping the address beside the credentials rather than inside
 * them is what stops a driver treating it as one.
 */
final readonly class ReaderPresentation
{
    /**
     * @param  string|null  $bearer  the `Authorization: Bearer` value, for
     *                               §8.12.16's reader tokens
     * @param  string|null  $shareSecret  a share link's secret, from the query
     *                                    string on first use or from its cookie
     *                                    afterwards (§8.12.16)
     * @param  string|null  $password  a submitted password, for the `password`
     *                                 driver or a passworded share link
     * @param  string|null  $remoteAddress  🛑 a `{gate}` input, never an
     *                                      identity. Read from
     *                                      `$request->ip()` — §8.9.4 forbids a
     *                                      trusted header, so this is the
     *                                      `TrustProxies`-resolved address and
     *                                      not `X-Forwarded-For` as sent.
     * @param  string|null  $sessionSubject  the reader's established session
     *                                       subject, for `portal_session`
     */
    public function __construct(
        public ?string $bearer = null,
        public ?string $shareSecret = null,
        public ?string $password = null,
        public ?string $remoteAddress = null,
        public ?string $sessionSubject = null,
        /*
         * 🛑 Which binding vouched for the session's reader, raw 16 bytes,
         * or null for a dashboard member's session (and for no session).
         *
         * Added in Phase 24 because `oidc` and `portal_session` are both
         * `{binding}` leaves established by a session, and §12.3 lets a rule
         * name one binding specifically — so "a reader with a session" is not a
         * fine enough fact. Without this, a project with a portal and an IdP
         * could not write one rule per audience: every session would satisfy
         * both rules, and `PortalSessionDriver`'s own promise that "a dashboard
         * member does not satisfy the IdP's rule" would be false.
         */
        public ?string $sessionBinding = null,
        /*
         * 🛑 §8.12.4's "facts only the TLS terminator can establish", as one
         * named object rather than as four more fields.
         *
         * Added in Phase 26b for `mtls` and `header_trust`, which are the two
         * drivers whose identity is established somewhere else and *told* to
         * DocUp. It is one field because the class note above says a fifth
         * takes a reviewer and a reason, and the reason is better stated once
         * about the whole category than four times about its members —
         * {@see EdgeAssertion} is where it is stated.
         *
         * Null is the ordinary case: an installation that configured none of
         * this, and every request that did not arrive through a hop the
         * installation declared its own.
         */
        public ?EdgeAssertion $edge = null,
    ) {}

    /** Nothing was presented, which is the ordinary case on a public page. */
    public static function none(): self
    {
        return new self;
    }

    /**
     * The same presentation with the session's two facts filled in.
     *
     * 🛑 The caller that knows what the reader presented is **not** the caller
     * that knows what their session says, and this method is that seam rather
     * than a longer constructor call. The transport reads cookies, headers and
     * the remote address; resolving a session handle to a subject and a binding
     * takes a database read that the transport has no business doing twice.
     *
     * Added in Phase 26a, when §8.12.25's simulator needed to supply the
     * credential half from an operator's choice and let the identity half be
     * derived from a stored identity exactly as a live request derives it. A
     * simulator that constructed the whole presentation would have had to know
     * which subject a session yields, which is precisely the knowledge
     * {@see ReaderSessions::contextFor()} exists to hold.
     *
     * @param  string|null  $sessionBinding  raw 16 bytes, or null for a
     *                                       dashboard member's session
     */
    public function withSession(?string $sessionSubject, ?string $sessionBinding): self
    {
        return new self(
            bearer: $this->bearer,
            shareSecret: $this->shareSecret,
            password: $this->password,
            remoteAddress: $this->remoteAddress,
            sessionSubject: $sessionSubject,
            sessionBinding: $sessionBinding,
            edge: $this->edge,
        );
    }

    /**
     * Whether the reader presented anything a driver could act on.
     *
     * 🛑 `remoteAddress` is **excluded**, and that is §8.12.17's classification
     * showing up as a one-line method. Every request has an address; counting
     * it as "something presented" would make §8.12.23's case (a) — "a
     * credential was presented and rejected" — true of every anonymous request
     * on earth, and every 404 would become a 401.
     */
    public function carriesCredential(): bool
    {
        return $this->bearer !== null
            || $this->shareSecret !== null
            || $this->password !== null
            || $this->sessionSubject !== null
            /*
             * 🛑 The certificate counts and the asserted subject does **not**,
             * and the asymmetry is the point rather than an oversight.
             *
             * A client certificate is one the reader's browser *chose* to send
             * from a store the reader controls — presented, in §8.12.23's sense,
             * and a reader holding a certificate for this installation already
             * knows its projects exist. An asserted subject was manufactured by
             * the terminator from a session the reader holds somewhere else;
             * the reader did not present it, did not choose it and usually
             * cannot see it.
             *
             * The consequence of getting this backwards is quiet and large: a
             * terminator forwards its identity header on **every** request, so
             * counting it as presented would make every private 404 on the
             * installation a 401 — an existence oracle for every private
             * project. {@see \App\Auth\Providers\Drivers\HeaderTrustDriver}
             * never returns a rejected credential for the same reason, and a
             * test asserts it over every hostile input in the suite.
             */
            || $this->edge?->clientCertificate !== null;
    }
}
