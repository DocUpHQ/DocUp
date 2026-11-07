<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\ReaderContext;

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
    ) {}

    /** Nothing was presented, which is the ordinary case on a public page. */
    public static function none(): self
    {
        return new self;
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
            || $this->sessionSubject !== null;
    }
}
