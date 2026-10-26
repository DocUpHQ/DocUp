<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * Why §8.10.11's permission endpoint answered as it did.
 *
 * 🛑 The reason never reaches the proxy. Caddy reads a status code and
 * nothing else, and an endpoint that explained itself over an unauthenticated
 * channel would be telling anybody who can open a TLS handshake which
 * hostnames this installation knows about, which are in backoff, and which
 * have exhausted their budget. The reason exists for the operator — a log
 * line, a metric label, a dashboard — and is discarded on the way out.
 */
enum PermissionVerdict: string
{
    /** Issue it. */
    case Permitted = 'permitted';

    /** No domain row, or one that is not serving. The common case, and the cheapest. */
    case NotEligible = 'not_eligible';

    /** 🛑 §8.10.10: covered by the installation's own wildcard; issuing would burn the budget. */
    case OwnZone = 'own_zone';

    /** 🛑 §8.10.13: the per-host breaker is open. */
    case InBackoff = 'in_backoff';

    /** 🛑 §8.10.13: the registrable domain's bucket is empty. */
    case BudgetExhausted = 'budget_exhausted';

    /** 🛑 §8.10.11: the hostname does not currently resolve to an ingress target. */
    case NotPointedHere = 'not_pointed_here';

    /** The resolvers could not answer. Fail closed: no proof, no certificate. */
    case Unresolvable = 'unresolvable';

    /** Too many questions about this hostname, or about all hostnames, too quickly. */
    case RateLimited = 'rate_limited';

    /** 🛑 §8.10.21: a passthrough host terminates TLS elsewhere; it needs no certificate here. */
    case Passthrough = 'passthrough';

    public function permits(): bool
    {
        return $this === self::Permitted;
    }
}
