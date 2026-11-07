<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 §8.12.6's five leaf kinds, classified once by §8.12.17.
 *
 * > "Reader access MUST be an ordered, **first-match-wins** list of rules …
 * > each carrying a schema-validated two-level boolean requirement tree over
 * > leaves `{binding}`, `{gate}`, `{share}`, `{bearer}`, `{public}`."
 *
 * 🛑 **The classification is the whole reason this enum exists rather than five
 * string constants.** §8.12.7's satisfiability invariant "is defined over that
 * classification", and §8.12.17 gives it in one table so there is one answer to
 * "does this leaf bear an identity". A second classification anywhere — a
 * driver flag, a `match` in a validator, a list in a test — is how
 * `ip_allowlist` ends up counting as authentication in one of the two places.
 *
 * The driver → leaf mapping is §8.12.17's own and lives in
 * {@see self::forDriver()}, so a new driver declares its leaf kind at the one
 * place the invariant reads.
 */
enum AccessLeaf: string
{
    /** `portal_session`, `password`, `oidc`, `saml`, `ldap`, `mtls`, `header_trust`. */
    case Binding = 'binding';

    /** 🛑 `ip_allowlist`, and the only non-public kind that bears no identity. */
    case Gate = 'gate';

    /** `shared_link` — §8.12.16's share-by-link, with mandatory expiry. */
    case Share = 'share';

    /** `reader_token` — an `Authorization: Bearer` token with version and path scope. */
    case Bearer = 'bearer';

    /** The public terminal. Satisfied by every request, including an anonymous one. */
    case Public = 'public';

    /**
     * 🛑 §8.12.17's identity-bearing column, verbatim.
     *
     * > "`ip_allowlist` is the reason §8.12.7 exists: it is a gate, never an
     * > identity, so a requirement tree satisfiable by it alone is rejected at
     * > write time."
     *
     * `{public}` is not identity-bearing either, which is why §8.12.7 has to
     * name the public terminal as an explicit exception rather than letting it
     * fall out of the classification.
     */
    public function bearsIdentity(): bool
    {
        return match ($this) {
            self::Binding, self::Share, self::Bearer => true,
            self::Gate, self::Public => false,
        };
    }

    /**
     * Whether this leaf carries a scope §12.3's last conjunct must check.
     *
     * §12.3: "share/bearer scope covers (project, version, path) **if that was
     * the satisfying leaf**". A binding establishes who the reader is and says
     * nothing about which paths they may read — the policy rule does that. A
     * share link and a bearer token carry their own scope, narrower than the
     * rule that admitted them, and the conditional is what makes a leaked link
     * to `/v1/internal/` useless against `/v2/`.
     */
    public function carriesScope(): bool
    {
        return match ($this) {
            self::Share, self::Bearer => true,
            default => false,
        };
    }

    /**
     * §8.12.17's driver table, as a function.
     *
     * @param  string  $driver  an `auth_provider_bindings.type` value
     * @return self|null null for a driver this classification has not been
     *                   taught, which {@see Requirement} refuses rather than
     *                   guessing at — an unclassified driver whose leaf kind
     *                   defaulted to `binding` would be an identity nobody
     *                   declared.
     */
    public static function forDriver(string $driver): ?self
    {
        return match ($driver) {
            'public' => self::Public,
            'portal_session', 'password', 'oidc', 'saml', 'ldap', 'mtls', 'header_trust' => self::Binding,
            'shared_link' => self::Share,
            'reader_token' => self::Bearer,
            'ip_allowlist' => self::Gate,
            default => null,
        };
    }
}
