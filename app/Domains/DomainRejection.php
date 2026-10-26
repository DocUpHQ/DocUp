<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * Why a domain write was refused, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract: these reach the audit log, the dashboard, the
 * API and an operator's tooling, so renaming one breaks something outside
 * this repository.
 *
 * 🛑 **Every value here is a refusal, never a warning**, and §8.10.4 is the
 * reason: "Proof of domain control MUST precede any certificate issuance or
 * any byte served for a custom hostname." A warning is a refusal somebody
 * clicked past, and what is on the other side of this one is serving another
 * organisation's hostname.
 */
enum DomainRejection: string
{
    /** Not a hostname: too long, empty label, illegal character. */
    case HostMalformed = 'domain.host_malformed';

    /**
     * 🛑 §8.10.7: "mixed-script or Unicode-confusable hostnames MUST be
     * rejected."
     *
     * The attack is `аpple.com` with a Cyrillic а — visually identical, a
     * different hostname, and a reader who checks the address bar is
     * reassured by it.
     */
    case HostConfusable = 'domain.host_confusable';

    /** The name is inside the installation's own apexes, which it owns. */
    case HostReserved = 'domain.host_reserved';

    /** 🛑 §8.10.5: another organisation has a **proven** claim on it. */
    case HostClaimed = 'domain.host_claimed';

    /**
     * 🛑 §8.10.4: the hostname sits under an apex another organisation has
     * proven. "No other organisation may bind under it."
     */
    case ParentClaimed = 'domain.parent_claimed';

    /**
     * 🛑 §8.10.9's tombstone: released within the last 90 days and claimed by
     * somebody other than the previous owner. "A dangling CNAME pointing at
     * the installation is otherwise a cross-tenant takeover."
     */
    case Tombstoned = 'domain.tombstoned';

    /** Verification ran and the record was absent or wrong. */
    case ProofMissing = 'domain.proof_missing';

    /**
     * 🛑 §8.10.6: the two resolvers disagreed. Treated as a failure rather
     * than as a retry, because one resolver seeing a record the other does
     * not is what a partially-propagated takeover looks like.
     */
    case ResolversDisagreed = 'domain.resolvers_disagreed';

    /**
     * 🛑 §8.10.6: "SSRF-hardened, rejecting private and link-local answers."
     * A claim whose CNAME target resolves into the installation's own network
     * is not proof of anything the claimant controls.
     */
    case AnswerNotPublic = 'domain.answer_not_public';

    /**
     * 🛑 §8.10.19: "`includeSubDomains` and `preload` MUST be validation
     * errors on any shared apex or any hostname that is a DNS suffix of
     * another claimed hostname — one tenant must not be able to break HTTPS
     * for another."
     */
    case HstsWouldSpanTenants = 'domain.hsts_would_span_tenants';

    /**
     * 🛑 §8.10.20: "Cross-organisation mounts on one hostname MUST NOT be
     * permitted: everything on one hostname shares one browser origin."
     */
    case SharedOriginCrossTenant = 'domain.shared_origin_cross_tenant';

    /** §8.10.20: a shared origin needs one exposure level across its mounts. */
    case SharedOriginExposureMismatch = 'domain.shared_origin_exposure_mismatch';

    /** §8.10.3: exactly one canonical mount per project. */
    case CanonicalMountExists = 'domain.canonical_mount_exists';

    /** A per-domain response header outside §8.10.22's allowlist. */
    case HeaderNotAllowed = 'domain.header_not_allowed';

    /** Reclaiming a tombstoned host, or verifying, needs a current token. */
    case TokenStale = 'domain.token_stale';

    public function identifier(): string
    {
        return $this->value;
    }
}
