<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

/**
 * 🛑 Why §8.13.7's provisioning refused, in terms no protocol owns.
 *
 * `ReaderProvisioning` is the **one** implementation of §8.13.7 — "JIT
 * provisioning MUST be per binding … reconciled — added *and* removed — on
 * every login" — and it has to be, because a second one would be a second
 * answer to whether a departed employee still has access. Phase 24 built it
 * inside `App\Auth\Providers\Oidc` because OIDC was the only caller; Phase 25
 * adds SAML, and a class two protocols share cannot raise one protocol's
 * exception.
 *
 * ## 🛑 Why this enum is not simply `OidcRejection`'s cases renamed
 *
 * The audit vocabulary is per protocol on purpose. §17 requires SAML's seven
 * failures to raise "distinct audit events", and an operator triaging a SAML
 * problem needs `saml.*`, not a shared prefix that buries which protocol was
 * being spoken. So this enum is the **internal** channel: provisioning says
 * what went wrong in protocol-free terms, and each callback translates it into
 * its own vocabulary before anything reaches §8.22's chain.
 *
 * The one exception is {@see self::DashboardRoleNotPermitted}, which is audited
 * from inside the reconciliation and keeps the `federation.` prefix. That is
 * deliberate: it is a fact about a **mapping row being wrong**, true whoever
 * logged in and whichever protocol they used, so naming a protocol in it would
 * make an operator think the protocol was relevant to the fix. It is also why
 * the prefix changed from Phase 24's `oidc.dashboard_role_not_permitted` —
 * recorded in the build log, and nothing asserted the old string.
 */
enum ProvisioningRejection: string
{
    /**
     * The verified facts carry no subject.
     *
     * 🛑 Already checked by whichever verifier produced them — this is a
     * narrowing rather than a real gate — but §8.12.1 keys a reader identity on
     * `(binding_id, subject_hash)`, so a missing subject is the one input that
     * cannot be defaulted or worked around.
     */
    case SubjectMissing = 'federation.subject_missing';

    /**
     * §8.13.7's `disabled`, or an identity an operator deprovisioned.
     *
     * 🛑 Two causes, one case, and both are "DocUp will not create or revive a
     * reader here". "Only readers I have already created" is a legitimate
     * posture, and a deprovisioned reader logging in is not an appeal.
     */
    case ProvisioningDisabled = 'federation.provisioning_disabled';

    /**
     * 🛑 §8.12.5's fourth enforcement: a `role` mapping reached by a reader.
     *
     * Audited and skipped rather than thrown, because the reader is legitimate
     * and the mapping is the operator's mistake — refusing the login would
     * punish the wrong party. See the reconciliation's own comment for why the
     * other three enforcements do not make this one redundant.
     */
    case DashboardRoleNotPermitted = 'federation.dashboard_role_not_permitted';

    /**
     * The audit action for this rejection.
     *
     * 🛑 Only {@see self::DashboardRoleNotPermitted} uses it. The other two are
     * translated by the caller into its own protocol's vocabulary, so calling
     * this on them would put a `federation.*` action in a chain an operator is
     * filtering for `oidc.*` or `saml.*`.
     */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }
}
