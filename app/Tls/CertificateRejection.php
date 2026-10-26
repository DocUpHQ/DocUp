<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * Why a certificate operation was refused, as a stable identifier.
 *
 * 🛑 §8.1.11 public contract, same as `DomainRejection`: these reach the
 * audit log, the dashboard, the API and an operator's tooling, so renaming
 * one breaks something outside this repository.
 */
enum CertificateRejection: string
{
    /** The PEM does not parse as a certificate. */
    case ChainUnreadable = 'certificate.chain_unreadable';

    /** The PEM does not parse as a private key. */
    case KeyUnreadable = 'certificate.key_unreadable';

    /** 🛑 The key is not the leaf's key. Accepted by every parser, refused by every client. */
    case KeyDoesNotMatch = 'certificate.key_does_not_match';

    /** The chain carries no name covering the hostname it was offered for. */
    case HostNotCovered = 'certificate.host_not_covered';

    /** Already expired, or not yet valid, at the moment it was offered. */
    case OutsideValidity = 'certificate.outside_validity';

    /** No ACME account is configured for the source that was asked to issue. */
    case NoAcmeAccount = 'certificate.no_acme_account';

    /** The CA answered, and said no. The detail carries its own problem document. */
    case AcmeRefused = 'certificate.acme_refused';

    /** The CA did not answer in a shape the client understands. */
    case AcmeUnreadable = 'certificate.acme_unreadable';

    /** 🛑 §8.10.13: the registrable domain has no tokens left. */
    case BudgetExhausted = 'certificate.budget_exhausted';

    /** 🛑 §8.10.13: the per-host circuit breaker is open. */
    case BreakerOpen = 'certificate.breaker_open';

    /** 🛑 §8.10.21: `passthrough` on a hostname serving a non-public project. */
    case PassthroughNotPublic = 'certificate.passthrough_not_public';

    /** 🛑 §8.10.12: the permission endpoint is HTTPS on a hostname this installation serves. */
    case PermissionEndpointDeadlock = 'certificate.permission_endpoint_deadlock';

    public function identifier(): string
    {
        return $this->value;
    }
}
