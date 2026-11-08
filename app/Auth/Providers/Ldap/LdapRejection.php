<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

/**
 * Every way an LDAP exchange can fail, as a closed vocabulary.
 *
 * 🛑 **The split that matters is operator fault versus reader fault**, and it
 * is not cosmetic. §8.12.19 gives a degraded binding "a branded 503 naming the
 * binding and linking to its health page", while §8.12.23 gives a refused
 * reader the project's `deny_status` with no explanation at all. Reporting one
 * as the other is a disclosure in one direction and a support ticket in the
 * other:
 *
 * - **An operator fault** means DocUp cannot talk to the directory —
 *   unreachable, no TLS, the service account refused. The reader did nothing
 *   wrong and is owed a 503 that says somebody else is fixing it.
 * - **A reader fault** means the directory answered and the answer was no.
 *   That is a 404 or a re-prompt, and it must carry none of the directory's own
 *   text: `ldap_error()` names hosts and DNs and sometimes says why an account
 *   is locked.
 */
enum LdapRejection: string
{
    // ------------------------------------------------------- operator faults

    /**
     * 🛑 `ext-ldap` is not installed on this installation.
     *
     * §11.2 makes it a composer `suggest` (amended in Phase 26b), so this is a
     * supported state rather than a broken one — and the message has to name
     * the extension, because the alternative is a fatal error about an
     * undefined function in a stack trace an operator cannot act on.
     */
    case ExtensionMissing = 'ldap.extension_missing';

    /** The URI did not parse, or nothing answered within the timeout. */
    case Unreachable = 'ldap.unreachable';

    /**
     * 🛑 StartTLS was refused, or the certificate did not verify.
     *
     * One case for both, deliberately: the remedy is the same — fix the
     * directory's TLS — and distinguishing them would mean reporting whether a
     * certificate verified, which tells anybody who can reach this endpoint
     * something about the operator's internal network.
     */
    case TlsUnavailable = 'ldap.tls_unavailable';

    /** §8.12.18's "bind credentials required", absent from the configuration. */
    case BindCredentialsMissing = 'ldap.bind_credentials_missing';

    /** The service account's own bind failed: a configuration fault. */
    case BindFailed = 'ldap.bind_failed';

    /** The search itself errored — a bad base DN, a size limit, a protocol error. */
    case SearchFailed = 'ldap.search_failed';

    /**
     * 🛑 The filter matched more than one entry.
     *
     * An operator fault rather than a reader's, and refused rather than
     * resolved: picking the first would authenticate whichever entry the
     * directory happened to return first — a coin toss between two people,
     * deterministic enough in testing to look correct.
     */
    case SubjectAmbiguous = 'ldap.subject_ambiguous';

    // --------------------------------------------------------- reader faults

    /**
     * The filter matched nothing.
     *
     * 🛑 Reported to the reader exactly as a wrong password is, because the
     * difference between "no such account" and "wrong password" is an
     * enumeration oracle for the operator's directory.
     */
    case SubjectNotFound = 'ldap.subject_not_found';

    /**
     * The reader's own bind failed, or they submitted no password.
     *
     * 🛑 An empty password is in this case rather than being a validation
     * error, and that is the single most important classification here: RFC
     * 4511 §4.2 makes a simple bind with an empty password an **anonymous**
     * bind, which succeeds on most directories — so treating it as anything
     * other than a rejected credential would authenticate a reader who
     * submitted nothing.
     */
    case CredentialsRejected = 'ldap.credentials_rejected';

    /**
     * Whether this failure is the operator's to fix, which decides whether
     * §8.12.19's degraded 503 or §8.12.23's `deny_status` is owed.
     */
    public function isOperatorFault(): bool
    {
        return match ($this) {
            self::SubjectNotFound,
            self::CredentialsRejected => false,
            default => true,
        };
    }

    /** The audit action this refusal is recorded under (§8.22.4's dotted names). */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }

    /**
     * What an operator is told, on §8.12.19's health page.
     *
     * 🛑 Never what a **reader** is told. A reader gets §8.12.23's
     * `deny_status` and an empty body; these sentences name the extension, the
     * TLS posture and the service account, which is operator-grade detail.
     */
    public function explain(): string
    {
        return match ($this) {
            self::ExtensionMissing => 'This installation has no `ext-ldap`. '
                .'It is a composer `suggest`, so install the PHP extension and restart; '
                .'the shipped container images already carry it.',
            self::Unreachable => 'Nothing answered at that address within '
                .LdapConnection::TIMEOUT_SECONDS.' seconds.',
            self::TlsUnavailable => 'LDAPS or StartTLS with a verifying certificate is required '
                .'(§8.12.18) and this directory offered neither. There is no option to skip it.',
            self::BindCredentialsMissing => 'A service account DN and password are required '
                .'(§8.12.18). An anonymous bind succeeds on many directories and returns '
                .'entries stripped of the attributes the filter needs, which looks like '
                .'every user being absent.',
            self::BindFailed => 'DocUp could not sign in to the directory with the configured '
                .'service account.',
            self::SearchFailed => 'The search failed. Check the base DN and the filter.',
            self::SubjectAmbiguous => 'The filter matched more than one entry, so the username is '
                .'not unique under that base DN. DocUp refuses rather than choosing.',
            self::SubjectNotFound => 'The filter matched no entry.',
            self::CredentialsRejected => 'The directory rejected those credentials.',
        };
    }
}
