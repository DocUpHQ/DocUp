<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * Every way §8.12.20's break-glass override can be refused, as a closed
 * vocabulary.
 *
 * > "An installation-owner **break-glass** read override MUST exist behind MFA,
 * > step-up re-authentication and a mandatory reason, rate-limited to 3/hour,
 * > raising an operator alert and audited."
 *
 * 🛑 **These are for the person opening it**, who is an installation owner at a
 * browser, acting deliberately. So each one says what to do instead, and the
 * explanations are specific — unlike every reader-facing refusal in this
 * namespace, which must say nothing (§8.12.23).
 *
 * 🛑 And every one of them is **audited even when it refuses**. A sequence of
 * refused break-glass attempts is exactly the signal an operator wants, and it
 * is the signal an attacker who has taken an owner's session would produce.
 */
enum BreakGlassRejection: string
{
    /**
     * 🛑 §8.12.20 says "installation-**owner**", and the word is load-bearing.
     *
     * Not `installation_security_admin`: §8.13.2 makes that role a separation
     * of duty holding "IdP configuration and audit export", which is the power
     * to change who can get in and to read the record of who did. Giving the
     * same role the ability to read any document would collapse the separation
     * — the one person who can edit the audit trail's export must not also be
     * the one who can read everything without a policy.
     */
    case NotAnInstallationOwner = 'break_glass.not_an_installation_owner';

    /**
     * §8.12.20's "behind MFA", and **enrolment** rather than requirement.
     *
     * 🛑 The distinction matters: §8.13.4 lets an installation require MFA, and
     * an owner on an installation that has not switched it on would otherwise
     * pass a check written as "is MFA required and satisfied". What this
     * requirement wants is a second factor on the account doing the override,
     * whatever the installation's policy is.
     */
    case MfaNotEnrolled = 'break_glass.mfa_not_enrolled';

    /**
     * §8.12.20's "step-up re-authentication", in §8.13.5's **5-minute**
     * window.
     *
     * The short window rather than the routine one, because §8.13.5 reserves it
     * for "mutations to authentication providers, domains, visibility, share
     * grants, token minting and audit export" — and reading every document on
     * the installation is at least that sensitive.
     */
    case StepUpRequired = 'break_glass.step_up_required';

    /**
     * 🛑 §8.12.20's "mandatory reason", where mandatory means more than NOT
     * NULL.
     *
     * A single character satisfies a database constraint. What a review needs
     * is a sentence, so the minimum is a length **and** a word count: a reason
     * of `aaaaaaaaaaaaaaaaaaaaaa` passes any length check and tells nobody
     * anything.
     */
    case ReasonTooThin = 'break_glass.reason_too_thin';

    /** The reason exceeds the column, which is also what makes it reviewable. */
    case ReasonTooLong = 'break_glass.reason_too_long';

    /**
     * §8.12.20's "rate-limited to 3/hour".
     *
     * 🛑 Counted from the grants table rather than from a cache bucket. A
     * Valkey counter resets on a flush, an eviction or a restart, so "3 per
     * hour" would be an honest claim only while the cache happened to be
     * healthy — and the one time it matters is an incident, which is also when
     * somebody is restarting things.
     */
    case RateLimited = 'break_glass.rate_limited';

    /**
     * A grant is already open for this project.
     *
     * 🛑 Refused rather than silently reused, so the rate limit cannot be
     * sidestepped by re-opening, and so that two reasons never attach to one
     * window. The owner closes the open grant or waits for it.
     */
    case AlreadyOpen = 'break_glass.already_open';

    /** The audit action this is recorded under (§8.22.4's dotted names). */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }

    /** What the owner is told, and what to do instead. */
    public function explain(): string
    {
        return match ($this) {
            self::NotAnInstallationOwner => 'Break-glass is the installation owner\'s override '
                .'(§8.12.20). `installation_security_admin` deliberately does not hold it: '
                .'§8.13.2 makes that role a separation of duty over IdP configuration and audit '
                .'export, and one person who can both read everything and export the record of '
                .'it is not a separation.',
            self::MfaNotEnrolled => 'Enrol a second factor on your own account first (§8.12.20). '
                .'This is about your account rather than the installation\'s policy: an override '
                .'that reads every document must not rest on a password alone.',
            self::StepUpRequired => 'Confirm your password again, then retry. §8.13.5 gives a '
                .'five-minute window to the most sensitive actions, and reading every document on '
                .'the installation is at least that sensitive.',
            self::ReasonTooThin => 'Write what you are investigating, in a sentence. §8.12.20 '
                .'makes the reason mandatory, and a review six months from now needs more than a '
                .'placeholder — so a minimum length and a few distinct words are required.',
            self::ReasonTooLong => 'Keep the reason under 500 characters. A bound is what makes '
                .'the field answerable in a review; link to the incident rather than pasting it.',
            self::RateLimited => 'Three activations an hour (§8.12.20). The limit is counted from '
                .'the grant records rather than a cache, so it cannot be cleared by a restart — '
                .'if you genuinely need a fourth, that is a conversation rather than a click.',
            self::AlreadyOpen => 'A break-glass window is already open for this project. Close it '
                .'or wait for it to expire: two reasons attached to one window would make neither '
                .'reviewable.',
        };
    }
}
