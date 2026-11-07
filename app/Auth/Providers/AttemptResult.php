<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\AccessLeaf;
use App\Access\CredentialScope;

/**
 * 🛑 What a driver found, as **evidence** and never as a verdict.
 *
 * §4.3 allows one decider and §12.3 names it, so a driver cannot return
 * "allowed". It returns three facts, and §12.3's function turns them into an
 * outcome:
 *
 * - whether the driver's leaf is **satisfied**;
 * - whether a credential was **presented and rejected**, which is the only
 *   thing that permits §8.12.23's 401;
 * - the credential's **scope**, which §12.3's last conjunct applies when this
 *   was the satisfying leaf.
 *
 * ## 🛑 Why "unsatisfied" and "rejected" are two different things
 *
 * They decide different statuses, and conflating them is a disclosure in one
 * direction and a usability failure in the other. A reader who presented
 * nothing gets §8.12.23's `deny_status` with no `WWW-Authenticate`, because
 * telling them to authenticate confirms the resource exists. A reader whose
 * share link expired presented a credential and gets a challenge, because they
 * already knew it existed — they had a link to it.
 */
final readonly class AttemptResult
{
    /**
     * @param  bool  $satisfied  the driver's leaf is satisfied
     * @param  bool  $credentialRejected  🛑 §8.12.23's case (a): something was
     *                                    presented and refused. Independent of
     *                                    `$satisfied`, because "nothing
     *                                    presented" and "bad credential" are
     *                                    two outcomes of an unsatisfied leaf.
     * @param  AccessLeaf|null  $leaf  which leaf was satisfied, from §8.12.17
     * @param  string|null  $subject  an opaque reader subject for §20.3's keyed
     *                                digest. 🛑 Never an email: §8.12.1 forbids
     *                                email for linking or lookup anywhere in
     *                                this population.
     * @param  CredentialScope|null  $scope  §12.3's last conjunct, when the
     *                                       satisfying credential carries one
     * @param  bool  $degraded  🛑 §8.12.19: the binding is degraded, so this
     *                          request must produce a branded 503 and **not**
     *                          fall through to another provider or to public
     * @param  string|null  $credentialId  raw 16 bytes of the
     *                                     `reader_credentials` row, so a use
     *                                     count can be incremented and a
     *                                     revocation traced
     */
    public function __construct(
        public bool $satisfied,
        public bool $credentialRejected = false,
        public ?AccessLeaf $leaf = null,
        public ?string $subject = null,
        public ?CredentialScope $scope = null,
        public bool $degraded = false,
        public ?string $credentialId = null,
    ) {}

    /**
     * Nothing was presented. 🛑 **Not an error**: this is what every anonymous
     * request on a public page produces.
     */
    public static function unsatisfied(): self
    {
        return new self(satisfied: false);
    }

    /**
     * Something was presented and refused — expired, revoked, out of uses, or
     * simply wrong.
     *
     * 🛑 The *reason* is deliberately not a parameter. §8.12.23 forbids the
     * response varying with what the client sent, and a reason on this object
     * is a reason one representation layer away from the wire. What the
     * operator needs goes to §8.22's audit chain from the driver, where the
     * response cannot reach it.
     */
    public static function rejected(): self
    {
        return new self(satisfied: false, credentialRejected: true);
    }

    /**
     * 🛑 §8.12.19: "A degraded binding MUST **deny** with a branded 503 naming
     * the binding and linking to its health page — never fall back to another
     * provider, never to public."
     *
     * Its own constructor because it is not a refusal of the reader. The reader
     * did nothing wrong and may hold a perfectly good credential; the
     * installation cannot currently tell. A 503 says that and a 404 does not.
     */
    public static function degraded(): self
    {
        return new self(satisfied: false, degraded: true);
    }

    /** The leaf is satisfied. */
    public static function satisfiedBy(
        AccessLeaf $leaf,
        ?string $subject = null,
        ?CredentialScope $scope = null,
        ?string $credentialId = null,
    ): self {
        return new self(
            satisfied: true,
            leaf: $leaf,
            subject: $subject,
            scope: $scope,
            credentialId: $credentialId,
        );
    }
}
