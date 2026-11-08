<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\Providers\ReaderPresentation;

/**
 * The identity half of §8.12.25's question, as the operator chose it.
 *
 * 🛑 **This names a stored row; it does not describe a reader.** The
 * distinction matters because it is what keeps the simulator honest: the
 * operator picks *which* identity, and every fact about that identity —
 * which binding vouched for it, which groups it carries, which roles it holds
 * — is read from the database by the same code the serving path reads it with.
 * An operator cannot type "a member of the finance group" and have the
 * simulator believe them. If the stored facts do not say so, the answer does
 * not say so either.
 *
 * {@see SimulatedIdentityKind} says why there is no hand-described case.
 *
 * 🛑 `remoteAddress` is **not** part of the identity and is typed beside it
 * rather than inside it, for the reason {@see ReaderPresentation}
 * gives: §8.12.17 classifies `ip_allowlist` as a `{gate}`, never an identity.
 * It is here because §12.3 lets a rule narrow on one and an operator debugging
 * "why can the office not read this" needs to vary it — not because being on a
 * network makes somebody anybody.
 */
final readonly class SimulatedIdentity
{
    /**
     * @param  string|null  $readerIdentityId  raw 16 bytes, for
     *                                         {@see SimulatedIdentityKind::Reader}
     * @param  string|null  $userId  raw 16 bytes, for
     *                               {@see SimulatedIdentityKind::Member}
     * @param  string|null  $remoteAddress  the address to evaluate a `{gate}`
     *                                      against, or null — which is a true
     *                                      answer and not a missing one: a
     *                                      reader on no allowlisted network
     */
    private function __construct(
        public SimulatedIdentityKind $kind,
        public ?string $readerIdentityId,
        public ?string $userId,
        public ?string $remoteAddress,
    ) {}

    /** Nobody, which is the case most worth checking and the easiest to forget. */
    public static function anonymous(?string $remoteAddress = null): self
    {
        return new self(SimulatedIdentityKind::Anonymous, null, null, $remoteAddress);
    }

    /** @param  string  $readerIdentityId  raw 16 bytes */
    public static function reader(string $readerIdentityId, ?string $remoteAddress = null): self
    {
        return new self(SimulatedIdentityKind::Reader, $readerIdentityId, null, $remoteAddress);
    }

    /** @param  string  $userId  raw 16 bytes */
    public static function member(string $userId, ?string $remoteAddress = null): self
    {
        return new self(SimulatedIdentityKind::Member, null, $userId, $remoteAddress);
    }

    /**
     * The stored row this identity names, raw 16 bytes, or null for anonymous.
     *
     * One accessor rather than two `?->` chains at every call site, because
     * exactly one of the two ids is ever set and the kind already says which.
     */
    public function subjectId(): ?string
    {
        return $this->readerIdentityId ?? $this->userId;
    }
}
