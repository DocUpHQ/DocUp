<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

/**
 * Why a handoff was refused — the audit vocabulary for §8.12.10.
 *
 * 🛑 Every case here is the **same** response to the reader: §8.12.23's
 * `deny_status` with no detail, because "the response MUST NOT vary with any
 * client-supplied header" and the same argument applies with more force to the
 * body. An attacker probing the handoff learns whether their code was unknown,
 * expired, already used or for another domain only if this enum reaches the
 * wire, and it never does.
 *
 * It reaches §8.22's audit chain instead, where the operator can see which of
 * these is happening and how often.
 */
enum HandoffRejection: string
{
    /** No `reader_handoff_codes` row has this digest. */
    case UnknownCode = 'unknown_code';

    /** 🛑 §8.12.10's "expiring within 30 seconds", past. */
    case Expired = 'expired';

    /**
     * 🛑 The single-use latch, lost.
     *
     * Worth distinguishing from {@see self::UnknownCode} in the audit: a
     * replayed code means somebody has a URL they should not, which is a
     * different operator action from a code that never existed.
     */
    case AlreadyUsed = 'already_used';

    /** The code was minted for another domain, or another project. */
    case WrongAudience = 'wrong_audience';

    /** No state cookie, so no verifier to check (§8.12.10). */
    case NoState = 'no_state';

    /** 🛑 The verifier does not satisfy the stored challenge (RFC 7636). */
    case VerifierMismatch = 'verifier_mismatch';

    /**
     * The domain row is unverified, suspended or gone.
     *
     * 🛑 Checked at redemption as well as at mint, because §8.10.6 — "Suspended
     * and unverified hosts MUST be neither served nor certified" — can become
     * true in the thirty seconds a code is alive.
     */
    case DomainNotServable = 'domain_not_servable';

    /** The reader may not read this project at all (§12.3). */
    case NotPermitted = 'not_permitted';

    /**
     * 🛑 The handoff has already been attempted and produced no session.
     *
     * The loop breaker. Without it, a browser that silently refuses the
     * session cookie — §18.10's unverified assumption, or a reader with
     * cookies blocked for the origin — bounces between the two origins
     * forever, with a 302 at each end and nothing in any log that looks like
     * an error.
     */
    case LoopDetected = 'loop_detected';
}
