<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Access\EffectiveAccess;
use App\Access\ReaderContext;
use App\Readers\Grants\Grant;

/**
 * What one request's cookies established about its reader.
 *
 * 🛑 **`context` is the only thing the decision function ever sees.** The grant
 * and the session are here for the two jobs that happen *after* a decision —
 * deciding whether to mint a fresh grant, and naming the session in §20.3's log
 * — and {@see EffectiveAccess} has no parameter that could receive
 * either, by design (see {@see ReaderContext}).
 */
final readonly class EstablishedReader
{
    /**
     * @param  ReaderContext  $context  what §12.3 decides against
     * @param  Grant|null  $grant  a verified grant, when one was presented and
     *                             is usable for this request. Null means the
     *                             request will need a fresh one minted if it is
     *                             allowed.
     * @param  SessionRecord|null  $session  the live session behind the reader,
     *                                       when the request had to read it.
     *                                       🛑 Null when a valid grant made the
     *                                       read unnecessary — which is
     *                                       §8.12.13's Tier A: "one signature
     *                                       verification, zero database
     *                                       round-trips".
     * @param  bool  $credentialRejected  🛑 §8.12.23's case (a): something was
     *                                    presented and refused. Carried
     *                                    separately because "no credential" and
     *                                    "a bad credential" decide whether a
     *                                    401 is permitted, and a null grant is
     *                                    both.
     */
    public function __construct(
        public ReaderContext $context,
        public ?Grant $grant = null,
        public ?SessionRecord $session = null,
        public bool $credentialRejected = false,
        public ?string $degradedBinding = null,
    ) {}

    /**
     * 🛑 §8.12.19: "A degraded binding MUST **deny** with a branded 503 naming
     * the binding and linking to its health page — never fall back to another
     * provider, never to public."
     *
     * Carried here rather than thrown, because the decision still has to run:
     * §8.12.14 forbids a path that bypasses it, and the 503 is a
     * *representation* of a refusal §12.3 reached — the same division §8.12.24
     * draws between an outcome and how it is rendered.
     *
     * The binding's **name** and nothing else. §8.12.19 wants the reader told
     * which provider is unavailable so they can tell somebody; it does not want
     * them told why, which is the health page's job and the operator's.
     */
    public function isDegraded(): bool
    {
        return $this->degradedBinding !== null;
    }

    /** An anonymous reader: no cookies, nothing presented. */
    public static function anonymous(): self
    {
        return new self(ReaderContext::anonymous());
    }

    /**
     * Whether an allowed request should be issued a fresh grant.
     *
     * 🛑 True exactly when a session exists and no usable grant does. A request
     * that already holds a valid grant is re-issued nothing — otherwise every
     * asset on a sixty-asset page would mint and set a cookie, which is sixty
     * signatures and sixty `Set-Cookie` headers where §8.12.13 budgets one.
     */
    public function needsGrant(): bool
    {
        return $this->session !== null && $this->grant === null;
    }
}
