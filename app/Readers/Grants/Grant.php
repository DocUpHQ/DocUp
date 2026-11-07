<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers\Grants;

use App\Access\AccessLeaf;
use App\Access\AccessSurface;
use App\Access\CredentialScope;
use App\Access\EffectiveAccess;
use App\Access\ReaderContext;
use App\Auth\AccessLevel;
use App\Support\Invalidation;

/**
 * §8.12.11's grant, as a claim set.
 *
 * > "🛑 The authorisation decision MUST be materialised as an **Ed25519**
 * > (`EdDSA`) token carrying audience-bound domain id, project/version scope,
 * > satisfied rule id, combined policy and identity epoch, and `exp` ≤ 10
 * > minutes."
 *
 * Every one of those five is a field below, and each is load-bearing:
 *
 * - `aud` is the **domain id**, not the project's. §17's exit criterion "a
 *   grant minted for domain A is refused on domain B" is this claim, checked.
 *   Binding to the project instead would make one grant work on every domain a
 *   project serves, which is precisely the cross-origin reuse §8.12.10's
 *   per-origin handoff exists to prevent.
 * - `sub` is the session, keyed and digested, never a reader identifier.
 * - `rid` is the satisfying rule, so §8.12.25's simulator and §20.3's log can
 *   name *why* without re-deciding.
 * - `ep` is the combined epoch — see {@see self::combinedEpoch()} for why one
 *   scalar is correct and what makes it orderable.
 * - `exp` is bounded by {@see GrantMinter::MAX_TTL_SECONDS}.
 *
 * 🛑 **No reader name, no email, no group list.** A grant is read by the edge
 * and lives in a cookie that documentation JavaScript cannot read but a proxy
 * log might; §8.12.1 keeps email out of this population entirely, and a claim
 * set is not the place to make an exception for debuggability.
 */
final readonly class Grant
{
    /**
     * @param  string  $sessionId  raw 16 bytes — the `docs_sessions` row this
     *                             grant was minted from, so a revoke can be
     *                             traced to the grants it ended
     * @param  string  $domainId  raw 16 bytes — 🛑 the audience
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $versionId  raw 16 bytes
     * @param  string  $versionSlug  for a verifier that holds a URL, not a row
     * @param  string|null  $ruleId  raw 16 bytes, or null when no rule matched
     *                               and the lattice alone admitted the reader
     * @param  int  $combinedEpoch  {@see self::combinedEpoch()}
     * @param  int  $issuedAt  unix seconds
     * @param  int  $expiresAt  unix seconds; 🛑 ≤ `$issuedAt + 600`
     * @param  AccessSurface  $surface  which of §8.12.21's four this grant was
     *                                  minted for. A grant for the search
     *                                  surface is not a grant for the proxy.
     * @param  AccessLevel  $level  🛑 the reader's **established** context
     *                              (§12.3), carried so that a request holding a
     *                              valid grant needs no database read to know
     *                              who the reader is — which is §8.12.13's Tier
     *                              A: "one signature verification, zero
     *                              database round-trips". It is re-derived from
     *                              `role_assignments` on every mint, never
     *                              stored on the session row, so the staleness
     *                              of a role change is exactly this grant's
     *                              remaining TTL and nothing longer.
     * @param  AccessLeaf|null  $satisfiedBy  the leaf kind that admitted the
     *                                        reader, for §12.3's scope conjunct
     * @param  string|null  $pathPrefix  the narrowest prefix the satisfying
     *                                   rule admitted, when it was path-scoped
     * @param  list<string>  $satisfiedBindings  binding ids this reader
     *                                           satisfied, for a `{binding}`
     *                                           leaf naming one. 🛑 **UUID
     *                                           text**, because that is what
     *                                           §8.12.6's requirement JSON
     *                                           holds and
     *                                           `ReaderContext::satisfies()`
     *                                           compares strictly — P24 found
     *                                           the verifier parsing these as
     *                                           bytes, which made every
     *                                           binding-named rule fail on the
     *                                           grant path. Empty
     *                                           throughout Phase 22 — no
     *                                           binding exists until P23 — and
     *                                           carried now because a grant
     *                                           without it would be **refused**
     *                                           by a rule naming a binding
     *                                           ({@see ReaderContext::satisfies()}),
     *                                           while the session behind it was
     *                                           allowed. Fail-closed, so not a
     *                                           hole; but every request would
     *                                           re-read the session and mint a
     *                                           grant that never helped.
     */
    public function __construct(
        public string $sessionId,
        public string $domainId,
        public string $projectId,
        public string $versionId,
        public string $versionSlug,
        public ?string $ruleId,
        public int $combinedEpoch,
        public int $issuedAt,
        public int $expiresAt,
        public AccessSurface $surface = AccessSurface::Proxy,
        public AccessLevel $level = AccessLevel::Authenticated,
        public ?AccessLeaf $satisfiedBy = null,
        public ?string $pathPrefix = null,
        public array $satisfiedBindings = [],
    ) {}

    /**
     * 🛑 The reader context this grant establishes, with no database read.
     *
     * The grant is signed, audience-bound and epoch-checked before this is
     * called, so its claims are this installation's own statement about a
     * reader made less than ten minutes ago — which is exactly what a
     * {@see ReaderContext} is. {@see EffectiveAccess} still
     * decides: §8.12.14 forbids a fast path that *bypasses* a decision, and
     * this bypasses only the lookup that establishes the inputs.
     */
    public function readerContext(): ReaderContext
    {
        $leaves = [AccessLeaf::Public];

        if ($this->satisfiedBy !== null && $this->satisfiedBy !== AccessLeaf::Public) {
            $leaves[] = $this->satisfiedBy;
        }

        return new ReaderContext(
            level: $this->level,
            satisfiedLeaves: $leaves,
            satisfiedBindings: $this->satisfiedBindings,
            credentialPresented: true,
            /*
             * 🛑 **A scoped leaf is reconstructed WITH its scope, or not at
             * all.** §12.3's last conjunct applies a share's or a bearer's
             * narrow scope "if that was the satisfying leaf", and
             * {@see ReaderContext::$scope} being null makes that conjunct pass
             * unconditionally. So a grant minted from a `/v1` share link, if it
             * established `{share}` with no scope, would read `/v2` — the exact
             * disclosure Phase 21 found and fixed in
             * {@see \App\Access\Requirement::satisfyingLeaf()}, arriving by a
             * different road.
             *
             * 🛑 Not reachable in Phase 22: no share link or bearer token
             * exists until P23, so `satisfiedBy` is only ever `binding` or
             * `public`, neither of which carries scope. It is closed **now**
             * because the first scoped driver would otherwise inherit a
             * fail-open conjunct from code that looks finished.
             *
             * The scope is the grant's own (project, version, prefix), which is
             * narrower than or equal to whatever admitted the reader — a grant
             * is minted per version and per surface, so scoping to it cannot
             * widen anything.
             */
            scope: $this->satisfiedBy?->carriesScope() === true
                ? new CredentialScope(
                    projectId: $this->projectId,
                    versionSlugs: [$this->versionSlug],
                    pathPrefixes: $this->pathPrefix === null ? [] : [$this->pathPrefix],
                )
                : null,
            /*
             * 🛑 The subject is the session, keyed and digested by
             * {@see \App\Access\DecisionLog}. §20.3's `subject_hash` is how an
             * allow aggregates "per session, version and hour", so it must be
             * the same value whether the request arrived with a grant or
             * established a fresh one — which it is, because both derive it
             * from this session id.
             */
            subject: $this->sessionId,
        );
    }

    /**
     * 🛑 §8.12.11's "combined policy and identity epoch", as **one orderable
     * scalar**, and the arithmetic is the argument.
     *
     * §8.12.13's Tier C condition is that the edge "refuse any grant **below**
     * the current epoch", which needs an ordering — so two separate claims
     * would make the edge compare two numbers and decide what "below" means
     * for a pair. The sum works, exactly, because both inputs are monotonic
     * non-decreasing counters on the same row:
     *
     * - neither can decrease, so the sum cannot decrease;
     * - a grant's sum is less than the current sum **if and only if** at least
     *   one of the two has moved since it was minted;
     * - and the pairs that collide on a sum — (5, 3) and (3, 5) — are not
     *   reachable from one another, because reaching the second from the first
     *   would require `identity_epoch` to go down.
     *
     * So "below the current combined epoch" is equivalent to "minted before
     * either epoch moved", which is the property §8.12.15 needs and the only
     * one it needs. The edge does not need to know *which* moved; the
     * application's audit trail already records that
     * ({@see Invalidation}).
     *
     * 🛑 This is a **clarification of §8.12.11 proposed in Phase 22**, recorded
     * because the requirement says "combined" without saying how: the obvious
     * reading — two claims — cannot satisfy §8.12.13's single ordering, and the
     * sum can only be justified by the monotonicity argument above. If either
     * counter ever becomes resettable, this breaks silently, which is why
     * `authz_epoch` and `identity_epoch` are both `UNSIGNED BIGINT` with no
     * code path that writes anything but `column + 1`.
     */
    public static function combinedEpoch(int $authzEpoch, int $identityEpoch): int
    {
        return $authzEpoch + $identityEpoch;
    }

    /** Whether this grant is still inside its own lifetime. */
    public function isUnexpired(int $now): bool
    {
        return $now < $this->expiresAt;
    }
}
