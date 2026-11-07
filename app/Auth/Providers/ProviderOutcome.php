<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\AccessLeaf;
use App\Access\CredentialScope;
use App\Access\ReaderContext;
use App\Auth\AccessLevel;

/**
 * 🛑 Every binding's evidence, merged into **one** {@see ReaderContext}.
 *
 * This is the only place driver results become a decision input, and the merge
 * rules are the interesting part — each one is a question that has a wrong
 * answer a reasonable person would give.
 *
 * ## 🛑 A degraded binding wins over everything
 *
 * §8.12.19: "A degraded binding MUST **deny** with a branded 503 naming the
 * binding and linking to its health page — never fall back to another provider,
 * never to public."
 *
 * So `degraded` is checked before anything is merged, and it short-circuits.
 * The tempting alternative — merge what the healthy bindings said and let the
 * decision function sort it out — is exactly the "fall back to another
 * provider" the requirement forbids: a project with an IdP and an
 * `ip_allowlist` would quietly keep serving to the office network while its IdP
 * was down, which is a privacy posture nobody chose.
 *
 * ## 🛑 The level is the strongest identity, and a gate cannot raise it
 *
 * §12.3: `authenticated` is "any reader who satisfied any identity leaf of any
 * binding in scope". A `{gate}` is not an identity ({@see AccessLeaf::bearsIdentity()}),
 * so satisfying an `ip_allowlist` leaves a reader at `public` — which is the
 * whole of why §8.12.7 refuses a requirement that rests on one.
 *
 * `members` is not reachable from a driver at all: §12.3 defines it as "an
 * identity mapping to a role assignment or group on this organisation", and
 * only the portal session knows that. `App\Readers\ReaderSessions` decides it
 * and this class takes it as the floor.
 */
final readonly class ProviderOutcome
{
    /**
     * @param  list<AccessLeaf>  $leaves
     * @param  list<string>  $bindings  binding ids satisfied, raw 16 bytes
     * @param  array<string, CredentialScope>  $scopes  keyed by leaf value
     * @param  list<string>  $credentialIds  raw 16 bytes, for a use count
     */
    private function __construct(
        public bool $degraded,
        public ?string $degradedBinding,
        public array $leaves,
        public array $bindings,
        public array $scopes,
        public ?string $subject,
        public bool $credentialPresented,
        public bool $credentialRejected,
        public array $credentialIds,
    ) {}

    /**
     * Merge the attempts of every binding in scope.
     *
     * @param  list<array{binding: BindingContext, result: AttemptResult}>  $attempts
     */
    public static function merge(array $attempts, bool $credentialPresented): self
    {
        /*
         * 🛑 First pass: a single degraded binding stops everything. §8.12.19
         * again — and it is a separate pass rather than a flag set during the
         * merge so that the short-circuit cannot be reordered away by a later
         * edit to the loop below.
         */
        foreach ($attempts as $attempt) {
            if ($attempt['result']->degraded) {
                return new self(
                    degraded: true,
                    degradedBinding: $attempt['binding']->name,
                    leaves: [],
                    bindings: [],
                    scopes: [],
                    subject: null,
                    credentialPresented: $credentialPresented,
                    credentialRejected: false,
                    credentialIds: [],
                );
            }
        }

        $leaves = [AccessLeaf::Public];
        $bindings = [];
        $scopes = [];
        $credentialIds = [];

        /** @var array<string, string> $subjects keyed by leaf value */
        $subjects = [];
        $subject = null;
        $rejected = false;

        foreach ($attempts as $attempt) {
            $result = $attempt['result'];

            /*
             * 🛑 A rejection from **any** binding counts, even when another
             * binding satisfied. §8.12.23's case (a) is about whether a
             * credential was presented and refused, and a reader whose share
             * link expired should be challenged about it rather than silently
             * admitted by an `ip_allowlist` and left wondering why their link
             * does nothing.
             */
            if ($result->credentialRejected) {
                $rejected = true;
            }

            if (! $result->satisfied || $result->leaf === null) {
                continue;
            }

            if (! in_array($result->leaf, $leaves, true)) {
                $leaves[] = $result->leaf;
            }

            /*
             * 🛑 The binding id is recorded **only for an identity leaf**. §12.3
             * lets a rule name a binding, and `ReaderContext::satisfies()`
             * checks the id — so recording a gate's binding would let a rule
             * written as "binding X" be satisfied by being on a network.
             */
            if ($result->leaf->bearsIdentity()) {
                $bindings[] = $attempt['binding']->id;
            }

            if ($result->scope !== null) {
                /*
                 * 🛑 Keyed by leaf, and the **first** scope for a leaf wins.
                 *
                 * Two share links both satisfying is possible — a reader with
                 * one in a cookie and another in a query string — and taking
                 * the first is arbitrary. What makes it safe is that the scope
                 * is a narrowing conjunct applied after §12.3 has admitted the
                 * reader: an arbitrary choice between two scopes can only ever
                 * be as wide as the rule, never wider.
                 */
                $scopes[$result->leaf->value] ??= $result->scope;
            }

            if ($result->credentialId !== null) {
                $credentialIds[] = $result->credentialId;
            }

            if ($result->subject !== null) {
                /*
                 * Collected per leaf and resolved after the loop — see below.
                 * Ranking inside the loop would depend on the order the
                 * bindings happened to resolve in.
                 */
                $subjects[$result->leaf->value] ??= $result->subject;
            }
        }

        /*
         * 🛑 The subject is the **strongest** satisfying leaf's, by the one
         * ordering in {@see AccessLeaf::strongestFirst()} — the same ordering
         * `Requirement::satisfyingLeaf()` uses, so the subject §20.3's log
         * aggregates on is the one §12.3 will say admitted the reader.
         *
         * A reader who signed in and also happens to hold a share link should
         * aggregate as the person, not as the link.
         */
        foreach (AccessLeaf::strongestFirst() as $candidate) {
            if (isset($subjects[$candidate->value])) {
                $subject = $subjects[$candidate->value];
                break;
            }
        }

        return new self(
            degraded: false,
            degradedBinding: null,
            leaves: $leaves,
            bindings: $bindings,
            scopes: $scopes,
            subject: $subject,
            credentialPresented: $credentialPresented,
            credentialRejected: $rejected,
            credentialIds: $credentialIds,
        );
    }

    /** Nothing in scope, which is a project with no bindings at all. */
    public static function none(): self
    {
        return new self(
            degraded: false,
            degradedBinding: null,
            leaves: [AccessLeaf::Public],
            bindings: [],
            scopes: [],
            subject: null,
            credentialPresented: false,
            credentialRejected: false,
            credentialIds: [],
        );
    }

    /**
     * The decision input §12.3 reads, **unioned with the session's own**.
     *
     * 🛑 **The union is the correction, and Phase 22's tests found it.**
     *
     * The first version used the session only for its `level` and took every
     * leaf from the drivers. That silently removed Phase 22's own mechanism: a
     * dashboard member reading a `members` version on a project with **no
     * bindings configured** satisfied `{binding}` in P22, and under the first
     * version of this method satisfied only `{public}` — so the decision header
     * read `by=public` on a response no anonymous reader could obtain, and a
     * rule written as `{binding}` would have refused the project's own members.
     *
     * §17 is explicit that this must keep working: P21's note says "readers are
     * members or anonymous only", and P23's own goal is "Useful private
     * documentation with **no IdP at all**". A reader session is the
     * installation's own mechanism, not a configured provider — §8.12.17 names
     * the `portal_session` *driver* so a rule can name it specifically, which
     * is an addition to the session's standing rather than a precondition for
     * it.
     *
     * So the session's leaves and bindings are unioned in, and the drivers add
     * theirs on top.
     *
     * @param  ReaderContext|null  $session  what the reader's session
     *                                       established, or null for a reader
     *                                       with none
     */
    public function toReaderContext(?ReaderContext $session = null): ReaderContext
    {
        $leaves = $this->leaves;
        $bindings = $this->bindings;

        /*
         * Narrowed once rather than `?->` at four call sites, which Larastan
         * flags as a nullsafe on a non-nullable property — and which reads as
         * four independent guards against one condition.
         */
        if ($session !== null) {
            foreach ($session->satisfiedLeaves as $leaf) {
                if (! in_array($leaf, $leaves, true)) {
                    $leaves[] = $leaf;
                }
            }

            foreach ($session->satisfiedBindings as $binding) {
                if (! in_array($binding, $bindings, true)) {
                    $bindings[] = $binding;
                }
            }
        }

        /*
         * 🛑 `authenticated` only from an identity leaf. A `{gate}` is not an
         * identity, so an `ip_allowlist` reader stays `public` — the fact
         * §8.12.7's whole invariant is built on.
         */
        $identity = false;

        foreach ($leaves as $leaf) {
            if ($leaf->bearsIdentity()) {
                $identity = true;
                break;
            }
        }

        /*
         * The session's level is the floor, because `members` is the one rung
         * no driver can reach: §12.3 defines it as an identity mapping to a
         * role assignment on this organisation, and only the portal session
         * knows that.
         */
        $floor = $session === null ? AccessLevel::Public : $session->level;
        $level = $floor;

        if ($identity && $floor->order() < AccessLevel::Authenticated->order()) {
            $level = AccessLevel::Authenticated;
        }

        return new ReaderContext(
            level: $level,
            satisfiedLeaves: $leaves,
            satisfiedBindings: $bindings,
            /*
             * 🛑 A session is a presented credential. P22 set this true for a
             * session-established reader, and dropping it here would change
             * which responses §8.12.23 permits a challenge on.
             */
            credentialPresented: $this->credentialPresented || $session !== null,
            credentialRejected: $this->credentialRejected,
            /*
             * The single-scope field stays null: with per-leaf scopes there is
             * no "the" scope, and leaving it set would give
             * {@see ReaderContext::scopeFor()} a fallback that could apply one
             * credential's scope to another's leaf.
             */
            scope: null,
            /*
             * 🛑 The session's subject wins when there is one. §20.3 aggregates
             * an allow "per session, version and hour", so a reader who signed
             * in must aggregate as that session however many credentials they
             * also happen to hold.
             */
            subject: $session !== null && $session->subject !== null ? $session->subject : $this->subject,
            scopes: $this->scopes,
        );
    }
}
