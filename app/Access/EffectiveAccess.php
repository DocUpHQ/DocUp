<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;

/**
 * 🛑 **One pure function, the sole call site for every reader access decision**
 * (§12.3, §4.3/7).
 *
 * > ```
 * > decision = DENY unless ALL of:
 * >   project.visibility permits                                (§8.2.10)
 * >   reader_policy first-match rule effect = allow             (§8.12.6)
 * >   project_version.visibility permits                        (§8.6.2)
 * >   domain_mount.mount_exposure permits   — narrow only       (§8.10.1)
 * >   component.min_access_snapshot permits — AFTER mount match (§8.7.7)
 * >   share/bearer scope covers (project, version, path)  if that was the
 * >                                                       satisfying leaf
 * > ```
 *
 * An architecture test asserts that nothing outside this namespace calls it and
 * that nothing anywhere else decides reader access. The argument is the one
 * §8.8.2 makes for `ArtifactIngestor` and §8.3.9 for `HardenedEgressClient`: a
 * second decision is not a duplication bug but an **unenforced** one. It gets
 * written in a hurry, for a download or a search filter or an addons payload,
 * by somebody who did not know this function existed — and it is the one that
 * does not consult the component ceiling, because the person writing it was
 * thinking about versions.
 *
 * ## Three properties, each load-bearing
 *
 * **Pure.** No database, no cache, no clock, no request. `now` is a parameter.
 * That is what makes {@see DecisionTable} able to assert the *entire* matrix —
 * §17's exit criterion asks for 48 combinations "asserted at 100%", and a
 * function reaching for I/O could only be sampled.
 *
 * **Blind to headers.** §8.12.23: "The denial outcome is decided by the
 * request's **authorisation state**, never by its `Accept` or `Sec-Fetch-*`
 * headers." {@see AccessRequest} and {@see ReaderContext} carry no headers, so
 * this is a property of the types rather than of anybody's discipline — and a
 * test greps this file for `Request`, `Accept` and `Sec-Fetch` to keep it that
 * way.
 *
 * **Conjunctive, in §12.3's own order, with a code per conjunct.** The order
 * does not change the allow/deny answer — a conjunction has no order — but it
 * decides *which* refusal is reported, and §8.12.25's simulator and
 * §8.12.22's doctor probe both need that. The one thing evaluated before the
 * conjunction is the reader's established level, because §12.3's
 * `restricted` rung is defined in terms of the rule that names the resource,
 * so the rule has to be matched before `permits` can be asked anything.
 */
final class EffectiveAccess
{
    /**
     * Decide one reader request.
     *
     * 🛑 The single call site. Everything about a reader's access to anything —
     * a page, a download, a search result, an addons payload — is this call.
     */
    public static function decide(AccessRequest $request): AccessDecision
    {
        /*
         * 🛑 §8.12.19, before anything else: "A degraded binding MUST **deny**
         * with a branded 503 naming the binding and linking to its health page
         * — never fall back to another provider, never to public."
         *
         * First because it is the one case where the answer does not depend on
         * the lattice at all: the installation cannot currently establish who
         * anybody is, so every answer it could give about identity would be
         * wrong. 503, not 404 — this is an outage and an operator must be able
         * to tell it from a policy refusal.
         */
        if ($request->bindingDegraded) {
            return self::denied(
                $request,
                AccessReason::BindingDegraded,
                $request->projectVisibility,
                $request->reader->level,
                status: 503,
            );
        }

        /*
         * 🛑 §8.12.21's fail-closed gate, and §10.8 gives it that word: "a
         * project's search MUST be **disabled** while its search generation
         * lags its policy generation".
         *
         * Before the lattice for the same reason: the index is a copy of
         * authorisation facts that are known to be out of date, so no decision
         * made from it can be trusted — including an allow that the live rows
         * would also have produced.
         */
        if ($request->surface->requiresCurrentSearchGeneration()
            && $request->searchGeneration < $request->policyGeneration) {
            return self::denied(
                $request,
                AccessReason::SearchGenerationStale,
                $request->projectVisibility,
                $request->reader->level,
            );
        }

        /*
         * §12.3's second conjunct, evaluated first because the rest needs its
         * answer. Matching is not satisfaction: the first rule whose selectors
         * match is *the* rule, and if its requirement is unsatisfied the answer
         * is deny — evaluation does not continue looking for a kinder rule
         * (§8.12.6, and the note on {@see PolicyRule::matches()}).
         */
        $rule = $request->policy->firstMatch(
            $request->versionSlug,
            $request->language,
            $request->path,
            $request->now,
        );

        $shadow = $request->policy->shadowMatch(
            $request->versionSlug,
            $request->language,
            $request->path,
            $request->now,
        );

        $satisfied = false;
        $satisfiedBy = null;
        $established = $request->reader->level;
        $publicCacheMode = false;

        /*
         * One narrowing, four consequences. Written as a block rather than as
         * four conditional expressions because every one of them is about the
         * same fact — the matched rule admits this reader — and three of them
         * had `$rule !== null` repeated in them before, which is noise around
         * the only interesting condition.
         */
        if ($rule !== null && $rule->allow && $rule->requirement->satisfiedBy($request->reader)) {
            $satisfied = true;
            $satisfiedBy = $rule->requirement->satisfyingLeaf($request->reader);
            $publicCacheMode = $rule->publicCacheMode;

            /*
             * 🛑 §12.3's `restricted` rung, established here and nowhere else:
             * "only a reader satisfying an explicit allow rule naming this
             * component or version".
             *
             * This is what makes the fourth level mean something different
             * from `members`. A reader with the strongest possible identity
             * does not reach a `restricted` resource on identity alone — a
             * rule has to name it. So `restricted` is the level an operator
             * uses for the one directory that must be listed explicitly, and a
             * policy written with wildcards cannot reach it by accident.
             */
            if ($rule->namesResourceExplicitly()) {
                $established = AccessLevel::Restricted;
            }
        }

        // The strongest demand any applicable column makes, for the record and
        // for the decision header. Computed over all four because §12.3 makes
        // all four authoritative, and reported even when an earlier conjunct is
        // the one that refused.
        $required = self::strongestDemand($request);

        /*
         * 🛑 §8.12.20's break-glass read override.
         *
         * > "An installation-owner **break-glass** read override MUST exist
         * > behind MFA, step-up re-authentication and a mandatory reason,
         * > rate-limited to 3/hour, raising an operator alert and audited."
         *
         * Every one of those preconditions is {@see BreakGlass}'s; by the time
         * the grant reaches this function it has been opened, audited and
         * alerted, and all that is left is to honour it. So this is three lines
         * and the position of them is the interesting part.
         *
         * 🛑 **After** §8.12.19's degraded binding and §8.12.21's stale
         * search generation, which are therefore NOT overridable — and that is
         * deliberate rather than incidental. Neither is a policy refusal: one is
         * an outage, where the installation cannot establish who anybody is and
         * every answer about identity would be wrong, and the other is a
         * known-stale copy of authorisation facts, where an allow would be
         * served from data the live rows have already contradicted. There is
         * nothing there for an owner to override, and an override that worked
         * through them would turn "I cannot tell" into "yes".
         *
         * 🛑 **After the rule match**, so the decision can report which rule
         * *would* have decided. An operator reviewing a window wants "break-glass,
         * over rule 7" rather than "break-glass"; and {@see AccessDecision::header()}
         * gives them that for free.
         *
         * 🛑 **Before** §12.3's conjunction, which is the only placement
         * that makes the override mean anything: the lattice is exactly what the
         * owner is overriding.
         *
         * 🛑 And `rulePubliclyCacheable` is **false**, unconditionally.
         * §9.3.2 forbids a public cache directive on private content, and an
         * override's allow is the most private response this system produces —
         * a single cached copy would serve, to everybody, a document one person
         * was briefly permitted to read. The parameter is defaulted false, and
         * it is named here anyway so that nobody has to check the default.
         */
        if ($request->reader->breakGlassId !== null) {
            return new AccessDecision(
                allowed: true,
                reason: AccessReason::BreakGlass,
                status: 200,
                required: $required,
                /*
                 * 🛑 `Restricted`, because that is what the override confers
                 * and reporting the reader's own level would understate it. The
                 * decision log's "established" column answers "how much access
                 * did this request actually have", and an override has all of
                 * it.
                 */
                established: AccessLevel::Restricted,
                rule: $rule,
                /*
                 * 🛑 No satisfying leaf, and there must not be one: no
                 * credential admitted this request. Naming a leaf would record
                 * the override as though an identity had satisfied a
                 * requirement, which is the one thing §8.12.7's satisfiability
                 * invariant is about.
                 */
                satisfiedBy: null,
                rulePubliclyCacheable: false,
                shadowRule: $shadow,
            );
        }

        // ---- §12.3's conjunction, in §12.3's order ----

        // 1. project.visibility permits (§8.2.10) — the operator kill switch.
        if (! $request->projectVisibility->permittedBy($established)) {
            return self::denied($request, AccessReason::ProjectVisibility, $required, $established, $rule, $shadow);
        }

        // 2. reader_policy first-match rule effect = allow (§8.12.6).
        if ($request->policy->isEmpty()) {
            // 🛑 §8.12.19's zero-rule policy. Distinct from "no rule matched":
            // nobody has written a rule, which is a configuration state an
            // operator must be told about rather than a selector mistake.
            return self::denied($request, AccessReason::PolicyEmpty, $required, $established, null, $shadow);
        }

        if ($request->policy->exists) {
            if ($rule === null) {
                // §8.12.6's "policy default effect **deny**".
                return self::denied($request, AccessReason::PolicyDefaultDeny, $required, $established, null, $shadow);
            }

            if (! $rule->allow) {
                return self::denied($request, AccessReason::RuleDenied, $required, $established, $rule, $shadow);
            }

            if (! $satisfied) {
                return self::denied($request, AccessReason::RequirementUnsatisfied, $required, $established, $rule, $shadow);
            }
        }

        // 3. project_version.visibility permits (§8.6.2).
        if (! $request->versionVisibility->permittedBy($established)) {
            return self::denied($request, AccessReason::VersionVisibility, $required, $established, $rule, $shadow);
        }

        // 4. domain_mount.mount_exposure permits — narrow only, never widens.
        if (! $request->resolvedMountExposure()->permittedBy($established)) {
            return self::denied($request, AccessReason::MountExposure, $required, $established, $rule, $shadow);
        }

        /*
         * 5. component.min_access_snapshot permits — §8.7.7, re-checked AFTER
         * mount matching, which is why it is the fifth conjunct and not folded
         * into the others: the caller does not know which component answers a
         * path until the mount has matched, so this value arrives later than
         * the rest and the ordering in §12.3 reflects a real sequence.
         */
        if ($request->componentMinAccess !== null
            && ! $request->componentMinAccess->permittedBy($established)) {
            return self::denied($request, AccessReason::ComponentMinAccess, $required, $established, $rule, $shadow);
        }

        /*
         * 6. share/bearer scope covers (project, version, path) — **if that was
         * the satisfying leaf**. §12.3's conditional, honoured literally: a
         * member who also happens to hold a share link is judged on the
         * stronger leaf, so the link's narrow scope is not applied to somebody
         * who did not need it.
         */
        if ($satisfiedBy !== null && $satisfiedBy->carriesScope()) {
            /*
             * 🛑 `scopeFor($satisfiedBy)`, not `->scope`. Phase 23 made it
             * possible for one reader to present two scoped credentials — a
             * share link and a bearer token — and §12.3's conditional is on the
             * **satisfying** leaf, so the scope has to be looked up by it. The
             * single field read a scope the transport happened to store, which
             * for a reader holding a wide link and a narrow token judged them
             * on the link while the rule named the token.
             */
            $scope = $request->reader->scopeFor($satisfiedBy);

            if ($scope === null
                || ! $scope->covers($request->projectId, $request->versionSlug, $request->path)) {
                return self::denied($request, AccessReason::ScopeMismatch, $required, $established, $rule, $shadow);
            }
        }

        return new AccessDecision(
            allowed: true,
            reason: AccessReason::Allowed,
            status: 200,
            required: $required,
            established: $established,
            rule: $rule,
            /*
             * 🛑 No rule matched, so no requirement decided this — the lattice
             * did, on the reader's established level. What admitted them is
             * therefore the strongest leaf they actually hold, which is
             * `public` for an anonymous reader and `binding` for a member.
             *
             * 🛑 This used to read `AccessLeaf::Public` unconditionally, and it
             * was correct for as long as every reader was anonymous — Phase 21
             * could construct no other kind. {@see ReaderContext::strongestLeaf()}
             * records what it started reporting the moment Phase 22 gave a
             * member a session.
             */
            satisfiedBy: $satisfiedBy ?? ($request->policy->exists ? null : $request->reader->strongestLeaf()),
            /*
             * 🛑 §9.3.2's third input, and **two** conditions rather than one.
             *
             * The admitting rule must permit public caching — and a rule may
             * only permit it when its requirement is literally the public
             * terminal, refused at write time otherwise
             * ({@see ReaderPolicies::assertRuleStorable()}). A project with no
             * policy row permits it by default, which is how every public
             * project built before this phase keeps its edge caching.
             *
             * 🛑 **And the resource itself must demand nothing above
             * `public`.** The first version of this left that to
             * `CachePolicy`, whose three-way check would indeed have caught it
             * — the generated decision table is what found the difference:
             * case 33, a member reading a private version, reported
             * `rulePubliclyCacheable: true` on a decision about a resource at
             * `members`. The response was still private, because `CachePolicy`
             * intersects. But §9.3.2's own argument is that "private is the
             * default rather than the exception — so a fourth input added
             * later that somebody forgets to wire in makes responses private,
             * not public", and a field that reads `true` about a private
             * resource is a trap for the next caller. §8.12.21's derived
             * surfaces read the decision directly and never pass through
             * `CachePolicy` at all.
             */
            rulePubliclyCacheable: $required === AccessLevel::Public
                && (! $request->policy->exists || $publicCacheMode),
            shadowRule: $shadow,
        );
    }

    /**
     * The strongest level any of §12.3's four columns demands.
     *
     * 🛑 §8.12.8's intersection, on the read side: "Effective access … MUST be
     * the intersection of every applicable policy." On an ordered scale an
     * intersection of demands is the **maximum**, because a higher order is a
     * stronger demand — so `narrows()` picks the winner and nothing can widen
     * by being evaluated later.
     */
    private static function strongestDemand(AccessRequest $request): AccessLevel
    {
        $strongest = $request->projectVisibility;

        foreach ([
            $request->versionVisibility,
            $request->resolvedMountExposure(),
            $request->componentMinAccess,
        ] as $level) {
            if ($level !== null && $level->narrows($strongest)) {
                $strongest = $level;
            }
        }

        return $strongest;
    }

    /**
     * Build a denial, applying §8.12.23's and §8.12.24's status rules.
     *
     * One place, because the three rules interact and each of the three is a
     * 🛑 requirement. Spread across six return statements they would be six
     * chances to get the 403 condition wrong.
     */
    private static function denied(
        AccessRequest $request,
        AccessReason $reason,
        AccessLevel $required,
        AccessLevel $established,
        ?PolicyRule $rule = null,
        ?PolicyRule $shadow = null,
        ?int $status = null,
    ): AccessDecision {
        if ($status !== null) {
            return new AccessDecision(
                allowed: false,
                reason: $reason,
                status: $status,
                required: $required,
                established: $established,
                rule: $rule,
                shadowRule: $shadow,
            );
        }

        /*
         * 🛑 §8.12.23 permits a 401 in exactly two cases, and this is both of
         * them and nothing else:
         *
         * > "(a) a credential was presented and rejected — an expired, revoked
         * > or out-of-scope grant, bearer token or share cookie; or (b) the
         * > resource's **existence is already public**, because the project
         * > appears in the visibility-filtered index of §8.2.7, and only its
         * > content requires authentication."
         *
         * Case (b) is conditioned on the project's *existence* being public
         * rather than on the project being public — a public project with a
         * private version has public existence, and challenging for it
         * discloses nothing a reader could not already see in the index.
         */
        $challenge = $request->reader->credentialRejected
            || ($request->existencePublic && ! $request->reader->isAuthenticated());

        if ($challenge) {
            return new AccessDecision(
                allowed: false,
                reason: $request->reader->credentialRejected
                    ? AccessReason::CredentialRejected
                    : AccessReason::AuthenticationRequired,
                status: 401,
                required: $required,
                established: $established,
                rule: $rule,
                challenge: true,
                shadowRule: $shadow,
            );
        }

        /*
         * 🛑 §8.12.23's `deny_status`, with its authenticated-only constraint:
         * "A per-project `deny_status='403'` MUST be available for
         * **authenticated** principals only, never anonymous, because the leak
         * register, audit reason codes and edge cacheability all key off this
         * distinction."
         *
         * So an anonymous reader gets 404 whatever the project configured. A
         * 403 to an anonymous request is a confirmation that the resource
         * exists, which is the one thing §8.2.2 and §8.2.7 are both built to
         * withhold — and the project's own preference is not permitted to
         * override it, because the project does not bear the consequence.
         */
        $status = $request->denyStatus === 403 && $request->reader->isAuthenticated() ? 403 : 404;

        return new AccessDecision(
            allowed: false,
            reason: $reason,
            status: $status,
            required: $required,
            established: $established,
            rule: $rule,
            shadowRule: $shadow,
        );
    }
}
