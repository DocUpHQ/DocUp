<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.12.22's nightly policy linter.
 *
 * > "a nightly policy linter that re-validates every active rule and **alerts
 * > on reachability changes**"
 *
 * ## 🛑 What re-validation catches that write-time validation cannot
 *
 * {@see ReaderPolicies::addRule()} already refuses a malformed requirement, a
 * regex path pattern, an unsatisfiable tree (§8.12.7) and a binding named as
 * the wrong leaf kind (§8.12.17). Everything it checks is a property of the
 * rule, and every one of those checks is still true tomorrow.
 *
 * What is **not** a property of the rule is the world the rule points at. A
 * binding gets deleted, moves out of §8.12.3's scope, drops out of `active`, or
 * has its driver type changed. The rule is then still valid, still matches, and
 * still consumes §8.12.6's first-match slot — and can no longer be satisfied by
 * anybody. The project refuses every reader with `requirement_unsatisfied`, and
 * the cause is in a different table.
 *
 * That is the class of failure this exists for, and it is the reason §8.12.22
 * says *nightly* rather than *on write*.
 *
 * ## 🛑 Reachability is a selector computation, and that is exact
 *
 * §8.12.6 is first-match-wins on **selectors only** — see
 * {@see PolicyRule::matches()}, which reads the version, language, path and
 * time window and never the requirement. So rule B is unreachable exactly when
 * some earlier rule A of the same class selects every URL B selects, within
 * every instant B is live. No search over URLs is needed and none is done: the
 * answer is a containment test over four finite axes, so the linter cannot
 * report a false shadow and cannot miss a real one.
 *
 * "Of the same class" matters: {@see ReaderPolicy::firstMatch()} skips shadow
 * rules entirely, so an enforced rule never shadows a shadow rule and the
 * reverse. Computing one ordering over both would report every shadow rule as
 * shadowing the enforced rules behind it — an alert on every policy that uses
 * the feature.
 *
 * ## 🛑 Direction, not just difference
 *
 * §8.12.22 asks for an alert on change; §17's exit criterion asks that "a
 * planted widening edit is caught". Those are different, and the difference is
 * the useful part: a rule that narrowed too far produces a support ticket from
 * somebody who cannot read their own documentation, and a rule that widened too
 * far produces nothing at all.
 *
 * So each change carries a direction, and where the direction cannot be
 * **established** it is reported as {@see PolicyFinding::Changed} rather than
 * guessed. The exactness is bought by evaluating the requirement tree over the
 * power set of the credential tokens either version names — a handful of
 * tokens, so a few dozen evaluations — through
 * {@see Requirement::satisfiedBy()}, the real evaluator. Past
 * {@see self::MAX_PROBE_TOKENS} the power set is abandoned and the direction is
 * unknown, which is a worse answer and never a wrong one.
 *
 * 🛑 This class builds {@see ReaderContext}s, and {@see PolicySimulator}
 * deliberately does not. The two are different jobs: the simulator answers
 * "what would *this reader* get", where an invented context is an answer about
 * a reader who cannot exist; the linter asks "what does this *tree* admit",
 * where a probe context is the only way to ask and the tree's own evaluator is
 * what answers.
 */
final readonly class PolicyLinter
{
    /**
     * The ceiling on the requirement power set: 2^10 evaluations of a tree
     * §8.12.6 caps at 16 leaves anyway.
     *
     * 🛑 A ceiling rather than a time budget, for the reason §8.11.4 gives
     * about the redirect evaluation cap: "a time-budget cap that silently skips
     * rules under load makes behaviour nondeterministic, which is worse than a
     * fixed cap". A linter whose findings depended on how busy the host was
     * would alert differently on different nights for no reason.
     */
    public const int MAX_PROBE_TOKENS = 10;

    public function __construct(
        private ReaderPolicies $policies,
        private Bindings $bindings,
        private OrganisationContext $context,
    ) {}

    /**
     * Lint one project's policy and record what was observed.
     *
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $organisationId  raw 16 bytes
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return list<PolicyObservation> one per rule, in policy order
     */
    public function lint(
        string $projectId,
        string $organisationId,
        int $authzEpoch,
        ?int $now = null,
    ): array {
        $now ??= time();

        $policy = $this->policies->forProject($projectId, $authzEpoch);

        if ($policy->rules === []) {
            return [];
        }

        $bindings = $this->bindingFacts($projectId, $organisationId, $authzEpoch);
        $previous = $this->previousFor($policy->rules);

        $observations = [];

        foreach ($policy->rules as $index => $rule) {
            $static = $this->staticFindings($rule, $policy->rules, $index, $bindings, $now);
            $breadth = $this->breadthOf($rule);

            $shadowedBy = $this->shadowedBy($rule, $policy->rules, $index);

            $observation = new PolicyObservation(
                ruleId: (string) $rule->id,
                position: $rule->position,
                label: $rule->label,
                /*
                 * 🛑 Reachable means "could decide a request", which a shadow
                 * rule deliberately cannot and an expired one can no longer.
                 * The three causes are kept apart in the findings; this is the
                 * one bit §8.12.22 names.
                 */
                reachable: $shadowedBy === null
                    && ! in_array(PolicyFinding::Expired, $static, true)
                    && ! $rule->shadow,
                shadowedBy: $shadowedBy,
                findings: $static,
                breadth: $breadth,
                fingerprint: self::fingerprintOf($rule->position, $shadowedBy, $static, $breadth),
                changes: [],
            );

            $observation = $observation->withChanges(
                $this->changesSince($previous[(string) $rule->id] ?? null, $observation, $rule),
            );

            $observations[] = $observation;
        }

        $this->store($observations, $projectId, $organisationId, $now);

        return $observations;
    }

    // ------------------------------------------------------- static findings

    /**
     * Everything wrong with one rule as it stands tonight.
     *
     * @param  list<PolicyRule>  $rules
     * @param  array<string, array{type: string, usable: bool}>  $bindings
     * @return list<PolicyFinding>
     */
    private function staticFindings(
        PolicyRule $rule,
        array $rules,
        int $index,
        array $bindings,
        int $now,
    ): array {
        $findings = [];

        if ($this->shadowedBy($rule, $rules, $index) !== null) {
            $findings[] = PolicyFinding::Shadowed;
        }

        if ($rule->notAfter !== null && $now >= $rule->notAfter) {
            $findings[] = PolicyFinding::Expired;
        }

        if ($rule->notBefore !== null && $now < $rule->notBefore) {
            $findings[] = PolicyFinding::NotYetActive;
        }

        /*
         * 🛑 The world the rule points at, which write-time validation checked
         * against a world that has since changed.
         */
        $broken = [];

        foreach ($rule->requirement->bindingLeaves() as $pair) {
            $fact = $bindings[$pair['binding_id']] ?? null;

            if ($fact === null) {
                $findings[] = PolicyFinding::BindingMissing;
                $broken[] = $pair;

                continue;
            }

            if (AccessLeaf::forDriver($fact['type']) !== $pair['leaf']) {
                /*
                 * §8.12.17's classification, re-checked. Refused at write time,
                 * so reaching here means the binding's driver type changed
                 * under a rule that was valid when it was written — and the
                 * mismatch is two tables apart from the symptom.
                 */
                $findings[] = PolicyFinding::BindingMisclassified;
                $broken[] = $pair;

                continue;
            }

            if (! $fact['usable']) {
                $findings[] = PolicyFinding::BindingNotActive;
                $broken[] = $pair;
            }
        }

        /*
         * 🛑 Computed, not concluded. A tree may name a dead binding in one
         * branch of an `OR` and remain perfectly satisfiable through the other
         * — reporting that as unsatisfiable would send an operator to fix a
         * rule that works.
         *
         * Only for an `allow` rule: §8.12.6 never evaluates a deny rule's
         * requirement at all (see {@see EffectiveAccess}), so a deny rule with
         * an unsatisfiable tree denies exactly as its author intended.
         */
        if ($broken !== [] && $rule->allow && ! $this->isSatisfiable($rule->requirement, $broken)) {
            $findings[] = PolicyFinding::RequirementUnsatisfiable;
        }

        return array_values(array_unique($findings, SORT_REGULAR));
    }

    /**
     * The position of the earliest rule that makes this one unreachable, or
     * null.
     *
     * @param  list<PolicyRule>  $rules
     */
    private function shadowedBy(PolicyRule $rule, array $rules, int $index): ?int
    {
        foreach ($rules as $earlier => $candidate) {
            if ($earlier >= $index) {
                break;
            }

            /*
             * 🛑 Same class only. {@see ReaderPolicy::firstMatch()} skips
             * shadow rules and {@see ReaderPolicy::shadowMatch()} considers
             * only them, so the two populations never compete — and one
             * ordering over both would report every shadow rule as shadowing
             * the enforced rules behind it.
             */
            if ($candidate->shadow !== $rule->shadow) {
                continue;
            }

            if (self::covers($candidate, $rule)) {
                return $candidate->position;
            }
        }

        return null;
    }

    /**
     * 🛑 Whether every request `$inner` selects, `$outer` also selects.
     *
     * Four axes, each a containment test, and the empty list means "all" on
     * three of them — which is the direction that makes an off-by-one here a
     * false *absence* of an alert rather than a false one. Written as explicit
     * cases rather than set arithmetic because "empty means everything" is
     * exactly the convention a clever one-liner gets backwards.
     */
    private static function covers(PolicyRule $outer, PolicyRule $inner): bool
    {
        if (! self::axisCovers($outer->versionSlugs, $inner->versionSlugs)) {
            return false;
        }

        if (! self::axisCovers($outer->languages, $inner->languages)) {
            return false;
        }

        if (! self::pathsCover($outer->pathPrefixes, $inner->pathPrefixes)) {
            return false;
        }

        /*
         * 🛑 And the time window, or a rule live all year would be reported as
         * shadowed by one live for a single week. §12.3's `not_before` and
         * `not_after` are part of matching, so they are part of coverage.
         */
        return self::windowCovers($outer, $inner);
    }

    /**
     * @param  list<string>  $outer
     * @param  list<string>  $inner
     */
    private static function axisCovers(array $outer, array $inner): bool
    {
        if ($outer === []) {
            return true;    // the outer rule selects every value on this axis
        }

        if ($inner === []) {
            return false;   // the inner selects every value and the outer does not
        }

        foreach ($inner as $value) {
            if (! in_array($value, $outer, true)) {
                return false;
            }
        }

        return true;
    }

    /**
     * @param  list<string>  $outer
     * @param  list<string>  $inner
     */
    private static function pathsCover(array $outer, array $inner): bool
    {
        if ($outer === []) {
            return true;
        }

        if ($inner === []) {
            return false;
        }

        foreach ($inner as $path) {
            $covered = false;

            foreach ($outer as $prefix) {
                /*
                 * 🛑 Through {@see PathPrefix::covers()}, which owns the
                 * boundary rule — `/internal` covers `/internal/x` and not
                 * `/internal-notes`. A `str_starts_with` here would be the
                 * off-by-one that rule exists to prevent, in a second place.
                 */
                if (PathPrefix::covers($prefix, rtrim($path, '/').'/')) {
                    $covered = true;

                    break;
                }
            }

            if (! $covered) {
                return false;
            }
        }

        return true;
    }

    private static function windowCovers(PolicyRule $outer, PolicyRule $inner): bool
    {
        /* The outer must start no later than the inner. */
        if ($outer->notBefore !== null && ($inner->notBefore === null || $inner->notBefore < $outer->notBefore)) {
            return false;
        }

        /* And end no earlier. */
        if ($outer->notAfter !== null && ($inner->notAfter === null || $inner->notAfter > $outer->notAfter)) {
            return false;
        }

        return true;
    }

    // ---------------------------------------------------------- satisfiability

    /**
     * Whether any combination of credentials could satisfy this tree, given
     * that the named pairs cannot be.
     *
     * 🛑 Through {@see Requirement::satisfiedBy()} — the real evaluator — with
     * probe contexts standing in for readers. Re-implementing the tree walk
     * here would be a second opinion about `AND`, `OR` and `NOT` that disagrees
     * on the first nested tree somebody writes.
     *
     * @param  list<array{leaf: AccessLeaf, binding_id: string}>  $broken
     */
    private function isSatisfiable(Requirement $requirement, array $broken): bool
    {
        foreach ($this->probeContexts($requirement, $broken) as $context) {
            if ($requirement->satisfiedBy($context)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every reader shape worth trying against this tree.
     *
     * The tokens are the (leaf, binding) pairs the tree names plus its bare
     * leaf kinds; a reader either holds a token or does not, so the power set
     * over them is the complete space as far as this tree can tell. 🛑 The
     * broken pairs are **excluded from every context**, which is what makes
     * "unsatisfiable" mean "unsatisfiable *now*" rather than "badly written".
     *
     * @param  list<array{leaf: AccessLeaf, binding_id: string}>  $broken
     * @return list<ReaderContext>
     */
    private function probeContexts(Requirement $requirement, array $broken): array
    {
        $deadBindings = array_map(static fn (array $pair): string => $pair['binding_id'], $broken);

        /** @var list<array{leaf: AccessLeaf, binding: string|null}> $tokens */
        $tokens = [];

        foreach ($requirement->bindingLeaves() as $pair) {
            if (in_array($pair['binding_id'], $deadBindings, true)) {
                continue;   // the reader cannot hold it, so it is not a variable
            }

            $tokens[] = ['leaf' => $pair['leaf'], 'binding' => $pair['binding_id']];
        }

        foreach ($requirement->leafKinds() as $leaf) {
            if ($leaf === AccessLeaf::Public) {
                continue;   // everybody holds it; see ReaderContext::satisfies()
            }

            $tokens[] = ['leaf' => $leaf, 'binding' => null];
        }

        if (count($tokens) > self::MAX_PROBE_TOKENS) {
            /*
             * 🛑 Over the ceiling, answer "satisfiable" — the direction that
             * raises no alert. A linter that reported a rule broken because its
             * tree was large would be a linter that cried wolf about the most
             * carefully-written policy on the installation.
             */
            return [];
        }

        $contexts = [];
        $combinations = 1 << count($tokens);

        for ($mask = 0; $mask < $combinations; $mask++) {
            $leaves = [AccessLeaf::Public];
            $heldBindings = [];

            foreach ($tokens as $bit => $token) {
                if (($mask & (1 << $bit)) === 0) {
                    continue;
                }

                if (! in_array($token['leaf'], $leaves, true)) {
                    $leaves[] = $token['leaf'];
                }

                if ($token['binding'] !== null) {
                    $heldBindings[] = $token['binding'];
                }
            }

            $contexts[] = new ReaderContext(
                satisfiedLeaves: $leaves,
                satisfiedBindings: array_values(array_unique($heldBindings)),
            );
        }

        return $contexts;
    }

    // ------------------------------------------------------------ comparison

    /**
     * What changed about this rule since the last run, and in which direction.
     *
     * @return list<PolicyFinding>
     */
    private function changesSince(?PolicyObservation $before, PolicyObservation $now, PolicyRule $rule): array
    {
        if ($before === null) {
            return [PolicyFinding::New];
        }

        if (hash_equals($before->fingerprint, $now->fingerprint)) {
            return [];
        }

        $changes = [];

        if ($before->position !== $now->position) {
            $changes[] = PolicyFinding::Moved;
        }

        if ($before->reachable !== $now->reachable) {
            $changes[] = PolicyFinding::ReachabilityChanged;
        }

        $direction = $this->directionOf($before->breadth, $now->breadth, $rule);

        if ($direction !== null) {
            $changes[] = $direction;
        } elseif ($before->breadth !== $now->breadth) {
            $changes[] = PolicyFinding::Changed;
        }

        if ($changes === []) {
            /*
             * The fingerprint moved and none of the above explains it, which
             * means the static findings changed — a binding went away, or came
             * back. Reported as a change so the operator looks.
             */
            $changes[] = PolicyFinding::Changed;
        }

        return array_values(array_unique($changes, SORT_REGULAR));
    }

    /**
     * 🛑 Which way the change went, in terms of **access** rather than of the
     * rule.
     *
     * The two are not the same and the difference is the whole value of this
     * method. Widening a *deny* rule's selectors narrows access: more URLs are
     * refused. §8.12.6 does not even evaluate a deny rule's requirement — see
     * {@see EffectiveAccess} — so for a deny rule the requirement is not part
     * of the direction at all.
     *
     * Returns null where the direction cannot be established, which
     * {@see PolicyFinding::Changed} then reports honestly.
     *
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     */
    private function directionOf(array $before, array $after, PolicyRule $rule): ?PolicyFinding
    {
        /* An effect flip dominates: nothing else about the rule matters as much. */
        if ($before['allow'] !== $after['allow']) {
            return $after['allow'] === true ? PolicyFinding::Widened : PolicyFinding::Narrowed;
        }

        /*
         * 🛑 A rule leaving `shadow` starts being enforced (§8.12.6), which
         * widens if it allows and narrows if it denies. Entering `shadow` is
         * the inverse. This is the shape of a "planted widening edit" that
         * changes no selector and no requirement.
         */
        if ($before['shadow'] !== $after['shadow']) {
            $enforcedNow = $after['shadow'] === false;

            return $enforcedNow === ($after['allow'] === true)
                ? PolicyFinding::Widened
                : PolicyFinding::Narrowed;
        }

        $grew = self::selectorsGrew($before, $after);
        $shrank = self::selectorsGrew($after, $before);

        if (! $rule->allow) {
            /* A deny rule: more URLs refused is less access. */
            if ($grew) {
                return PolicyFinding::Narrowed;
            }

            return $shrank ? PolicyFinding::Widened : null;
        }

        /*
         * 🛑 The definitive requirement signal: a tree that needed an identity
         * and no longer does. §8.12.7 permits exactly one such tree — the
         * public terminal — so this transition is a rule becoming readable by
         * anybody on the internet, which is §19/40's named failure mode.
         */
        if ($before['identity'] === true && $after['identity'] === false) {
            return PolicyFinding::Widened;
        }

        if ($before['identity'] === false && $after['identity'] === true) {
            return PolicyFinding::Narrowed;
        }

        if ($before['admits'] !== $after['admits']) {
            /*
             * 🛑 Narrowed to `list<string>` rather than cast, and §9.4's level 9
             * on this namespace is what insisted. `breadth` comes back from a
             * JSON column, so `admits` is `mixed`: an `is_array()` check leaves
             * `array<mixed>`, and `array_diff` on that throws at runtime the
             * moment one element is itself an array. A linter that crashed on a
             * malformed stored observation would take the nightly job with it,
             * and the observation is the one thing here that an earlier version
             * of this code wrote.
             */
            $beforeAdmits = self::shapeList($before['admits']);
            $afterAdmits = self::shapeList($after['admits']);

            /*
             * The exact comparison: the set of reader shapes the tree admits.
             * A superset is a widening and nothing else can be, because the
             * sets are the tree's own evaluator's answers.
             */
            if ($beforeAdmits !== [] || $afterAdmits !== []) {
                $added = array_diff($afterAdmits, $beforeAdmits);
                $removed = array_diff($beforeAdmits, $afterAdmits);

                if ($added !== [] && $removed === []) {
                    return PolicyFinding::Widened;
                }

                if ($removed !== [] && $added === []) {
                    return PolicyFinding::Narrowed;
                }

                return null;    // both directions at once: a rewrite, not a tweak
            }
        }

        if ($grew) {
            return PolicyFinding::Widened;
        }

        if ($shrank) {
            return PolicyFinding::Narrowed;
        }

        /*
         * 🛑 §9.3.2's caching axis, and it is **defence against a hand-edited
         * row** rather than a transition the product can produce.
         *
         * `ReaderPolicies::addRule()` refuses `cache_mode = 'public'` unless
         * the requirement is literally `{"leaf":"public"}`, so the flag is
         * pinned to the requirement's shape: a rule that legitimately changes
         * it must change its requirement too, and the `identity` branch above
         * has already answered by then. What reaches here is a row somebody
         * wrote by hand — which is exactly the row worth reporting, and the
         * direction is still knowable.
         */
        if ($before['public_cache'] === false && $after['public_cache'] === true) {
            return PolicyFinding::Widened;
        }

        if ($before['public_cache'] === true && $after['public_cache'] === false) {
            return PolicyFinding::Narrowed;
        }

        return self::windowDirection($before, $after);
    }

    /**
     * Whether `$after` selects everything `$before` did, and more.
     *
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     */
    private static function selectorsGrew(array $before, array $after): bool
    {
        /*
         * 🛑 **At least one axis must actually have moved**, and the first
         * version of this method got that wrong in a way worth recording.
         *
         * It began `if ($before === $after) return false`, comparing the whole
         * breadth array — so a change to `public_cache` or to the time window
         * left all three selector axes equal, every iteration `continue`d, and
         * the method returned "grew" with no selector having grown. Both
         * `$grew` and `$shrank` came back true at the call site, and `Widened`
         * was returned before the branches that know about those two axes were
         * ever reached.
         *
         * The visible failure was an operator told `widened` for turning a
         * public cache directive **off** — a false alarm in the frightening
         * direction, which is precisely the "alert with the wrong label is read
         * and dismissed" that {@see self::directionOf()} exists to avoid.
         */
        $moved = false;

        foreach (['versions', 'languages', 'paths'] as $axis) {
            $old = is_array($before[$axis]) ? $before[$axis] : [];
            $new = is_array($after[$axis]) ? $after[$axis] : [];

            if ($old === $new) {
                continue;
            }

            $moved = true;

            /* `['*']` is the stored spelling of "every value on this axis". */
            if ($new === ['*']) {
                continue;   // the new one is as wide as possible: still growing
            }

            if ($old === ['*']) {
                return false;   // it was everything and is not any more
            }

            if ($axis === 'paths') {
                if (! self::pathsCover(self::axisList($new), self::axisList($old))) {
                    return false;
                }

                continue;
            }

            if (! self::axisCovers(self::axisList($new), self::axisList($old))) {
                return false;
            }
        }

        return $moved;
    }

    /**
     * 🛑 §12.3's validity window, as a direction.
     *
     * A rule live for longer admits more and one live for less admits less, so
     * editing `not_before` or `not_after` is a reachability change with a
     * direction — and the linter said nothing about it until the selector bug
     * above was fixed, because `selectorsGrew()` was swallowing every
     * window-only edit as a widening.
     *
     * Null means the two windows overlap without either containing the other,
     * which is a reschedule rather than a tightening or a loosening.
     *
     * @param  array<string, mixed>  $before
     * @param  array<string, mixed>  $after
     */
    private static function windowDirection(array $before, array $after): ?PolicyFinding
    {
        $old = is_array($before['window'] ?? null) ? $before['window'] : [];
        $new = is_array($after['window'] ?? null) ? $after['window'] : [];

        if ($old === $new) {
            return null;
        }

        $oldFrom = is_int($old['not_before'] ?? null) ? $old['not_before'] : null;
        $oldTo = is_int($old['not_after'] ?? null) ? $old['not_after'] : null;
        $newFrom = is_int($new['not_before'] ?? null) ? $new['not_before'] : null;
        $newTo = is_int($new['not_after'] ?? null) ? $new['not_after'] : null;

        /* Null is unbounded, so it contains every bound on that side. */
        $startsNoLater = $newFrom === null || ($oldFrom !== null && $newFrom <= $oldFrom);
        $endsNoEarlier = $newTo === null || ($oldTo !== null && $newTo >= $oldTo);

        if ($startsNoLater && $endsNoEarlier) {
            return PolicyFinding::Widened;
        }

        $startsNoEarlier = $oldFrom === null || ($newFrom !== null && $oldFrom <= $newFrom);
        $endsNoLater = $oldTo === null || ($newTo !== null && $oldTo >= $newTo);

        return $startsNoEarlier && $endsNoLater ? PolicyFinding::Narrowed : null;
    }

    /**
     * Every string in a value read back from a JSON column.
     *
     * 🛑 The one place `breadth`'s stored shape is trusted, and it is trusted
     * only this far. See the call site: §9.4 runs this namespace at level 9
     * because a type error in it is a security bug, and `array_diff` over
     * anything but strings is a crash in a scheduled job.
     *
     * @return list<string>
     */
    private static function shapeList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $shapes = [];

        foreach ($value as $shape) {
            if (is_string($shape)) {
                $shapes[] = $shape;
            }
        }

        return $shapes;
    }

    /**
     * @param  array<array-key, mixed>  $axis
     * @return list<string>
     */
    private static function axisList(array $axis): array
    {
        if ($axis === ['*']) {
            return [];  // back to the `matches()` convention: empty is everything
        }

        return array_values(array_filter($axis, 'is_string'));
    }

    // -------------------------------------------------------------- breadth

    /**
     * 🛑 What this rule admits, as comparable facts rather than a score.
     *
     * A score would sort; it would not say which way. Every field here exists
     * because {@see self::directionOf()} reads it, and `admits` is the exact
     * one — the set of reader shapes the tree's own evaluator accepts, which
     * makes a requirement rewrite's direction a set comparison rather than a
     * judgement.
     *
     * @return array<string, mixed>
     */
    private function breadthOf(PolicyRule $rule): array
    {
        return [
            'versions' => $rule->versionSlugs === [] ? ['*'] : self::sorted($rule->versionSlugs),
            'languages' => $rule->languages === [] ? ['*'] : self::sorted($rule->languages),
            'paths' => $rule->pathPrefixes === [] ? ['*'] : self::sorted($rule->pathPrefixes),
            'allow' => $rule->allow,
            'shadow' => $rule->shadow,
            'public_cache' => $rule->publicCacheMode,
            /*
             * 🛑 §8.12.7's own predicate, which is the one definitive statement
             * about a requirement's strength: a tree satisfiable without any
             * identity is readable by anybody on the internet.
             */
            'identity' => ! $rule->requirement->satisfiedWithoutIdentity(),
            'admits' => $this->admittedShapes($rule->requirement),
            'window' => [
                'not_before' => $rule->notBefore,
                'not_after' => $rule->notAfter,
            ],
        ];
    }

    /**
     * The reader shapes this tree admits, each as a sorted token string.
     *
     * 🛑 Binding ids are included, because `{binding: A}` and `{binding: B}`
     * admit different people and a comparison over leaf *kinds* would call
     * repointing a rule at another provider "no change".
     *
     * @return list<string>
     */
    private function admittedShapes(Requirement $requirement): array
    {
        $shapes = [];

        foreach ($this->probeContexts($requirement, []) as $context) {
            if (! $requirement->satisfiedBy($context)) {
                continue;
            }

            $tokens = array_map(
                static fn (AccessLeaf $leaf): string => $leaf->value,
                $context->satisfiedLeaves,
            );

            foreach ($context->satisfiedBindings as $binding) {
                $tokens[] = 'binding:'.$binding;
            }

            sort($tokens);
            $shapes[] = implode('+', $tokens);
        }

        sort($shapes);

        return array_values(array_unique($shapes));
    }

    /**
     * @param  list<string>  $values
     * @return list<string>
     */
    private static function sorted(array $values): array
    {
        sort($values);

        return $values;
    }

    /**
     * @param  list<PolicyFinding>  $findings
     * @param  array<string, mixed>  $breadth
     */
    private static function fingerprintOf(int $position, ?int $shadowedBy, array $findings, array $breadth): string
    {
        return hash(
            'sha256',
            (string) json_encode([
                'position' => $position,
                'shadowed_by' => $shadowedBy,
                'findings' => array_map(static fn (PolicyFinding $f): string => $f->value, $findings),
                'breadth' => $breadth,
            ]),
            binary: true,
        );
    }

    // -------------------------------------------------------------- storage

    /**
     * The driver type and usability of every binding this project can reach.
     *
     * 🛑 Through {@see Bindings}, never from `auth_provider_bindings`: §8.12.2
     * makes that class the one reader of the provider tables, and an
     * architecture test enforces it. {@see Bindings::contextsFor()} also
     * applies §8.12.3's most-specific-of-type resolution, which is exactly the
     * set a rule's binding reference has to be in — a binding that exists on
     * the installation but has been superseded for this project is, for this
     * rule, missing.
     *
     * @param  string  $projectId  raw 16 bytes
     * @return array<string, array{type: string, usable: bool}> keyed by UUID text
     */
    private function bindingFacts(string $projectId, string $organisationId, int $authzEpoch): array
    {
        $facts = [];

        foreach ($this->bindings->contextsFor($projectId, $organisationId, $authzEpoch) as $binding) {
            /*
             * Keyed by UUID **text**, because that is the form a requirement
             * tree holds — see `ProviderOutcome::merge()`'s note on why
             * storing raw bytes there would make every binding rule silently
             * unsatisfiable.
             */
            $facts[Uuid::toText($binding->id)] = [
                'type' => $binding->type,
                'usable' => $binding->isUsable(),
            ];
        }

        return $facts;
    }

    /**
     * Last night's observations for these rules.
     *
     * @param  list<PolicyRule>  $rules
     * @return array<string, PolicyObservation>
     */
    private function previousFor(array $rules): array
    {
        $ids = [];

        foreach ($rules as $rule) {
            if ($rule->id !== null) {
                $ids[] = Uuid::toBytes($rule->id);
            }
        }

        if ($ids === []) {
            return [];
        }

        /*
         * 🛑 Spanning every organisation, like {@see ReaderPolicies} and for
         * the same reason: this runs from a scheduled command with no tenant
         * declared, and the keys are primary keys taken from rows already
         * loaded for this project — so the span cannot return another tenant's
         * anything.
         */
        /** @var list<object{rule_id: string, position: int, reachable: int, shadowed_by: int|null, findings: string, breadth: string, fingerprint: string}> $rows */
        $rows = $this->context->acrossAllOrganisations(
            static fn (): array => DB::table('policy_lint_observations')
                ->whereIn('rule_id', $ids)
                ->get(['rule_id', 'position', 'reachable', 'shadowed_by', 'findings', 'breadth', 'fingerprint'])
                ->all(),
        );

        $previous = [];

        foreach ($rows as $row) {
            $findings = [];

            $decoded = json_decode($row->findings, true);

            if (is_array($decoded)) {
                foreach ($decoded as $code) {
                    $finding = is_string($code) ? PolicyFinding::tryFrom($code) : null;

                    if ($finding !== null) {
                        $findings[] = $finding;
                    }
                }
            }

            $breadth = json_decode($row->breadth, true);

            $previous[Uuid::toText($row->rule_id)] = new PolicyObservation(
                ruleId: Uuid::toText($row->rule_id),
                position: $row->position,
                label: '',
                reachable: (bool) $row->reachable,
                shadowedBy: $row->shadowed_by,
                findings: $findings,
                breadth: is_array($breadth) ? $breadth : [],
                fingerprint: $row->fingerprint,
                changes: [],
            );
        }

        return $previous;
    }

    /**
     * Record tonight's observations, replacing last night's.
     *
     * 🛑 One row per rule, upserted. The question is "did this change since
     * last night", which needs one previous observation; a history would grow
     * with (rules × nights) and nothing would ever read past the last row. The
     * permanent record of an alert is §20.3's audit chain, which is
     * tamper-evident and already has a retention policy.
     *
     * @param  list<PolicyObservation>  $observations
     * @param  string  $projectId  raw 16 bytes
     */
    private function store(array $observations, string $projectId, string $organisationId, int $now): void
    {
        $rows = [];

        foreach ($observations as $observation) {
            $rows[] = [
                'id' => Uuid::toBytes(Uuid::v7()),
                'organisation_id' => $organisationId,
                'project_id' => $projectId,
                'rule_id' => Uuid::toBytes($observation->ruleId),
                'position' => $observation->position,
                'reachable' => $observation->reachable,
                'shadowed_by' => $observation->shadowedBy,
                'findings' => (string) json_encode(array_map(
                    static fn (PolicyFinding $finding): string => $finding->value,
                    $observation->findings,
                )),
                'breadth' => (string) json_encode($observation->breadth),
                'fingerprint' => $observation->fingerprint,
                'observed_at' => date('Y-m-d H:i:s.v', $now),
                'created_at' => date('Y-m-d H:i:s.v', $now),
                'updated_at' => date('Y-m-d H:i:s.v', $now),
            ];
        }

        if ($rows === []) {
            return;
        }

        $this->context->acrossAllOrganisations(static function () use ($rows): void {
            DB::table('policy_lint_observations')->upsert(
                $rows,
                ['rule_id'],
                ['position', 'reachable', 'shadowed_by', 'findings', 'breadth', 'fingerprint', 'observed_at', 'updated_at'],
            );
        });
    }
}
