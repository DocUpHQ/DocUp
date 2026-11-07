<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 §8.12.6's "schema-validated two-level boolean requirement tree", and the
 * home of §8.12.7's satisfiability invariant.
 *
 * The shape, exhaustively:
 *
 * ```json
 * {"leaf": "public"}
 * {"leaf": "binding", "driver": "oidc", "binding_id": "<uuid>"}
 * {"all": [ <leaf>, … ]}
 * {"any": [ <leaf>, … ]}
 * {"all": [ {"any": [ <leaf>, … ]}, <leaf>, … ]}
 * ```
 *
 * Two levels: a group may contain leaves and groups, a group inside a group may
 * contain only leaves. That bound is §8.12.6's and it earns its place twice —
 * §8.12.25 needs an operator to read a rule and say who it admits, and
 * §8.12.7's invariant below is decided by **one** evaluation of the tree rather
 * than by enumerating assignments, which only works because the tree is finite
 * and small.
 *
 * 🛑 **This class is pure and holds no reader.** It answers two questions about
 * a *requirement*: is it well-formed and safe to store (write time), and is it
 * satisfied by a given set of leaves (read time). The decision about a reader
 * is {@see EffectiveAccess} and there is exactly one of those (§4.3/7, §12.3).
 */
final class Requirement
{
    /**
     * §8.12.6's depth, as a number this class can assert against.
     *
     * 1 is a bare leaf, 2 is a group of leaves, 3 is a group of groups of
     * leaves — "two-level" counting the groups, which is the reading that makes
     * `{"all": [{"any": [...]}, ...]}` legal and a fourth level not.
     */
    private const MAX_DEPTH = 3;

    /**
     * A ceiling on leaves, so one rule cannot become a program.
     *
     * §10.6 caps rules at 50 per project; without a cap here a single rule
     * could hold thousands of leaves and §8.12.7's evaluation — and every
     * request's — would scale with whatever an operator pasted in. 64 is far
     * beyond any policy anybody has described and far below anything that
     * costs a measurable amount to evaluate.
     */
    private const MAX_LEAVES = 64;

    /** @param array<string, mixed> $tree the validated JSON structure */
    private function __construct(private readonly array $tree) {}

    /**
     * Parse and validate a requirement tree, refusing anything unsafe.
     *
     * 🛑 Every refusal is a write-time refusal. A tree that reaches storage has
     * passed §8.12.7, so {@see self::satisfiedBy()} does not have to be
     * defensive about the invariant at read time — which matters because read
     * time is §9.2's hot path and write time is a form submission.
     *
     * @param  array<string, mixed>  $tree
     * @param  bool  $allowNetworkOnly  §8.12.7's one escape: the project has
     *                                  "explicitly enabled network-only access
     *                                  (UI-flagged weak, audited)"
     *
     * @throws PolicyRefused
     */
    public static function parse(array $tree, bool $allowNetworkOnly = false): self
    {
        self::validate($tree, depth: 1, leaves: new LeafCounter);

        $requirement = new self($tree);

        /*
         * 🛑 §8.12.7, and the one line that implements it:
         *
         * > "The system MUST reject **at write time** any requirement
         * > satisfiable without at least one **identity-bearing** leaf …
         * > unless it is literally the public terminal or the project has
         * > explicitly enabled network-only access."
         *
         * Decided by evaluating the tree under the **worst case**: every
         * non-identity-bearing leaf true, every identity-bearing leaf false. If
         * it still comes out true, there is a reader with no identity at all
         * who satisfies it — which is the condition the requirement describes,
         * stated as one evaluation rather than as an enumeration of assignments.
         *
         * Both exceptions are literal. "The public terminal" means the tree is
         * exactly `{"leaf": "public"}` — not a tree containing a public leaf,
         * because `{"any": [{"leaf":"public"}, {"leaf":"binding"}]}` is a public
         * rule with a decorative binding beside it, and §8.12.7 says
         * **literally**.
         */
        if ($requirement->isPublicTerminal() || $allowNetworkOnly) {
            return $requirement;
        }

        if ($requirement->satisfiedWithoutIdentity()) {
            throw PolicyRefused::of(
                RequirementRejection::SatisfiableWithoutIdentity,
                'a reader bearing no identity satisfies this requirement',
            );
        }

        return $requirement;
    }

    /**
     * The validated tree, for storage.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->tree;
    }

    /**
     * 🛑 Exactly `{"leaf": "public"}` and nothing else.
     *
     * Two things turn on this being strict: §8.12.7's exception to the
     * satisfiability invariant, and §9.3.2's `cache_mode = 'public'`, which
     * {@see ReaderPolicies} permits only here. A looser reading of "the public
     * terminal" would let a rule demanding a credential declare itself publicly
     * cacheable, and the response would land in a shared cache.
     */
    public function isPublicTerminal(): bool
    {
        return $this->tree === ['leaf' => AccessLeaf::Public->value];
    }

    /**
     * Whether a reader satisfies this requirement.
     *
     * 🛑 **Empty groups are false, in both directions.** An empty conjunction
     * is true in logic, so `{"all": []}` would admit everybody —
     * §8.12.7's "vacuous-truth fail-open … evaluated over an empty identity
     * set". {@see self::validate()} refuses an empty group at write time; this
     * answers false for one anyway, because a defence present in only one of
     * those two places is one refactor from being gone.
     */
    public function satisfiedBy(ReaderContext $reader): bool
    {
        return $this->evaluate($this->tree, static fn (AccessLeaf $leaf, ?string $bindingId): bool => $reader->satisfies($leaf, $bindingId));
    }

    /**
     * Which leaf satisfied it — the `satisfied_by` §8.12.25's simulator reports.
     *
     * 🛑 The **strongest** satisfying leaf rather than the first, because
     * §12.3's last conjunct is conditional on it: "share/bearer scope covers
     * (project, version, path) **if that was the satisfying leaf**". A reader
     * holding both a session and a share link must be judged on the session —
     * reporting the share link would apply the link's narrower scope to
     * somebody who did not need it and deny them a page they may read.
     *
     * Returns null when the requirement is not satisfied at all.
     */
    public function satisfyingLeaf(ReaderContext $reader): ?AccessLeaf
    {
        if (! $this->satisfiedBy($reader)) {
            return null;
        }

        /*
         * 🛑 Each leaf is tested with **its own** `binding_id`, not with null.
         *
         * The first version of this method asked `$reader->satisfies($leaf,
         * null)` per kind, and that is a widening bug rather than a reporting
         * one: a reader holding a session for binding Y and a share link
         * scoped to `/v1/` satisfies `{"any": [{binding: X}, {share}]}` only
         * through the share leaf — but the lenient check would report
         * `binding`, §12.3's last conjunct is conditional on the satisfying
         * leaf, and the scope check would therefore be skipped. They would read
         * `/v2/` on a `/v1/` link.
         */
        $satisfied = [];

        $this->walk($this->tree, static function (AccessLeaf $leaf, ?string $bindingId) use ($reader, &$satisfied): void {
            if ($reader->satisfies($leaf, $bindingId) && ! in_array($leaf, $satisfied, true)) {
                $satisfied[] = $leaf;
            }
        });

        /*
         * 🛑 The ordering lives in {@see AccessLeaf::strongestFirst()} and the
         * reason it does is beside it. Phase 22 needed the same ordering for a
         * reader the lattice admitted with no rule, and a second copy of a
         * security ordering is how one of them goes stale.
         */
        foreach (AccessLeaf::strongestFirst() as $leaf) {
            if (in_array($leaf, $satisfied, true)) {
                return $leaf;
            }
        }

        return null;
    }

    /** Whether the tree mentions a leaf kind at all. */
    public function usesLeaf(AccessLeaf $kind): bool
    {
        return in_array($kind, $this->leafKinds(), true);
    }

    /**
     * Every leaf kind in the tree, deduplicated.
     *
     * @return list<AccessLeaf>
     */
    public function leafKinds(): array
    {
        $kinds = [];

        $this->walk($this->tree, static function (AccessLeaf $leaf) use (&$kinds): void {
            if (! in_array($leaf, $kinds, true)) {
                $kinds[] = $leaf;
            }
        });

        return $kinds;
    }

    /**
     * Every binding id the tree names, for §8.12.19's "A referenced binding
     * MUST NOT be deletable".
     *
     * @return list<string>
     */
    public function bindingIds(): array
    {
        $ids = [];

        $this->walk($this->tree, static function (AccessLeaf $leaf, ?string $bindingId) use (&$ids): void {
            if ($bindingId !== null && ! in_array($bindingId, $ids, true)) {
                $ids[] = $bindingId;
            }
        });

        return $ids;
    }

    /**
     * §8.12.7's evaluation: non-identity leaves true, identity leaves false.
     *
     * Public here rather than private so the write-time invariant can be
     * asserted directly by a test on a tree, independently of whether
     * {@see self::parse()} happens to call it.
     */
    public function satisfiedWithoutIdentity(): bool
    {
        return $this->evaluate(
            $this->tree,
            static fn (AccessLeaf $leaf): bool => ! $leaf->bearsIdentity(),
        );
    }

    /**
     * Evaluate the tree with an arbitrary leaf oracle.
     *
     * One evaluator for both the read-time question and the write-time
     * invariant, because two would eventually disagree about an empty group —
     * and the two answers an empty group can have are "admit everybody" and
     * "admit nobody".
     *
     * @param  array<string, mixed>  $node
     * @param  callable(AccessLeaf, ?string): bool  $oracle
     */
    private function evaluate(array $node, callable $oracle): bool
    {
        if (isset($node['leaf'])) {
            $leaf = AccessLeaf::tryFrom(is_string($node['leaf']) ? $node['leaf'] : '');

            // An unrecognised leaf is false. It cannot reach storage
            // (validate() refuses it), so this is the case where a future
            // migration adds a kind this code has not been taught — and an
            // uninterpretable requirement must not admit anybody.
            return $leaf !== null && $oracle($leaf, is_string($node['binding_id'] ?? null) ? $node['binding_id'] : null);
        }

        foreach (['all', 'any'] as $operator) {
            if (! isset($node[$operator]) || ! is_array($node[$operator])) {
                continue;
            }

            /** @var list<mixed> $children */
            $children = array_values($node[$operator]);

            // 🛑 The vacuous-truth guard. Both operators answer false on an
            // empty list, which for `all` is a deliberate departure from
            // boolean logic — see the class note and §8.12.7.
            if ($children === []) {
                return false;
            }

            foreach ($children as $child) {
                if (! is_array($child)) {
                    return false;
                }

                /** @var array<string, mixed> $child */
                $satisfied = $this->evaluate($child, $oracle);

                if ($operator === 'all' && ! $satisfied) {
                    return false;
                }

                if ($operator === 'any' && $satisfied) {
                    return true;
                }
            }

            return $operator === 'all';
        }

        return false;
    }

    /**
     * Visit every leaf.
     *
     * @param  array<string, mixed>  $node
     * @param  callable(AccessLeaf, ?string): void  $visitor
     */
    private function walk(array $node, callable $visitor): void
    {
        if (isset($node['leaf'])) {
            $leaf = AccessLeaf::tryFrom(is_string($node['leaf']) ? $node['leaf'] : '');

            if ($leaf !== null) {
                $visitor($leaf, is_string($node['binding_id'] ?? null) ? $node['binding_id'] : null);
            }

            return;
        }

        foreach (['all', 'any'] as $operator) {
            if (! isset($node[$operator]) || ! is_array($node[$operator])) {
                continue;
            }

            foreach ($node[$operator] as $child) {
                if (is_array($child)) {
                    /** @var array<string, mixed> $child */
                    $this->walk($child, $visitor);
                }
            }
        }
    }

    /**
     * Validate one node, recursively.
     *
     * @param  array<string, mixed>  $node
     *
     * @throws PolicyRefused
     */
    private static function validate(array $node, int $depth, LeafCounter $leaves): void
    {
        if ($depth > self::MAX_DEPTH) {
            throw PolicyRefused::of(
                RequirementRejection::TooDeep,
                '§8.12.6 bounds the tree at two levels',
            );
        }

        if (isset($node['leaf'])) {
            self::validateLeaf($node, $leaves);

            return;
        }

        $operators = array_values(array_intersect(['all', 'any'], array_keys($node)));

        if (count($operators) !== 1) {
            throw PolicyRefused::of(
                RequirementRejection::Malformed,
                'a node must be exactly one of `leaf`, `all` or `any`',
            );
        }

        $children = $node[$operators[0]];

        if (! is_array($children) || $children === []) {
            throw PolicyRefused::of(
                RequirementRejection::EmptyGroup,
                '🛑 an empty `'.$operators[0].'` is the vacuous-truth fail-open of §8.12.7',
            );
        }

        foreach ($children as $child) {
            if (! is_array($child)) {
                throw PolicyRefused::of(RequirementRejection::Malformed, 'a child must be a node');
            }

            /** @var array<string, mixed> $child */
            self::validate($child, $depth + 1, $leaves);
        }
    }

    /**
     * Validate a leaf: a known kind, and a driver §8.12.17 classifies.
     *
     * @param  array<string, mixed>  $node
     *
     * @throws PolicyRefused
     */
    private static function validateLeaf(array $node, LeafCounter $leaves): void
    {
        $leaves->increment();

        if ($leaves->count() > self::MAX_LEAVES) {
            throw PolicyRefused::of(
                RequirementRejection::TooManyLeaves,
                'at most '.self::MAX_LEAVES.' leaves in one requirement',
            );
        }

        $kind = AccessLeaf::tryFrom(is_string($node['leaf']) ? $node['leaf'] : '');

        if ($kind === null) {
            throw PolicyRefused::of(
                RequirementRejection::Malformed,
                'unknown leaf kind',
            );
        }

        $driver = $node['driver'] ?? null;

        if ($driver === null) {
            return;
        }

        if (! is_string($driver)) {
            throw PolicyRefused::of(RequirementRejection::Malformed, 'driver must be a string');
        }

        /*
         * 🛑 The declared leaf kind must be the one §8.12.17 gives the driver.
         * Without this check a rule could name `ip_allowlist` as a `{binding}`
         * and §8.12.7's invariant would read it as identity-bearing — the whole
         * point of the classification, defeated by a typo in a JSON payload.
         */
        $classified = AccessLeaf::forDriver($driver);

        if ($classified === null) {
            throw PolicyRefused::of(
                RequirementRejection::UnknownDriver,
                '§8.12.17 does not classify driver `'.$driver.'`',
            );
        }

        if ($classified !== $kind) {
            throw PolicyRefused::of(
                RequirementRejection::Malformed,
                '§8.12.17 classifies `'.$driver.'` as `'.$classified->value.'`, not `'.$kind->value.'`',
            );
        }
    }
}
