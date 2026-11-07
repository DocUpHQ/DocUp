<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * One project's reader policy: §8.12.6's ordered, first-match-wins rule list.
 *
 * 🛑 **There is no policy for a collection and there never will be.** §8.12.8:
 * "`reader_policies` is keyed on `project_id` and a collection holds no policy
 * of its own, so a widening inheritance flag would have nothing to inherit from
 * and would exist only as a way to defeat this requirement." The absence is the
 * control, and it is visible here as the absence of a parent pointer.
 */
final class ReaderPolicy
{
    /**
     * @param  list<PolicyRule>  $rules  in ascending position order
     * @param  bool  $exists  false when the project has no policy row at all
     * @param  bool  $allowNetworkOnlyAccess  §8.12.7's audited escape
     * @param  int  $epoch  which policy a decision or grant was made under
     */
    public function __construct(
        public readonly array $rules = [],
        public readonly bool $exists = false,
        public readonly bool $allowNetworkOnlyAccess = false,
        public readonly int $epoch = 0,
    ) {}

    /**
     * The policy of a project that has none.
     *
     * 🛑 Not the same thing as an empty policy, and the difference decides a
     * reader's fate. A project with **no policy row** has not opted into reader
     * authentication at all, so §12.3's second conjunct has nothing to say and
     * the lattice columns decide alone — which is how every public project
     * built before this phase keeps serving. A project with a policy row and
     * **zero rules** has opted in and said nobody may read: §8.12.19 makes
     * that "deny with a red banner".
     *
     * Conflating them would either break every existing public project or
     * silently publish a project mid-configuration, and those are the two
     * worst available outcomes.
     */
    public static function absent(): self
    {
        return new self;
    }

    /**
     * A policy row with rules.
     *
     * @param  list<PolicyRule>  $rules
     */
    public static function of(array $rules, bool $allowNetworkOnlyAccess = false, int $epoch = 0): self
    {
        usort($rules, static fn (PolicyRule $a, PolicyRule $b): int => $a->position <=> $b->position);

        return new self($rules, exists: true, allowNetworkOnlyAccess: $allowNetworkOnlyAccess, epoch: $epoch);
    }

    /**
     * §8.12.6's first match, or null.
     *
     * 🛑 Shadow rules are **skipped** here rather than matched and ignored.
     * A shadow rule that matched would consume the first-match slot and deny
     * everything behind it — so "evaluated and recorded, never enforced" has to
     * mean it does not participate in the ordering at all.
     * {@see self::shadowMatch()} is where the recording half reads it.
     *
     * @param  int  $now  unix seconds
     */
    public function firstMatch(string $versionSlug, string $language, string $path, int $now): ?PolicyRule
    {
        foreach ($this->rules as $rule) {
            if (! $rule->shadow && $rule->matches($versionSlug, $language, $path, $now)) {
                return $rule;
            }
        }

        return null;
    }

    /**
     * The first *shadow* rule that would have matched, for the observability
     * half of §8.12.22's "nightly policy linter … alerts on reachability
     * changes".
     *
     * @param  int  $now  unix seconds
     */
    public function shadowMatch(string $versionSlug, string $language, string $path, int $now): ?PolicyRule
    {
        foreach ($this->rules as $rule) {
            if ($rule->shadow && $rule->matches($versionSlug, $language, $path, $now)) {
                return $rule;
            }
        }

        return null;
    }

    /** 🛑 §8.12.19's zero-rule policy, which denies rather than falling back. */
    public function isEmpty(): bool
    {
        return $this->exists && $this->rules === [];
    }
}
