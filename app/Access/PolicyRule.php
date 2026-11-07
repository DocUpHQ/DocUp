<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * One `reader_policy_rules` row, as the decision function sees it (§8.12.6).
 *
 * Pure, immutable, and holding no model: the rule set is loaded once per
 * request and {@see EffectiveAccess} is a function of it, which is what lets
 * the generated decision table drive the real decision path with no database at
 * all.
 */
final class PolicyRule
{
    /**
     * @param  string|null  $id  raw 16 bytes, or null for a synthesised rule
     * @param  int  $position  §8.12.6's first-match-wins order
     * @param  list<string>  $versionSlugs  the slugs this rule names; empty
     *                                      means every version
     * @param  list<string>  $languages  the languages this rule names; empty
     *                                   means every language
     * @param  list<string>  $pathPrefixes  §12.3: "expressed **relative to a
     *                                      component mount**"; empty means
     *                                      every path
     * @param  bool  $shadow  🛑 evaluated and recorded, never enforced
     * @param  int|null  $notBefore  unix seconds
     * @param  int|null  $notAfter  unix seconds
     */
    public function __construct(
        public readonly ?string $id,
        public readonly int $position,
        public readonly string $label,
        public readonly bool $allow,
        public readonly Requirement $requirement,
        public readonly array $versionSlugs = [],
        public readonly array $languages = [],
        public readonly array $pathPrefixes = [],
        public readonly bool $publicCacheMode = false,
        public readonly ?bool $listedOverride = null,
        public readonly bool $shadow = false,
        public readonly ?int $notBefore = null,
        public readonly ?int $notAfter = null,
        public readonly ?int $grantTtlSeconds = null,
    ) {}

    /**
     * Whether this rule applies to a request.
     *
     * 🛑 **Matching is separate from satisfaction**, and §8.12.6's
     * first-match-wins is why. The *first* rule whose selectors match decides
     * the request — if its requirement is then unsatisfied the answer is deny,
     * and evaluation does **not** continue to a later rule that might have
     * allowed. Folding satisfaction into matching would turn the list into
     * "any rule that lets you in", which is a different and much weaker policy
     * language: an operator could no longer write a deny that holds.
     *
     * @param  int  $now  unix seconds
     */
    public function matches(string $versionSlug, string $language, string $path, int $now): bool
    {
        if ($this->notBefore !== null && $now < $this->notBefore) {
            return false;
        }

        if ($this->notAfter !== null && $now >= $this->notAfter) {
            return false;
        }

        if ($this->versionSlugs !== [] && ! in_array($versionSlug, $this->versionSlugs, true)) {
            return false;
        }

        if ($this->languages !== [] && ! in_array($language, $this->languages, true)) {
            return false;
        }

        if ($this->pathPrefixes === []) {
            return true;
        }

        foreach ($this->pathPrefixes as $prefix) {
            if (PathPrefix::covers($prefix, $path)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 🛑 Whether this rule names the resource **explicitly**, which is what
     * §12.3's `restricted` level requires.
     *
     * > "`restricted` … only a reader satisfying an explicit allow rule naming
     * > this component or version."
     *
     * So a rule with a wildcard version selector cannot admit a reader to a
     * `restricted` version, however strong their identity. That is the
     * difference between `restricted` and `members`, and without this
     * predicate the two levels would behave identically — making the fourth
     * rung of the lattice decorative.
     *
     * A named path prefix counts as naming the component, because §12.3 says
     * "naming this component **or** version" and §12.3's own note makes path
     * patterns "relative to a component mount".
     */
    public function namesResourceExplicitly(): bool
    {
        return $this->versionSlugs !== [] || $this->pathPrefixes !== [];
    }
}
