<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\BuildSkipRule;
use App\Models\Project;
use App\Webhooks\PushEvent;
use Illuminate\Support\Collection;

/**
 * §8.5.4's second deduplication layer.
 *
 * > "ordered pre-dispatch skip rules (branch/tag regex, changed-path globs,
 * > commit-message regex, PR label) resolving to `skipped` and never
 * > `failed`"
 *
 * 🛑 **Pre-dispatch** is not decoration. The evaluation happens before a job
 * is enqueued, so a skipped push leaves a `build_requests` row in `skipped`
 * and nothing in the queue — which is what Phase 11's exit criterion checks:
 * "A changed-paths rule fires project A and provably does **not** enqueue
 * project B, asserted on the enqueued job list." A rule evaluated inside the
 * build would still satisfy "does not build" while failing "does not
 * enqueue", and on a monorepo feeding forty projects the difference is the
 * whole point.
 *
 * 🛑 **Never `failed`.** Every outcome of this class is `skipped` or
 * "carry on". A rule that cannot be evaluated — an operator's regex that
 * does not compile, a glob list that is empty — is passed over rather than
 * raised, because a project that stops building and reports an error nobody
 * wrote is worse than one that builds when it need not have.
 */
final readonly class SkipRuleEvaluator
{
    /**
     * Decide whether this push should be skipped.
     *
     * First match wins, in `position` order, which is what "ordered" means
     * in the requirement. A rule with {@see SkipEffect::Build} stops the
     * evaluation and allows the build — that is how "build when `docs/**`
     * changed, skip otherwise" is written.
     *
     * @return SkipDecision the rule that decided, and which way
     */
    public function decide(Project $project, PushEvent $event): SkipDecision
    {
        $rules = BuildSkipRule::query()
            ->where('project_id', $project->id)
            ->where('enabled', true)
            ->orderBy('position')
            ->get();

        /*
         * 🛑 §8.5.4, both halves of it, and this is the subtle one:
         *
         *   "Where a provider may truncate its changed-file arrays, the
         *    system MUST treat the payload as 'everything changed'. ... A
         *    changed-path skip rule MUST NOT be applied to a payload
         *    detected as truncated."
         *
         * The obvious implementation — pass over the path rules and keep
         * evaluating — gets the exit criterion wrong, and it took writing
         * the test to see why. The monorepo rule set §8.6.8 describes is
         * written as a PAIR: "build when `docs/alpha/**` changed" followed
         * by "skip everything else". Passing over the first rule lands on
         * the second, and the project does not build — which is the exact
         * opposite of "treat the payload as everything changed".
         *
         * So a truncated payload short-circuits the whole evaluation for
         * any project whose rules are path-based. The presence of a
         * changed-path rule IS the statement that this project filters by
         * path; when the path data cannot be trusted, the filter cannot be
         * applied at all, and §8.5.4's stated fallback is to rebuild.
         *
         * A project with no path rules is unaffected: its branch and
         * commit-message rules read fields a truncation does not touch.
         */
        if (! $event->changedPathsAreTrustworthy() && $this->filtersByPath($rules)) {
            return new SkipDecision(SkipEffect::Build, null);
        }

        foreach ($rules as $rule) {
            if (! $this->matches($rule, $event)) {
                continue;
            }

            return new SkipDecision($rule->effect, $rule);
        }

        /*
         * No rule matched. The default is to build: a project with no rules
         * at all must behave exactly as it did before rules existed, and an
         * operator who writes three skip rules and forgets the fourth case
         * gets a build rather than silence.
         */
        return new SkipDecision(SkipEffect::Build, null);
    }

    /**
     * Whether this project's rule set decides anything by path.
     *
     * @param  Collection<int, BuildSkipRule>  $rules
     */
    private function filtersByPath(Collection $rules): bool
    {
        foreach ($rules as $rule) {
            if ($rule->kind->readsChangedPaths()) {
                return true;
            }
        }

        return false;
    }

    private function matches(BuildSkipRule $rule, PushEvent $event): bool
    {
        return match ($rule->kind) {
            SkipRuleKind::BranchTagRegex => $rule->pattern !== null
                && SafePattern::matches($rule->pattern, $event->refName),

            SkipRuleKind::ChangedPaths => $rule->path_globs !== null
                && $rule->path_globs !== []
                && PathGlob::anyMatches($rule->path_globs, $event->changedPaths),

            SkipRuleKind::CommitMessageRegex => $rule->pattern !== null
                && SafePattern::matches($rule->pattern, $event->commitMessageBlob()),

            /*
             * A label is compared literally, not as a regex: labels are a
             * closed set the provider supplies, and an operator typing
             * `do-not-build` means that label rather than a pattern that
             * happens to contain a hyphen.
             *
             * 🛑 Always false for an ordinary push, because a push carries
             * no labels. §8.20's pull-request previews are P32's, and the
             * rule shape exists now so that the four §8.5.4 filters are all
             * expressible — a rule an operator can write and that silently
             * never matches is exactly what §8.6.8's validation refuses
             * elsewhere, so the UI surfaces this one as PR-only.
             */
            SkipRuleKind::PrLabel => $rule->pattern !== null
                && in_array($rule->pattern, $event->labels, true),
        };
    }
}
