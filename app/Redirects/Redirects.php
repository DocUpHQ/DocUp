<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Project;
use App\Models\RedirectRule;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * The one place a redirect rule is written (§8.11.2, §8.11.3, §8.11.4).
 *
 * 🛑 Every refusal in §8.11 is a **save-time** refusal, and they are all
 * here. A rule that reached the table unvalidated would be a rule the
 * engine then has to be defensive about on every request — which is both
 * slower and, worse, a second place the policy lives. The engine is pure
 * and trusts its input precisely because nothing else can write one.
 */
final readonly class Redirects
{
    /**
     * §8.11.2 asks for "explicit ordering" and says nothing about how many.
     * 500 is the cap, chosen against the exit criterion's own figure: "a
     * 1,000-redirect project resolves in one query under 10 ms" is a
     * performance claim, not a licence, and the number that matters for
     * correctness is that a project cannot grow a rule set nobody can
     * reason about. A project needing more has a reorganisation problem
     * that a prefix rule would solve.
     */
    public const int MAX_RULES_PER_PROJECT = 500;

    /** @throws RedirectRefused */
    public function create(
        Project $project,
        RedirectKind $kind,
        string $from,
        string $to,
        int $status = 301,
        bool $forced = false,
        ?int $position = null,
        ?string $description = null,
    ): RedirectRule {
        $this->assertStatus($status);

        $from = $this->normalisePattern($kind, $from);
        $to = $this->normaliseTarget($kind, $from, $to, (string) $project->organisation_id);

        $existing = $this->literalEdges($project);

        if (count($existing) >= self::MAX_RULES_PER_PROJECT) {
            throw RedirectRefused::of(
                RedirectRejection::TooManyRules,
                self::MAX_RULES_PER_PROJECT.' rules is the cap for one project',
            );
        }

        $cycle = CycleDetector::cycleFor($existing, ['from' => $from, 'to' => $to]);

        if ($cycle !== null) {
            throw RedirectRefused::of(
                RedirectRejection::CycleDetected,
                implode(' → ', $cycle),
            );
        }

        $rule = new RedirectRule;

        $rule->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'position' => $position ?? $this->nextPosition($project),
            'kind' => $kind,
            'forced' => $forced,
            'from_pattern' => $from,
            'to_target' => $to,
            'status' => $status,
            'enabled' => true,
            'description' => $description,
        ]);

        try {
            $rule->save();
        } catch (UniqueConstraintViolationException) {
            /*
             * 🛑 Caught from the database rather than checked first, because
             * a check-then-insert loses the race that matters: two rules
             * created at once would both see the position free. The unique
             * index is the arbiter and this turns its error into §8.1.11's
             * own identifier.
             */
            throw RedirectRefused::of(
                RedirectRejection::PositionRefused,
                'position '.$rule->position.' is taken',
            );
        }

        $this->settle($project, 'redirect.rule_created', $rule);

        return $rule;
    }

    /**
     * Turn a rule off, or back on.
     *
     * 🛑 Not a delete. §8.11's whole subject is URLs that survive, and the
     * common operator action is "disable this and see what breaks" — a
     * delete frees the position and loses the rule, so the undo is a
     * retype.
     */
    public function setEnabled(RedirectRule $rule, bool $enabled): RedirectRule
    {
        if ($rule->enabled === $enabled) {
            return $rule;
        }

        $rule->forceFill(['enabled' => $enabled])->save();

        $project = Project::query()->find($rule->project_id);

        if ($project instanceof Project) {
            $this->settle($project, $enabled ? 'redirect.rule_enabled' : 'redirect.rule_disabled', $rule);
        }

        return $rule;
    }

    public function delete(RedirectRule $rule): void
    {
        $project = Project::query()->find($rule->project_id);

        $rule->delete();

        if ($project instanceof Project) {
            $this->settle($project, 'redirect.rule_deleted', $rule);
        }
    }

    /**
     * Every enabled rule for a project, in position order, from **one**
     * query, cached on the routing epoch.
     *
     * 🛑 §17's exit criterion in one method: "a 1,000-redirect project
     * resolves in one query under 10 ms". The query is here and nowhere
     * else, and the cache key carries the epoch so a rule change is picked
     * up by addressing a different key rather than by a purge (§8.9.10).
     */
    public function setFor(string $projectId, int $routingEpoch): RedirectSet
    {
        $cached = Cache::remember(
            'redirects:'.Uuid::toText($projectId).':'.$routingEpoch,
            300,
            function () use ($projectId): array {
                $rules = [];

                /*
                 * 🛑 `DB::table`, not the model, and for two reasons that
                 * point the same way.
                 *
                 * **Tenancy.** `RedirectRule` is organisation-scoped, and
                 * this runs on the serving path where no organisation is
                 * current and none can be — a request is a hostname and a
                 * path. The scope would raise "No organisation context
                 * declared (§8.2.1)", which is exactly the trap Phase 19's
                 * `PermittedHosts` hit on the handshake path. The project id
                 * is already the boundary here: it came out of the routing
                 * snapshot, which resolved it from the host.
                 *
                 * **Cost.** §17's criterion is "a 1,000-redirect project
                 * resolves in one query under 10 ms", and hydrating a
                 * thousand Eloquent models with casts and events spends most
                 * of that budget on objects this closure throws away.
                 */
                foreach (
                    DB::table('redirect_rules')
                        ->where('project_id', $projectId)
                        ->where('enabled', true)
                        ->orderBy('position')
                        ->get(['id', 'position', 'kind', 'forced', 'from_pattern', 'to_target', 'status']) as $rule
                ) {
                    $rules[] = [
                        'id' => Uuid::toText((string) $rule->id),
                        'position' => (int) $rule->position,
                        'kind' => (string) $rule->kind,
                        'forced' => (bool) $rule->forced,
                        'from' => (string) $rule->from_pattern,
                        'to' => (string) $rule->to_target,
                        'status' => (int) $rule->status,
                    ];
                }

                return $rules;
            },
        );

        /** @var list<array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}> $cached */
        return new RedirectSet($cached, RegexGuard::enabled());
    }

    /** @throws RedirectRefused */
    private function assertStatus(int $status): void
    {
        /*
         * 🛑 §8.11.2's four, and the pair that matters is 307/308: they
         * preserve the method and the body where 301/302 are permitted to
         * rewrite a POST into a GET. Read the Docs has only 301/302, which
         * is why a documentation API that moved cannot be expressed there.
         */
        if (! in_array($status, [301, 302, 307, 308], true)) {
            throw RedirectRefused::of(
                RedirectRejection::StatusRefused,
                $status.' is not 301, 302, 307 or 308',
            );
        }
    }

    /** @throws RedirectRefused */
    private function normalisePattern(RedirectKind $kind, string $from): string
    {
        $from = trim($from);

        if ($from === '') {
            throw RedirectRefused::of(RedirectRejection::PatternMalformed, 'empty');
        }

        if ($kind === RedirectKind::Regex) {
            /*
             * 🛑 §8.11.4's kill switch, checked here rather than in the
             * guard: it is policy, not containment, and keeping it out of
             * `RegexGuard` is what lets that class stay pure. An
             * installation that has turned regex rules off refuses to
             * **create** one; the ones it already has are skipped by the
             * engine rather than deleted, so turning the switch back on
             * restores them.
             */
            if (! RegexGuard::enabled()) {
                throw RedirectRefused::of(
                    RedirectRejection::RegexDisabled,
                    'regular-expression rules are disabled for this installation (§8.11.4)',
                );
            }

            RegexGuard::assertUsable($from);

            return $from;
        }

        if (! str_starts_with($from, '/')) {
            throw RedirectRefused::of(
                RedirectRejection::PatternMalformed,
                '"'.$from.'" is not root-relative; a pattern that is not anchored at the root matches nothing',
            );
        }

        if (str_contains($from, ':splat') && $kind !== RedirectKind::Prefix) {
            throw RedirectRefused::of(
                RedirectRejection::SplatNotAvailable,
                $kind->value.' rules have no remainder to put in :splat',
            );
        }

        return $from;
    }

    /** @throws RedirectRefused */
    private function normaliseTarget(RedirectKind $kind, string $from, string $to, string $organisationId): string
    {
        /*
         * 🛑 The two URL-style kinds derive their target from the request,
         * so what the operator supplies is a **scope** and not a
         * destination. Validating it as a target would refuse `/`, which is
         * the commonest scope there is.
         */
        if ($kind->derivesTarget()) {
            $scope = trim($to) === '' ? $from : trim($to);

            if (! str_starts_with($scope, '/')) {
                throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'a scope must be root-relative');
            }

            return $scope;
        }

        if ($kind === RedirectKind::Prefix && str_contains($from, ':splat') && ! str_contains($to, ':splat')) {
            /*
             * 🛑 A prefix rule whose target drops the splat sends every
             * page in a section to one page. That is occasionally what
             * somebody means and overwhelmingly what they did by accident,
             * so it is refused and the deliberate case is written as an
             * `exact` rule on the section root plus a prefix rule, or as a
             * target that mentions `:splat` and ignores it.
             */
            throw RedirectRefused::of(
                RedirectRejection::SplatMissing,
                'the pattern captures a remainder and the target discards it: '.
                'every page under "'.$from.'" would land on "'.$to.'"',
            );
        }

        $to = $kind === RedirectKind::Regex || str_contains($to, ':splat')
            ? $this->normaliseTemplate($to)
            : RedirectTarget::normalise($to, $organisationId);

        if ($kind !== RedirectKind::Regex && $to === $from) {
            throw RedirectRefused::of(RedirectRejection::SelfRedirect, $from.' redirects to itself');
        }

        return $to;
    }

    /**
     * A target carrying `:splat` or `$1` cannot be parsed as a URL, so it
     * is checked for the things that would make the **expanded** target
     * dangerous and left otherwise alone.
     *
     * 🛑 The expansion happens at request time from a path that has already
     * passed §8.9.6's canonical-path check, so the substituted text cannot
     * contain a control byte, a backslash or a dot segment. What it could
     * contain is the start of an absolute URL, which is why a template may
     * not begin with a scheme or with `//`.
     *
     * @throws RedirectRefused
     */
    private function normaliseTemplate(string $to): string
    {
        $to = trim($to);

        if ($to === '' || strlen($to) > RedirectTarget::MAX_BYTES) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'empty or over the cap');
        }

        if (preg_match('/[\x00-\x20\x7f]/', $to) === 1) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'control byte or whitespace');
        }

        if (str_starts_with($to, '//') || str_starts_with($to, '/\\')) {
            throw RedirectRefused::of(RedirectRejection::TargetMalformed, 'scheme-relative');
        }

        if (! str_starts_with($to, '/')) {
            throw RedirectRefused::of(
                RedirectRejection::TargetMalformed,
                'a template target must be root-relative; an absolute one cannot be checked against a proven host until it is expanded, and by then it is a Location header',
            );
        }

        return $to;
    }

    /**
     * The literal edges of a project's rule graph, for §8.11.3.
     *
     * @return list<array{from: string, to: string}>
     */
    private function literalEdges(Project $project): array
    {
        $edges = [];

        foreach (
            RedirectRule::query()
                ->where('project_id', $project->id)
                ->orderBy('position')
                ->get(['from_pattern', 'to_target']) as $rule
        ) {
            $edges[] = ['from' => (string) $rule->from_pattern, 'to' => (string) $rule->to_target];
        }

        return $edges;
    }

    private function nextPosition(Project $project): int
    {
        $highest = DB::table('redirect_rules')
            ->where('project_id', $project->id)
            ->max('position');

        return is_numeric($highest) ? ((int) $highest) + 1 : 1;
    }

    /**
     * Bump the epoch and record the change.
     *
     * 🛑 Through §10.8's one registry, never by incrementing the column
     * here: an architecture test asserts that `Invalidation` is the only
     * thing that moves an epoch, and the epoch is how `setFor()`'s cache
     * key changes.
     */
    private function settle(Project $project, string $action, RedirectRule $rule): void
    {
        Invalidation::bumpRouting(
            (string) $project->id,
            'redirect',
            (string) $project->organisation_id,
        );

        Audit::record(
            action: $action,
            actorType: ActorType::System,
            organisationId: (string) $project->organisation_id,
            subjectType: 'redirect_rule',
            subjectId: (string) $rule->id,
            payload: ['kind' => $rule->kind->value, 'position' => $rule->position],
        );
    }
}
