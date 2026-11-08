<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Models\Project;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * The one place a reader policy is read or written (§8.12.6, §8.12.7, §8.12.8).
 *
 * 🛑 **Every refusal in §8.12 is a write-time refusal, and they are all here.**
 * §8.12.7 says "MUST reject **at write time**" in as many words, and the reason
 * is that {@see EffectiveAccess} is pure and trusts its input: a tree that
 * reached the table unvalidated would force the decision function to be
 * defensive on every request, which is both slower and — worse — a second place
 * the policy lives.
 *
 * 🛑 **An architecture test asserts that nothing else reads the policy
 * tables.** §17's Phase 21 exit criterion: "The architecture test fails when a
 * second class reads the policy tables." The argument is §8.12.21's: every
 * derived surface — search, sitemap, `llms.txt`, flyout, addons, manifests —
 * has to be "generated from the **authorised** view", and a second reader of
 * `reader_policy_rules` is a second interpretation of first-match-wins. The
 * first one somebody writes will iterate the rules looking for an allow,
 * because that reads naturally and is not what the policy language means.
 */
final readonly class ReaderPolicies
{
    /**
     * §10.6: "a hard cap of 50 rules per project."
     *
     * Far lower than §8.11.2's 500 redirect rules, and the asymmetry is the
     * point: a redirect set is a migration history that grows forever, while an
     * access policy is a thing an operator has to be able to read and be sure
     * about. §8.12.25 requires a simulator precisely because people get this
     * wrong at far fewer than fifty rules.
     */
    public const int MAX_RULES_PER_PROJECT = 50;

    /** How long a loaded policy may sit in the cache, inside its epoch key. */
    private const int CACHE_SECONDS = 300;

    /**
     * Every rule for a project, in position order, from **one** query, cached
     * on the authz epoch.
     *
     * 🛑 Keyed on the epoch rather than purged, which is what gives §8.12.15 its
     * bound: "revoking a session or editing a policy takes effect on the **next
     * request**". A bump addresses a different key, so there is no window in
     * which a stale policy can be read — and no purge to fail.
     *
     * 🛑 `DB::table`, not the model, for the two reasons Phase 20 recorded on
     * `Redirects::setFor()`: the serving path has no current organisation and
     * cannot have one (a request is a hostname and a path), so §8.2.1's global
     * scope would raise; and hydrating models with casts and events spends the
     * request budget on objects this closure throws away.
     *
     * @param  string  $projectId  raw 16 bytes
     */
    public function forProject(string $projectId, int $authzEpoch): ReaderPolicy
    {
        /** @var array{exists: bool, allow_network_only: bool, epoch: int, rules: list<array<string, mixed>>} $cached */
        $cached = Cache::remember(
            'authz:policy:'.Uuid::toText($projectId).':'.$authzEpoch,
            self::CACHE_SECONDS,
            fn (): array => $this->load($projectId),
        );

        if ($cached['exists'] !== true) {
            return ReaderPolicy::absent();
        }

        $rules = [];

        foreach ($cached['rules'] as $row) {
            $rule = $this->hydrate($row);

            if ($rule !== null) {
                $rules[] = $rule;
            }
        }

        return ReaderPolicy::of(
            $rules,
            /*
             * 🛑 Cast, never read raw. Phase 20's finding: "a cache read returns
             * whatever the driver made of the value" — the array store returns
             * what it was given and Redis returns what it serialised, and a
             * boolean that came back as the string "1" would make `is_bool`
             * false and a strict comparison wrong. The whole payload is
             * normalised on the way out for that reason.
             */
            allowNetworkOnlyAccess: (bool) $cached['allow_network_only'],
            epoch: (int) $cached['epoch'],
        );
    }

    /**
     * Create a project's policy row.
     *
     * 🛑 One per project, enforced by a UNIQUE index, because §8.12.8 depends
     * on there being nowhere else for a policy to live: "a collection holds no
     * policy of its own … so a widening inheritance flag would have nothing to
     * inherit from".
     *
     * @param  bool  $allowNetworkOnlyAccess  §8.12.7's audited escape. 🛑 The
     *                                        caller is the UI, which §8.12.7
     *                                        requires to flag it weak; the audit
     *                                        record is written here so it cannot
     *                                        be set silently.
     *
     * @throws PolicyRefused
     */
    public function createFor(Project $project, bool $allowNetworkOnlyAccess = false, ?string $actorId = null): string
    {
        $id = Uuid::v7();

        DB::table('reader_policies')->insert([
            'id' => $id,
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'fail_mode' => 'closed',
            'default_effect' => 'deny',
            'allow_network_only_access' => $allowNetworkOnlyAccess,
            'epoch' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->settle(
            $project,
            'reader_policy.created',
            $actorId,
            ['network_only' => $allowNetworkOnlyAccess ? '1' : '0'],
        );

        return $id;
    }

    /**
     * Add a rule, refusing everything §8.12 refuses at write time.
     *
     * @param  array<string, mixed>  $requirement  the raw tree, validated here
     * @param  list<string>  $versionSlugs
     * @param  list<string>  $languages
     * @param  list<string>  $pathPatterns  🛑 §12.3: "expressed **relative to a
     *                                      component mount**. Changing a mount
     *                                      prefix therefore invalidates
     *                                      dependent path rules and MUST
     *                                      require re-confirmation." The
     *                                      re-confirmation is the dashboard's
     *                                      (Phase 26); what is enforceable here
     *                                      is that the pattern is a literal
     *                                      prefix and not a regex.
     *
     * @throws PolicyRefused
     */
    public function addRule(
        Project $project,
        string $label,
        bool $allow,
        array $requirement,
        array $versionSlugs = [],
        array $languages = [],
        array $pathPatterns = [],
        bool $publicCacheMode = false,
        ?bool $listedOverride = null,
        bool $shadow = false,
        ?int $position = null,
        ?int $grantTtlSeconds = null,
        ?string $actorId = null,
    ): string {
        $policy = DB::table('reader_policies')->where('project_id', $project->id)->first(['id', 'allow_network_only_access']);

        if ($policy === null) {
            throw PolicyRefused::of(
                RequirementRejection::Malformed,
                'the project has no reader policy; create one first',
            );
        }

        $policyId = (string) $policy->id;

        $existing = DB::table('reader_policy_rules')->where('policy_id', $policyId)->count();

        if ($existing >= self::MAX_RULES_PER_PROJECT) {
            throw PolicyRefused::of(
                RequirementRejection::TooManyRules,
                self::MAX_RULES_PER_PROJECT.' rules is the cap for one project (§10.6)',
            );
        }

        $parsed = Requirement::parse($requirement, (bool) $policy->allow_network_only_access);

        $this->assertRuleStorable($parsed, $pathPatterns, $publicCacheMode);

        if ($position === null) {
            // `max()` is null on an empty table and mixed to the analyser, so
            // the narrowing is explicit: the first rule takes position 1.
            $highest = DB::table('reader_policy_rules')->where('policy_id', $policyId)->max('position');

            $position = (is_numeric($highest) ? (int) $highest : 0) + 1;
        }

        if (DB::table('reader_policy_rules')->where('policy_id', $policyId)->where('position', $position)->exists()) {
            throw PolicyRefused::of(
                RequirementRejection::DuplicatePosition,
                'position '.$position.' is taken; first-match-wins cannot resolve a tie',
            );
        }

        $id = Uuid::v7();

        DB::table('reader_policy_rules')->insert([
            'id' => $id,
            'organisation_id' => $project->organisation_id,
            'policy_id' => $policyId,
            'position' => $position,
            'label' => $label,
            // Already lists by declared type, so no `array_values` — JSON would
            // otherwise encode a gapped array as an object and the reader would
            // get a shape its own type annotation forbids.
            'version_selector' => json_encode(['slugs' => $versionSlugs, 'languages' => $languages]),
            'path_patterns' => json_encode($pathPatterns),
            'effect' => $allow ? 'allow' : 'deny',
            'requirement' => json_encode($parsed->toArray()),
            'grant_ttl_seconds' => $grantTtlSeconds,
            'cache_mode' => $publicCacheMode ? 'public' : 'private',
            'listed_override' => $listedOverride,
            'shadow' => $shadow,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->settle($project, 'reader_policy_rule.created', $actorId, [
            'rule' => Uuid::toText($id),
            'position' => (string) $position,
            'effect' => $allow ? 'allow' : 'deny',
        ]);

        return $id;
    }

    /**
     * 🛑 §12.3 / §8.12.8's narrowing-only override, refused at write time.
     *
     * > "`mount_exposure` MUST satisfy `narrows(mount_exposure,
     * > project.visibility)`; a write that would not is refused (§8.12.8)."
     *
     * §17's exit criterion asks for both directions: "A per-domain override
     * that would widen access is rejected; one that narrows is accepted."
     *
     * 🛑 This duplicates no logic. `App\Collections\MountExposure` holds the
     * same refusal for the collection-membership path, where the rejection
     * vocabulary is `CollectionRejection`; both call the one relation on
     * {@see AccessLevel}, which is where §12.3 puts it ("one relation rather
     * than three mappings"). What must never be duplicated is the *relation* —
     * and it is not.
     *
     * @throws PolicyRefused
     */
    /**
     * 🛑 Every project whose reader policy has **no rules**, for §8.12.19's
     * red banner.
     *
     * > "A zero-rule policy MUST deny with a red banner."
     *
     * The **denial** needs no code: §10.6 makes `reader_policies.default_effect`
     * a single-valued `ENUM('deny')`, so a policy with no rules denies
     * everything by construction. What was missing is anybody being *told*, and
     * telling them is a read of the policy tables — which is why it is here.
     * This class is their sole reader (asserted by the architecture suite),
     * because first-match-wins has exactly one reading and a second query is a
     * second reading.
     *
     * 🛑 Across every organisation, and deliberately: an installation
     * operator asking "is anything misconfigured" is asking about the
     * installation. The caller spans the scope; this method does the counting.
     *
     * @return list<string> project slugs, sorted
     */
    /**
     * Every project that has a reader policy, for §8.12.22's nightly linter.
     *
     * 🛑 Here rather than in the command, and §17's Phase 21 exit criterion is
     * why: "the architecture test fails when a second class reads the policy
     * tables". The reason that invariant exists is §8.12.6's first-match-wins —
     * "not what anybody writes by accident" — and the discipline is worth more
     * than the three lines it costs. {@see self::projectsWithNoRules()} is the
     * same shape, for `doctor`.
     *
     * Returns the four facts the linter needs and nothing else: it loads each
     * policy through {@see self::forProject()} anyway, so handing it rows would
     * be a second decode of the selectors.
     *
     * @param  string|null  $projectId  raw 16 bytes to narrow to one project
     * @return list<array{id: string, organisation_id: string, slug: string, authz_epoch: int}>
     */
    public function projectsWithAPolicy(?string $projectId = null): array
    {
        $query = DB::table('reader_policies')
            ->join('projects', 'projects.id', '=', 'reader_policies.project_id')
            ->whereNull('projects.deleted_at')
            ->select([
                'projects.id',
                'projects.organisation_id',
                'projects.slug',
                'projects.authz_epoch',
            ])
            ->orderBy('projects.slug');

        if ($projectId !== null) {
            $query->where('projects.id', $projectId);
        }

        $projects = [];

        foreach ($query->get() as $row) {
            $projects[] = [
                'id' => (string) $row->id,
                'organisation_id' => (string) $row->organisation_id,
                'slug' => is_string($row->slug) ? $row->slug : '?',
                'authz_epoch' => (int) $row->authz_epoch,
            ];
        }

        return $projects;
    }

    /**
     * Every project whose policy has no rules at all, for `doctor`.
     *
     * 🛑 §8.12.19's zero-rule policy denies everybody rather than falling back
     * to public, so this is a configuration state an operator has to be told
     * about by name — a project nobody can read looks identical to a project
     * nobody has published.
     *
     * @return list<string> project slugs
     */
    public function projectsWithNoRules(): array
    {
        $slugs = [];

        $rows = DB::table('reader_policies')
            ->leftJoin('reader_policy_rules', 'reader_policy_rules.policy_id', '=', 'reader_policies.id')
            ->leftJoin('projects', 'projects.id', '=', 'reader_policies.project_id')
            ->whereNull('reader_policy_rules.id')
            ->orderBy('projects.slug')
            ->get(['projects.slug']);

        foreach ($rows as $row) {
            $slugs[] = is_string($row->slug) ? $row->slug : '?';
        }

        return $slugs;
    }

    public function assertOverrideNarrows(string $mountExposure, AccessLevel $projectVisibility): void
    {
        $mount = AccessLevel::tryFrom($mountExposure);

        if ($mount === null) {
            // `inherit`, which takes the project's value and so widens nothing.
            return;
        }

        if (! $mount->narrows($projectVisibility)) {
            throw PolicyRefused::of(
                RequirementRejection::ExposureWidens,
                '🛑 '.$mountExposure.' would widen '.$projectVisibility->value.' (§8.12.8)',
            );
        }
    }

    /**
     * The write-time invariants that are about a rule rather than its tree.
     *
     * @param  list<string>  $pathPatterns
     *
     * @throws PolicyRefused
     */
    private function assertRuleStorable(Requirement $requirement, array $pathPatterns, bool $publicCacheMode): void
    {
        foreach ($pathPatterns as $pattern) {
            PathPrefix::assertLiteral($pattern);
        }

        /*
         * 🛑 §9.3.2, as data rather than as code. `cache_mode = 'public'` is the
         * third input to the single three-way public check, so a rule that
         * demanded a credential and declared itself publicly cacheable would
         * put a private response in a shared cache — the exact failure the
         * architecture test around `CachePolicy` exists to prevent, arriving
         * through a form instead of through a commit.
         *
         * Permitted only on the literal public terminal, which is the same
         * strictness §8.12.7 applies for its own exception.
         */
        if ($publicCacheMode && ! $requirement->isPublicTerminal()) {
            throw PolicyRefused::of(
                RequirementRejection::PublicCacheModeNeedsPublicTerminal,
                '🛑 §9.3.2: only a rule whose requirement is literally {"leaf":"public"} may be publicly cacheable',
            );
        }

        $this->assertBindingLeavesAgree($requirement);
    }

    /**
     * 🛑 §8.12.17's classification, checked against the **referenced
     * binding** and not only against a declared `driver`.
     *
     * {@see Requirement::validateLeaf()} already refuses
     * `{"leaf": "binding", "driver": "ip_allowlist"}` — that is corpus case
     * `authz-004`. It cannot refuse `{"leaf": "binding", "binding_id": "<an
     * ip_allowlist binding>"}`, because the driver type is a database row and a
     * requirement is a value object parsed on the serving path, where
     * {@see EffectiveAccess} must issue no queries.
     *
     * 🛑 **Phase 23 added this check and the corpus case `provider-009`
     * found that it was missing.** The gap failed *closed* — a gate records no
     * binding id at read time, so such a rule admitted nobody — but failing
     * closed silently is the configuration mistake §8.12.7's family of
     * write-time refusals exists to prevent: the rule reads as "signed in via
     * the office allowlist" and in fact denies everybody, and the operator's
     * only evidence is readers reporting a 404.
     *
     * A binding id naming no row is **not** refused here. A rule may legitimately
     * be written before its binding exists, or outlive one an operator removed,
     * and §8.12.19 already makes a *referenced* binding undeletable — so the
     * only reachable case is a rule written ahead of its binding, which denies
     * until the binding appears and discloses nothing meanwhile.
     *
     * @throws PolicyRefused
     */
    private function assertBindingLeavesAgree(Requirement $requirement): void
    {
        foreach ($requirement->bindingLeaves() as $pair) {
            $id = Uuid::tryToBytes($pair['binding_id']);

            if ($id === null) {
                throw PolicyRefused::of(
                    RequirementRejection::Malformed,
                    'binding_id is not a UUID',
                );
            }

            /*
             * The query builder, not a model, so §8.2.1's global scope does not
             * apply — which is what this lookup needs: an installation-scoped
             * binding has a NULL `organisation_id` and a rule naming one is
             * exactly the case §8.12.3's resolution exists for. The same reason
             * {@see \App\Auth\Providers\Bindings::forProject()} queries this
             * table directly.
             *
             * 🛑 And this reads a **type**, never grants anything. The
             * outcome can only be a refusal, so an id belonging to another
             * organisation cannot widen a rule — §12.3 matches at read time on
             * the ids `Bindings::forProject()` returns, which are scoped.
             */
            $type = DB::table('auth_provider_bindings')->where('id', $id)->value('type');

            if (! is_string($type)) {
                continue;
            }

            $classified = AccessLeaf::forDriver($type);

            if ($classified === null) {
                throw PolicyRefused::of(
                    RequirementRejection::UnknownDriver,
                    '§8.12.17 does not classify driver `'.$type.'`',
                );
            }

            if ($classified !== $pair['leaf']) {
                throw PolicyRefused::of(
                    RequirementRejection::Malformed,
                    '§8.12.17 classifies binding driver `'.$type.'` as `'.$classified->value
                    .'`, so it cannot be named as `'.$pair['leaf']->value.'`',
                );
            }
        }
    }

    /**
     * Bump the epochs and write the audit record — one place, every write.
     *
     * 🛑 §10.8 makes a policy write bump **both** `authz_epoch` and
     * `policy_generation`, and routing them all through here is what makes that
     * true of every write rather than of the writes somebody remembered.
     *
     * @param  array<string, string>  $payload  §8.22.5: identifiers and fixed
     *                                          vocabulary only, never names or
     *                                          free text
     */
    private function settle(Project $project, string $action, ?string $actorId, array $payload): void
    {
        Invalidation::bumpAuthz(
            projectId: (string) $project->id,
            cause: 'policy',
            policyWrite: true,
            organisationId: (string) $project->organisation_id,
            actorId: $actorId,
        );

        Audit::record(
            action: $action,
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: (string) $project->organisation_id,
            actorId: $actorId,
            subjectType: 'project',
            subjectId: (string) $project->id,
            payload: $payload,
        );
    }

    /**
     * One query for the policy, one for its rules.
     *
     * @param  string  $projectId  raw 16 bytes
     * @return array{exists: bool, allow_network_only: bool, epoch: int, rules: list<array<string, mixed>>}
     */
    private function load(string $projectId): array
    {
        $policy = DB::table('reader_policies')
            ->where('project_id', $projectId)
            ->first(['id', 'allow_network_only_access', 'epoch']);

        if ($policy === null) {
            return ['exists' => false, 'allow_network_only' => false, 'epoch' => 0, 'rules' => []];
        }

        $rules = [];

        foreach (
            DB::table('reader_policy_rules')
                ->where('policy_id', $policy->id)
                ->orderBy('position')
                ->get([
                    'id', 'position', 'label', 'effect', 'requirement', 'version_selector',
                    'path_patterns', 'cache_mode', 'listed_override', 'shadow',
                    'not_before', 'not_after', 'grant_ttl_seconds',
                ]) as $row
        ) {
            $rules[] = [
                'id' => Uuid::toText((string) $row->id),
                'position' => (int) $row->position,
                'label' => (string) $row->label,
                'allow' => $row->effect === 'allow',
                'requirement' => (string) $row->requirement,
                'version_selector' => (string) $row->version_selector,
                'path_patterns' => (string) $row->path_patterns,
                'publicly_cacheable' => $row->cache_mode === 'public',
                'listed_override' => $row->listed_override === null ? null : (bool) $row->listed_override,
                'shadow' => (bool) $row->shadow,
                'not_before' => $row->not_before === null ? null : strtotime((string) $row->not_before),
                'not_after' => $row->not_after === null ? null : strtotime((string) $row->not_after),
                'grant_ttl_seconds' => $row->grant_ttl_seconds === null ? null : (int) $row->grant_ttl_seconds,
            ];
        }

        return [
            'exists' => true,
            'allow_network_only' => (bool) $policy->allow_network_only_access,
            'epoch' => (int) $policy->epoch,
            'rules' => $rules,
        ];
    }

    /**
     * Turn one cached row into a {@see PolicyRule}.
     *
     * 🛑 Returns **null** on a row this code cannot interpret, and the caller
     * drops it. That is the fail-closed direction and it needs saying: a
     * malformed `allow` rule that was skipped denies, while one that was
     * admitted with a requirement nobody could parse would be an allow with no
     * condition on it. {@see Requirement::parse()} would throw, and throwing on
     * the serving path turns one bad row into a 500 for every reader of the
     * project — so the row is dropped and the policy's default deny applies.
     *
     * @param  array<string, mixed>  $row
     */
    private function hydrate(array $row): ?PolicyRule
    {
        $requirement = json_decode(is_string($row['requirement'] ?? null) ? $row['requirement'] : '', true);

        if (! is_array($requirement)) {
            return null;
        }

        $selector = json_decode(is_string($row['version_selector'] ?? null) ? $row['version_selector'] : '', true);
        $patterns = json_decode(is_string($row['path_patterns'] ?? null) ? $row['path_patterns'] : '', true);

        try {
            /** @var array<string, mixed> $requirement */
            $parsed = Requirement::parse($requirement, allowNetworkOnly: true);
        } catch (PolicyRefused) {
            /*
             * 🛑 `allowNetworkOnly: true` here, and it is not a loosening. The
             * satisfiability invariant is a **write-time** rule (§8.12.7) and a
             * stored row has already passed it under the policy's own flag,
             * which may since have been turned off. Re-applying it at read time
             * would mean clearing the flag silently changed a rule's meaning —
             * the operator would have to re-save fifty rules to discover which.
             * The audited flag is what §8.12.7 makes the decision, and it was
             * made when the rule was written.
             */
            return null;
        }

        return new PolicyRule(
            id: is_string($row['id'] ?? null) ? $row['id'] : null,
            position: is_numeric($row['position'] ?? null) ? (int) $row['position'] : 0,
            label: is_string($row['label'] ?? null) ? $row['label'] : '',
            allow: (bool) ($row['allow'] ?? false),
            requirement: $parsed,
            versionSlugs: self::strings(is_array($selector) ? ($selector['slugs'] ?? []) : []),
            languages: self::strings(is_array($selector) ? ($selector['languages'] ?? []) : []),
            pathPrefixes: self::strings($patterns),
            publicCacheMode: (bool) ($row['publicly_cacheable'] ?? false),
            listedOverride: is_bool($row['listed_override'] ?? null) ? $row['listed_override'] : null,
            shadow: (bool) ($row['shadow'] ?? false),
            notBefore: is_numeric($row['not_before'] ?? null) ? (int) $row['not_before'] : null,
            notAfter: is_numeric($row['not_after'] ?? null) ? (int) $row['not_after'] : null,
            grantTtlSeconds: is_numeric($row['grant_ttl_seconds'] ?? null) ? (int) $row['grant_ttl_seconds'] : null,
        );
    }

    /**
     * A list of strings from whatever JSON decoding produced.
     *
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $strings[] = $item;
            }
        }

        return $strings;
    }
}
