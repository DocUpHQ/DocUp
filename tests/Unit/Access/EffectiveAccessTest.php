<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Access;

use App\Access\AccessLeaf;
use App\Access\AccessReason;
use App\Access\AccessRequest;
use App\Access\AccessSurface;
use App\Access\CredentialScope;
use App\Access\EffectiveAccess;
use App\Access\PolicyRule;
use App\Access\ReaderContext;
use App\Access\ReaderPolicy;
use App\Access\Requirement;
use App\Auth\AccessLevel;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §12.3's six conjuncts, one at a time, plus §8.12.23's status rules.
 *
 * ```
 * decision = DENY unless ALL of:
 *   project.visibility permits                                (§8.2.10)
 *   reader_policy first-match rule effect = allow             (§8.12.6)
 *   project_version.visibility permits                        (§8.6.2)
 *   domain_mount.mount_exposure permits   — narrow only       (§8.10.1)
 *   component.min_access_snapshot permits — AFTER mount match (§8.7.7)
 *   share/bearer scope covers (project, version, path)
 * ```
 *
 * The generated 48-case matrix in {@see DecisionTableTest} is the exit
 * criterion; these are the cases the matrix deliberately leaves out, because
 * each needs a policy, a scope or a component the matrix holds constant.
 */
final class EffectiveAccessTest extends TestCase
{
    /** 🛑 §8.2.10's kill switch dominates a permissive version and a permissive rule. */
    public function test_project_visibility_dominates_everything(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Members,
            versionVisibility: AccessLevel::Public,
            // A rule that admits everybody, on a project that admits nobody.
            policy: ReaderPolicy::of([$this->publicRule()]),
            reader: ReaderContext::anonymous(),
        ));

        $this->assertFalse($decision->allowed);
        $this->assertSame(AccessReason::ProjectVisibility, $decision->reason);
        $this->assertSame(
            AccessLevel::Members,
            $decision->required,
            'the strongest demand is reported even when an earlier conjunct refused',
        );
    }

    /**
     * 🛑 §8.12.19: "A zero-rule policy MUST deny with a red banner."
     *
     * And it must be distinguishable from "no rule matched", because the two
     * need different operator responses: no match means the selectors are
     * wrong, no rules means nobody has written one.
     */
    public function test_a_zero_rule_policy_denies(): void
    {
        $empty = EffectiveAccess::decide($this->request(policy: ReaderPolicy::of([])));

        $this->assertFalse($empty->allowed);
        $this->assertSame(AccessReason::PolicyEmpty, $empty->reason);

        // A policy with a rule that does not match this version.
        $noMatch = EffectiveAccess::decide($this->request(
            policy: ReaderPolicy::of([$this->publicRule(versionSlugs: ['v1'])]),
        ));

        $this->assertFalse($noMatch->allowed);
        $this->assertSame(AccessReason::PolicyDefaultDeny, $noMatch->reason);
    }

    /**
     * 🛑 §8.12.6's first-match-wins, and the half that is easy to get wrong:
     * evaluation **stops** at the first matching rule.
     *
     * A deny at position 1 is not overridden by an allow at position 2. The
     * natural way to read an ordered rule list is to iterate it looking for an
     * allow, and that turns a list containing a deny into a list that ignores
     * it — which is why §17 gives the policy tables a sole-reader architecture
     * test.
     */
    public function test_a_deny_at_the_first_match_is_not_overridden_by_a_later_allow(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            policy: ReaderPolicy::of([
                new PolicyRule(
                    id: null,
                    position: 1,
                    label: 'the internal section is nobody\'s',
                    allow: false,
                    requirement: Requirement::parse(['leaf' => 'public']),
                    pathPrefixes: ['/internal'],
                ),
                $this->publicRule(position: 2),
            ]),
            path: '/internal/runbook.html',
        ));

        $this->assertFalse($decision->allowed);
        $this->assertSame(AccessReason::RuleDenied, $decision->reason);
        $this->assertSame(1, $decision->rule?->position);
    }

    /**
     * 🛑 §12.3's `restricted` rung: an explicit allow rule **naming** the
     * version, and nothing weaker.
     *
     * > "`restricted` … only a reader satisfying an explicit allow rule naming
     * > this component or version."
     *
     * This is what makes the fourth level different from `members`. Without it
     * the two would behave identically and the lattice would have three values
     * and a label.
     */
    public function test_restricted_needs_a_rule_that_names_the_resource(): void
    {
        $wildcard = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Restricted,
            policy: ReaderPolicy::of([$this->bindingRule()]),
            reader: ReaderContext::member('subject'),
        ));

        $this->assertFalse($wildcard->allowed, 'a wildcard rule cannot reach a restricted version');
        $this->assertSame(AccessReason::VersionVisibility, $wildcard->reason);

        $named = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Restricted,
            policy: ReaderPolicy::of([$this->bindingRule(versionSlugs: ['v2'])]),
            reader: ReaderContext::member('subject'),
        ));

        $this->assertTrue($named->allowed, 'a rule naming the version reaches it');
        $this->assertSame(AccessLevel::Restricted, $named->established);
    }

    /**
     * 🛑 §8.10.1's `mount_exposure` narrows one domain and widens none.
     *
     * §17's exit criterion: "A per-domain override that would widen access is
     * rejected; one that narrows is accepted." The write-time half is
     * `ReaderPolicies::assertOverrideNarrows()`; this is the read-time half,
     * which has to hold even for a row that predates the refusal.
     */
    public function test_mount_exposure_narrows_and_never_widens(): void
    {
        // Narrowing: a public project exposed at `members` on this domain.
        $narrowed = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Public,
            versionVisibility: AccessLevel::Public,
            mountExposure: 'members',
            reader: ReaderContext::anonymous(),
        ));

        $this->assertFalse($narrowed->allowed);
        $this->assertSame(AccessReason::MountExposure, $narrowed->reason);

        /*
         * 🛑 And the widening direction has no effect, which is the property
         * that matters: a stored `public` exposure on a `members` project — a
         * row written before the refusal existed, or by hand — must not open
         * it. §12.3's intersection is the maximum of the demands, so the
         * project's own value stands.
         */
        $widened = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Members,
            versionVisibility: AccessLevel::Public,
            mountExposure: 'public',
            reader: ReaderContext::anonymous(),
        ));

        $this->assertFalse($widened->allowed, '🛑 a widening exposure must not open a guarded project');
        $this->assertSame(AccessReason::ProjectVisibility, $widened->reason);
    }

    /** `inherit` takes the project's value, which is what the sentinel means. */
    public function test_inherit_resolves_to_the_project_visibility(): void
    {
        $request = $this->request(
            projectVisibility: AccessLevel::Members,
            mountExposure: 'inherit',
        );

        $this->assertSame(AccessLevel::Members, $request->resolvedMountExposure());

        // And so does a value this code has not been taught, which is the
        // fail-safe direction.
        $this->assertSame(
            AccessLevel::Members,
            $this->request(projectVisibility: AccessLevel::Members, mountExposure: 'something_new')
                ->resolvedMountExposure(),
        );
    }

    /**
     * 🛑 §8.7.7's component ceiling, which is checked **after** mount matching
     * and can refuse a request every other conjunct allowed.
     *
     * The requirement's reason: without it "any project admin in the
     * organisation can mount any component onto a public project — a
     * declassification primitive in a product whose headline feature is
     * per-project authentication".
     */
    public function test_the_component_ceiling_can_refuse_what_the_version_allowed(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Public,
            versionVisibility: AccessLevel::Public,
            componentMinAccess: AccessLevel::Members,
            reader: ReaderContext::anonymous(),
        ));

        $this->assertFalse($decision->allowed);
        $this->assertSame(AccessReason::ComponentMinAccess, $decision->reason);
        $this->assertSame(AccessLevel::Members, $decision->required);

        // A member passes it, and the public project stays public for them.
        $member = EffectiveAccess::decide($this->request(
            componentMinAccess: AccessLevel::Members,
            reader: ReaderContext::member('subject'),
        ));

        $this->assertTrue($member->allowed);
    }

    /**
     * 🛑 §12.3's last conjunct: a share or bearer scope that does not cover the
     * path refuses — **and only when that leaf was the satisfying one**.
     */
    public function test_a_bearer_scope_must_cover_the_path(): void
    {
        $scoped = new ReaderContext(
            level: AccessLevel::Authenticated,
            satisfiedLeaves: [AccessLeaf::Public, AccessLeaf::Bearer],
            credentialPresented: true,
            scope: new CredentialScope(pathPrefixes: ['/api']),
            subject: 'token-subject',
        );

        $policy = ReaderPolicy::of([
            new PolicyRule(
                id: null,
                position: 1,
                label: 'token readers',
                allow: true,
                requirement: Requirement::parse(['leaf' => 'bearer', 'driver' => 'reader_token']),
            ),
        ]);

        $covered = EffectiveAccess::decide($this->request(policy: $policy, reader: $scoped, path: '/api/v1.html'));

        $this->assertTrue($covered->allowed);
        $this->assertSame(AccessLeaf::Bearer, $covered->satisfiedBy);

        $outside = EffectiveAccess::decide($this->request(policy: $policy, reader: $scoped, path: '/guide/intro.html'));

        $this->assertFalse($outside->allowed);
        $this->assertSame(AccessReason::ScopeMismatch, $outside->reason);
    }

    /**
     * 🛑 And the conditional half: a reader whose **stronger** leaf satisfied
     * the requirement is not held to a scope they did not need.
     *
     * The first implementation of `Requirement::satisfyingLeaf()` tested each
     * leaf kind with a null binding id, which reported `binding` for a reader
     * who had in fact only satisfied `share` — and §12.3's conjunct being
     * conditional meant the scope check was then skipped. That is a widening,
     * and this is the case that would catch it.
     */
    public function test_a_reader_is_judged_on_the_strongest_satisfying_leaf(): void
    {
        /*
         * The rule admits either a specific binding or a share link. The reader
         * holds a session for a DIFFERENT binding and a share link scoped to
         * `/v1`. Only the share leaf satisfies, so the scope must apply.
         */
        $policy = ReaderPolicy::of([
            new PolicyRule(
                id: null,
                position: 1,
                label: 'employees or a link',
                allow: true,
                requirement: Requirement::parse(['any' => [
                    ['leaf' => 'binding', 'driver' => 'oidc', 'binding_id' => 'binding-A'],
                    ['leaf' => 'share', 'driver' => 'shared_link'],
                ]]),
            ),
        ]);

        $reader = new ReaderContext(
            level: AccessLevel::Authenticated,
            satisfiedLeaves: [AccessLeaf::Public, AccessLeaf::Binding, AccessLeaf::Share],
            // 🛑 A session for binding B, not the binding the rule names.
            satisfiedBindings: ['binding-B'],
            credentialPresented: true,
            scope: new CredentialScope(pathPrefixes: ['/v1']),
            subject: 'subject',
        );

        $decision = EffectiveAccess::decide($this->request(policy: $policy, reader: $reader, path: '/v2/secret.html'));

        $this->assertFalse(
            $decision->allowed,
            '🛑 the share link is the satisfying leaf, so its scope must apply',
        );
        $this->assertSame(AccessReason::ScopeMismatch, $decision->reason);

        // And with the binding the rule names, the share scope is irrelevant.
        $employee = new ReaderContext(
            level: AccessLevel::Authenticated,
            satisfiedLeaves: [AccessLeaf::Public, AccessLeaf::Binding, AccessLeaf::Share],
            satisfiedBindings: ['binding-A'],
            credentialPresented: true,
            scope: new CredentialScope(pathPrefixes: ['/v1']),
            subject: 'subject',
        );

        $allowed = EffectiveAccess::decide($this->request(policy: $policy, reader: $employee, path: '/v2/secret.html'));

        $this->assertTrue($allowed->allowed);
        $this->assertSame(AccessLeaf::Binding, $allowed->satisfiedBy);
    }

    /**
     * 🛑 §8.12.23's `deny_status`, with its authenticated-only constraint.
     *
     * > "A per-project `deny_status='403'` MUST be available for
     * > **authenticated** principals only, never anonymous."
     *
     * A 403 to an anonymous request confirms the resource exists, and the
     * project's own preference is not permitted to override that — the project
     * does not bear the consequence.
     */
    public function test_deny_status_403_is_for_authenticated_principals_only(): void
    {
        $anonymous = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Restricted,
            reader: ReaderContext::anonymous(),
            denyStatus: 403,
        ));

        $this->assertSame(404, $anonymous->status, '🛑 §8.12.23: never 403 for an anonymous reader');

        $member = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Restricted,
            reader: ReaderContext::member('subject'),
            denyStatus: 403,
        ));

        $this->assertSame(403, $member->status);

        // And a project that did not configure it gets 404 either way.
        $default = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Restricted,
            reader: ReaderContext::member('subject'),
        ));

        $this->assertSame(404, $default->status);
    }

    /**
     * 🛑 §8.12.23 permits a 401 in exactly two cases and this asserts both,
     * plus the much larger case where it does not.
     */
    public function test_a_401_is_permitted_in_exactly_two_cases(): void
    {
        // (a) a credential was presented and rejected.
        $rejected = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Members,
            reader: new ReaderContext(credentialPresented: true, credentialRejected: true),
        ));

        $this->assertSame(401, $rejected->status);
        $this->assertSame(AccessReason::CredentialRejected, $rejected->reason);
        $this->assertTrue($rejected->mayChallenge());

        // (b) the resource's existence is already public.
        $publicExistence = EffectiveAccess::decide($this->request(
            versionVisibility: AccessLevel::Members,
            reader: ReaderContext::anonymous(),
            existencePublic: true,
        ));

        $this->assertSame(401, $publicExistence->status);
        $this->assertSame(AccessReason::AuthenticationRequired, $publicExistence->reason);

        /*
         * 🛑 And the default: "In every other case, including an anonymous
         * non-interactive request for a resource whose existence is private,
         * the response is the project's `deny_status` with **no**
         * `WWW-Authenticate` header." The header is the disclosure — it tells
         * a crawler there is something here to authenticate for.
         */
        $private = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Members,
            reader: ReaderContext::anonymous(),
        ));

        $this->assertSame(404, $private->status);
        $this->assertFalse($private->mayChallenge(), '🛑 no challenge for a resource whose existence is private');
    }

    /**
     * 🛑 §8.12.21's fail-closed search gate: stale index, no answer.
     *
     * > "a project's search MUST be **disabled** while its search generation
     * > lags its policy generation"
     *
     * And it is the one place the surface axis changes an answer, which is what
     * makes that axis real rather than decorative.
     */
    public function test_search_is_disabled_while_its_generation_lags(): void
    {
        $stale = EffectiveAccess::decide($this->request(
            surface: AccessSurface::Search,
            policyGeneration: 7,
            searchGeneration: 6,
        ));

        $this->assertFalse($stale->allowed);
        $this->assertSame(AccessReason::SearchGenerationStale, $stale->reason);

        // The other three surfaces read the live rows and are unaffected.
        foreach ([AccessSurface::Proxy, AccessSurface::Download, AccessSurface::Addons] as $surface) {
            $this->assertTrue(
                EffectiveAccess::decide($this->request(
                    surface: $surface,
                    policyGeneration: 7,
                    searchGeneration: 6,
                ))->allowed,
                $surface->value.' does not read the index and must be unaffected',
            );
        }

        // Caught up, and search answers again.
        $this->assertTrue(
            EffectiveAccess::decide($this->request(
                surface: AccessSurface::Search,
                policyGeneration: 7,
                searchGeneration: 7,
            ))->allowed,
        );
    }

    /**
     * 🛑 §8.12.19: "A degraded binding MUST **deny** with a branded 503 … never
     * fall back to another provider, never to public."
     *
     * 503 rather than 404, because this is an outage and an operator must be
     * able to tell it from a policy refusal. Asserted on a **public** project,
     * which is the case where falling back to public would look harmless.
     */
    public function test_a_degraded_binding_denies_with_503_and_never_falls_back(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            projectVisibility: AccessLevel::Public,
            versionVisibility: AccessLevel::Public,
            bindingDegraded: true,
        ));

        $this->assertFalse($decision->allowed);
        $this->assertSame(503, $decision->status);
        $this->assertSame(AccessReason::BindingDegraded, $decision->reason);
    }

    /**
     * 🛑 A shadow rule is recorded and never enforced, in both directions.
     *
     * It must not allow, and — the easier one to get wrong — it must not
     * **consume the first-match slot**, which would deny everything behind it.
     */
    public function test_a_shadow_rule_is_recorded_and_never_enforced(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            policy: ReaderPolicy::of([
                new PolicyRule(
                    id: null,
                    position: 1,
                    label: 'proposed: lock the guide down',
                    allow: false,
                    requirement: Requirement::parse(['leaf' => 'public']),
                    shadow: true,
                ),
                $this->publicRule(position: 2),
            ]),
        ));

        $this->assertTrue($decision->allowed, '🛑 a shadow rule must not consume the first-match slot');
        $this->assertSame(2, $decision->rule?->position);
        $this->assertSame(1, $decision->shadowRule?->position, 'and it is recorded');
    }

    /** §8.12.6's `not_before` / `not_after` window, over the passed-in clock. */
    public function test_a_rule_outside_its_window_does_not_match(): void
    {
        $rule = $this->publicRule(notBefore: 2_000, notAfter: 3_000);

        foreach ([1_999 => false, 2_000 => true, 2_999 => true, 3_000 => false] as $now => $matches) {
            $decision = EffectiveAccess::decide($this->request(
                policy: ReaderPolicy::of([$rule]),
                now: $now,
            ));

            $this->assertSame($matches, $decision->allowed, 'at '.$now);
        }
    }

    /**
     * 🛑 §8.12.9's segment boundary: `/internal` does not cover
     * `/internal-notes`.
     *
     * The same mistake §18.8 records on the routing side — a mount at `api`
     * must not match `apiary/…` — and here the two directions of the error are
     * "a reader sees a page they may not" and "a reader is refused a page they
     * may". Neither is visible to an operator reading their own policy, because
     * the policy says `/internal`.
     */
    public function test_a_path_rule_matches_on_a_segment_boundary(): void
    {
        $policy = ReaderPolicy::of([
            new PolicyRule(
                id: null,
                position: 1,
                label: 'the internal section',
                allow: false,
                requirement: Requirement::parse(['leaf' => 'public']),
                pathPrefixes: ['/internal'],
            ),
            $this->publicRule(position: 2),
        ]);

        foreach (['/internal' => false, '/internal/x.html' => false, '/internal-notes/x.html' => true, '/internals.html' => true] as $path => $allowed) {
            $this->assertSame(
                $allowed,
                EffectiveAccess::decide($this->request(policy: $policy, path: $path))->allowed,
                $path,
            );
        }
    }

    // ---------------------------------------------------------------- helpers

    private function request(
        AccessLevel $projectVisibility = AccessLevel::Public,
        AccessLevel $versionVisibility = AccessLevel::Public,
        string $mountExposure = 'inherit',
        ?ReaderPolicy $policy = null,
        ?ReaderContext $reader = null,
        string $path = '/guide/intro.html',
        AccessSurface $surface = AccessSurface::Proxy,
        ?AccessLevel $componentMinAccess = null,
        int $denyStatus = 404,
        int $now = 2_500,
        int $policyGeneration = 0,
        int $searchGeneration = 0,
        bool $existencePublic = false,
        bool $bindingDegraded = false,
    ): AccessRequest {
        return new AccessRequest(
            projectId: str_repeat("\x22", 16),
            projectVisibility: $projectVisibility,
            versionVisibility: $versionVisibility,
            mountExposure: $mountExposure,
            policy: $policy ?? ReaderPolicy::absent(),
            reader: $reader ?? ReaderContext::anonymous(),
            versionSlug: 'v2',
            path: $path,
            surface: $surface,
            componentMinAccess: $componentMinAccess,
            denyStatus: $denyStatus,
            now: $now,
            policyGeneration: $policyGeneration,
            searchGeneration: $searchGeneration,
            existencePublic: $existencePublic,
            bindingDegraded: $bindingDegraded,
        );
    }

    /** @param list<string> $versionSlugs */
    private function publicRule(
        int $position = 1,
        array $versionSlugs = [],
        ?int $notBefore = null,
        ?int $notAfter = null,
    ): PolicyRule {
        return new PolicyRule(
            id: null,
            position: $position,
            label: 'everybody',
            allow: true,
            requirement: Requirement::parse(['leaf' => 'public']),
            versionSlugs: $versionSlugs,
            publicCacheMode: true,
            notBefore: $notBefore,
            notAfter: $notAfter,
        );
    }

    /** @param list<string> $versionSlugs */
    private function bindingRule(int $position = 1, array $versionSlugs = []): PolicyRule
    {
        return new PolicyRule(
            id: null,
            position: $position,
            label: 'signed-in readers',
            allow: true,
            requirement: Requirement::parse(['leaf' => 'binding', 'driver' => 'oidc']),
            versionSlugs: $versionSlugs,
        );
    }
}
