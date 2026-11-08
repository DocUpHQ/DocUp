<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

use App\Access\AccessLeaf;
use App\Access\EffectiveAccess;
use App\Access\PathPrefix;
use App\Access\PolicyFinding;
use App\Access\PolicyLinter;
use App\Access\PolicyObservation;
use App\Access\ReaderPolicies;
use App\Access\ReaderPolicy;
use App\Access\Requirement;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Notifications\PolicyReachabilityChanged;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 26a exit criterion for the linter.
 *
 * > "The nightly linter alerts when an edit changes a rule's reachability, and
 * > **a planted widening edit is caught**."
 *
 * ## 🛑 Why "planted" is the word that matters
 *
 * A linter that reports every rule's state every night satisfies §8.12.22 on
 * paper and is worthless: the operator filters its mail by the second week, and
 * §8.12.22's value was the one night the message was different. So every test
 * here runs the linter **twice** — once to establish last night, once after an
 * edit — and asserts on the difference. The property being tested is not "the
 * linter can describe a policy" but "the linter notices a change and says which
 * way it went".
 *
 * The planted edits are the four shapes a widening actually takes, and three of
 * them change no requirement at all:
 *
 * | Planted edit | Why it is easy to miss |
 * |---|---|
 * | a version selector widened | the rule still reads as a restriction |
 * | the identity requirement dropped | one word in a JSON tree, and §19/40's named failure mode |
 * | a rule taken out of `shadow` | nothing about the rule changed, only whether it is enforced |
 * | a deny rule narrowed | widening access by *shrinking* a rule, which reads backwards |
 *
 * ## 🛑 And a narrowing is reported too, in the other direction
 *
 * Not for symmetry — because an unintended narrowing is an outage, and the
 * asymmetry is already in the mail: {@see PolicyReachabilityChanged} leads with
 * the widenings. A rule narrowed too far produces a support ticket within the
 * hour; a rule widened too far produces nothing at all.
 */
final class PolicyLinterTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $owner;

    private Project $project;

    private ReaderPolicies $policies;

    private string $bindingId;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
        Notification::fake();

        $this->context = app(OrganisationContext::class);

        $this->organisation = Organisation::query()->create([
            'name' => 'Linter Co',
            'slug' => 'linter-'.bin2hex(random_bytes(3)),
        ]);

        $this->context->for($this->organisation->id);

        $this->owner = User::factory()->create();

        /* An owner, so §8.12.22's alert has somewhere to go. */
        DB::table('role_assignments')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->owner->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => 'org_admin',
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->project = Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'slug' => 'handbook',
            'name' => 'Handbook',
            'visibility' => 'members',
        ]);

        $this->policies = app(ReaderPolicies::class);
        $this->policies->createFor($this->project);

        $this->bindingId = $this->bind('Acme staff');
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ------------------------------------------------- reachability

    /**
     * 🛑 A shadowed rule, reported **with its cause**.
     *
     * §8.12.6 is first-match-wins, so a rule whose URLs are all covered by an
     * earlier rule can never decide. An operator told only "rule 2 is
     * unreachable" has to read their whole policy to find out why; the answer
     * is always another rule, and the linter already knows which.
     */
    public function test_a_shadowed_rule_is_reported_with_its_cause(): void
    {
        /* Rule 1 covers every version and every path. */
        $this->rule('everything', allow: true);
        $this->rule('just the guide', allow: true, versions: ['v1'], paths: ['/guide']);

        $observations = $this->lint();

        $this->assertCount(2, $observations);
        $this->assertTrue($observations[0]->reachable);

        $this->assertFalse($observations[1]->reachable);
        $this->assertContains(PolicyFinding::Shadowed, $observations[1]->findings);
        $this->assertSame(
            $observations[0]->position,
            $observations[1]->shadowedBy,
            '🛑 §8.12.22: the cause, not just the symptom',
        );
    }

    /** And a rule an earlier one does not fully cover stays reachable. */
    public function test_a_partially_overlapping_rule_is_not_shadowed(): void
    {
        $this->rule('v1 only', allow: true, versions: ['v1']);
        $this->rule('v1 and v2', allow: true, versions: ['v1', 'v2']);

        $observations = $this->lint();

        $this->assertTrue(
            $observations[1]->reachable,
            'a rule selecting a version the earlier one does not can still decide',
        );
        $this->assertNull($observations[1]->shadowedBy);
    }

    /**
     * 🛑 The path boundary is {@see PathPrefix}'s, not
     * `str_starts_with`'s.
     *
     * `/internal` covers `/internal/notes` and does **not** cover
     * `/internal-notes`. A linter that got this wrong would report a real rule
     * as dead — and an operator who deleted it on that advice would open the
     * section it was protecting.
     */
    public function test_a_sibling_path_prefix_is_not_covered(): void
    {
        $this->rule('internal', allow: true, paths: ['/internal']);
        $this->rule('internal notes', allow: true, paths: ['/internal-notes']);
        $this->rule('inside internal', allow: true, paths: ['/internal/deep']);

        $observations = $this->lint();

        $this->assertNull(
            $observations[1]->shadowedBy,
            '🛑 `/internal` must not cover `/internal-notes`',
        );
        $this->assertSame(
            $observations[0]->position,
            $observations[2]->shadowedBy,
            '`/internal` does cover `/internal/deep`',
        );
    }

    /**
     * 🛑 A deliberate shadow rule does not shadow the rules behind it.
     *
     * {@see ReaderPolicy::firstMatch()} skips shadow rules
     * entirely, so the two populations never compete. One ordering over both
     * would report every enforced rule behind a shadow rule as unreachable —
     * an alert on every policy that uses the feature, which is how a feature
     * gets abandoned.
     */
    public function test_a_shadow_rule_does_not_shadow_an_enforced_rule(): void
    {
        $this->rule('a trial', allow: true, shadow: true);
        $this->rule('the real one', allow: true);

        $observations = $this->lint();

        $this->assertFalse(
            $observations[0]->reachable,
            'a shadow rule cannot decide a request, by design',
        );
        $this->assertTrue($observations[1]->reachable);
        $this->assertNull($observations[1]->shadowedBy);
    }

    /** An expired rule can never match again, which is both unreachable and a fault. */
    public function test_an_expired_rule_is_unreachable_and_a_fault(): void
    {
        $this->rule('last year', allow: true, versions: ['v1']);

        DB::table('reader_policy_rules')
            ->where('label', 'last year')
            ->update(['not_after' => date('Y-m-d H:i:s.v', time() - 86400)]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertFalse($observations[0]->reachable);
        $this->assertContains(PolicyFinding::Expired, $observations[0]->findings);
        $this->assertTrue($observations[0]->isFaulty());
    }

    /**
     * 🛑 A rule live all year is not shadowed by one live for a week.
     *
     * §12.3 makes `not_before` and `not_after` part of matching, so they are
     * part of coverage. Ignoring the window would report the year-round rule as
     * dead for the fifty-one weeks it is the only one working.
     */
    public function test_a_time_limited_rule_does_not_shadow_a_permanent_one(): void
    {
        $this->rule('this week only', allow: true);
        $this->rule('always', allow: true);

        DB::table('reader_policy_rules')
            ->where('label', 'this week only')
            ->update([
                'not_before' => date('Y-m-d H:i:s.v', time() - 3600),
                'not_after' => date('Y-m-d H:i:s.v', time() + 604800),
            ]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertTrue($observations[1]->reachable);
        $this->assertNull($observations[1]->shadowedBy);
    }

    // ------------------------------------------------- §17: planted widenings

    /**
     * 🛑 **§17's criterion: a planted widening edit is caught.**
     *
     * The selector widens from one version to every version. The rule still
     * reads as a restriction — it still names a binding, it still has an allow
     * effect — and it now governs documentation it did not govern yesterday.
     */
    public function test_a_planted_selector_widening_is_caught(): void
    {
        $this->rule('staff read v1', allow: true, versions: ['v1']);

        $this->lint();      // establish last night

        $this->selectVersions('staff read v1', []);

        $observations = $this->lint();

        $this->assertContains(
            PolicyFinding::Widened,
            $observations[0]->changes,
            '🛑 §17: a planted widening edit must be caught',
        );
        $this->assertTrue($observations[0]->widened());
    }

    /**
     * 🛑 **The §19/40 failure mode, as one word in a JSON tree.**
     *
     * > "the observed failure mode is defaulting projects to public, which
     * > quietly voids G3"
     *
     * The rule's requirement goes from naming a binding to the public terminal.
     * Nothing else about the rule changes: same label, same position, same
     * selectors, same allow effect. Everybody on the internet can now read it.
     */
    public function test_dropping_the_identity_requirement_is_a_widening(): void
    {
        $this->rule('staff read the guide', allow: true, versions: ['v1']);

        $this->lint();

        DB::table('reader_policy_rules')
            ->where('label', 'staff read the guide')
            ->update(['requirement' => (string) json_encode(['leaf' => AccessLeaf::Public->value])]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(
            PolicyFinding::Widened,
            $observations[0]->changes,
            '🛑 §8.12.7: a tree satisfiable without identity is readable by anybody',
        );
    }

    /**
     * 🛑 A rule taken out of `shadow` starts being enforced, which is a
     * widening that changes nothing about the rule.
     *
     * No selector moved, no requirement changed, and the policy now admits
     * readers it did not admit yesterday — because §8.12.6's `firstMatch` was
     * skipping it and is not any more.
     */
    public function test_a_rule_leaving_shadow_is_a_widening(): void
    {
        $this->rule('a trial', allow: true, versions: ['v1'], shadow: true);

        $this->lint();

        DB::table('reader_policy_rules')->where('label', 'a trial')->update(['shadow' => false]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(PolicyFinding::Widened, $observations[0]->changes);
        $this->assertContains(
            PolicyFinding::ReachabilityChanged,
            $observations[0]->changes,
            '§8.12.22 names this one exactly: reachability changed',
        );
    }

    /**
     * 🛑 **Widening a deny rule narrows access**, and the alert has to say so.
     *
     * The direction is about access, not about the rule, and this is the case
     * where the two read backwards. §8.12.6 never evaluates a deny rule's
     * requirement — see {@see EffectiveAccess} — so for a deny rule
     * only the selectors move the needle, and more URLs refused is less access.
     *
     * An alert that labelled this "widened" would be an alert that cried wolf
     * about somebody tightening something, which teaches an operator to
     * disbelieve the word.
     */
    public function test_widening_a_deny_rule_is_reported_as_a_narrowing(): void
    {
        $this->rule('block the appendix', allow: false, paths: ['/appendix']);
        $this->rule('everything else', allow: true);

        $this->lint();

        /* The deny now covers every path rather than one. */
        DB::table('reader_policy_rules')
            ->where('label', 'block the appendix')
            ->update(['path_patterns' => (string) json_encode([])]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(
            PolicyFinding::Narrowed,
            $observations[0]->changes,
            '🛑 more URLs denied is less access, however much wider the rule is',
        );
        $this->assertNotContains(PolicyFinding::Widened, $observations[0]->changes);

        /* And the rule behind it is now unreachable, which is the real story. */
        $this->assertFalse($observations[1]->reachable);
        $this->assertContains(PolicyFinding::ReachabilityChanged, $observations[1]->changes);
    }

    /** And narrowing an allow rule is a narrowing. */
    public function test_narrowing_an_allow_rule_is_reported_as_a_narrowing(): void
    {
        $this->rule('staff read everything', allow: true);

        $this->lint();

        $this->selectVersions('staff read everything', ['v1']);

        $observations = $this->lint();

        $this->assertContains(PolicyFinding::Narrowed, $observations[0]->changes);
        $this->assertNotContains(PolicyFinding::Widened, $observations[0]->changes);
    }

    /**
     * 🛑 Repointing a rule at another provider is a change whose direction
     * cannot be established, and is reported as such.
     *
     * The leaf kind is identical, the selectors are identical, the effect is
     * identical — and a different population of people can read. Neither
     * "widened" nor "narrowed" is true, and claiming one would be worse than
     * saying "look at this": a labelled alert is read and dismissed.
     */
    public function test_repointing_a_rule_at_another_binding_is_a_change(): void
    {
        $other = $this->bind('Globex contractors');

        $this->rule('staff read v1', allow: true, versions: ['v1']);

        $this->lint();

        DB::table('reader_policy_rules')
            ->where('label', 'staff read v1')
            ->update(['requirement' => (string) json_encode([
                'leaf' => AccessLeaf::Binding->value,
                'binding_id' => Uuid::toText($other),
            ])]);

        Cache::flush();

        $observations = $this->lint();

        $this->assertNotEmpty($observations[0]->changes);
        $this->assertContains(PolicyFinding::Changed, $observations[0]->changes);
        $this->assertNotContains(PolicyFinding::Widened, $observations[0]->changes);
        $this->assertNotContains(PolicyFinding::Narrowed, $observations[0]->changes);
    }

    /**
     * 🛑 Under first-match-wins, **position is semantics**. A reorder is an
     * edit.
     */
    public function test_a_reordered_rule_is_reported_as_moved(): void
    {
        $this->rule('first', allow: true, versions: ['v1']);
        $this->rule('second', allow: true, versions: ['v2']);

        $this->lint();

        /* Swap them, through the unique (policy_id, position) index. */
        DB::table('reader_policy_rules')->where('label', 'first')->update(['position' => 99]);
        DB::table('reader_policy_rules')->where('label', 'second')->update(['position' => 1]);
        DB::table('reader_policy_rules')->where('label', 'first')->update(['position' => 2]);

        Cache::flush();

        $observations = $this->lint();

        foreach ($observations as $observation) {
            $this->assertContains(
                PolicyFinding::Moved,
                $observation->changes,
                '🛑 §8.12.6: reordering a policy changes which rule decides',
            );
        }
    }

    // ------------------------------------------------- re-validation

    /**
     * 🛑 The whole reason §8.12.22 says *nightly*: a rule that was valid when
     * it was written and points at a binding that is gone.
     *
     * The rule still matches, so it still consumes §8.12.6's first-match slot,
     * and it can no longer be satisfied by anybody. The project refuses every
     * reader with `requirement_unsatisfied` and the cause is in another table.
     */
    public function test_a_rule_naming_a_vanished_binding_is_unsatisfiable(): void
    {
        $doomed = $this->bind('Temporary IdP');

        $this->policies->addRule(
            project: $this->project,
            label: 'contractors read v1',
            allow: true,
            requirement: ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($doomed)],
            versionSlugs: ['v1'],
            actorId: $this->owner->id,
        );

        app(Bindings::class)->delete($doomed, $this->owner->id);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(PolicyFinding::BindingMissing, $observations[0]->findings);
        $this->assertContains(PolicyFinding::RequirementUnsatisfiable, $observations[0]->findings);
        $this->assertTrue($observations[0]->isFaulty());
    }

    /**
     * And a binding that merely left `active` is a **different** finding,
     * because the remedy is different: one is re-pointing a rule, the other is
     * finishing a binding's verification (§8.12.19).
     */
    public function test_a_binding_out_of_service_is_reported_separately(): void
    {
        $this->rule('staff read v1', allow: true, versions: ['v1']);

        app(Bindings::class)->transition($this->bindingId, BindingState::Disabled, $this->owner->id);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(PolicyFinding::BindingNotActive, $observations[0]->findings);
        $this->assertNotContains(PolicyFinding::BindingMissing, $observations[0]->findings);
    }

    /**
     * 🛑 A tree whose other `OR` branch survives is **not** unsatisfiable.
     *
     * Computed through {@see Requirement::satisfiedBy()} rather
     * than concluded from the presence of a dead binding, because concluding
     * would send an operator to fix a rule that works — and the next thing they
     * would do is widen it.
     */
    public function test_a_surviving_or_branch_keeps_a_rule_satisfiable(): void
    {
        $doomed = $this->bind('Temporary IdP');

        $this->policies->addRule(
            project: $this->project,
            label: 'either provider',
            allow: true,
            requirement: ['any' => [
                ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($doomed)],
                ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($this->bindingId)],
            ]],
            versionSlugs: ['v1'],
            actorId: $this->owner->id,
        );

        app(Bindings::class)->delete($doomed, $this->owner->id);

        Cache::flush();

        $observations = $this->lint();

        $this->assertContains(PolicyFinding::BindingMissing, $observations[0]->findings);
        $this->assertNotContains(
            PolicyFinding::RequirementUnsatisfiable,
            $observations[0]->findings,
            '🛑 the other branch still admits the staff binding',
        );
    }

    // ------------------------------------------------- not crying wolf

    /**
     * 🛑 An unchanged policy raises **nothing** on the second run, and that is
     * the property §8.12.22's value rests on.
     *
     * The first run records a baseline (`new`, which does not alert, or a
     * project's first night would mail about every rule it has). The second
     * finds nothing. A linter that reported the same shadow every night would
     * be filtered by the second week, and §8.12.22's value was the one night
     * the message was different.
     */
    public function test_an_unchanged_policy_raises_nothing_on_a_second_run(): void
    {
        $this->rule('everything', allow: true);
        $this->rule('shadowed on purpose', allow: true, versions: ['v1']);

        $first = $this->lint();

        foreach ($first as $observation) {
            $this->assertSame([PolicyFinding::New], $observation->changes);
            $this->assertFalse($observation->alerts(), 'a baseline must not alert');
        }

        $second = $this->lint();

        foreach ($second as $observation) {
            $this->assertSame([], $observation->changes);
            $this->assertFalse($observation->alerts());
        }

        /* And the shadowed rule is still reported as shadowed, just not alerted. */
        $this->assertContains(PolicyFinding::Shadowed, $second[1]->findings);
    }

    /** One row per rule, replaced rather than appended. */
    public function test_one_observation_is_kept_per_rule(): void
    {
        $this->rule('everything', allow: true);

        $this->lint();
        $this->lint();
        $this->lint();

        $this->assertSame(
            1,
            DB::table('policy_lint_observations')->where('project_id', $this->project->id)->count(),
            '🛑 the question is "did this change since last night", which needs one row',
        );
    }

    // ------------------------------------------------- the command

    /**
     * 🛑 The exit code is for a **fault**, not for a change.
     *
     * A change is for a human to judge; a fault will not fix itself. Failing
     * the nightly job on an intentional shadow rule is how a nightly job gets
     * switched off, after which §8.12.22 is satisfied by a cron entry.
     */
    public function test_the_command_exits_non_zero_only_for_a_fault(): void
    {
        $this->rule('everything', allow: true);
        $this->rule('shadowed on purpose', allow: true, versions: ['v1']);

        $this->context->forget();

        $this->assertSame(0, $this->lintExitCode());

        $this->context->for($this->organisation->id);

        app(Bindings::class)->transition($this->bindingId, BindingState::Disabled, $this->owner->id);

        Cache::flush();
        $this->context->forget();

        $this->assertSame(1, $this->lintExitCode());
    }

    /**
     * 🛑 §8.12.22's alert reaches a person, and names the rule as the operator
     * wrote it.
     */
    public function test_a_widening_alerts_the_organisations_owners(): void
    {
        $this->rule('staff read v1', allow: true, versions: ['v1']);

        $this->context->forget();
        $this->lintExitCode();

        Notification::assertNothingSent();

        $this->context->for($this->organisation->id);

        DB::table('reader_policy_rules')
            ->where('label', 'staff read v1')
            ->update(['requirement' => (string) json_encode(['leaf' => AccessLeaf::Public->value])]);

        Cache::flush();
        $this->context->forget();

        /*
         * Still exit 0: a widening is a change for a human to judge, not a
         * fault for a machine to page about. See PolicyFinding::isFault().
         */
        $this->assertSame(0, $this->lintExitCode());

        Notification::assertSentTo(
            $this->owner,
            PolicyReachabilityChanged::class,
            function (PolicyReachabilityChanged $notification): bool {
                $mail = $notification->toMail($this->owner);

                $this->assertStringContainsString('admits more readers', (string) $mail->subject);

                $body = implode("\n", array_map('strval', $mail->introLines));

                $this->assertStringContainsString('staff read v1', $body);
                $this->assertStringContainsString('simulator', $body);

                return true;
            },
        );
    }

    /**
     * 🛑 And the audit chain has it, whether or not the mail arrives.
     *
     * §20.3's chain is tamper-evident and an operator cannot delete a row from
     * it; mail is best effort and lands in a folder. The record that the
     * installation **noticed** is the one §8.12.22 is really asking for.
     */
    public function test_a_finding_is_recorded_in_the_audit_chain(): void
    {
        $this->rule('staff read v1', allow: true, versions: ['v1']);

        $this->context->forget();
        $this->lintExitCode();

        $this->context->for($this->organisation->id);

        $this->selectVersions('staff read v1', []);
        $this->context->forget();

        $before = DB::table('audit_events')->where('action', 'policy.lint.widened')->count();

        $this->lintExitCode();

        $this->assertGreaterThan(
            $before,
            DB::table('audit_events')->where('action', 'policy.lint.widened')->count(),
        );
    }

    // ------------------------------------------------------------- fixtures

    /**
     * The command's exit code.
     *
     * 🛑 `Artisan::call()` rather than `$this->artisan()`, because the latter
     * is typed `PendingCommand|int` and Larastan refuses the method call on the
     * union — §9.4 runs level 8 repo-wide, and a suppressed error in a test is
     * a suppressed error.
     */
    private function lintExitCode(): int
    {
        return Artisan::call('docup:policy:lint');
    }

    /** @return list<PolicyObservation> */
    private function lint(): array
    {
        $project = Project::query()->findOrFail($this->project->id);

        return app(PolicyLinter::class)->lint(
            projectId: $project->id,
            organisationId: (string) $project->organisation_id,
            authzEpoch: (int) $project->authz_epoch,
        );
    }

    /**
     * Replace a rule's version selector, in the shape the policy reads.
     *
     * 🛑 `version_selector` stores `{"slugs": [...], "languages": [...]}` and
     * not a bare list. Writing a bare list decodes to **no slugs**, which is
     * "every version" — so a test that meant to narrow a rule would silently
     * widen it, and the assertion would fail for the opposite of the reason it
     * looked like.
     *
     * @param  list<string>  $versions
     */
    private function selectVersions(string $label, array $versions): void
    {
        DB::table('reader_policy_rules')
            ->where('label', $label)
            ->update(['version_selector' => (string) json_encode([
                'slugs' => $versions,
                'languages' => [],
            ])]);

        Cache::flush();
    }

    /**
     * @param  list<string>  $versions
     * @param  list<string>  $paths
     */
    private function rule(
        string $label,
        bool $allow,
        array $versions = [],
        array $paths = [],
        bool $shadow = false,
    ): string {
        return $this->policies->addRule(
            project: $this->project,
            label: $label,
            allow: $allow,
            /*
             * A `{binding}` requirement throughout, because §8.12.7 refuses a
             * tree satisfiable without identity — so a fixture using `{public}`
             * everywhere could not express a rule that then *drops* to public,
             * which is the edit this suite is most interested in.
             */
            requirement: ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($this->bindingId)],
            versionSlugs: $versions,
            pathPatterns: $paths,
            shadow: $shadow,
            actorId: $this->owner->id,
        );
    }

    /**
     * One `portal_session` binding, Active.
     *
     * 🛑 `portal_session` here, where `PolicySimulatorTest` needs `saml`: the
     * linter never establishes a reader, so the driver's `attempt()` is never
     * called and the only thing that matters is §8.12.17's leaf kind — which is
     * `{binding}` for both. `portal_session` needs no certificate and no
     * identity provider, so the fixture is the cheapest honest one.
     */
    private function bind(string $name): string
    {
        $bindings = app(Bindings::class);

        $binding = $bindings->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: 'portal_session',
            name: $name,
            organisationId: $this->organisation->id,
            actorId: $this->owner->id,
        );

        $bindings->transition($binding, BindingState::Verifying, $this->owner->id);
        $bindings->recordTestLogin($binding, $this->owner->id);

        $probe = $bindings->probe($binding);

        $this->assertTrue($probe->passed, $probe->summary);

        $bindings->transition($binding, BindingState::Active, $this->owner->id);

        return $binding;
    }
}
