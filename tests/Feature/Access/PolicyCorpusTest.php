<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

use App\Access\PolicyFinding;
use App\Access\SimulationRefused;
use App\Auth\Capability;
use App\Auth\Role;
use Tests\Feature\Auth\MfaEnforcementTest;
use Tests\TestCase;

/**
 * 🛑 §9.4: a security-critical phase appends named cases to the permanent abuse
 * corpus, and this is the gate that keeps them from becoming decoration.
 *
 * The corpus is a commitment, and a commitment nobody checks is a comment. Four
 * things are asserted here, each because its absence has a specific failure:
 *
 * 1. **Every `policy` case's `expect` names something the code can produce.** A
 *    case expecting an identifier no enum carries fails later as a confusing
 *    assertion mismatch inside a dataset, long after the rename that caused it.
 * 2. **Every case has a live proof, by name**, and every proof covers a case.
 *    Both directions: a case with no test is a promise, and a test nobody
 *    mapped is a case somebody will add again.
 * 3. **A new case cannot be coarse.** `reject` was good enough for the cases
 *    Phase 00 wrote before any of this existed; a case appended now must name
 *    the identifier, or the corpus stops being evidence and becomes a list of
 *    worries.
 * 4. **Every `PolicyFinding` is either reachable or declared unreachable.** The
 *    linter's vocabulary is the alert's vocabulary, and a finding no code path
 *    can produce is a sentence an operator will never see — which is fine, as
 *    long as somebody decided that rather than drifted into it.
 *
 * 🛑 The map below is read through reflection and the corpus is read from disk,
 * for a reason Phase 25 learned the hard way: Larastan folds constant-array
 * lookups by literal keys to literal types, so `self::PROVEN_BY['policy-001'][0]
 * !== PolicySimulatorTest::class` is an expression the analyser evaluates — and
 * an assertion the analyser can evaluate is an assertion that cannot fail.
 */
final class PolicyCorpusTest extends TestCase
{
    /**
     * Each Phase 26a corpus case and the test that proves it.
     *
     * @var array<string, array{0: class-string, 1: string}>
     */
    private const array PROVEN_BY = [
        'policy-001' => [PolicySimulatorTest::class, 'test_another_organisations_identity_is_refused'],
        'policy-002' => [PolicySimulatorTest::class, 'test_a_deprovisioned_identity_is_refused'],
        'policy-003' => [PolicySimulatorRouteTest::class, 'test_a_project_reader_may_not_simulate'],
        'policy-004' => [PolicySimulatorTest::class, 'test_a_simulation_mints_nothing'],
        'policy-005' => [PolicySimulatorTest::class, 'test_a_simulation_writes_no_decision_log_row'],
        'policy-006' => [PolicyLinterTest::class, 'test_dropping_the_identity_requirement_is_a_widening'],
        'policy-007' => [PolicyLinterTest::class, 'test_a_planted_selector_widening_is_caught'],
        'policy-008' => [PolicyLinterTest::class, 'test_a_rule_leaving_shadow_is_a_widening'],
        'policy-009' => [PolicyLinterTest::class, 'test_widening_a_deny_rule_is_reported_as_a_narrowing'],
        'policy-010' => [PolicyLinterTest::class, 'test_repointing_a_rule_at_another_binding_is_a_change'],
        'policy-011' => [PolicyLinterTest::class, 'test_a_sibling_path_prefix_is_not_covered'],
        'policy-012' => [PolicyLinterTest::class, 'test_a_shadow_rule_does_not_shadow_an_enforced_rule'],
        'policy-013' => [PolicyLinterTest::class, 'test_a_rule_naming_a_vanished_binding_is_unsatisfiable'],
        'policy-014' => [PolicyLinterTest::class, 'test_a_surviving_or_branch_keeps_a_rule_satisfiable'],
        'policy-015' => [MfaEnforcementTest::class, 'test_enrolment_means_a_confirmed_secret'],
        'policy-016' => [MfaEnforcementTest::class, 'test_a_project_scoped_admin_is_blocked'],
        'policy-017' => [MfaEnforcementTest::class, 'test_the_installation_switch_dominates'],
        'policy-018' => [MfaEnforcementTest::class, 'test_the_enrolment_page_is_reachable_while_blocked'],
        'policy-019' => [MfaEnforcementTest::class, 'test_a_project_writer_is_not_blocked'],
        'policy-020' => [MfaEnforcementTest::class, 'test_the_user_model_is_two_factor_authenticatable'],
    ];

    /**
     * 🛑 Findings with no code path, declared rather than discovered.
     *
     * `New` is produced (a baseline run) but raises no alert by design, so it
     * has no abuse case; `Changed` is the direction-unknown report. Both are
     * reachable and neither is an abuse, which is why the list below is about
     * *reachability* and not about corpus coverage.
     *
     * @var list<string>
     */
    private const array NOT_AN_ABUSE = [
        'new',
        'not_yet_active',
        'expired',
        'reachability_changed',
        'moved',
        'shadowed',
        'binding_not_active',
        'requirement_unsatisfiable',
        'binding_misclassified',
    ];

    /** Every `policy` case's expectation names something the code can produce. */
    public function test_every_case_expects_something_real(): void
    {
        $known = [
            /* §8.12.22's finding vocabulary. */
            ...array_map(static fn (PolicyFinding $finding): string => $finding->value, PolicyFinding::cases()),
            /* The simulator's two refusals. */
            'no_such_identity',
            'identity_deprovisioned',
            /* The MFA gate's machine-readable code and Fortify's challenge route. */
            'mfa_enrolment_required',
            'two-factor.login',
            /*
             * The outcomes that are not identifiers: an HTTP status, a count, a
             * reachability verdict, a pass. Listed so a typo is still caught.
             */
            '404', '0', 'reachable', 'allowed',
        ];

        $unknown = [];

        foreach ($this->cases() as $case) {
            if (! in_array($case['expect'], $known, true)) {
                $unknown[] = $case['id'].' expects '.$case['expect'];
            }
        }

        $this->assertSame(
            [],
            $unknown,
            '🛑 §9.4: a corpus case expecting an identifier nothing produces fails later as a '
                .'dataset mismatch: '.implode('; ', $unknown),
        );
    }

    /**
     * 🛑 A case appended now may not say `reject`.
     *
     * Phase 00's cases predate every identifier in the product and are
     * exempted by the corpus README. A `policy` case is new, so vagueness here
     * would be a choice — and a corpus of vague expectations passes against
     * almost any behaviour.
     */
    public function test_no_case_is_coarse(): void
    {
        $coarse = [];

        foreach ($this->cases() as $case) {
            if (in_array($case['expect'], ['reject', 'refuse', 'deny', 'error'], true)) {
                $coarse[] = $case['id'];
            }
        }

        $this->assertSame([], $coarse, 'a Phase 26a case must name its identifier: '.implode(', ', $coarse));
    }

    /**
     * 🛑 Every case has a live proof, and every proof covers a case.
     *
     * Read through reflection on purpose: a `method_exists(Foo::class, 'bar')`
     * over a constant array is something Larastan evaluates at analysis time,
     * which turns the assertion into a tautology the suite reports as passing.
     */
    public function test_every_case_has_a_live_proof(): void
    {
        $missing = [];

        foreach ($this->cases() as $case) {
            $proof = self::PROVEN_BY[$case['id']] ?? null;

            if ($proof === null) {
                $missing[] = $case['id'].' has no mapped proof';

                continue;
            }

            if (! $this->methodExists($proof[0], $proof[1])) {
                $missing[] = $case['id'].' names '.$proof[0].'::'.$proof[1].', which does not exist';
            }
        }

        $this->assertSame([], $missing, implode('; ', $missing));

        /* And the other direction: a mapping for a case nobody wrote. */
        $ids = array_map(static fn (array $case): string => $case['id'], $this->cases());
        $orphans = array_values(array_diff(array_keys(self::PROVEN_BY), $ids));

        $this->assertSame(
            [],
            $orphans,
            'a proof mapped to no corpus case: '.implode(', ', $orphans),
        );
    }

    /**
     * 🛑 Every `PolicyFinding` is either exercised by a corpus case or listed
     * as not an abuse.
     *
     * The linter's vocabulary is the alert's vocabulary. A finding nothing can
     * produce is a sentence an operator will never read, which is fine as long
     * as somebody decided it rather than drifted into it.
     */
    public function test_every_finding_is_covered_or_declared(): void
    {
        $expected = array_map(static fn (array $case): string => $case['expect'], $this->cases());

        $uncovered = [];

        foreach (PolicyFinding::cases() as $finding) {
            if (in_array($finding->value, $expected, true)) {
                continue;
            }

            if (in_array($finding->value, self::NOT_AN_ABUSE, true)) {
                continue;
            }

            $uncovered[] = $finding->value;
        }

        $this->assertSame(
            [],
            $uncovered,
            '🛑 §9.4: a finding with neither a corpus case nor a declaration: '
                .implode(', ', $uncovered),
        );
    }

    /**
     * 🛑 And §8.12.25's capability is withheld from the roles the corpus says
     * it is withheld from.
     *
     * `policy-003` asserts the HTTP refusal; this asserts the matrix behind it,
     * because the two can drift: a capability added to `project_reader` would
     * make the route test's 404 come from somewhere else and still pass.
     */
    public function test_the_simulator_capability_is_withheld_from_readers_and_writers(): void
    {
        foreach ([Role::ProjectReader, Role::ProjectWriter, Role::OrgMember] as $role) {
            $this->assertFalse(
                $role->can(Capability::ProjectPolicySimulate),
                '🛑 §8.12.25 discloses the organisation\'s readership; '.$role->value.' may not',
            );
        }

        foreach ([Role::OrgAdmin, Role::ProjectAdmin, Role::OrgAuditor, Role::InstallationSecurityAdmin] as $role) {
            $this->assertTrue(
                $role->can(Capability::ProjectPolicySimulate),
                '🛑 §17: "an operator can prove what any identity may read" — '.$role->value.' is an operator',
            );
        }
    }

    /** The two refusal codes the corpus names are the ones the class produces. */
    public function test_the_simulator_refusals_are_the_corpus_codes(): void
    {
        $this->assertSame('no_such_identity', SimulationRefused::noSuchIdentity()->reasonCode);
        $this->assertSame('identity_deprovisioned', SimulationRefused::deprovisioned()->reasonCode);
    }

    // ------------------------------------------------------------- fixtures

    /**
     * @param  class-string  $class
     */
    private function methodExists(string $class, string $method): bool
    {
        $names = array_map(
            static fn (\ReflectionMethod $reflected): string => $reflected->getName(),
            (new \ReflectionClass($class))->getMethods(),
        );

        return in_array($method, $names, true);
    }

    /**
     * Every `policy` case, from the file on disk.
     *
     * @return list<array{id: string, category: string, expect: string, note: string}>
     */
    private function cases(): array
    {
        /** @var array{cases: list<array<string, string>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2).'/Fixtures/AbuseCorpus/corpus.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $cases = [];

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) !== 'policy') {
                continue;
            }

            /** @var array{id: string, category: string, expect: string, note: string} $case */
            $cases[] = $case;
        }

        $this->assertGreaterThanOrEqual(
            20,
            count($cases),
            'Phase 26a appended twenty `policy` cases; the corpus is append-only (§9.4)',
        );

        return $cases;
    }
}
