<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\Providers\Saml\SamlRejection;
use Tests\Feature\Providers\FiveProviderSessionTest;
use Tests\TestCase;

/**
 * 🛑 §17: "The corpus is a **release gate**: adding a case that passes
 * incorrectly fails CI."
 *
 * That sentence is about a failure mode, not about coverage, and the failure
 * mode is specific: a case that is green for the wrong reason. There are
 * exactly two ways that happens, and this file closes both.
 *
 * 1. **The expectation is not a real outcome.** `saml-001` to `-014` were
 *    authored in Phase 00 and say only `reject`, which the corpus README's own
 *    rule 3 asks us to improve on — "a status code, a stable error identifier,
 *    or `reject`". `reject` cannot tell fourteen controls apart: one surviving
 *    control would keep every case green while thirteen had regressed, which
 *    is precisely §17's "passes incorrectly".
 *
 *    So `saml-015` to `-035` restate each vector against the exact
 *    {@see SamlRejection} identifier it must produce, and this file asserts
 *    every one of those identifiers is a case the enum really has. A renamed
 *    enum value breaks the build rather than quietly orphaning a case.
 *
 *    🛑 The originals are **kept**, per the README's rule 1 ("a case is never
 *    deleted and never weakened") and following Phase 05's `git_url`
 *    precedent: they are coarse, not wrong, and they still pass.
 *
 * 2. **The proof has been deleted.** A case naming a test that no longer exists
 *    defends nothing while reading as coverage, which is worse than no case at
 *    all. {@see self::PROVEN_BY} names the method for every case in both
 *    directions, so a case without a proof and a proof without a case are both
 *    failures.
 *
 * 🛑 The proofs live in the files that exercise the behaviour, not here.
 * Duplicating them would mean two places to update when the behaviour changes,
 * and §9.4 asks for the case to be *named*, not asserted twice.
 */
final class SamlCorpusTest extends TestCase
{
    /**
     * Every `saml` case, mapped to the method that proves it.
     *
     * 🛑 `[class, method]` pairs rather than `Class::method` strings, because a
     * string is not something `method_exists()` can check and an analyser can
     * see through — which is the whole point of the second assertion below.
     *
     * 🛑 An original and its restatement share a proof **on purpose**. The pair
     * is one vector asserted at two precisions: the Phase 00 case says "this
     * must be refused" and the Phase 25 case says "refused *as this*". One test
     * establishes both, and pointing them at different tests would invent a
     * second proof for a single fact.
     *
     * @var array<string, array{class-string, string}>
     */
    private const array PROVEN_BY = [
        /* Phase 00's fourteen, coarse. */
        'saml-001' => [SignatureVerifierTest::class, 'test_a_stripped_signature_is_refused'],
        'saml-002' => [SignatureVerifierTest::class, 'test_an_unsigned_assertion_under_a_signed_response_is_refused'],
        'saml-003' => [SignatureVerifierTest::class, 'test_a_wrapped_signature_is_refused'],
        'saml-004' => [SignatureVerifierTest::class, 'test_a_symmetric_signature_algorithm_is_refused'],
        'saml-005' => [ResponseValidatorTest::class, 'test_two_assertions_are_refused'],
        'saml-006' => [ResponseValidatorTest::class, 'test_a_wrong_audience_is_refused'],
        'saml-007' => [ResponseValidatorTest::class, 'test_a_wrong_destination_is_refused'],
        'saml-008' => [ResponseValidatorTest::class, 'test_an_expired_assertion_is_refused'],
        'saml-009' => [ResponseValidatorTest::class, 'test_a_replayed_assertion_is_refused'],
        'saml-010' => [SafeXmlTest::class, 'test_a_comment_inside_a_value_is_refused'],
        'saml-011' => [SafeXmlTest::class, 'test_no_parser_is_constructed_for_a_doctype'],
        'saml-012' => [ResponseValidatorTest::class, 'test_an_encrypted_assertion_is_refused'],
        'saml-013' => [ResponseValidatorTest::class, 'test_an_idp_initiated_response_is_refused'],
        'saml-014' => [ResponseValidatorTest::class, 'test_the_skew_ceiling_holds_at_both_edges'],

        /*
         * Phase 25's restatements, each asserted at the route so the audit
         * event §17 asks for is part of the proof rather than an assumption.
         */
        'saml-015' => [SamlAcsTest::class, 'test_a_stripped_signature_is_refused_with_its_own_event'],
        'saml-016' => [SignatureVerifierTest::class, 'test_an_unsigned_assertion_under_a_signed_response_is_refused'],
        'saml-017' => [SignatureVerifierTest::class, 'test_a_wrapped_signature_is_refused'],
        'saml-018' => [SamlAcsTest::class, 'test_a_wrapped_signature_is_refused_with_its_own_event'],
        'saml-019' => [SignatureVerifierTest::class, 'test_a_symmetric_signature_algorithm_is_refused'],
        'saml-020' => [ResponseValidatorTest::class, 'test_two_assertions_are_refused'],
        'saml-021' => [SamlAcsTest::class, 'test_a_wrong_audience_is_refused_with_its_own_event'],
        'saml-022' => [ResponseValidatorTest::class, 'test_a_wrong_destination_is_refused'],
        'saml-023' => [SamlAcsTest::class, 'test_an_expired_window_is_refused_with_its_own_event'],
        'saml-024' => [SamlAcsTest::class, 'test_a_replayed_assertion_is_refused_with_its_own_event'],
        'saml-025' => [SamlAcsTest::class, 'test_a_comment_truncation_payload_is_refused_with_its_own_event'],
        'saml-026' => [SamlAcsTest::class, 'test_an_xxe_payload_is_refused_with_its_own_event'],
        'saml-027' => [SamlAcsTest::class, 'test_an_entity_expansion_payload_is_refused_with_its_own_event'],
        'saml-028' => [ResponseValidatorTest::class, 'test_an_encrypted_assertion_is_refused'],
        'saml-029' => [SamlAcsTest::class, 'test_an_idp_initiated_response_is_refused'],
        'saml-030' => [ResponseValidatorTest::class, 'test_the_skew_ceiling_holds_at_both_edges'],
        'saml-031' => [ResponseValidatorTest::class, 'test_a_response_from_another_entity_id_is_refused'],
        'saml-032' => [ResponseValidatorTest::class, 'test_an_assertion_from_another_entity_id_is_refused'],
        'saml-033' => [SamlAcsTest::class, 'test_a_forged_relay_state_is_refused'],
        'saml-034' => [SamlAcsTest::class, 'test_the_same_response_cannot_be_posted_twice'],
        'saml-035' => [SamlAcsTest::class, 'test_an_assertion_cannot_be_moved_between_exchanges'],
    ];

    /**
     * 🛑 Every case names a real outcome and names its requirement.
     *
     * The release gate's first half. An `expect` that is not an identifier the
     * code can produce is a case nothing can fail — and the way that happens in
     * practice is a rename, which is why this is a test and not a review step.
     */
    public function test_every_saml_corpus_case_is_real(): void
    {
        $cases = self::corpus();

        $this->assertGreaterThanOrEqual(
            35,
            count($cases),
            '🛑 §9.4: Phase 00 authored fourteen and Phase 25 restated them; the corpus is append-only',
        );

        $known = array_merge(
            array_map(static fn (SamlRejection $case): string => $case->value, SamlRejection::cases()),
            /*
             * 🛑 `reject` and `reject-unless-enabled` are Phase 00's coarse
             * vocabulary, admitted **only** because the README's rule 1 keeps
             * the original cases. They are not available to a new case: the
             * assertion below refuses them for anything numbered above the
             * originals, which is what stops the restatement from being undone
             * by the next person in a hurry.
             */
            ['reject', 'reject-unless-enabled'],
        );

        $problems = [];

        foreach ($cases as $case) {
            $id = (string) $case['id'];
            $expect = (string) ($case['expect'] ?? '');

            if (! in_array($expect, $known, true)) {
                $problems[] = $id.' expects "'.$expect.'", which no SamlRejection names';
            }

            if (($case['defends'] ?? '') === '') {
                $problems[] = $id.' names no requirement';
            }
        }

        $this->assertSame([], $problems, '🛑 §9.4: a corpus case must name a real outcome');
    }

    /**
     * 🛑 And a case added from now on must be precise.
     *
     * §17 makes the corpus a release gate, and the gate is only as good as its
     * vocabulary: a new case saying `reject` would be a new case that fourteen
     * different bugs could satisfy. Phase 00's cases keep their coarse
     * expectation because the README forbids weakening a case — but "do not
     * weaken" is not "may stay coarse for ever", and the boundary is where the
     * originals end.
     */
    public function test_a_new_saml_case_states_an_exact_rejection(): void
    {
        $precise = array_map(static fn (SamlRejection $case): string => $case->value, SamlRejection::cases());

        $coarse = [];

        foreach (self::corpus() as $case) {
            $id = (string) $case['id'];

            /* The fourteen Phase 00 authored, by number rather than by name. */
            if ((int) substr($id, 5) <= 14) {
                continue;
            }

            if (! in_array((string) ($case['expect'] ?? ''), $precise, true)) {
                $coarse[] = $id;
            }
        }

        $this->assertSame(
            [],
            $coarse,
            '🛑 §17: a case added after Phase 00 must name the exact rejection it expects',
        );
    }

    /**
     * 🛑 Every case has a proof that still exists, and every proof a case.
     *
     * The release gate's second half, and the direction people forget is the
     * second one: a proof with no case is a test somebody wrote and nobody
     * recorded, so the corpus stops being the list of what DocUp defends
     * against.
     */
    public function test_every_saml_corpus_case_has_a_live_proof(): void
    {
        $ids = array_map(static fn (array $case): string => (string) $case['id'], self::corpus());

        $this->assertSame(
            $ids,
            array_keys(self::PROVEN_BY),
            '🛑 §9.4: every corpus case needs a proof, and every proof a case',
        );

        $missing = [];

        foreach (self::PROVEN_BY as $id => [$class, $method]) {
            if (! method_exists($class, $method)) {
                $missing[] = $id.' is proved by '.$class.'::'.$method.', which does not exist';
            }
        }

        $this->assertSame([], $missing, '🛑 §9.4: a corpus case whose proof was deleted defends nothing');
    }

    /**
     * 🛑 §17's seven are each proved **at the route**, not only as an exception.
     *
     * > "A stripped signature, a wrapped signature, a replayed assertion, a
     * > wrong audience, an expired `NotOnOrAfter`, a comment-truncation payload
     * > and an XXE payload are each rejected with **distinct audit events**."
     *
     * An audit event is something an HTTP request raises, so a proof that only
     * catches an exception is proving the wrong thing — the controller could
     * swallow the reason or record one shared action and the exception-level
     * test would stay green. So each of the seven needs a case whose proof
     * lives in {@see SamlAcsTest}, which drives the real ACS and reads the
     * chain.
     *
     * 🛑 Searched in the **corpus** rather than asserted against hard-coded
     * ids, and the reason is a lesson from the build rather than taste:
     * Larastan folds a constant-array lookup by a literal key down to a literal
     * type, so comparing `PROVEN_BY['saml-018'][0]` against a class name is an
     * always-false comparison it refuses at level 8 — correctly, because an
     * assertion the analyser can evaluate is an assertion that cannot fail.
     * Driving the search from the corpus file makes the data runtime data, and
     * it also makes the test survive a renumbering.
     */
    public function test_section_17_s_seven_are_each_proved_at_the_route(): void
    {
        $seven = [
            SamlRejection::SignatureMissing,
            SamlRejection::SignatureWrapped,
            SamlRejection::AssertionReplayed,
            SamlRejection::AudienceMismatch,
            SamlRejection::ConditionsExpired,
            SamlRejection::CommentInValueRefused,
            SamlRejection::EntityDeclarationRefused,
        ];

        $this->assertCount(
            7,
            array_unique(array_map(static fn (SamlRejection $r): string => $r->value, $seven)),
            '🛑 §17: seven distinct events, not one value reached seven ways',
        );

        /* Which rejections a case proved inside `SamlAcsTest` expects. */
        $atTheRoute = [];

        foreach (self::corpus() as $case) {
            $proof = self::PROVEN_BY[(string) $case['id']] ?? null;

            if ($proof === null || $proof[0] !== SamlAcsTest::class || ! method_exists($proof[0], $proof[1])) {
                continue;
            }

            $atTheRoute[] = (string) ($case['expect'] ?? '');
        }

        $missing = [];

        foreach ($seven as $rejection) {
            if (! in_array($rejection->value, $atTheRoute, true)) {
                $missing[] = $rejection->value;
            }
        }

        $this->assertSame(
            [],
            $missing,
            '🛑 §17: each of the seven needs its own audit event, raised by a request: '
                .implode(', ', $missing),
        );
    }

    /**
     * 🛑 Every rejection the vocabulary has is reachable, or says why not.
     *
     * The gate's third hole, and the subtlest: a `SamlRejection` case nothing
     * can produce is dead vocabulary, and an operator who writes an alert for
     * it gets silence that looks like safety. So every case is either named by
     * a corpus case or listed here with the reason it is unreachable from a
     * hostile *document*.
     */
    public function test_every_rejection_is_reachable_or_declared_unreachable(): void
    {
        /*
         * 🛑 Not reachable by a crafted response, each for a stated reason —
         * which is why they are listed rather than given corpus cases. A corpus
         * case is a hostile *input*; these are operator and infrastructure
         * states.
         */
        $notFromADocument = [
            /* The binding's own configuration, not anything a response carries. */
            SamlRejection::ConfigInvalid->value,
            /* A signature that fails under the configured key: tampering, covered by SignatureVerifierTest. */
            SamlRejection::SignatureInvalid->value,
            /* Not XML at all, or the wrong root: covered by SafeXmlTest's own cases. */
            SamlRejection::ResponseMalformed->value,
            /* The provider said no. A refusal, not an attack. */
            SamlRejection::StatusNotSuccess->value,
            /* A provider sending no NameID is misconfigured, not hostile. */
            SamlRejection::SubjectMissing->value,
            /* SubjectConfirmation is checked with InResponseTo; saml-029 and -035 cover it. */
            SamlRejection::SubjectConfirmationInvalid->value,
            /* §8.12.18's size ceiling: a resource bound, covered by SafeXmlTest. */
            SamlRejection::ResponseTooLarge->value,
            /* §8.13.7's `disabled`, reached by configuration rather than by a document. */
            SamlRejection::ProvisioningDisabled->value,
        ];

        $expected = [];

        foreach (self::corpus() as $case) {
            $expected[] = (string) ($case['expect'] ?? '');
        }

        $orphans = [];

        foreach (SamlRejection::cases() as $rejection) {
            if (in_array($rejection->value, $notFromADocument, true)) {
                continue;
            }

            if (! in_array($rejection->value, $expected, true)) {
                $orphans[] = $rejection->value;
            }
        }

        $this->assertSame(
            [],
            $orphans,
            '🛑 a rejection no corpus case expects is a rejection nothing proves: '.implode(', ', $orphans),
        );
    }

    /**
     * 🛑 And the exit criterion's own demonstration is named.
     *
     * §17's Phase 25 criteria have two halves, and the corpus only records the
     * second. Naming the first here keeps them together: if the five-provider
     * test is deleted, the phase's evidence goes with it and this is what
     * notices.
     */
    public function test_the_five_provider_demonstration_is_named(): void
    {
        /*
         * 🛑 Reflection rather than `method_exists`, for the reason the test
         * above gives: a literal class and a literal method name let the
         * analyser evaluate the call, and an assertion it can evaluate is one
         * that cannot fail. A method list is runtime data.
         */
        $methods = array_map(
            static fn (\ReflectionMethod $method): string => $method->getName(),
            (new \ReflectionClass(FiveProviderSessionTest::class))->getMethods(\ReflectionMethod::IS_PUBLIC),
        );

        $this->assertContains(
            'test_five_providers_serve_five_projects_in_one_session',
            $methods,
            '🛑 §17: "five projects on one installation … demonstrated in one browser session"',
        );

        $this->assertContains(
            'test_no_credential_reaches_another_project',
            $methods,
            '🛑 §17: and the negative half, which is what makes five providers mean five',
        );
    }

    // ---------------------------------------------------------- fixtures

    /** @return list<array<string, mixed>> */
    private static function corpus(): array
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2).'/Fixtures/AbuseCorpus/corpus.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $cases = [];

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) === 'saml') {
                $cases[] = $case;
            }
        }

        return $cases;
    }
}
