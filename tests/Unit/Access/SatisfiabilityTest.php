<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Access;

use App\Access\AccessLeaf;
use App\Access\PolicyRefused;
use App\Access\Requirement;
use App\Access\RequirementRejection;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.12.7's satisfiability invariant, and §17's exit criterion: "A rule
 * satisfiable by IP allowlist alone is **rejected at write time**."
 *
 * > "The system MUST reject **at write time** any requirement satisfiable
 * > without at least one **identity-bearing** leaf … unless it is literally the
 * > public terminal or the project has explicitly enabled network-only access
 * > (UI-flagged weak, audited). This **satisfiability invariant** is what stops
 * > an IP allowlist standing in for authentication, and it closes the
 * > vacuous-truth fail-open where 'all preconditions pass, any one identity
 * > suffices' is evaluated over an empty identity set."
 *
 * 🛑 Two distinct failures are named in that paragraph and both have cases
 * below: the *gate standing in for an identity*, and the *empty group* whose
 * conjunction is vacuously true. The second is the subtler one and the one a
 * hand-written validator misses, because `{"all": []}` looks like a rule that
 * requires everything.
 */
final class SatisfiabilityTest extends TestCase
{
    /**
     * 🛑 The exit criterion: a requirement an IP allowlist alone satisfies is
     * refused.
     *
     * Four shapes, because an operator reaches this state four ways — the bare
     * gate, the gate beside an identity under `any`, the gate under a nested
     * `any`, and the gate beside a `{public}` leaf that is not the terminal.
     */
    public function test_a_requirement_satisfiable_by_ip_allowlist_alone_is_refused(): void
    {
        $refused = [
            'the bare gate' => ['leaf' => 'gate', 'driver' => 'ip_allowlist'],

            // 🛑 The one that reads as safe and is not: "from the office OR
            // signed in" is "from the office".
            'gate OR binding' => ['any' => [
                ['leaf' => 'gate', 'driver' => 'ip_allowlist'],
                ['leaf' => 'binding', 'driver' => 'oidc'],
            ]],

            // The same mistake one level down, where a reviewer stops reading.
            'all of (gate OR binding)' => ['all' => [
                ['any' => [
                    ['leaf' => 'gate', 'driver' => 'ip_allowlist'],
                    ['leaf' => 'binding', 'driver' => 'oidc'],
                ]],
            ]],

            // 🛑 Not "literally the public terminal", so the exception does not
            // apply — and it is a public rule with a decorative binding.
            'public OR binding' => ['any' => [
                ['leaf' => 'public'],
                ['leaf' => 'binding', 'driver' => 'password'],
            ]],
        ];

        foreach ($refused as $name => $tree) {
            $this->assertRefused($tree, RequirementRejection::SatisfiableWithoutIdentity, $name);
        }
    }

    /**
     * And the same shapes with `all` are accepted, because both are then
     * needed.
     *
     * Without this the invariant could satisfy the criterion by refusing
     * everything, which would meet the letter of §8.12.7 and remove the
     * feature — `ip_allowlist` is a supported v1 driver (§8.12.17) and
     * "from the office **and** signed in" is the policy it is for.
     */
    public function test_a_gate_combined_with_an_identity_is_accepted(): void
    {
        $accepted = [
            'gate AND binding' => ['all' => [
                ['leaf' => 'gate', 'driver' => 'ip_allowlist'],
                ['leaf' => 'binding', 'driver' => 'oidc'],
            ]],
            'gate AND (binding OR share)' => ['all' => [
                ['leaf' => 'gate', 'driver' => 'ip_allowlist'],
                ['any' => [
                    ['leaf' => 'binding', 'driver' => 'oidc'],
                    ['leaf' => 'share', 'driver' => 'shared_link'],
                ]],
            ]],
            'bearer alone' => ['leaf' => 'bearer', 'driver' => 'reader_token'],
        ];

        foreach ($accepted as $name => $tree) {
            $requirement = Requirement::parse($tree);

            $this->assertFalse(
                $requirement->satisfiedWithoutIdentity(),
                $name.' must need an identity',
            );
        }

        $this->addToAssertionCount(count($accepted));
    }

    /**
     * 🛑 §8.12.7's "literally the public terminal", and the word is literally.
     *
     * `{"leaf": "public"}` is the only accepted shape. Anything containing a
     * public leaf beside something else is a public rule wearing a disguise,
     * and §9.3.2's `cache_mode` depends on the same strictness — a looser
     * reading would let a rule demanding a credential declare itself publicly
     * cacheable.
     */
    public function test_only_the_literal_public_terminal_is_the_public_terminal(): void
    {
        $this->assertTrue(Requirement::parse(['leaf' => 'public'])->isPublicTerminal());

        $notTerminal = [
            ['all' => [['leaf' => 'public']]],
            ['any' => [['leaf' => 'public']]],
            ['leaf' => 'public', 'driver' => 'public'],
        ];

        foreach ($notTerminal as $tree) {
            $this->assertFalse(
                Requirement::parse($tree, allowNetworkOnly: true)->isPublicTerminal(),
                json_encode($tree).' is not literally the public terminal',
            );
        }
    }

    /**
     * 🛑 The vacuous-truth fail-open §8.12.7 names, refused at write time
     * **and** false at read time.
     *
     * An empty conjunction is true in logic, so `{"all": []}` would admit
     * everybody — and it reads as the strictest rule anybody could write. Both
     * halves are asserted because a defence present in only one of the two
     * places is one refactor from being gone.
     */
    public function test_an_empty_group_is_refused_and_evaluates_false(): void
    {
        $this->assertRefused(['all' => []], RequirementRejection::EmptyGroup, 'empty all');
        $this->assertRefused(['any' => []], RequirementRejection::EmptyGroup, 'empty any');

        // And nested, where the outer group is well formed.
        $this->assertRefused(
            ['all' => [['leaf' => 'binding', 'driver' => 'oidc'], ['any' => []]]],
            RequirementRejection::EmptyGroup,
            'nested empty any',
        );
    }

    /**
     * 🛑 §8.12.7's one escape, and it is the project's to take: "the project has
     * explicitly enabled network-only access (UI-flagged weak, audited)".
     *
     * The flag is on `reader_policies` and defaults false, so the escape cannot
     * be taken by accident — and the audit record is written by
     * `ReaderPolicies::createFor()` so it cannot be taken silently.
     */
    public function test_network_only_access_is_the_one_audited_escape(): void
    {
        $gateOnly = ['leaf' => 'gate', 'driver' => 'ip_allowlist'];

        $this->assertRefused($gateOnly, RequirementRejection::SatisfiableWithoutIdentity, 'without the flag');

        $requirement = Requirement::parse($gateOnly, allowNetworkOnly: true);

        $this->assertTrue($requirement->satisfiedWithoutIdentity(), 'and it is still weak, by construction');
    }

    /**
     * 🛑 §8.12.17's classification is one table, and a leaf may not contradict
     * it.
     *
     * Without this check a rule could declare `ip_allowlist` as a `{binding}`
     * and the invariant would read it as identity-bearing — the whole point of
     * the classification, defeated by a typo in a JSON payload rather than by
     * a change to any code.
     */
    public function test_a_leaf_may_not_misclassify_its_driver(): void
    {
        $this->assertRefused(
            ['leaf' => 'binding', 'driver' => 'ip_allowlist'],
            RequirementRejection::Malformed,
            'ip_allowlist declared as a binding',
        );

        $this->assertRefused(
            ['leaf' => 'binding', 'driver' => 'not_a_driver'],
            RequirementRejection::UnknownDriver,
            'an unclassified driver',
        );
    }

    /** §8.12.17's table, as this codebase holds it. */
    public function test_section_8_12_17_classifies_every_first_party_driver(): void
    {
        $identityBearing = ['portal_session', 'password', 'shared_link', 'reader_token', 'oidc', 'saml', 'ldap', 'mtls', 'header_trust'];

        foreach ($identityBearing as $driver) {
            $leaf = AccessLeaf::forDriver($driver);

            $this->assertNotNull($leaf, $driver.' must be classified');
            $this->assertTrue($leaf->bearsIdentity(), $driver.' bears an identity');
        }

        // 🛑 The two that do not, and the reason §8.12.7 exists.
        $this->assertFalse(AccessLeaf::forDriver('ip_allowlist')?->bearsIdentity());
        $this->assertFalse(AccessLeaf::forDriver('public')?->bearsIdentity());
    }

    /** §8.12.6 bounds the tree at two levels, and a deeper one is refused. */
    public function test_a_tree_deeper_than_two_levels_is_refused(): void
    {
        $this->assertRefused(
            ['all' => [['any' => [['all' => [['leaf' => 'binding', 'driver' => 'oidc']]]]]]],
            RequirementRejection::TooDeep,
            'three nested groups',
        );
    }

    /**
     * 🛑 §9.4's permanent abuse corpus: every `authz` case names a refusal this
     * code can actually produce.
     *
     * §17 makes this a security-critical phase and §9.4 requires one to
     * "additionally append a named case to the permanent abuse corpus". The
     * corpus README's rule 4 names authorisation explicitly.
     *
     * Asserted the way Phase 05's and Phase 03's corpus tests are: the corpus
     * is the commitment, and this stops the implementation quietly choosing
     * different words. A case expecting an identifier no enum carries would
     * otherwise fail only as a confusing mismatch, in a dataset, long after the
     * rename that caused it.
     */
    public function test_every_authz_corpus_case_names_a_real_refusal(): void
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        /*
         * Read by path rather than through `base_path()`, because this is a
         * unit test and §12.3's purity is what lets it be one — there is no
         * Laravel application booted to ask.
         */
        $corpus = json_decode(
            (string) file_get_contents(dirname(__DIR__, 2).'/Fixtures/AbuseCorpus/corpus.json'),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        $known = array_map(
            static fn (RequirementRejection $case): string => $case->value,
            RequirementRejection::cases(),
        );

        $unknown = [];
        $named = 0;

        foreach ($corpus['cases'] as $case) {
            if (($case['category'] ?? null) !== 'authz') {
                continue;
            }

            $named++;
            $expect = (string) ($case['expect'] ?? '');

            // `authz-006` expects an HTTP status rather than a refusal
            // identifier, because §8.12.23's rule is about a response.
            if (ctype_digit($expect)) {
                continue;
            }

            if (! in_array($expect, $known, true)) {
                $unknown[] = $case['id'].' expects '.$expect;
            }
        }

        $this->assertGreaterThan(0, $named, '§9.4: this phase must append at least one corpus case');
        $this->assertSame([], $unknown, 'corpus cases naming no real refusal: '.implode(', ', $unknown));
    }

    /** @param array<string, mixed> $tree */
    private function assertRefused(array $tree, RequirementRejection $expected, string $name): void
    {
        try {
            Requirement::parse($tree);
        } catch (PolicyRefused $refused) {
            $this->assertSame($expected, $refused->rejection, 'wrong refusal for "'.$name.'"');

            return;
        }

        $this->fail('"'.$name.'" was accepted and should have been refused');
    }
}
