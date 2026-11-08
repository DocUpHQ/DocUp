<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Oidc;

use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Oidc\Discovery;
use App\Auth\Providers\Oidc\GroupMappings;
use App\Auth\Providers\Oidc\OidcRefused;
use App\Auth\Providers\Oidc\OidcRejection;
use App\Auth\Scope;
use App\Egress\DnsResolver;
use Tests\Feature\Readers\GrantTest;
use Tests\Support\FakeDnsResolver;
use Tests\TestCase;

/**
 * 🛑 §9.4's abuse corpus, for Phase 24's `oidc` category.
 *
 * > "Security-critical phases additionally append a named case to the permanent
 * > abuse corpus."
 *
 * The same two jobs Phase 23's corpus test has, and the first keeps the second
 * honest: every case names a real outcome, and every case names a test that
 * proves it. A case whose expectation is a renamed enum value, or whose proof
 * has been deleted, passes while defending nothing — which reads as coverage
 * and is worse than no case at all.
 *
 * 🛑 Most of the proofs live in {@see IdTokenVerifierTest},
 * {@see OidcExchangeTest} and {@see TwoRealmLoginTest} rather than here,
 * because those are where the behaviour is exercised. Duplicating them would
 * mean two places to update when the behaviour changes, and §9.4 asks for the
 * case to be *named*, not for it to be asserted twice.
 */
final class OidcCorpusTest extends TestCase
{
    /**
     * Every `oidc` case, mapped to the method that proves it.
     *
     * @var array<string, array{class-string, string}>
     */
    private const array PROVEN_BY = [
        'oidc-001' => [IdTokenVerifierTest::class, 'test_alg_none_is_refused'],
        'oidc-002' => [IdTokenVerifierTest::class, 'test_a_symmetric_algorithm_is_refused'],
        'oidc-003' => [IdTokenVerifierTest::class, 'test_a_wrong_issuer_is_refused'],
        'oidc-004' => [IdTokenVerifierTest::class, 'test_a_wrong_audience_is_refused'],
        'oidc-005' => [IdTokenVerifierTest::class, 'test_a_missing_at_hash_is_refused'],
        'oidc-006' => [IdTokenVerifierTest::class, 'test_an_unknown_kid_does_not_buy_an_unbounded_refresh'],
        'oidc-007' => [IdTokenVerifierTest::class, 'test_an_unpinned_kid_is_refused'],
        'oidc-008' => [OidcExchangeTest::class, 'test_a_state_is_consumable_exactly_once'],
        'oidc-009' => [TwoRealmLoginTest::class, 'test_an_implicit_flow_response_is_refused_without_spending_the_state'],
        'oidc-010' => [GrantTest::class, 'test_a_grant_carries_a_satisfied_binding_as_text'],
        'oidc-011' => [self::class, 'test_a_project_scoped_role_mapping_is_refused'],
        'oidc-012' => [TwoRealmLoginTest::class, 'test_a_group_removed_at_the_idp_is_removed_on_next_login'],
        'oidc-013' => [IdTokenVerifierTest::class, 'test_a_token_with_no_subject_is_refused'],
        'oidc-014' => [self::class, 'test_an_issuer_in_private_address_space_is_refused'],
        'oidc-015' => [OidcExchangeTest::class, 'test_the_endpoints_own_query_cannot_shadow_docups_parameters'],
    ];

    /** 🛑 Every case names a real outcome and names its requirement. */
    public function test_every_oidc_corpus_case_is_real(): void
    {
        $cases = self::corpus();

        $this->assertGreaterThanOrEqual(
            15,
            count($cases),
            '🛑 §9.4: Phase 24 appended fifteen cases; the corpus is append-only',
        );

        $known = array_merge(
            array_map(static fn (OidcRejection $c): string => $c->value, OidcRejection::cases()),
            array_map(static fn (BindingRejection $c): string => $c->value, BindingRejection::cases()),
            /*
             * The outcomes no enum names, declared rather than free-form. The
             * corpus README asks for "a status code, a stable error identifier,
             * or `reject`"; these are stable in the only sense available for a
             * property that is a *correct* behaviour rather than a refusal — a
             * parameter that must survive, a group that must go, a comparison
             * that must not match.
             */
            [
                'the group is removed',
                'code',
            ],
        );

        $unknown = [];

        foreach ($cases as $case) {
            $expect = (string) ($case['expect'] ?? '');

            if (! ctype_digit($expect) && ! in_array($expect, $known, true)) {
                $unknown[] = $case['id'].' expects "'.$expect.'"';
            }

            if (($case['defends'] ?? '') === '') {
                $unknown[] = $case['id'].' names no requirement';
            }
        }

        $this->assertSame([], $unknown, '🛑 §9.4: a corpus case must name a real outcome');
    }

    /** 🛑 And every case has a proof that still exists. */
    public function test_every_oidc_corpus_case_has_a_live_proof(): void
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

    // --------------------------------------------- the two proved here

    /**
     * 🛑 `oidc-011`: a project-scoped binding may not map a dashboard role.
     *
     * Proved against {@see GroupMappings} directly
     * because the write-time refusal is the one §8.12.5 names as the
     * "validation invariant", distinct from the driver capability flag — and a
     * test driving it through an API would be testing the API.
     */
    public function test_a_project_scoped_role_mapping_is_refused(): void
    {
        $mappings = app(GroupMappings::class);

        try {
            $mappings->add(
                bindingId: random_bytes(16),
                bindingScopeType: 'project',
                organisationId: null,
                providerGroup: 'admins',
                target: 'role',
                targetValue: 'installation_owner',
                scope: Scope::Installation,
            );
            $this->fail('a project-scoped binding mapped a dashboard role');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::DashboardRoleNotPermitted, $refused->rejection);
        }

        /*
         * 🛑 And the rung above: an organisation-scoped binding mapping an
         * **installation**-scope role is the same escalation one level up.
         */
        try {
            $mappings->add(
                bindingId: random_bytes(16),
                bindingScopeType: 'organisation',
                organisationId: null,
                providerGroup: 'admins',
                target: 'role',
                targetValue: 'installation_owner',
                scope: Scope::Installation,
            );
            $this->fail('an organisation-scoped binding mapped an installation role');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::DashboardRoleNotPermitted, $refused->rejection);
        }
    }

    /**
     * 🛑 `oidc-014`: an issuer in private address space is refused by §8.3.9.
     *
     * The case §8.3.9's own architecture test names — "an OIDC discovery
     * document" — so it is worth asserting rather than assuming. Driven through
     * the container-bound client, which is the one the controllers use.
     */
    public function test_an_issuer_in_private_address_space_is_refused(): void
    {
        $this->app->instance(DnsResolver::class, (new FakeDnsResolver)
            ->stable('metadata.idp.example.test', ['169.254.169.254'])
            ->stable('internal.idp.example.test', ['10.0.0.5']));

        $discovery = app(Discovery::class);

        foreach (['metadata', 'internal'] as $host) {
            try {
                $discovery->metadataFor(
                    random_bytes(16),
                    'https://'.$host.'.idp.example.test/realms/acme',
                );
                $this->fail('discovery reached '.$host);
            } catch (OidcRefused $refused) {
                $this->assertSame(
                    OidcRejection::DiscoveryFailed,
                    $refused->rejection,
                    '🛑 §8.3.9: an operator-supplied issuer is exactly what the egress policy is for',
                );
            }
        }
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
            if (($case['category'] ?? null) === 'oidc') {
                $cases[] = $case;
            }
        }

        return $cases;
    }
}
