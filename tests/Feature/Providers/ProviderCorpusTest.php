<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Providers;

use App\Access\PolicyRefused;
use App\Access\ReaderPolicies;
use App\Access\RequirementRejection;
use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Drivers\IpAllowlistDriver;
use App\Auth\Providers\ProviderOutcome;
use App\Auth\Providers\ProviderResolver;
use App\Auth\Providers\ReaderCredentials;
use App\Auth\Providers\ReaderPresentation;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Readers\ReaderResolver;
use App\Serving\SnapshotProject;
use App\Support\Uuid;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Tests\TestCase;

/**
 * 🛑 §9.4's abuse corpus, for Phase 23's `provider` category.
 *
 * > "Security-critical phases additionally append a named case to the permanent
 * > abuse corpus."
 *
 * Two jobs, and the first is the one that keeps the second honest:
 *
 * 1. **Every `provider` case names a real outcome**, and names a test that
 *    proves it. A case whose expectation is a renamed enum value, or whose
 *    proof has quietly been deleted, passes while defending nothing — which is
 *    worse than having no case, because it reads as coverage.
 * 2. **The cases run.** Each one below is the smallest thing that would fail if
 *    the control it names were removed.
 *
 * The exit criteria of §17 live in {@see ReaderProviderTest}; this file is the
 * corpus, and the split is deliberate. An exit criterion is a promise to the
 * operator about what the feature does; a corpus case is a promise about what
 * it refuses, and the two are reviewed by different people for different
 * reasons.
 */
final class ProviderCorpusTest extends TestCase
{
    use DatabaseTransactions;

    /**
     * 🛑 Every `provider` case, mapped to the method that proves it.
     *
     * The map is asserted complete in both directions: a case with no proof
     * fails, and a proof naming a case that does not exist fails. §9.4's corpus
     * is evidence, and evidence nobody checks is decoration.
     *
     * Four cases are proved in {@see ReaderProviderTest} instead, because they
     * are also §17 exit criteria and asserting them twice would mean two places
     * to update when the behaviour changes. They are named here so the map stays
     * total.
     *
     * Class and method as two fields rather than one `Class::method` string,
     * because a string has to be parsed and a parse of a constant the analyser
     * can see through is a parse it reports on. Two fields need none.
     *
     * @var array<string, array{class-string, string}>
     */
    private const array PROVEN_BY = [
        'provider-001' => [ReaderProviderTest::class, 'test_a_degraded_binding_does_not_fall_back_to_a_healthy_one'],
        'provider-002' => [self::class, 'test_a_probe_alone_does_not_reach_active'],
        'provider-003' => [self::class, 'test_a_passing_probe_on_a_degraded_binding_reaches_verifying_not_active'],
        'provider-004' => [self::class, 'test_the_database_refuses_a_share_link_with_no_expiry'],
        'provider-005' => [ReaderProviderTest::class, 'test_an_expired_link_404s'],
        'provider-006' => [self::class, 'test_a_live_link_with_a_wrong_password_challenges'],
        'provider-007' => [self::class, 'test_a_single_use_link_counts_atomically'],
        'provider-008' => [self::class, 'test_a_flood_is_throttled_before_any_argon2_verification'],
        'provider-009' => [self::class, 'test_a_rule_naming_a_gate_binding_is_refused_at_write_time'],
        'provider-010' => [self::class, 'test_an_unreadable_envelope_degrades_rather_than_throws'],
        'provider-011' => [self::class, 'test_a_project_binding_does_not_shadow_an_installation_binding_of_another_type'],
        'provider-012' => [self::class, 'test_the_read_the_docs_token_scheme_is_nothing'],
        'provider-013' => [self::class, 'test_an_ipv4_mapped_address_never_matches_an_ipv4_range'],
    ];

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private User $operator;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Corpus Co',
            'slug' => 'corpus-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'corpus-'.bin2hex(random_bytes(3)),
            'name' => 'Corpus',
            'visibility' => 'public',
        ]);

        $this->operator = User::query()->create([
            'name' => 'Operator',
            'email' => 'corpus-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ----------------------------------------------- the corpus itself

    /**
     * 🛑 Every `provider` case names a real outcome and a live proof.
     *
     * The same technique the `reader` category's own corpus test uses, in
     * `tests/Unit/Readers/HandoffSafetyTest.php`, extended with the proof map.
     * Written as a path rather than as a `{@see}` because Pint's
     * `fully_qualified_strict_types` turns a class reference in a docblock into
     * a real import, and an import used only by a comment is dead code the Pest
     * preset refuses.
     *
     * A rename otherwise fails as a confusing mismatch in a dataset, long
     * after the change that caused it, and a deleted test fails not at all.
     */
    public function test_every_provider_corpus_case_is_real(): void
    {
        $cases = self::corpus();

        $this->assertGreaterThanOrEqual(
            13,
            count($cases),
            '🛑 §9.4: Phase 23 appended thirteen cases; the corpus is append-only',
        );

        $known = array_merge(
            array_map(static fn (BindingRejection $c): string => $c->value, BindingRejection::cases()),
            array_map(static fn (RequirementRejection $c): string => $c->value, RequirementRejection::cases()),
            /*
             * The prose outcomes, declared rather than free-form. Rule 3 of the
             * corpus README asks for "a status code, a stable error identifier,
             * or `reject`"; these are stable identifiers in the only sense
             * available for a property no enum names — a race won exactly once,
             * work not done, a state reached, a comparison that must not match.
             */
            [
                'exactly one 200',
                'throttled before any argon2 verification',
                'both resolve',
                'no match',
                BindingState::Verifying->value,
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
    public function test_every_provider_corpus_case_has_a_live_proof(): void
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

    // -------------------------------------------- §8.12.19's lifecycle

    /** 🛑 `provider-002`: a passing probe alone does not reach `active`. */
    public function test_a_probe_alone_does_not_reach_active(): void
    {
        $bindings = app(Bindings::class);
        $id = $this->binding('password', 'probe only', secrets: [
            'password_hash' => Hash::make('correct horse'),
        ]);

        $bindings->transition($id, BindingState::Verifying);

        $probe = $bindings->probe($id);
        $this->assertTrue($probe->passed, 'the fixture must probe cleanly for this to test anything');

        try {
            $bindings->transition($id, BindingState::Active);
            $this->fail('a binding reached active with no human test login');
        } catch (BindingRefused $refused) {
            $this->assertSame(BindingRejection::TransitionNotPermitted, $refused->rejection);
            $this->assertStringContainsString('test login', $refused->getMessage());
        }

        /* And the row did not move. */
        $this->assertSame(
            BindingState::Verifying->value,
            DB::table('auth_provider_bindings')->where('id', $id)->value('state'),
        );
    }

    /**
     * 🛑 `provider-003`: a probe may rescue a degraded binding only as far as
     * `verifying`.
     */
    public function test_a_passing_probe_on_a_degraded_binding_reaches_verifying_not_active(): void
    {
        $bindings = app(Bindings::class);
        $id = $this->activeBinding('password', 'the recovered portal', secrets: [
            'password_hash' => Hash::make('correct horse'),
        ]);

        DB::table('auth_provider_bindings')
            ->where('id', $id)
            ->update(['state' => BindingState::Degraded->value, 'probe_failures' => 5]);

        Cache::flush();

        $result = $bindings->probe($id);

        $this->assertTrue($result->passed);

        /*
         * 🛑 `verifying`, and the operator has to look. This binding has a
         * recorded test login already — it was active once — so a path that
         * promoted on "probe passes AND a test login exists" would restore it
         * silently, and the five failures that degraded it would never be
         * diagnosed.
         */
        $this->assertSame(
            BindingState::Verifying->value,
            DB::table('auth_provider_bindings')->where('id', $id)->value('state'),
        );
    }

    // ------------------------------------------ §8.12.16's share links

    /**
     * 🛑 `provider-004`: the **database** refuses a share link with no expiry.
     *
     * The application refuses it too, and {@see ReaderProviderTest} asserts
     * that. This asserts the second defence, by writing the row the way a
     * future maintainer who did not read §8.12.16 would: directly.
     */
    public function test_the_database_refuses_a_share_link_with_no_expiry(): void
    {
        $this->expectException(QueryException::class);

        DB::table('reader_credentials')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'binding_id' => $this->activeBinding('shared_link', 'direct insert', shareable: true),
            'kind' => 'shared_link',
            'label' => 'no expiry',
            'secret_hash' => str_repeat('a', 64),
            'secret_hash_prefix' => 'aaaaaaaa',
            'expires_at' => null,
            'uses' => 0,
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);
    }

    /**
     * 🛑 `provider-006`: a **live** link with a wrong password is a rejected
     * credential, and so challengeable.
     *
     * The mirror of `provider-005`. The reader has proved they hold a working
     * link, so the resource's existence is already certain to them and
     * §8.12.16's passworded flow needs the challenge to offer them a page.
     */
    public function test_a_live_link_with_a_wrong_password_challenges(): void
    {
        $binding = $this->activeBinding('shared_link', 'the passworded link', shareable: true);

        $issued = app(ReaderCredentials::class)->issue(
            $this->project,
            $binding,
            'shared_link',
            'guarded link',
            expiresAt: time() + 3600,
            password: 'correct horse',
        );

        $outcome = $this->resolve(shareSecret: $issued['secret'], password: 'wrong');

        $this->assertTrue(
            $outcome->credentialRejected,
            '🛑 a live link with a wrong password must be a rejected credential (§8.12.23 case (a))',
        );

        /* And an **unresolved** secret is not, which is `provider-005`'s half. */
        $this->assertFalse(
            $this->resolve(shareSecret: 'docup_link_'.str_repeat('z', 40))->credentialRejected,
            '🛑 §17: an unresolved share secret 404s; it does not challenge',
        );
    }

    /**
     * 🛑 `provider-007`: the use count is one atomic conditional write.
     *
     * Asserted by draining the count rather than by racing threads, which a
     * single-process test suite cannot do honestly. What it proves is the
     * property the race depends on: the guard is in the `UPDATE`'s own `WHERE`,
     * so the n+1th caller sees no row affected rather than a stale count.
     */
    public function test_a_single_use_link_counts_atomically(): void
    {
        $binding = $this->activeBinding('shared_link', 'one use', shareable: true);

        $issued = app(ReaderCredentials::class)->issue(
            $this->project,
            $binding,
            'shared_link',
            'one use',
            expiresAt: time() + 3600,
            maxUses: 1,
        );

        $credentials = app(ReaderCredentials::class);

        $first = $credentials->resolve($issued['secret'], 'shared_link', $this->project->id);
        $this->assertNotNull($first);
        $this->assertTrue($credentials->countUse($first['id']));

        /*
         * 🛑 The second count fails, and it fails in the database rather than
         * after a read: `countUse()` is `UPDATE … SET uses = uses + 1 WHERE id
         * = ? AND (max_uses IS NULL OR uses < max_uses)`, so two callers
         * holding the same stale `uses` cannot both succeed.
         */
        $this->assertFalse($credentials->countUse($first['id']));

        /* And the credential then resolves to nothing at all. */
        $this->assertNull($credentials->resolve($issued['secret'], 'shared_link', $this->project->id));
    }

    /**
     * 🛑 `provider-008`: the limiter is checked **before** the Argon2
     * comparison.
     *
     * Proved by cost rather than by assertion: once the per-address limit is
     * spent, the verification must not run, so a correct password presented
     * after the limit is still refused. A limiter checked after the comparison
     * would admit it — and would have burned the Argon2 work on every attempt
     * that got there.
     */
    public function test_a_flood_is_throttled_before_any_argon2_verification(): void
    {
        $binding = $this->activeBinding('shared_link', 'the flooded link', shareable: true);

        $issued = app(ReaderCredentials::class)->issue(
            $this->project,
            $binding,
            'shared_link',
            'flooded',
            expiresAt: time() + 3600,
            password: 'correct horse',
        );

        $credentials = app(ReaderCredentials::class);
        $resolved = $credentials->resolve($issued['secret'], 'shared_link', $this->project->id);

        $this->assertNotNull($resolved);

        /* The limit is five per address per window; spend it on wrong guesses. */
        for ($i = 0; $i < 6; $i++) {
            $this->assertFalse(
                $credentials->passwordMatches($resolved['id'], 'wrong '.$i, '203.0.113.7'),
            );
        }

        $this->assertFalse(
            $credentials->passwordMatches($resolved['id'], 'correct horse', '203.0.113.7'),
            '🛑 §8.12.16: past the limit, the right password is refused without a comparison',
        );

        /*
         * 🛑 And the limiter is per **address** as well as per credential, so
         * one attacker cannot lock the credential out for everybody else. The
         * per-credential limit is twenty, and six attempts have not reached it.
         */
        $this->assertTrue(
            $credentials->passwordMatches($resolved['id'], 'correct horse', '198.51.100.9'),
            '🛑 §8.12.16: a flood from one address must not deny every other reader',
        );
    }

    // ------------------------------------------- §8.12.17's classification

    /**
     * 🛑 `provider-009`: a rule naming a **gate** binding as `{binding}` is
     * refused at write time.
     *
     * §8.12.17 classifies each driver exactly once. A leaf contradicting the
     * table would make an `ip_allowlist` identity-bearing by a typo in a JSON
     * payload rather than by any change to code.
     */
    public function test_a_rule_naming_a_gate_binding_is_refused_at_write_time(): void
    {
        $gate = $this->activeBinding('ip_allowlist', 'the office', config: [
            'ranges' => ['203.0.113.0/24'],
        ]);

        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project, actorId: $this->operator->id);

        try {
            $policies->addRule(
                project: $this->project,
                label: 'the gate as an identity',
                allow: true,
                requirement: ['leaf' => 'binding', 'binding_id' => Uuid::toText($gate)],
                versionSlugs: ['v1'],
                actorId: $this->operator->id,
            );
            $this->fail('a gate binding was accepted as an identity leaf');
        } catch (PolicyRefused $refused) {
            $this->assertSame(RequirementRejection::Malformed, $refused->rejection);
        }
    }

    // -------------------------------------------- §8.12.2 and §8.12.3

    /**
     * 🛑 `provider-010`: an unreadable envelope **degrades**.
     *
     * Not a 500, and emphatically not a skip. A binding whose secret will not
     * open is a guard that has stopped guarding, and the one behaviour that
     * neither discloses content nor lies to the operator is §8.12.19's
     * degraded state.
     */
    public function test_an_unreadable_envelope_degrades_rather_than_throws(): void
    {
        $id = $this->activeBinding('password', 'the unreadable portal', secrets: [
            'password_hash' => Hash::make('correct horse'),
        ]);

        /*
         * Corrupt the envelope the way a rotated-away `APP_KEY` would: no
         * configured KEK unwraps the data key any more.
         *
         * 🛑 The **wrapped key**, not `kek_fingerprint`.
         * {@see \App\Credentials\EnvelopeCipher::open()} tries every candidate
         * KEK and never consults the stored fingerprint, so the fingerprint is
         * a diagnostic hint rather than the lookup. An earlier version of this
         * test corrupted it, the envelope opened cleanly, and the test asserted
         * nothing. The wrapped key is what §9.1.7's "losing APP_KEY makes every
         * provider secret unrecoverable" actually means.
         */
        DB::table('auth_provider_bindings')
            ->where('id', $id)
            ->update(['wrapped_key' => random_bytes(60)]);

        Cache::flush();

        $outcome = $this->resolve(password: 'correct horse');

        $this->assertTrue($outcome->degraded, '🛑 §8.12.19: an unreadable secret degrades');
        $this->assertSame('the unreadable portal', $outcome->degradedBinding);
        $this->assertSame([], $outcome->leaves, '🛑 a degraded outcome carries no leaf, not even public');
    }

    /**
     * 🛑 `provider-011`: resolution is most-specific **of type**.
     *
     * A project adding a `password` binding must not thereby disable the
     * installation's identity provider for its own documentation — which is a
     * privilege change performed by configuring something unrelated.
     */
    public function test_a_project_binding_does_not_shadow_an_installation_binding_of_another_type(): void
    {
        $bindings = app(Bindings::class);

        $installation = $bindings->create(
            scopeType: 'installation',
            scopeId: null,
            type: 'portal_session',
            name: 'the installation portal',
            organisationId: null,
        );

        $this->activate($installation);

        $project = $this->activeBinding('password', 'the project password', secrets: [
            'password_hash' => Hash::make('correct horse'),
        ]);

        Cache::flush();

        $resolved = array_map(
            static fn (BindingContext $context): string => $context->name,
            $bindings->contextsFor(
                (string) $this->project->id,
                (string) $this->project->organisation_id,
                0,
            ),
        );

        sort($resolved);

        $this->assertSame(
            ['the installation portal', 'the project password'],
            $resolved,
            '🛑 §8.12.3: most-specific **of type**, so both are in scope',
        );

        /* And the project's own binding is not duplicated by the join. */
        $this->assertCount(2, $resolved);
        unset($project);
    }

    // ----------------------------------------------- parsing and matching

    /**
     * 🛑 `provider-012`: `Authorization: Token <T>` is nothing.
     *
     * §20 lists the Read the Docs scheme as a deliberate incompatibility. A
     * lenient parse is the tempting fix, and a parser that accepts several
     * shapes is a parser whose shape an attacker chooses.
     */
    public function test_the_read_the_docs_token_scheme_is_nothing(): void
    {
        $binding = $this->activeBinding('reader_token', 'the CI token');

        $issued = app(ReaderCredentials::class)->issue(
            $this->project,
            $binding,
            'reader_token',
            'ci',
        );

        /* The same secret, presented the DocUp way, does satisfy. */
        $this->assertTrue(
            $this->resolve(bearer: $issued['secret'])->leaves !== [],
        );

        /*
         * 🛑 And the header parser never produces it from the Read the Docs
         * form. Asserted on the parser rather than through HTTP because this is
         * a statement about `Authorization` shapes, and the surface that reads
         * it is shared by all four reader surfaces (§8.12.21).
         */
        foreach ([
            'Token '.$issued['secret'],
            'token '.$issued['secret'],
            'Basic '.base64_encode($issued['secret'].':'),
            'Bearer '.$issued['secret'].' extra',
            'Bearer',
        ] as $header) {
            $request = Request::create('https://docs.example.test/en/v1/');
            $request->headers->set('Authorization', $header);

            $parsed = (new \ReflectionMethod(ReaderResolver::class, 'bearer'))
                ->invoke(null, $request);

            $this->assertNull($parsed, '🛑 §8.12.16: "'.$header.'" is not a Bearer token');
        }
    }

    /**
     * 🛑 `provider-013`: an IPv4-mapped IPv6 address never matches an IPv4
     * range.
     *
     * The encoding a deny list in dotted quads does not recognise, in its
     * mirror image: an allowlist that normalised the mapped form would admit
     * from a family the operator never entered.
     */
    public function test_an_ipv4_mapped_address_never_matches_an_ipv4_range(): void
    {
        $this->assertTrue(IpAllowlistDriver::covers('127.0.0.0/8', '127.0.0.1'));

        $this->assertFalse(
            IpAllowlistDriver::covers('127.0.0.0/8', '::ffff:127.0.0.1'),
            '🛑 §8.12.4: a v6 address never matches a v4 range',
        );

        $this->assertFalse(
            IpAllowlistDriver::covers('::ffff:127.0.0.0/104', '127.0.0.1'),
            '🛑 §8.12.4: and not in the other direction either',
        );

        /* Nor does a malformed range match anything, including itself. */
        $this->assertFalse(IpAllowlistDriver::covers('127.0.0.0/33', '127.0.0.1'));
        $this->assertFalse(IpAllowlistDriver::covers('not an address', 'not an address'));
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
            if (($case['category'] ?? null) === 'provider') {
                $cases[] = $case;
            }
        }

        return $cases;
    }

    /**
     * @param  array<string, mixed>  $config
     * @param  array<string, string>  $secrets
     * @return string raw 16 bytes
     */
    private function binding(
        string $type,
        string $name,
        array $config = [],
        array $secrets = [],
        bool $shareable = false,
    ): string {
        return app(Bindings::class)->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: $type,
            name: $name,
            config: $config,
            secrets: $secrets,
            organisationId: $this->organisation->id,
            shareable: $shareable,
        );
    }

    /**
     * @param  array<string, mixed>  $config
     * @param  array<string, string>  $secrets
     * @return string raw 16 bytes
     */
    private function activeBinding(
        string $type,
        string $name,
        array $config = [],
        array $secrets = [],
        bool $shareable = false,
    ): string {
        $id = $this->binding($type, $name, $config, $secrets, $shareable);

        $this->activate($id);

        return $id;
    }

    /** §8.12.19's progression, in full, because nothing may shortcut it. */
    private function activate(string $bindingId): void
    {
        $bindings = app(Bindings::class);

        $bindings->transition($bindingId, BindingState::Verifying);
        $bindings->probe($bindingId);
        $bindings->recordTestLogin($bindingId, $this->operator->id);
        $bindings->transition($bindingId, BindingState::Active);

        Cache::flush();
    }

    /** Every binding in scope, run against one presentation. */
    private function resolve(
        ?string $password = null,
        ?string $shareSecret = null,
        ?string $bearer = null,
        ?string $remoteAddress = '127.0.0.1',
    ): ProviderOutcome {
        return $this->context->acrossAllOrganisations(
            fn (): ProviderOutcome => app(ProviderResolver::class)->resolve(
                new SnapshotProject(
                    id: (string) $this->project->id,
                    slug: (string) $this->project->slug,
                    urlPrefix: null,
                    versioningScheme: 'lang_and_version',
                    routingEpoch: 0,
                    visibility: 'public',
                    chromeMode: 'docup',
                    defaultVersionId: null,
                    organisationId: (string) $this->project->organisation_id,
                ),
                new ReaderPresentation(
                    bearer: $bearer,
                    shareSecret: $shareSecret,
                    password: $password,
                    remoteAddress: $remoteAddress,
                ),
            ),
        );
    }
}
