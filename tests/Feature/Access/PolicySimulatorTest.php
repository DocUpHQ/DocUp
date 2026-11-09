<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

use App\Access\AccessDecision;
use App\Access\AccessLeaf;
use App\Access\AccessReason;
use App\Access\AccessSurface;
use App\Access\EffectiveAccess;
use App\Access\PolicySimulator;
use App\Access\ReaderGate;
use App\Access\ReaderPolicies;
use App\Access\SimulatedIdentity;
use App\Access\SimulationAnswer;
use App\Access\SimulationRefused;
use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Bindings;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\Drivers\PortalSessionDriver;
use App\Auth\Providers\Federation\GroupMappings;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\Federation\ReaderProvisioning;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ReaderIdentity;
use App\Models\User;
use App\Readers\Grants\Grant;
use App\Readers\ReaderCookies;
use App\Readers\ReaderSessions;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Symfony\Component\HttpFoundation\Response;
use Tests\Support\ArchiveWriter;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 26a exit criterion for the simulator, in full.
 *
 * > "The simulator answers 'as this identity, on this URL' with the decision,
 * > the matching rule number and the satisfying binding, and its answer
 * > **provably agrees with a live request made as that identity** — the same
 * > `EffectiveAccess` call site, asserted by test, not a reimplementation."
 *
 * ## 🛑 How "provably agrees" is asserted here
 *
 * By comparing the simulator's answer against the **decision header of a real
 * HTTP response**, byte for byte. §17 calls that header "the decision header"
 * and {@see AccessDecision::header()} builds it from the reason
 * code, the rule position and the satisfying leaf — exactly the three facts
 * §8.12.25 asks the simulator to report. So one `assertSame` covers all three
 * at once, and it covers them in the one form an operator can also read from
 * outside the process.
 *
 * A weaker version of this test would assert the simulator allows where the
 * live request allows. That passes against a simulator that agrees on the
 * verdict and names the wrong rule — which is the failure an operator would
 * act on, because they would go and edit the rule the tool named.
 *
 * ## 🛑 The fixture is a project where the answer is not obvious
 *
 * A public project would agree trivially. This one is public at the project
 * level and `members` at the version level — §8.2.10's dominance applies, the
 * reader's established level has to reach `restricted` through a rule that
 * names the version explicitly (§12.3), and the satisfying leaf is a
 * `{binding}` naming one specific provider. Every fact §8.12.25 wants printed
 * is therefore non-default, and a simulator that guessed any of them would
 * guess wrong.
 */
final class PolicySimulatorTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $operator;

    private Project $project;

    private string $host;

    private string $bindingId;

    private string $bindingName = 'Acme employees';

    private ReaderIdentity $reader;

    private string $sessionHandle;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-simulator-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);

        $this->organisation = Organisation::query()->create([
            'name' => 'Simulator Co',
            'slug' => 'simulator-'.bin2hex(random_bytes(3)),
        ]);

        $this->context->for($this->organisation->id);

        $this->operator = User::factory()->create();

        $this->project = Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'slug' => 'handbook',
            'name' => 'Handbook',
            /*
             * 🛑 Public at the project level on purpose: it makes §8.12.23's
             * `existencePublic` true for the public version and false for the
             * `members` one, so the live response and the simulation have to
             * agree about a challenge as well as a verdict.
             */
            'visibility' => 'public',
        ]);

        $this->publish('v1', 'members');
        $this->publish('open', 'public');

        /*
         * 🛑 A third version, for the one thing the other two cannot show.
         * §12.3 elevates a reader to `restricted` when the matched allow rule
         * `namesResourceExplicitly()`, and both rules above name their version
         * — so on `v1` and `open` the established level is `restricted` whatever
         * the reader's own floor was. `wide` is governed by a rule with **no**
         * selectors, so no elevation fires and the floor is what decides.
         */
        $this->publish('wide', 'members');

        /*
         * 🛑 Under the installation's own documentation apex, because
         * §8.9.3's `default_subdomain` candidate is built from
         * `docup.origins.docs` — a host outside it resolves to nothing, and
         * every assertion here would pass against a simulator that always
         * answered "unresolved". Phase 25 hit the same trap from the other
         * side, with an underscore in a hostname.
         */
        $this->host = 'handbook-'.bin2hex(random_bytes(3)).'.'.$this->docsApex();
        $this->mount();

        $this->bindingId = $this->bind();
        $this->reader = $this->provisionReader('employee-7', ['engineering']);

        /*
         * 🛑 The rule names the version explicitly. §12.3 only reaches the
         * `restricted` rung through
         * {@see \App\Access\PolicyRule::namesResourceExplicitly()}, and a rule
         * with an empty slug list would leave the reader at `authenticated` —
         * which a `members` version refuses. The test would then be two
         * agreeing 404s, which is agreement about nothing.
         */
        $policies = app(ReaderPolicies::class);
        $policies->createFor($this->project);

        $policies->addRule(
            project: $this->project,
            label: 'employees read the handbook',
            allow: true,
            requirement: ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($this->bindingId)],
            versionSlugs: ['v1'],
            actorId: $this->operator->id,
        );

        /*
         * 🛑 The public version needs a rule of its own, and that is §8.12.6
         * rather than an oversight: "policy default effect **deny**", so once a
         * policy exists a page with no matching rule is refused however public
         * its visibility. An operator meeting this for the first time is
         * exactly who §8.12.25 is for.
         */
        $policies->addRule(
            project: $this->project,
            label: 'the open version is public',
            allow: true,
            requirement: ['leaf' => AccessLeaf::Public->value],
            versionSlugs: ['open'],
            publicCacheMode: true,
            actorId: $this->operator->id,
        );

        /*
         * 🛑 No version selector and no path prefix, so
         * `namesResourceExplicitly()` is false and §12.3's `restricted`
         * elevation does not fire. Last in the policy, so §8.12.6's
         * first-match leaves `v1` and `open` to the rules above and this
         * governs everything else.
         */
        $policies->addRule(
            project: $this->project,
            label: 'any of our people, anywhere else',
            allow: true,
            requirement: ['leaf' => AccessLeaf::Binding->value, 'binding_id' => Uuid::toText($this->bindingId)],
            actorId: $this->operator->id,
        );

        $this->sessionHandle = $this->signIn($this->reader);

        $this->context->forget();
        Cache::flush();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ------------------------------------------- §17's exit criterion

    /**
     * 🛑 The criterion itself: the simulator's answer and a live reader's
     * response carry the **same decision header**.
     */
    public function test_the_simulator_agrees_with_a_live_request_as_the_same_identity(): void
    {
        $live = $this->read('/en/v1/', withSession: true);

        $live->assertOk();

        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->assertNotNull($answer->decision);
        $this->assertTrue($answer->decision->allowed);

        $this->assertSame(
            $live->headers->get(ReaderGate::DECISION_HEADER),
            $answer->decision->header(),
            '🛑 §17: the simulator must agree with a live request made as that identity, '
                .'and the decision header is all three facts §8.12.25 asks for at once',
        );
    }

    /**
     * 🛑 And it agrees on a **denial**, which is the harder half.
     *
     * An allow that agrees could come from two functions that both say yes. A
     * denial carries a reason code naming which of §12.3's conjuncts refused,
     * and two implementations agreeing on *that* is not a coincidence.
     */
    public function test_the_simulator_agrees_with_a_live_anonymous_request(): void
    {
        $live = $this->read('/en/v1/', withSession: false);

        $answer = $this->simulate(SimulatedIdentity::anonymous(), '/en/v1/');

        $this->assertNotNull($answer->decision);
        $this->assertFalse($answer->decision->allowed);

        $this->assertSame(
            $live->headers->get(ReaderGate::DECISION_HEADER),
            $answer->decision->header(),
            '🛑 §17: a refusal must agree too, reason code and all',
        );

        $this->assertSame($live->getStatusCode(), $answer->decision->status);
    }

    /** And on a page both may read, so the agreement is not an artefact of one verdict. */
    public function test_the_simulator_agrees_on_a_public_version(): void
    {
        foreach ([true, false] as $withSession) {
            $live = $this->read('/en/open/', withSession: $withSession);

            $live->assertOk();

            $answer = $this->simulate(
                $withSession ? SimulatedIdentity::reader($this->reader->id) : SimulatedIdentity::anonymous(),
                '/en/open/',
            );

            $this->assertNotNull($answer->decision);
            $this->assertSame(
                $live->headers->get(ReaderGate::DECISION_HEADER),
                $answer->decision->header(),
                'the public version must agree for both readers',
            );
        }
    }

    // ------------------------------------------- §8.12.25's sentence

    /**
     * 🛑 §8.12.25's exact shape: "allow, by rule 7, satisfied by binding X".
     *
     * The rule **position** and the binding **name**, not the leaf kind and not
     * an id — because the requirement is about what an operator can act on, and
     * neither a leaf kind nor a UUID tells them which line of their own
     * configuration decided.
     */
    public function test_the_answer_names_the_rule_position_and_the_binding(): void
    {
        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->assertNotNull($answer->decision);
        $this->assertNotNull($answer->decision->rule);

        $this->assertSame('employees read the handbook', $answer->decision->rule->label);
        $this->assertSame(AccessLeaf::Binding, $answer->decision->satisfiedBy);
        $this->assertSame($this->bindingName, $answer->satisfiedByBinding);

        /* And the one-line form carries all three, which is what the audit row records. */
        $this->assertStringContainsString('rule='.$answer->decision->rule->position, $answer->summary());
        $this->assertStringContainsString('binding='.$this->bindingName, $answer->summary());
    }

    /** The identity is described from stored facts, so an operator can confirm their choice. */
    public function test_the_answer_describes_the_identity_it_simulated(): void
    {
        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->assertSame('employee-7', $answer->identityLabel);
        $this->assertSame(['engineering'], $answer->identityGroups);
    }

    /**
     * 🛑 The path the **policy** saw, which is not the path the reader typed.
     *
     * §12.3 writes `path_patterns` "relative to a component mount" while a
     * reader types a version-rooted URL. An operator debugging a rule that
     * matches nothing is as likely to have the wrong path space as the wrong
     * pattern, and a simulator that printed only the typed path would confirm
     * the wrong thing.
     */
    public function test_the_answer_reports_the_mount_relative_path(): void
    {
        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/guide/index.html');

        $this->assertSame('/en/v1/guide/index.html', $answer->requestPath);
        $this->assertSame('guide/index.html', ltrim((string) $answer->mountRelativePath, '/'));
        $this->assertSame('v1', $answer->versionSlug);
        $this->assertSame('en', $answer->language);
    }

    // ------------------------------------------- what a simulation must not do

    /**
     * 🛑 **Nothing reaches §20.3's decision log.**
     *
     * The reason is in {@see ReaderGate::simulate()}: a simulation is not a
     * request, and an *allow* row attributed to a reader who never asked would
     * be indistinguishable from a real one for ever, because §20.3 stores only
     * a keyed digest of the subject. The count is taken around both a live
     * request and a simulation, so the test also proves the live path still
     * writes — a simulator that passed by breaking logging altogether would
     * fail here.
     */
    public function test_a_simulation_writes_no_decision_log_row(): void
    {
        $before = DB::table('access_decisions')->count();

        $this->read('/en/v1/', withSession: true);

        $afterLive = DB::table('access_decisions')->count();

        $this->assertGreaterThan($before, $afterLive, 'a live request must still be logged');

        for ($i = 0; $i < 3; $i++) {
            $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');
            $this->simulate(SimulatedIdentity::anonymous(), '/en/v1/');
        }

        $this->assertSame(
            $afterLive,
            DB::table('access_decisions')->count(),
            '🛑 §20.3: a simulation is not a reader request and must leave no row',
        );
    }

    /**
     * 🛑 And no session, no grant and no credential use is created either.
     *
     * A simulator that minted a session to ask its question would hand an
     * operator a working credential for somebody else's identity every time
     * they used it — and §8.12.15's session inventory would fill with sessions
     * nobody signed in to.
     */
    public function test_a_simulation_mints_nothing(): void
    {
        $sessions = DB::table('docs_sessions')->count();

        for ($i = 0; $i < 3; $i++) {
            $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');
        }

        $this->assertSame($sessions, DB::table('docs_sessions')->count());
    }

    // ------------------------------------------- honest answers

    /**
     * 🛑 A URL that resolves to nothing is **not** a denial.
     *
     * §8.9.3 and §8.11.1 decide what a URL means before §12.3 decides who may
     * read it. Reporting "deny" here would send an operator to edit a policy
     * that was never consulted — which is the most expensive wrong answer this
     * tool could give, because the edit they make will be a widening one.
     */
    public function test_an_unresolvable_url_is_not_reported_as_a_denial(): void
    {
        $answer = $this->simulate(SimulatedIdentity::anonymous(), '/en/no-such-version/');

        $this->assertFalse($answer->reachedAVersion());
        $this->assertNull($answer->decision);
        $this->assertNotNull($answer->rejection);
        $this->assertStringStartsWith('unresolved:', $answer->summary());
    }

    /** An unknown host is the same class of answer, not a 404 dressed as a refusal. */
    public function test_an_unknown_host_is_not_reported_as_a_denial(): void
    {
        $this->context->for($this->organisation->id);

        $answer = app(PolicySimulator::class)->simulate(
            SimulatedIdentity::anonymous(),
            'nothing-here.example.test',
            '/en/v1/',
        );

        $this->context->forget();

        $this->assertFalse($answer->reachedAVersion());
        $this->assertNull($answer->decision);
    }

    /**
     * 🛑 A leaf no simulation can establish is **reported**, never faked.
     *
     * §9.1.4 stores a share link's and a reader token's secret hashed, so there
     * is nothing to present to the driver. Two denials that look identical mean
     * opposite things — "your policy refuses this identity" and "this identity
     * was never the one that rule is for" — and an operator told only `deny`
     * concludes the first.
     */
    public function test_a_leaf_that_cannot_be_simulated_is_reported(): void
    {
        $this->context->for($this->organisation->id);

        app(ReaderPolicies::class)->addRule(
            project: $this->project,
            label: 'token holders read the appendix',
            allow: true,
            requirement: ['leaf' => AccessLeaf::Bearer->value],
            versionSlugs: ['v1'],
            pathPatterns: ['/appendix'],
            actorId: $this->operator->id,
        );

        $this->context->forget();
        Cache::flush();

        $answer = $this->simulate(SimulatedIdentity::anonymous(), '/en/v1/appendix/secret.html');

        $this->assertSame([AccessLeaf::Bearer], $answer->unsimulatable);

        /* And a URL that rule does not match says nothing about it. */
        $elsewhere = $this->simulate(SimulatedIdentity::anonymous(), '/en/v1/');

        $this->assertSame([], $elsewhere->unsimulatable);
    }

    /**
     * 🛑 A future `now` answers about the future, and the decider is what
     * answers it.
     *
     * §12.3's `not_after` is a decision input rather than a scheduled job, so
     * "will this still hold next week" is a question {@see EffectiveAccess}
     * can answer exactly. A simulator that compared dates itself would be a
     * second implementation of the one clause most likely to be tested by an
     * operator and least likely to be noticed when wrong.
     */
    public function test_a_future_clock_answers_about_the_future(): void
    {
        $this->context->for($this->organisation->id);

        /* The admitting rule stops applying in an hour. */
        DB::table('reader_policy_rules')
            ->where('label', 'employees read the handbook')
            ->update(['not_after' => date('Y-m-d H:i:s.v', time() + 3600)]);

        $this->context->forget();
        Cache::flush();

        $now = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->assertNotNull($now->decision);
        $this->assertTrue($now->decision->allowed, 'the rule still applies today');

        $this->context->for($this->organisation->id);

        $later = app(PolicySimulator::class)->simulate(
            SimulatedIdentity::reader($this->reader->id),
            $this->host,
            '/en/v1/',
            now: time() + 7200,
        );

        $this->context->forget();

        $this->assertNotNull($later->decision);

        /*
         * 🛑 Past `not_after` the rule is not applicable, and §8.12.6's
         * first-match hands the decision to the **next** rule that matches —
         * which is the catch-all added for the group tests. So the observable
         * consequence of an expiry is not a denial but a different decider, and
         * asserting the rule is sharper than asserting the verdict: a test that
         * only checked `allowed` would pass against a policy where rule 1 had
         * never applied at all.
         */
        $this->assertNotNull($later->decision->rule);
        $this->assertSame(
            'any of our people, anywhere else',
            $later->decision->rule->label,
            '🛑 §8.12.6: an expired rule hands first-match to the next one that matches',
        );
        $this->assertNotSame(
            $now->decision->rule?->label,
            $later->decision->rule->label,
            'and that is a different rule from the one deciding today',
        );
    }

    /** §8.12.21's surfaces are an input, so the simulator can be asked about each. */
    public function test_a_surface_is_part_of_the_question(): void
    {
        $proxy = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->context->for($this->organisation->id);

        $search = app(PolicySimulator::class)->simulate(
            SimulatedIdentity::reader($this->reader->id),
            $this->host,
            '/en/v1/',
            surface: AccessSurface::Search,
        );

        $this->context->forget();

        $this->assertNotNull($proxy->decision);
        $this->assertNotNull($search->decision);

        $this->assertTrue($proxy->decision->allowed);

        /*
         * 🛑 §8.12.21: "a project's search MUST be **disabled** while its
         * search generation lags its policy generation". A policy was written
         * in `setUp` and nothing has reindexed, so the search surface is
         * legitimately refused — and the simulator reporting a *different*
         * answer per surface is the proof it passes the surface through rather
         * than hard-coding the proxy.
         */
        $this->assertFalse($search->decision->allowed);
        $this->assertSame(AccessReason::SearchGenerationStale, $search->decision->reason);
    }

    // ------------------------------------------- the identity guards

    /**
     * 🛑 Another organisation's reader identity is **refused**, not denied.
     *
     * A `reader_identities` row carries the binding that vouched for it and the
     * groups §8.13.7 reconciled onto it, and both would be rendered into an
     * answer in this tenant's dashboard. §8.2.2 makes a cross-tenant reference
     * a 404; a `deny` would be a statement about somebody else's reader that
     * this operator is not entitled to make.
     */
    public function test_another_organisations_identity_is_refused(): void
    {
        $other = Organisation::query()->create([
            'name' => 'Globex',
            'slug' => 'globex-'.bin2hex(random_bytes(3)),
        ]);

        $this->context->for($other->id);

        $stranger = new ReaderIdentity;
        $stranger->forceFill([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $other->id,
            'binding_id' => $this->bindingId,
            'subject_hash' => hash('sha256', 'stranger', binary: true),
            'display_label' => 'a stranger',
            'created_at' => now(),
            'updated_at' => now(),
        ])->save();

        $this->context->forget();

        try {
            $this->simulate(SimulatedIdentity::reader($stranger->id), '/en/v1/');
            $this->fail('another organisation’s identity was simulated');
        } catch (SimulationRefused $refused) {
            $this->assertSame('no_such_identity', $refused->reasonCode);
        }
    }

    /** §8.13.7's deprovisioned identity has no reader to simulate. */
    public function test_a_deprovisioned_identity_is_refused(): void
    {
        $this->context->for($this->organisation->id);

        DB::table('reader_identities')
            ->where('id', $this->reader->id)
            ->update(['deprovisioned_at' => now()]);

        $this->context->forget();

        try {
            $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');
            $this->fail('a deprovisioned identity was simulated');
        } catch (SimulationRefused $refused) {
            $this->assertSame('identity_deprovisioned', $refused->reasonCode);
        }
    }

    /** An id naming nothing is refused rather than treated as anonymous. */
    public function test_an_unknown_identity_is_refused(): void
    {
        try {
            $this->simulate(SimulatedIdentity::reader(Uuid::toBytes(Uuid::v7())), '/en/v1/');
            $this->fail('an absent identity was simulated');
        } catch (SimulationRefused $refused) {
            $this->assertSame('no_such_identity', $refused->reasonCode);
        }
    }

    /**
     * 🛑 A dashboard member reaches §12.3's `members` rung, and a reader
     * identity never does.
     *
     * §8.12.1 forbids a reader identity from holding a role assignment at all,
     * so the two populations are legitimately different answers to the same
     * URL — and a simulator that collapsed them would tell an operator their
     * `members` rule admits their IdP's readers, which it does not.
     */
    public function test_a_member_is_refused_by_the_rule_written_for_an_idp(): void
    {
        $this->context->for($this->organisation->id);

        DB::table('role_assignments')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->operator->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => 'org_admin',
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->forget();
        Cache::flush();

        $member = $this->simulate(SimulatedIdentity::member($this->operator->id), '/en/v1/');
        $reader = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/v1/');

        $this->assertNotNull($member->decision);
        $this->assertNotNull($reader->decision);

        /*
         * 🛑 **The member is refused, and this is the trap §8.12.25 exists
         * for.**
         *
         * Their established level is `members` — the strongest rung a role
         * assignment reaches — and they are still denied, because §8.12.6 is
         * first-match-wins and rule 1 matched: it selects version `v1` for
         * *everybody*, and its requirement names the SAML binding, which a
         * dashboard session does not carry
         * ({@see \App\Auth\Providers\Drivers\PortalSessionDriver}, Phase
         * 24's narrowing). So an operator who adds an IdP rule to a version
         * locks their own staff out of it, with a `members` level that looks
         * like it should be enough.
         *
         * There is no way to discover that from the lattice, from the rule, or
         * from the level in isolation. It is visible in one place: a simulation
         * that names the rule that refused. An operator told only "denied"
         * would widen the version's visibility and leak it.
         */
        $this->assertFalse($member->decision->allowed);
        $this->assertSame('members', $member->decision->established->value);
        $this->assertSame(AccessReason::RequirementUnsatisfied, $member->decision->reason);
        $this->assertNotNull($member->decision->rule);
        $this->assertSame('employees read the handbook', $member->decision->rule->label);

        /* And the reader the rule was written for is admitted by it, elevated
         * to `restricted` because
         * {@see \App\Access\PolicyRule::namesResourceExplicitly()} holds. */
        $this->assertTrue($reader->decision->allowed);
        $this->assertSame('restricted', $reader->decision->established->value);
        $this->assertSame($this->bindingName, $reader->satisfiedByBinding);
        $this->assertNull(
            $member->satisfiedByBinding,
            '🛑 §8.12.1: a dashboard session carries no binding, so no binding satisfied it',
        );
    }

    /**
     * 🛑 **§12.3's `members` rung by GROUP — the half of its own definition
     * that nothing implemented until Phase 26b.**
     *
     * §12.3: "`members` — a reader whose identity maps to a role assignment
     * **or group** on this organisation." Phase 24 built the write side
     * (§8.13.7 reconciles `reader_groups` on every login, added and removed)
     * and Phase 26a found that **no decision path ever read the column**. So an
     * operator could map an IdP group to a reader group, watch it land on the
     * identity, and find their `members` rule still refusing every reader it
     * was written for — with nothing anywhere saying why.
     *
     * The simulator is how that was found and this is where it is fixed, which
     * is a fair summary of what §8.12.25 is for.
     *
     * 🛑 Asserted on `wide`, whose rule names no version, because §12.3's
     * `restricted` elevation would otherwise mask the floor the group raised —
     * which is the whole of what is being tested.
     */
    public function test_a_reader_with_a_mapped_group_reaches_the_members_rung(): void
    {
        /* The fixture maps `engineering`, so this reader carries a group. */
        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/wide/');

        $this->assertSame(
            ['engineering'],
            $answer->identityGroups,
            'the fixture reader carries a reconciled group',
        );

        $this->assertNotNull($answer->decision);
        $this->assertSame(
            'members',
            $answer->decision->established->value,
            '🛑 §12.3: a mapped group is "a group on this organisation", so the reader is a member',
        );
        $this->assertTrue(
            $answer->decision->allowed,
            'and `members` is what a `members` version requires',
        );
    }

    /**
     * 🛑 And a reader with **no** group stays at `authenticated` — and is
     * therefore refused, which is what makes the previous test mean something.
     *
     * Without this the elevation could be unconditional, every
     * provider-authenticated reader a member, and §12.3's second rung would
     * have collapsed into its third with every test still green.
     */
    public function test_a_reader_with_no_group_stays_authenticated_and_is_refused(): void
    {
        $this->forgetGroups();

        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/wide/');

        $this->assertSame([], $answer->identityGroups);

        $this->assertNotNull($answer->decision);
        $this->assertSame(
            'authenticated',
            $answer->decision->established->value,
            '🛑 §12.3: no group, no `members` — the rungs stay distinct',
        );
        $this->assertFalse($answer->decision->allowed, 'a `members` version refuses an `authenticated` reader');
    }

    /**
     * 🛑 **§17's Phase 26b exit criterion, in the form it can actually hold:
     * removing the group drops the access.**
     *
     * §17 words it "an LDAP group removal drops access on the next decision".
     * The honest bound is the next **login**, or the next request after an epoch
     * bump — not the next decision. §12.3's decision function is pure and reads
     * a `ReaderContext`, so the groups have to be in the context already, and
     * putting a directory round-trip on every reader request is not something
     * this product does. §8.12.26 states that latency honestly for SCIM —
     * "epoch bump plus grant TTL plus the refresh-session ceiling" — and the
     * same words apply here. **Proposed amendment** to the criterion, recorded
     * in the build log.
     *
     * What this asserts is the half that is a property of the code: once the
     * group is gone from the identity, the access is gone from the decision.
     * And it asserts it both ways round, so it cannot pass against a decision
     * that refuses everybody.
     */
    public function test_removing_the_group_drops_the_access(): void
    {
        $before = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/wide/');

        $this->assertNotNull($before->decision);
        $this->assertTrue($before->decision->allowed, 'the reader reads it while the group holds');

        $this->forgetGroups();

        $after = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/wide/');

        $this->assertNotNull($after->decision);
        $this->assertFalse($after->decision->allowed, '🛑 §17: the group removal drops the access');
        $this->assertSame('authenticated', $after->decision->established->value);
    }

    /**
     * 🛑 And a **live request** agrees, because the elevation happens in
     * `ReaderSessions::contextFor()` — on the path the simulator and the
     * serving path share. A test of only one would not prove the other, and
     * §17's own criterion for the simulator is that the two agree.
     */
    public function test_a_live_request_agrees_about_the_group(): void
    {
        $live = $this->read('/en/wide/', withSession: true);

        $live->assertOk();

        $answer = $this->simulate(SimulatedIdentity::reader($this->reader->id), '/en/wide/');

        $this->assertNotNull($answer->decision);
        $this->assertSame(
            $live->headers->get(ReaderGate::DECISION_HEADER),
            $answer->decision->header(),
        );

        $this->forgetGroups();

        $this->read('/en/wide/', withSession: true)->assertNotFound();
    }

    // ------------------------------------------------------------- fixtures

    /**
     * 🛑 Inside a tenant context, because the simulator requires one.
     *
     * {@see PolicySimulator::describe()} finds a reader identity through
     * §8.2.1's global scope, which is what makes "belongs to another
     * organisation" indistinguishable from "does not exist" — the guard is the
     * absence of a row rather than a comparison this code could get wrong. The
     * dashboard always has a context (the `tenant` middleware), so declaring
     * one here is modelling the real caller and not working around a bug.
     *
     * The contrast with {@see self::read()} is the point: the serving path
     * declares **no** context, because §8.9.4 resolves a project from the host
     * and path alone and a reader is not a tenant. Both callers of the same
     * decision, one scoped and one not.
     */
    /**
     * §8.13.7's reconciliation, with the group gone.
     *
     * Written directly rather than through a re-login, because a re-login is
     * the *mechanism* and this suite is about the decision: what matters is
     * that the decision follows the column, whoever changed it.
     */
    private function forgetGroups(): void
    {
        $this->context->for($this->organisation->id);

        DB::table('reader_identities')
            ->where('id', $this->reader->id)
            ->update(['reader_groups' => '[]']);

        $this->context->forget();

        Cache::flush();
    }

    private function simulate(SimulatedIdentity $identity, string $path): SimulationAnswer
    {
        $this->context->for($this->organisation->id);

        try {
            return app(PolicySimulator::class)->simulate($identity, $this->host, $path);
        } finally {
            $this->context->forget();
        }
    }

    /**
     * One live documentation request, with **no** tenant context.
     *
     * 🛑 §8.9.4: the project is resolved from the host and the path alone, so
     * the serving path declares no organisation. Forgetting it here is what
     * makes this a real request rather than a dashboard one wearing a reader's
     * cookie.
     *
     * @return TestResponse<Response>
     */
    private function read(string $path, bool $withSession): TestResponse
    {
        $this->context->forget();

        $request = Request::create(
            'https://'.$this->host.$path,
            'GET',
            [],
            $withSession ? [ReaderCookies::SESSION => $this->sessionHandle] : [],
            [],
            ['REMOTE_ADDR' => '127.0.0.1'],
        );

        return TestResponse::fromBaseResponse($this->app->handle($request));
    }

    private function publish(string $slug, string $visibility): void
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => $visibility,
        ])->save();

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>{$slug}</body></html>\n")
            ->add('html/guide/index.html', "<!doctype html><html><head></head><body>guide</body></html>\n")
            ->add('html/appendix/secret.html', "<!doctype html><html><head></head><body>appendix</body></html>\n")
            ->toTarGz($this->fixtures.'/'.$slug.'.tar.gz');

        app(Publisher::class)->publishUpload($version, $archive);
    }

    private function mount(): void
    {
        $domainId = Uuid::v7();

        DB::table('domains')->insert([
            'id' => $domainId,
            'organisation_id' => $this->organisation->id,
            'host' => $this->host,
            'kind' => 'default_subdomain',
            'state' => 'active',
            'verified_at' => now(),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        DB::table('domain_mounts')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'domain_id' => $domainId,
            'project_id' => $this->project->id,
            'path_prefix' => '',
            'mode' => 'canonical',
            'mount_exposure' => 'inherit',
            'position' => 0,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /**
     * One `saml` binding, Active, with one group mapping.
     *
     * 🛑 `saml` rather than `portal_session`, and the reason is a real
     * constraint rather than a preference: a reader identity's session carries
     * the binding that vouched for it, and
     * {@see PortalSessionDriver::attempt()}
     * refuses precisely that — Phase 24's narrowing, so that a project writing
     * `{"driver": "portal_session"}` means "our own people" and not "anybody
     * with a session". `saml` is chosen over `oidc` because §8.12.18's driver
     * probe makes **no outbound request**: it parses the certificate. So this
     * fixture needs no identity provider standing up, and a failure here is a
     * simulator failure rather than a transport one.
     */
    private function bind(): string
    {
        $bindings = app(Bindings::class);
        $idp = new HostileSamlResponses;

        $binding = $bindings->create(
            scopeType: 'project',
            scopeId: $this->project->id,
            type: 'saml',
            name: $this->bindingName,
            config: [
                'idp_entity_id' => HostileSamlResponses::ISSUER,
                'sso_url' => 'https://idp.example.test/sso',
                'certificate' => $idp->certificate(),
                'provisioning' => ProvisioningMode::CreateReaderAndMapGroups->value,
                'groups_attribute' => 'groups',
            ],
            organisationId: $this->organisation->id,
            actorId: $this->operator->id,
        );

        /*
         * 🛑 Both steps. `recordTestLogin` records §8.12.19's proof and does
         * **not** promote; `transition(Active)` additionally re-runs `probe()`.
         * Phase 25 learned this the slow way: without them every request 404s,
         * and the symptom reads as a bad certificate.
         */
        $bindings->transition($binding, BindingState::Verifying, $this->operator->id);
        $bindings->recordTestLogin($binding, $this->operator->id);

        /* The stored probe result is what the Active gate reads. */
        $probe = $bindings->probe($binding);

        $this->assertTrue($probe->passed, $probe->summary);

        $bindings->transition($binding, BindingState::Active, $this->operator->id);

        /*
         * §8.13.7's mapping, so the identity's reconciled groups are a real
         * reconciliation rather than a claim copied through. Without a mapping
         * the asserted group is discarded, which is correct and would make the
         * simulator's group display untested.
         */
        app(GroupMappings::class)->add(
            bindingId: $binding,
            bindingScopeType: 'project',
            organisationId: $this->organisation->id,
            providerGroup: 'engineering',
            target: 'group',
            targetValue: 'engineering',
        );

        return $binding;
    }

    /**
     * A reader identity, through §8.13.7's own provisioning path.
     *
     * 🛑 Not a hand-written row: {@see ReaderProvisioning} is what computes
     * §8.12.1's keyed subject hash and §8.13.7's reconciled groups, and a
     * fixture that wrote those columns itself would be testing the simulator
     * against data no sign-in could produce.
     *
     * @param  list<string>  $groups
     */
    private function provisionReader(string $subject, array $groups): ReaderIdentity
    {
        $binding = app(Bindings::class)->byId($this->bindingId);

        $this->assertNotNull($binding);

        return app(ReaderProvisioning::class)->provision(
            binding: $binding,
            mode: ProvisioningMode::CreateReaderAndMapGroups,
            claims: ['sub' => $subject, 'name' => $subject, 'groups' => $groups],
            groupsClaim: 'groups',
        );
    }

    private function docsApex(): string
    {
        $apex = config('docup.origins.docs');

        return is_string($apex) && $apex !== '' ? $apex : 'docs.docup.localhost';
    }

    /** The session a live request will carry, established by the live code. */
    private function signIn(ReaderIdentity $reader): string
    {
        $domainId = (string) DB::table('domains')->where('host', $this->host)->value('id');

        $project = Project::query()->findOrFail($this->project->id);

        $established = app(ReaderSessions::class)->establish(
            project: $project,
            domainId: $domainId,
            subject: $reader,
            combinedEpoch: Grant::combinedEpoch((int) $project->authz_epoch, (int) $project->identity_epoch),
        );

        return (string) $established['handle'];
    }
}
