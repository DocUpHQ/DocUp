<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Admission\AdmissionProfile;
use App\Builds\Admission\Dispatcher;
use App\Models\Organisation;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 Phase 07's fairness exit criterion.
 *
 * > "Organisation A queuing 50 builds does not delay organisation B's first
 * > build past one slot."
 *
 * And the sentence behind it, from §8.5.5:
 *
 * > "🛑 Read the Docs holds an **organisation-scoped** lock over a
 * > **per-project** FIFO queue — a verified fairness bug where one
 * > organisation's backlog starves another's first build. Neither profile
 * > may reproduce it."
 *
 * 🛑 **Asserted on a list rather than on running containers**, deliberately.
 * Fifty real builds would take half an hour and would be skipped in CI, so
 * the property would never be checked. {@see Dispatcher::order()} is the
 * thing that decides, and a list is exactly what it returns.
 */
final class FairAdmissionTest extends TestCase
{
    use DatabaseTransactions;

    /** @var array<string, string> organisation id => project id */
    private array $projects = [];

    /** @var array<string, string> organisation id => component id */
    private array $components = [];

    /** 🛑 The exit criterion, under the `fair` profile. */
    public function test_fifty_builds_from_one_organisation_do_not_delay_another(): void
    {
        config()->set('builds.admission.profile', 'fair');

        [$a, $b] = $this->twoOrganisations();

        // A gets in first, fifty times over. B arrives last of all, which
        // is the worst case a FIFO could give it.
        for ($i = 0; $i < 50; $i++) {
            $this->queueBuild($a);
        }

        $bBuild = $this->queueBuild($b);

        $order = Dispatcher::fromConfig()->order();
        $position = array_search(bin2hex($bBuild), $order, true);

        $this->assertNotFalse($position, "B's build is missing from the admission order");

        /*
         * Position 1, zero-based: after exactly one grant to A. That is
         * "not past one slot" read literally, and it is what deficit
         * round-robin gives when both organisations carry the default
         * share of 1.
         */
        $this->assertSame(
            1,
            $position,
            'organisation B waited behind '.$position.' of A\'s builds (§8.5.5 starvation)',
        );
    }

    /**
     * 🛑 The control: the same fifty builds under `simple`.
     *
     * `simple` is strict arrival order across the installation, so B — which
     * queued last — is genuinely last, and that is correct rather than a
     * bug. The distinction §8.5.5 draws is between *arrival order* and
     * *starvation*: a queue that is slow because fifty things arrived first
     * is fair; a queue that never reaches you because somebody else holds
     * the lock is not.
     *
     * Stated as a test so nobody later "fixes" `simple` into `fair` and
     * removes the operator's choice between them.
     */
    public function test_the_simple_profile_is_arrival_order_across_the_installation(): void
    {
        config()->set('builds.admission.profile', 'simple');

        [$a, $b] = $this->twoOrganisations();

        for ($i = 0; $i < 5; $i++) {
            $this->queueBuild($a);
        }

        $bBuild = $this->queueBuild($b);
        $order = Dispatcher::fromConfig()->order();

        $this->assertSame(5, array_search(bin2hex($bBuild), $order, true));
        $this->assertSame(AdmissionProfile::Simple, Dispatcher::fromConfig()->profile());
    }

    /**
     * The rotation itself, as a pure function.
     *
     * Three organisations interleave one grant each per pass, whatever the
     * arrival pattern — which is the property that makes the fifty-build
     * case above a consequence rather than a coincidence.
     */
    public function test_deficit_round_robin_interleaves_organisations(): void
    {
        $rows = [
            ['a1', 'A'], ['a2', 'A'], ['a3', 'A'], ['a4', 'A'],
            ['b1', 'B'], ['b2', 'B'],
            ['c1', 'C'],
        ];

        $this->assertSame(
            ['a1', 'b1', 'c1', 'a2', 'b2', 'a3', 'a4'],
            Dispatcher::deficitRoundRobin($rows),
        );
    }

    /** §8.5.5's "weighted by organisation share", as the weight actually doing something. */
    public function test_a_higher_share_earns_more_grants_per_rotation(): void
    {
        $rows = [
            ['a1', 'A'], ['a2', 'A'], ['a3', 'A'], ['a4', 'A'],
            ['b1', 'B'], ['b2', 'B'],
        ];

        $this->assertSame(
            ['a1', 'a2', 'a3', 'b1', 'a4', 'b2'],
            Dispatcher::deficitRoundRobin($rows, ['A' => 3, 'B' => 1]),
        );
    }

    /**
     * 🛑 A share of zero does not hang the dispatcher.
     *
     * An organisation that earns nothing per pass would spin the rotation
     * for ever if the loop waited for its deficit to reach one. The weight
     * is floored at 1 and the loop is bounded, so the worst a stray update
     * can do is give somebody an ordinary share — never suspend the whole
     * installation's builds, which is not a decision a number in a column
     * should be able to make.
     */
    public function test_a_zero_share_cannot_hang_the_rotation(): void
    {
        $out = Dispatcher::deficitRoundRobin([['a1', 'A'], ['b1', 'B']], ['A' => 0, 'B' => 0]);

        $this->assertCount(2, $out);
    }

    /** @return array{0: string, 1: string} two organisation ids, raw bytes */
    private function twoOrganisations(): array
    {
        $a = Organisation::query()->create(['name' => 'Org A', 'slug' => 'a-'.bin2hex(random_bytes(4))]);
        $b = Organisation::query()->create(['name' => 'Org B', 'slug' => 'b-'.bin2hex(random_bytes(4))]);

        return [$a->id, $b->id];
    }

    /**
     * A queued build row and nothing else.
     *
     * 🛑 Inserted directly rather than through the pipeline: admission
     * ordering reads `builds` and nothing else, and routing fifty rows
     * through the whole pipeline would make this test depend on the
     * container runtime for a property that has nothing to do with it.
     *
     * 🛑 **One version per build, because §10.3 insists.** The `inflight`
     * unique index permits at most one queued-or-running build per version
     * per kind — so fifty queued builds for one version is not a backlog,
     * it is a constraint violation. That is the right behaviour and it
     * shapes the fixture: a real fifty-build backlog is fifty versions, or
     * fifty projects, and never fifty attempts at the same one.
     */
    private function queueBuild(string $organisationId): string
    {
        static $sequence = 0;

        $id = Uuid::v7();
        $timestamp = now()->addMilliseconds($sequence++)->format('Y-m-d H:i:s.v');
        $projectId = $this->projectFor($organisationId);
        $versionId = Uuid::v7();

        DB::table('project_versions')->insert([
            'id' => $versionId,
            'organisation_id' => $organisationId,
            'project_id' => $projectId,
            'slug' => 'v'.bin2hex(random_bytes(6)),
            'created_at' => $timestamp,
            'updated_at' => $timestamp,
        ]);

        DB::table('builds')->insert([
            'id' => $id,
            'organisation_id' => $organisationId,
            'project_version_id' => $versionId,
            'component_id' => $this->componentFor($organisationId),

            /*
             * §8.8.1 makes `content_key` NOT NULL **and unique**, because
             * two builds with the same content are the same artifact. A
             * queued build has no content yet, so the fixture gives each
             * one a distinct placeholder - a shared one is rejected by the
             * uniqueness constraint doing exactly what it is for.
             * Admission reads `organisation_id`, `state` and `queued_at`
             * and none of this.
             */
            'content_key' => bin2hex(random_bytes(32)),
            'state' => 'queued',
            'kind' => 'full',
            'queued_at' => $timestamp,
            'created_at' => $timestamp,
            'updated_at' => $timestamp,
        ]);

        return $id;
    }

    /**
     * One project per organisation, created on first use.
     *
     * 🛑 Through the query builder rather than the model, like every other
     * row here. §8.2.1's global scope refuses a model query with no
     * declared organisation context, and this fixture spans TWO
     * organisations on purpose — declaring one of them would be declaring
     * the wrong one for half the rows. The scope is doing its job; the
     * fixture is below it.
     */
    private function projectFor(string $organisationId): string
    {
        if (isset($this->projects[$organisationId])) {
            return $this->projects[$organisationId];
        }

        $id = Uuid::v7();

        DB::table('projects')->insert([
            'id' => $id,
            'organisation_id' => $organisationId,
            'slug' => 'p-'.bin2hex(random_bytes(5)),
            'name' => 'Admission',
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        return $this->projects[$organisationId] = $id;
    }

    /** One component per organisation, likewise. */
    private function componentFor(string $organisationId): string
    {
        if (isset($this->components[$organisationId])) {
            return $this->components[$organisationId];
        }

        $id = Uuid::v7();

        DB::table('components')->insert([
            'id' => $id,
            'organisation_id' => $organisationId,
            'key' => 'c-'.bin2hex(random_bytes(5)),
            'name' => 'Admission',
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        return $this->components[$organisationId] = $id;
    }
}
