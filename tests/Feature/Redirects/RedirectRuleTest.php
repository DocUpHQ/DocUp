<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Redirects;

use App\Auth\OrganisationContext;
use App\Models\Domain;
use App\Models\Organisation;
use App\Models\Project;
use App\Redirects\RedirectEngine;
use App\Redirects\RedirectKind;
use App\Redirects\RedirectRefused;
use App\Redirects\RedirectRejection;
use App\Redirects\Redirects;
use App\Redirects\RedirectSet;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 §8.11.2's save-time refusals, §8.11.3's cycle detection, and §17's
 * performance criterion.
 *
 * > "A 1,000-redirect project resolves in **one query** under 10 ms. An
 * > A→B→A cycle is rejected at save time; a runtime chain exceeding the hop
 * > cap 404s."
 */
final class RedirectRuleTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private Redirects $redirects;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hosted Co',
            'slug' => 'hosted-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'manual-'.bin2hex(random_bytes(3)),
            'name' => 'Manual',
            'visibility' => 'public',
        ]);

        $this->redirects = new Redirects;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /** 🛑 §8.11.3: "An A→B→A cycle is rejected at save time." */
    public function test_a_two_rule_cycle_is_rejected_at_save_time(): void
    {
        $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/b.html');

        try {
            $this->redirects->create($this->project, RedirectKind::Exact, '/b.html', '/a.html');
            $this->fail('the cycle was accepted');
        } catch (RedirectRefused $refused) {
            $this->assertSame(RedirectRejection::CycleDetected, $refused->rejection);

            /*
             * The message names the cycle, because an operator looking at a
             * form needs to know which of their rules closed the loop —
             * "cycle detected" with no path is a refusal they cannot act
             * on.
             */
            $this->assertStringContainsString('/b.html → /a.html → /b.html', $refused->getMessage());
        }

        $this->assertSame(1, DB::table('redirect_rules')->where('project_id', $this->project->id)->count());
    }

    /** And a longer one: A→B→C→A. */
    public function test_a_three_rule_cycle_is_rejected(): void
    {
        $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/b.html');
        $this->redirects->create($this->project, RedirectKind::Exact, '/b.html', '/c.html');

        $this->expectException(RedirectRefused::class);

        $this->redirects->create($this->project, RedirectKind::Exact, '/c.html', '/a.html');
    }

    /** A rule pointing at itself is the degenerate cycle, named separately. */
    public function test_a_self_redirect_is_rejected(): void
    {
        try {
            $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/a.html');
            $this->fail('accepted');
        } catch (RedirectRefused $refused) {
            $this->assertSame(RedirectRejection::SelfRedirect, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.11.3's runtime half: "a runtime chain exceeding the hop cap
     * 404s".
     *
     * A `prefix` rule whose target falls under its own pattern is a loop no
     * graph over literals can see — the save-time detector drops templated
     * edges on purpose, because `/b/:splat` is not a path. This is the case
     * the hop cap exists for.
     */
    public function test_a_runtime_chain_past_the_hop_cap_matches_nothing(): void
    {
        $engine = new RedirectEngine;

        /*
         * `/loop/:splat` → `/loop/x/:splat` grows the path forever: every
         * target matches the pattern again, and no two hops repeat a path,
         * so the revisit check never fires and only the cap stops it.
         */
        $set = new RedirectSet([
            [
                'id' => 'r1',
                'position' => 1,
                'kind' => 'prefix',
                'forced' => false,
                'from' => '/loop/:splat',
                'to' => '/loop/x/:splat',
                'status' => 301,
            ],
        ], regexEnabled: true);

        $this->assertNull(
            $engine->follow($set, '/loop/page.html'),
            '🛑 a chain past the cap must match nothing, so the caller 404s',
        );
    }

    /** A chain inside the cap is followed and reported as one redirect. */
    public function test_a_chain_inside_the_cap_is_followed_server_side(): void
    {
        $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/b.html');
        $this->redirects->create($this->project, RedirectKind::Exact, '/b.html', '/c.html');

        $set = $this->redirects->setFor((string) $this->project->id, 1);
        $match = (new RedirectEngine)->follow($set, '/a.html');

        $this->assertNotNull($match);
        $this->assertSame('/c.html', $match->to, 'the reader gets one redirect, not two round trips');
        $this->assertSame(2, $match->hops);
    }

    /**
     * 🛑 §17: "A 1,000-redirect project resolves in **one query** under 10
     * ms."
     *
     * Both halves asserted, and the query count is the one that constrains
     * the design: no index can answer "which of these patterns matches this
     * string", so the rules are loaded whole and matched in PHP. An
     * implementation that asked the database per rule would pass a timing
     * assertion on a fast machine and fail this one always.
     */
    public function test_a_thousand_rules_resolve_in_one_query_under_ten_milliseconds(): void
    {
        $this->seedRules(1_000);

        $queries = 0;
        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $started = hrtime(true);
        $set = $this->redirects->setFor((string) $this->project->id, 7);
        $match = (new RedirectEngine)->follow($set, '/bulk/rule-999.html');
        $elapsed = (hrtime(true) - $started) / 1_000_000;

        $this->assertSame(1, $queries, '🛑 one query, whatever the rule count');
        $this->assertNotNull($match, 'the thousandth rule must still be reachable');
        $this->assertSame('/bulk/moved-999.html', $match->to);
        $this->assertLessThan(10.0, $elapsed, 'resolved in '.round($elapsed, 2).' ms');
    }

    /** And a second resolution costs no query at all, because of the epoch key. */
    public function test_a_repeat_resolution_is_served_from_the_epoch_keyed_cache(): void
    {
        $this->seedRules(50);
        $this->redirects->setFor((string) $this->project->id, 7);

        $queries = 0;
        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        $this->redirects->setFor((string) $this->project->id, 7);

        $this->assertSame(0, $queries);
    }

    /**
     * 🛑 §8.11.2's open-redirect refusal, which is the one that keeps a
     * redirect rule from becoming an attack.
     */
    public function test_an_absolute_target_to_an_unproven_host_is_refused(): void
    {
        foreach (['https://evil.test/phish', 'http://evil.test/', '//evil.test/', '/\\evil.test'] as $target) {
            try {
                $this->redirects->create($this->project, RedirectKind::Exact, '/go.html', $target);
                $this->fail($target.' was accepted');
            } catch (RedirectRefused $refused) {
                $this->assertContains(
                    $refused->rejection,
                    [RedirectRejection::TargetNotProven, RedirectRejection::TargetMalformed],
                    'for '.$target,
                );
            }
        }
    }

    /**
     * 🛑 And credentials in the authority, which point somewhere other than
     * they read.
     */
    public function test_a_target_whose_authority_lies_is_refused(): void
    {
        $this->provenHost('docs.acme.example');

        try {
            $this->redirects->create(
                $this->project,
                RedirectKind::Exact,
                '/go.html',
                'https://docs.acme.example@evil.test/',
            );
            $this->fail('accepted');
        } catch (RedirectRefused $refused) {
            $this->assertSame(RedirectRejection::TargetMalformed, $refused->rejection);
        }
    }

    /**
     * An absolute target to a hostname this organisation **has** proven is
     * accepted — §8.11.2's second reading, and the reason it is the one
     * DocUp takes.
     */
    public function test_an_absolute_target_to_a_proven_host_is_accepted(): void
    {
        $this->provenHost('handbook.acme.example');

        $rule = $this->redirects->create(
            $this->project,
            RedirectKind::Exact,
            '/guide.html',
            'https://handbook.acme.example/guide/',
        );

        $this->assertSame('https://handbook.acme.example/guide/', $rule->to_target);
    }

    /** 🛑 Another organisation's proven host is still refused. */
    public function test_another_organisations_proven_host_is_refused(): void
    {
        $other = Organisation::query()->create([
            'name' => 'Other Co',
            'slug' => 'other-'.bin2hex(random_bytes(4)),
        ]);

        $this->provenHost('theirs.example', (string) $other->id);

        try {
            $this->redirects->create($this->project, RedirectKind::Exact, '/go.html', 'https://theirs.example/');
            $this->fail('accepted');
        } catch (RedirectRefused $refused) {
            $this->assertSame(RedirectRejection::TargetNotProven, $refused->rejection);
        }
    }

    /** §8.11.2's four status codes, and nothing else. */
    public function test_only_the_four_documented_statuses_are_accepted(): void
    {
        foreach ([301, 302, 307, 308] as $status) {
            $rule = $this->redirects->create(
                $this->project,
                RedirectKind::Exact,
                '/s'.$status.'.html',
                '/t'.$status.'.html',
                $status,
            );

            $this->assertSame($status, $rule->status);
        }

        foreach ([200, 303, 310, 404, 500] as $status) {
            try {
                $this->redirects->create($this->project, RedirectKind::Exact, '/x.html', '/y.html', $status);
                $this->fail($status.' was accepted');
            } catch (RedirectRefused $refused) {
                $this->assertSame(RedirectRejection::StatusRefused, $refused->rejection);
            }
        }
    }

    /**
     * 🛑 A prefix rule whose target drops the splat sends a whole section to
     * one page.
     */
    public function test_a_prefix_rule_that_discards_its_remainder_is_refused(): void
    {
        try {
            $this->redirects->create($this->project, RedirectKind::Prefix, '/guide/:splat', '/handbook/');
            $this->fail('accepted');
        } catch (RedirectRefused $refused) {
            $this->assertSame(RedirectRejection::SplatMissing, $refused->rejection);
            $this->assertStringContainsString('every page under', $refused->getMessage());
        }
    }

    /** Creating a rule moves the routing epoch, so the cache key changes. */
    public function test_creating_a_rule_moves_the_routing_epoch(): void
    {
        $before = (int) DB::table('projects')->where('id', $this->project->id)->value('routing_epoch');

        $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/b.html');

        $after = (int) DB::table('projects')->where('id', $this->project->id)->value('routing_epoch');

        $this->assertGreaterThan($before, $after, '§8.9.10: a rule change is picked up by a different cache key');
    }

    /** A disabled rule is skipped and keeps its position. */
    public function test_a_disabled_rule_is_skipped_and_keeps_its_position(): void
    {
        $rule = $this->redirects->create($this->project, RedirectKind::Exact, '/a.html', '/b.html');

        $this->redirects->setEnabled($rule, false);

        $set = $this->redirects->setFor((string) $this->project->id, 99);

        $this->assertTrue($set->isEmpty());
        $this->assertSame(
            1,
            (int) DB::table('redirect_rules')->where('id', $rule->id)->value('position'),
            'the position is kept, so turning it back on is not a retype',
        );
    }

    private function seedRules(int $count): void
    {
        $rows = [];
        $now = Carbon::now()->format('Y-m-d H:i:s.v');

        for ($i = 0; $i < $count; $i++) {
            $rows[] = [
                'id' => Uuid::v7(),
                'organisation_id' => $this->organisation->id,
                'project_id' => $this->project->id,
                'position' => $i + 1,
                'kind' => 'exact',
                'forced' => false,
                'from_pattern' => '/bulk/rule-'.$i.'.html',
                'to_target' => '/bulk/moved-'.$i.'.html',
                'status' => 301,
                'enabled' => true,
                'description' => null,
                'created_at' => $now,
                'updated_at' => $now,
            ];
        }

        foreach (array_chunk($rows, 250) as $chunk) {
            DB::table('redirect_rules')->insert($chunk);
        }
    }

    /** A hostname with a proven claim, which is what §8.11.2 gates on. */
    private function provenHost(string $host, ?string $organisationId = null): Domain
    {
        $domain = new Domain;

        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $organisationId ?? $this->organisation->id,
            'host' => $host,
            'kind' => 'custom',
            'state' => 'active',
            'verified_at' => Carbon::now(),
        ])->save();

        return $domain;
    }
}
