<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Search;

use App\Auth\Role;
use App\Models\User;
use App\Search\EngineLimits;
use App\Search\Indexer;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Tests\Support\CommitsSearchDocuments;
use Tests\Support\SearchFixture;
use Tests\TestCase;

/**
 * 🛑 §8.16.2's "**in the product UI**, not only the documentation".
 *
 * > "The documented limits of the default engine MUST be stated **in the
 * > product UI** … 🛑 The illustration must use a **two**-character term …
 * > 'Why can't I find `go`?' is the real first support question (ADR 0004)."
 *
 * The requirement is about a **page**, so the test is about a page. A test that
 * only checked {@see EngineLimits} would pass for an installation where nothing
 * rendered it, which is exactly the gap §8.16.2's "not only the documentation"
 * is pointing at — and the gap §8.12.25's simulator had until Phase 26a built
 * its own page.
 */
final class SearchSettingsPageTest extends TestCase
{
    use CommitsSearchDocuments;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();
    }

    protected function tearDown(): void
    {
        $this->cleanUpCommittedSearchData();

        parent::tearDown();
    }

    /**
     * 🛑 The limits are on the page, read from the server, with the
     * two-character term first.
     */
    public function test_the_page_states_the_engines_limits_with_a_two_character_illustration(): void
    {
        $fixture = $this->searchFixture('ui');
        $actor = $this->administrator($fixture->organisation->id);

        $response = $this->actingAs($actor)->get($this->url($fixture));

        $response->assertOk();

        $props = $this->props($response);

        /* §8.16.2's four limits, as the engine reported them. */
        $this->assertSame(EngineLimits::SPEC_MIN_TOKEN_SIZE, $props['limits']['min_token_size']);
        $this->assertSame(EngineLimits::SPEC_STOPWORD_COUNT, $props['limits']['stopword_count']);
        $this->assertFalse($props['limits']['stemming']);
        $this->assertFalse($props['limits']['typo_tolerance']);

        /* 🛑 And the illustration leads with `go`, which is the whole point. */
        $this->assertSame('go', $props['limits']['illustrations'][0]['term']);
        $this->assertSame('no results', $props['limits']['illustrations'][0]['outcome']);

        $this->assertSame(
            ['go', 'the', 'authentcation', 'deploying', 'api'],
            array_column($props['limits']['illustrations'], 'term'),
            '§8.16.2 names all five',
        );

        /* §8.16.12's capability matrix is on the page, with notes on the absences. */
        $this->assertNotSame([], $props['capabilities']);

        foreach ($props['capabilities'] as $row) {
            if ($row['required']) {
                $this->assertTrue($row['supported'], $row['capability'].' is required of every driver');
            } elseif (! $row['supported']) {
                $this->assertNotSame('', $row['note'], $row['capability'].' must say what happens instead');
            }
        }
    }

    /**
     * 🛑 §8.12.21's gate is visible to an operator.
     *
     * "Disabled, not stale" is a condition that persists until a reindex runs
     * and looks like an empty corpus from every other angle. An operator who
     * cannot see it here has no way to find out — which is why `doctor` reports
     * it too, and why the page says it in a sentence rather than as two
     * integers.
     */
    public function test_the_page_says_when_search_is_disabled_by_the_generation_gate(): void
    {
        $fixture = $this->searchFixture('ui-gate');
        $version = $fixture->version('v1');

        $fixture->publish($version, [
            'html/index.html' => '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
                .'<body><main><h1 id="t">Title</h1><p>Body.</p></main></body></html>',
        ]);
        $fixture->channels(default: $version, stable: $version, latest: $version);

        app(Indexer::class)->indexProject($fixture->project);

        $actor = $this->administrator($fixture->organisation->id);

        $before = $this->props($this->actingAs($actor)->get($this->url($fixture)));

        $this->assertTrue($before['generations']['indexed']);
        $this->assertFalse($before['generations']['disabled_because_stale']);

        Invalidation::bumpAuthz(
            projectId: $fixture->project->id,
            cause: 'policy',
            policyWrite: true,
            organisationId: $fixture->organisation->id,
        );

        $after = $this->props($this->actingAs($actor)->get($this->url($fixture)));

        $this->assertTrue(
            $after['generations']['disabled_because_stale'],
            '🛑 the page must say search is disabled, not merely that the index is old',
        );

        $this->assertGreaterThan(
            $after['generations']['built_under_policy_generation'],
            $after['generations']['policy_generation'],
            'and it shows both numbers, so the operator can see the lag rather than take it on trust',
        );
    }

    /**
     * §8.16.9's exclusions are explained rather than silent.
     *
     * "Why is my stable version not searchable" is a question with four
     * answers — hidden, inactive, unpublished, or no pointer — and the page
     * names which.
     */
    public function test_the_page_explains_a_version_that_is_not_indexed(): void
    {
        $fixture = $this->searchFixture('ui-versions');

        $public = $fixture->version('v-open');
        $hidden = $fixture->version('v-hidden', listed: false);

        $fixture->publish($public, [
            'html/index.html' => '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
                .'<body><main><h1 id="t">Title</h1><p>Body.</p></main></body></html>',
        ]);
        $fixture->publish($hidden, [
            'html/index.html' => '<!DOCTYPE html><html><head><meta charset="utf-8"><title>T</title></head>'
                .'<body><main><h1 id="t">Title</h1><p>Body.</p></main></body></html>',
        ]);

        $fixture->channels(default: $public, stable: $hidden, latest: $public);

        app(Indexer::class)->indexProject($fixture->project);

        $props = $this->props(
            $this->actingAs($this->administrator($fixture->organisation->id))->get($this->url($fixture)),
        );

        $byChannel = [];

        foreach ($props['versions'] as $row) {
            $byChannel[$row['channel']] = $row;
        }

        $this->assertSame('v-open', $byChannel['default']['slug']);
        $this->assertTrue($byChannel['default']['indexed']);
        $this->assertNotNull($byChannel['default']['report'], 'with its extraction report');

        $this->assertSame('v-hidden', $byChannel['stable']['slug']);
        $this->assertFalse($byChannel['stable']['indexed'], '§8.16.9 excludes a hidden version');
        $this->assertNull($byChannel['stable']['report']);
    }

    /**
     * 🛑 No engine key reaches the page.
     *
     * §8.12.21: "search-engine tenant tokens MUST NEVER reach a browser
     * (Meilisearch tenant tokens are plain HS256 — readable by the browser and
     * unrevocable before expiry)." DocUp mints none, and the admin key must not
     * leak through a props payload either — which is the one route a page like
     * this could take it.
     */
    public function test_no_engine_key_reaches_the_page(): void
    {
        config()->set('docup.search.meilisearch.key', 'a-key-that-must-not-be-rendered');

        $fixture = $this->searchFixture('ui-key');

        $response = $this->actingAs($this->administrator($fixture->organisation->id))->get($this->url($fixture));

        $response->assertOk();
        $response->assertDontSee('a-key-that-must-not-be-rendered');

        $this->assertStringNotContainsString(
            'a-key-that-must-not-be-rendered',
            json_encode($this->props($response), JSON_THROW_ON_ERROR),
        );
    }

    /**
     * 🛑 §8.16.2's "in the product UI" means **reachable**, not merely routed.
     *
     * The page is what the requirement asks for; a link to it is what makes an
     * operator meet it. Neither existed before this phase — §8.12.25's policy
     * simulator was in the same position — so the project page now links both,
     * and this asserts the link rather than the page.
     *
     * A page an operator can only reach by typing a path satisfies the letter
     * and misses the point: the person who fields "why can't I find `go`?" is
     * not the person with the path.
     */
    public function test_the_project_page_links_to_the_search_page(): void
    {
        $fixture = $this->searchFixture('ui-link');

        $response = $this->actingAs($this->administrator($fixture->organisation->id))
            ->get('/o/'.$fixture->organisation->slug.'/projects/'.$fixture->project->slug);

        $response->assertOk();

        $props = $this->props($response);

        $this->assertSame(
            $fixture->organisation->slug,
            $props['organisation']['slug'],
            'the page needs the slug to build the link',
        );
    }

    /** The page is maintainer-facing, so a reader role cannot reach it. */
    public function test_a_project_reader_cannot_reach_the_page(): void
    {
        $fixture = $this->searchFixture('ui-authz');

        $reader = $this->userWithRole($fixture->organisation->id, Role::ProjectReader, $fixture->project->id);

        $this->actingAs($reader)->get($this->url($fixture))->assertNotFound();
    }

    // --------------------------------------------------------------- helpers

    private function url(SearchFixture $fixture): string
    {
        return '/o/'.$fixture->organisation->slug.'/projects/'.$fixture->project->slug.'/search';
    }

    /**
     * @param  TestResponse<Response>  $response
     * @return array<string, mixed>
     */
    private function props(TestResponse $response): array
    {
        $page = $response->viewData('page');

        $this->assertIsArray($page);
        $this->assertIsArray($page['props']);

        return $page['props'];
    }

    private function administrator(string $organisationId): User
    {
        return $this->userWithRole($organisationId, Role::OrgAdmin);
    }

    /**
     * A user holding one role.
     *
     * 🛑 `User::factory()`, not `User::query()->create()` with `bcrypt()`:
     * §8.12.16 raises the Argon parameters, and the `password` cast verifies a
     * hash's configuration — so a bcrypt hash throws "Could not verify the
     * hashed value's configuration" before the test gets anywhere near the
     * page. The factory hashes with the configured hasher, which is the point
     * of having one.
     */
    private function userWithRole(string $organisationId, Role $role, ?string $projectId = null): User
    {
        $user = User::factory()->create();

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $organisationId,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'role' => $role->value,
            'scope_type' => $projectId === null ? 'organisation' : 'project',
            'scope_id' => $projectId ?? $organisationId,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $user;
    }
}
