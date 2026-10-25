<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Versions;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Builds\RefResolver;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\Uuid;
use App\Versions\ChannelResolver;
use App\Versions\DiscoveredRef;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Versions\SyncOutcome;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tests\TestCase;

/**
 * 🛑 Phase 10's exit criteria.
 *
 * > "Pushing `v2.0.0` creates a version and moves `stable`. A test proves
 * > `active`, `listed`, `published` and `visibility` are independent in all
 * > combinations. A version with `listed=false` still returns 200 by direct
 * > URL and is absent from the version list the API returns. A renamed slug
 * > leaves a working 301. `v1.10` sorts above `v1.9` under the `semver`
 * > comparator and below it under `alphabetical`. 🛑 A new branch on a
 * > project that has ever been guarded is born **private**."
 *
 * The comparator half lives in {@see VersionComparatorTest}, which needs no
 * database; the serving half of the `listed` criterion lives in
 * {@see HiddenVersionServingTest}, which needs the edge. This file is the
 * write side.
 *
 * 🛑 **The refs are supplied rather than advertised.** `RefSync::discover()`
 * is a `git ls-remote` over the §8.3.9 client and is exercised for real by
 * `EndToEndBuildTest`; what is under test here is what happens to versions
 * when refs change, and driving that from a live repository would make the
 * test depend on somebody else's tagging habits.
 */
final class VersionSyncTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private Repository $repository;

    private RefSync $sync;

    private ChannelResolver $channels;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Versions Co',
            'slug' => 'versions-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'visibility' => 'public',
        ]);

        $this->repository = new Repository;
        $this->repository->forceFill([
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/docs.git',
            'normalised_url' => 'https://github.com/docup/docs',
            'default_branch' => 'main',
            'provider_repo_id' => 'docs',
        ])->save();

        $this->sync = new RefSync(app(RefResolver::class));
        $this->channels = new ChannelResolver;
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /** 🛑 "Pushing `v2.0.0` creates a version and moves `stable`." */
    public function test_pushing_a_tag_creates_a_version_and_moves_stable(): void
    {
        $before = $this->syncRefs([
            ['main', RefKind::Branch],
            ['v1.9.0', RefKind::Tag],
        ]);

        $this->assertCount(2, $before->created);
        $this->assertSame('v1.9.0', $this->channels->reconcile(
            $this->project,
            $this->versions(),
            'main',
        )->stable?->slug);

        // ---------------------------------------------- the push

        $after = $this->syncRefs([
            ['main', RefKind::Branch],
            ['v1.9.0', RefKind::Tag],
            ['v2.0.0', RefKind::Tag],
        ]);

        $this->assertCount(1, $after->created, 'only the new tag became a version');
        $this->assertSame('v2.0.0', $after->created[0]->slug);
        $this->assertSame('release', $after->created[0]->kind, 'a tag is a release, a branch is a channel');

        /*
         * 🛑 §8.8.7: "`publish_mode` MUST default to `auto` for channel-kind
         * versions and `manual` for release-kind versions."
         *
         * Asserted at **birth**, because that is the only moment a version
         * learns its kind and a column default cannot say two things.
         * `ProjectVersion::defaultPublishModeFor()` existed from Phase 10 and
         * nothing called it, so every tag-born version was created `auto` and
         * §8.8.7's drift gate would never have engaged on a real release.
         * Found while implementing the gate in Phase 14.
         */
        $this->assertSame('manual', $after->created[0]->publish_mode, 'a release does not republish itself');

        foreach ($before->created as $born) {
            if ($born->kind === 'channel') {
                $this->assertSame('auto', $born->publish_mode, 'a channel tracks a branch and moves on its own');
            }
        }

        $outcome = $this->channels->reconcile($this->reload($this->project), $this->versions(), 'main');

        $this->assertSame('v2.0.0', $outcome->stable?->slug);
        $this->assertTrue($outcome->stableMoved(), 'stable must have MOVED, not merely be correct');

        // ...and `latest` is the default branch, which did not move.
        $this->assertSame('main', $outcome->latest?->slug);
        $this->assertFalse($outcome->latestMoved());
    }

    /**
     * 🛑 §8.6.4's step 5: "no `stable` at all, which is a valid state and
     * MUST NOT fall back to the default branch."
     *
     * The tempting implementation returns `main`. A `stable` that quietly
     * means `main` is a URL readers bookmark believing it is pinned.
     */
    public function test_a_project_with_no_release_tags_has_no_stable(): void
    {
        $this->syncRefs([['main', RefKind::Branch], ['develop', RefKind::Branch]]);

        $outcome = $this->channels->reconcile($this->project, $this->versions(), 'main');

        $this->assertNull($outcome->stable, '§8.6.4 step 5: no stable, and NOT the default branch');
        $this->assertSame('main', $outcome->latest?->slug, 'but latest is the default branch (step 3)');
    }

    /** §8.6.4's step 2 beats the comparator: a ref literally named `stable`. */
    public function test_a_ref_named_stable_wins_over_the_highest_tag(): void
    {
        $this->syncRefs([
            ['main', RefKind::Branch],
            ['stable', RefKind::Branch],
            ['v9.9.9', RefKind::Tag],
        ]);

        $this->assertSame(
            'stable',
            $this->channels->reconcile($this->project, $this->versions(), 'main')->stable?->slug,
        );
    }

    /** §8.6.4: prereleases are excluded from `stable`. */
    public function test_a_release_candidate_does_not_become_stable(): void
    {
        $this->syncRefs([
            ['main', RefKind::Branch],
            ['v1.0.0', RefKind::Tag],
            ['v2.0.0-rc1', RefKind::Tag],
        ]);

        $this->assertSame(
            'v1.0.0',
            $this->channels->reconcile($this->project, $this->versions(), 'main')->stable?->slug,
            'a release candidate must not be served to readers who did not pick a version',
        );
    }

    /**
     * 🛑 §8.6.15: "the version MUST be deactivated rather than silently
     * deleted, its URLs MUST continue to resolve until an operator or an
     * automation rule removes it."
     */
    public function test_a_disappeared_ref_hides_its_version_without_deleting_it(): void
    {
        $this->syncRefs([['main', RefKind::Branch], ['v1.0.0', RefKind::Tag]]);

        $outcome = $this->syncRefs([['main', RefKind::Branch]]);

        $this->assertCount(1, $outcome->disappeared);

        $gone = $outcome->disappeared[0]->fresh();

        $this->assertInstanceOf(ProjectVersion::class, $gone, 'the row must still exist');
        $this->assertNotNull($gone->ref_disappeared_at);
        $this->assertFalse($gone->listed, 'absent from the flyout');
        $this->assertTrue($gone->active, '🛑 and still resolvable: §8.6.15 keeps its URLs working');

        // ...and `stable` moves off it without anybody deleting anything.
        $this->assertNull($this->channels->reconcile($this->project, $this->versions(), 'main')->stable);
    }

    /** A ref that comes back is not a version somebody reactivated. */
    public function test_a_returning_ref_clears_the_disappearance_but_not_a_deactivation(): void
    {
        $this->syncRefs([['v1.0.0', RefKind::Tag]]);
        $this->syncRefs([]);

        $version = ProjectVersion::query()->where('ref_name', 'v1.0.0')->firstOrFail();
        $version->forceFill(['active' => false])->save();

        $this->syncRefs([['v1.0.0', RefKind::Tag]]);

        $returned = $version->fresh();

        $this->assertInstanceOf(ProjectVersion::class, $returned);
        $this->assertNull($returned->ref_disappeared_at, 'the ref is back');
        $this->assertFalse($returned->active, '🛑 and the operator\'s decision stands');
    }

    // ------------------------------------------------------------- §8.6.3

    /**
     * 🛑 The exit criterion: "A new branch on a project that has ever been
     * guarded is born **private**."
     *
     * Both directions, because a test that only proved the restriction
     * would pass against a system that made every version restricted.
     */
    public function test_a_new_version_on_an_ever_guarded_project_is_born_private(): void
    {
        // The control: a project that has never been guarded.
        $this->syncRefs([['main', RefKind::Branch]]);

        $this->assertSame(
            AccessLevel::Public,
            ProjectVersion::query()->where('ref_name', 'main')->firstOrFail()->visibility,
            'a public project that has never been guarded gives a public version',
        );

        // 🛑 And now the latch, which is the requirement. Note that the
        // project is STILL public — §8.6.3 says "has **ever** had a
        // non-public access rule", so flipping it back must not undo this.
        $this->project->forceFill(['has_ever_been_guarded' => true])->save();

        $this->syncRefs([['main', RefKind::Branch], ['v3.0.0', RefKind::Tag]]);

        $born = ProjectVersion::query()->where('ref_name', 'v3.0.0')->firstOrFail();

        $this->assertSame(
            AccessLevel::Restricted,
            $born->visibility,
            '🛑 §8.6.3: making a project public must never retroactively expose a version',
        );

        $this->assertSame(
            AccessLevel::Public,
            $this->project->fresh()?->visibility,
            'the control: the project itself is still public, so this is the latch and not the current state',
        );
    }

    // ------------------------------------------------------------- §8.6.2

    /**
     * 🛑 "A test proves `active`, `listed`, `published` and `visibility` are
     * independent in all combinations."
     *
     * All sixteen boolean combinations against all four visibility levels —
     * sixty-four rows, each written and read back. Not a sample: §8.6.2 says
     * the axes "MUST NOT be collapsed or derived from one another", and a
     * derivation that only fired for one combination is exactly what a
     * sample misses.
     */
    public function test_the_four_axes_are_independent_in_all_combinations(): void
    {
        $levels = [AccessLevel::Public, AccessLevel::Authenticated, AccessLevel::Members, AccessLevel::Restricted];
        $checked = 0;

        foreach ([true, false] as $active) {
            foreach ([true, false] as $listed) {
                foreach ([true, false] as $published) {
                    foreach ($levels as $visibility) {
                        $version = new ProjectVersion;
                        $version->forceFill([
                            'id' => Uuid::v7(),
                            'organisation_id' => $this->organisation->id,
                            'project_id' => $this->project->id,
                            'slug' => 'axes-'.$checked,
                            'language' => 'en',
                            'kind' => 'channel',
                            'active' => $active,
                            'listed' => $listed,
                            'published' => $published,
                            'visibility' => $visibility,
                        ])->save();

                        $read = $version->fresh();

                        $this->assertInstanceOf(ProjectVersion::class, $read);
                        $this->assertSame($active, $read->active, "active changed under {$checked}");
                        $this->assertSame($listed, $read->listed, "listed changed under {$checked}");
                        $this->assertSame($published, $read->published, "published changed under {$checked}");
                        $this->assertSame($visibility, $read->visibility, "visibility changed under {$checked}");

                        $checked++;
                    }
                }
            }
        }

        $this->assertSame(32, $checked, 'every combination of the four axes');
    }

    /**
     * 🛑 "A version with `listed=false` ... is absent from the version list
     * the API returns."
     *
     * The direct-URL half of the same criterion is
     * {@see HiddenVersionServingTest}, which needs the serving edge.
     */
    public function test_an_unlisted_version_is_absent_from_the_api_list(): void
    {
        $this->syncRefs([['main', RefKind::Branch], ['v1.0.0', RefKind::Tag]]);

        $hidden = ProjectVersion::query()->where('ref_name', 'v1.0.0')->firstOrFail();
        $hidden->forceFill(['listed' => false])->save();

        $response = $this->actingAs($this->viewer())->getJson(sprintf(
            '/api/v3/organisations/%s/projects/%s/versions',
            $this->organisation->slug,
            $this->project->slug,
        ));

        $response->assertOk();

        $slugs = array_column((array) $response->json('data'), 'slug');

        $this->assertContains('main', $slugs);
        $this->assertNotContains('v1.0.0', $slugs, '🛑 §8.6.2: a hidden version is absent from the list');

        // ...and the four axes are reported separately rather than collapsed.
        $main = (array) $response->json('data.0');

        foreach (['active', 'listed', 'published', 'visibility'] as $axis) {
            $this->assertArrayHasKey($axis, $main, '§8.6.2 forbids deriving one axis from another');
        }
    }

    /** §8.6.5: the API list is ordered by the project's comparator. */
    public function test_the_api_list_uses_the_projects_comparator(): void
    {
        $this->syncRefs([['v1.9', RefKind::Tag], ['v1.10', RefKind::Tag]]);

        $this->project->forceFill(['pin_channels_to_top' => false])->save();

        $semver = $this->versionSlugsFromApi();
        $this->assertSame(['v1.10', 'v1.9'], $semver);

        $this->project->forceFill(['version_comparator' => 'alphabetical'])->save();

        $this->assertSame(['v1.9', 'v1.10'], $this->versionSlugsFromApi());
    }

    /** §8.6.5's toggle: the channels on top, or sorted in place. */
    public function test_the_channels_are_pinned_to_the_top_when_the_project_says_so(): void
    {
        $this->syncRefs([
            ['main', RefKind::Branch],
            ['v1.0.0', RefKind::Tag],
            ['v2.0.0', RefKind::Tag],
        ]);

        $this->channels->reconcile($this->project, $this->versions(), 'main');

        // `latest` is `main` and `stable` is `v2.0.0`, in that order on top.
        $this->assertSame(['main', 'v2.0.0', 'v1.0.0'], $this->versionSlugsFromApi());

        $this->project->forceFill(['pin_channels_to_top' => false])->save();

        // Sorted in place: `main` is unreadable to semver, so it sorts last.
        $this->assertSame(['v2.0.0', 'v1.0.0', 'main'], $this->versionSlugsFromApi());
    }

    // ----------------------------------------------------------- helpers

    /**
     * @param  list<array{0: string, 1: RefKind}>  $refs
     */
    private function syncRefs(array $refs): SyncOutcome
    {
        $discovered = [];

        foreach ($refs as [$name, $kind]) {
            $discovered[] = new DiscoveredRef($name, $kind, hash('sha1', $name));
        }

        return $this->sync->sync($this->project, $this->repository, $discovered);
    }

    /** @return list<ProjectVersion> */
    private function versions(): array
    {
        return array_values(
            ProjectVersion::query()->where('project_id', $this->project->id)->get()->all(),
        );
    }

    /** @return list<string> */
    private function versionSlugsFromApi(): array
    {
        $response = $this->actingAs($this->viewer())->getJson(sprintf(
            '/api/v3/organisations/%s/projects/%s/versions',
            $this->organisation->slug,
            $this->project->slug,
        ));

        $response->assertOk();

        /** @var list<string> $slugs */
        $slugs = array_column((array) $response->json('data'), 'slug');

        return $slugs;
    }

    private function viewer(): User
    {
        $user = User::factory()->create();

        RoleAssignment::query()->create([
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => Role::OrgAdmin->value,
        ]);

        return $user;
    }

    /** `fresh()` with the nullability resolved once; see the note in VersionLifecycleTest. */
    private function reload(Project $project): Project
    {
        $fresh = $project->fresh();

        $this->assertInstanceOf(Project::class, $fresh);

        return $fresh;
    }
}
