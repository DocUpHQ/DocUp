<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Composition\Components;
use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;
use App\Composition\Mounts;
use App\Models\Component;
use App\Models\ComponentGrant;
use App\Models\ComponentMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Team;
use App\Models\TeamMember;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * 🛑 §8.7.7's ceiling and §8.7.8's grant — Phase 13's security exit
 * criterion.
 *
 * > "🛑 Mounting a `min_access='members'` component onto a public project
 * > is **refused, not warned**."
 *
 * §8.7.7 says why in its own words: without it "any project admin in the
 * organisation can mount any component onto a public project — a
 * declassification primitive in a product whose headline feature is
 * per-project authentication."
 */
final class MountPolicyTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Components $components;

    private Mounts $mounts;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Ceiling Co',
            'slug' => 'ceiling-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->components = new Components;
        $this->mounts = new Mounts;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 The exit criterion, verbatim: a `members` component onto a public
     * project is refused.
     */
    public function test_a_members_component_cannot_be_mounted_on_a_public_project(): void
    {
        $component = $this->makeComponent(AccessLevel::Members);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        try {
            $this->mounts->attach($version, $component);
            $this->fail('🛑 §8.7.7: this must be refused, not warned');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::CeilingExceeded, $refused->rejection);
            $this->assertSame('composition.min_access_ceiling_exceeded', $refused->identifier());
        }

        // 🛑 "Refused, not warned" means no row exists afterwards. A warning
        // that still wrote the mount would pass an assertion on the message
        // and declassify the component anyway.
        $this->assertSame(
            0,
            ComponentMount::query()->where('project_version_id', $version->id)->count(),
            'a refused mount must leave no row',
        );
    }

    /**
     * Every combination of ceiling and effective visibility, so the rule is
     * tested rather than one example of it.
     *
     * §8.7.7's comparison is `stricter(component.min_access, effective
     * visibility)` — a component may demand LESS than its target offers
     * (public content on a members-only project is fine; the project's own
     * authentication still applies) and never more.
     */
    #[DataProvider('ceilingCases')]
    public function test_the_ceiling_permits_exactly_what_it_should(
        AccessLevel $ceiling,
        AccessLevel $projectVisibility,
        AccessLevel $versionVisibility,
        bool $permitted,
    ): void {
        $component = $this->makeComponent($ceiling);
        $version = $this->version($projectVisibility, $versionVisibility);

        if ($permitted) {
            $mount = $this->mounts->attach($version, $component);

            $this->assertSame($ceiling, $mount->min_access_snapshot);

            return;
        }

        $this->expectException(CompositionRefused::class);

        $this->mounts->attach($version, $component);
    }

    /** @return array<string, array{0: AccessLevel, 1: AccessLevel, 2: AccessLevel, 3: bool}> */
    public static function ceilingCases(): array
    {
        return [
            'public onto public' => [AccessLevel::Public, AccessLevel::Public, AccessLevel::Public, true],
            'members onto public' => [AccessLevel::Members, AccessLevel::Public, AccessLevel::Public, false],
            'members onto members' => [AccessLevel::Members, AccessLevel::Members, AccessLevel::Members, true],
            'public onto members' => [AccessLevel::Public, AccessLevel::Members, AccessLevel::Members, true],
            'restricted onto members' => [AccessLevel::Restricted, AccessLevel::Members, AccessLevel::Members, false],
            'restricted onto restricted' => [AccessLevel::Restricted, AccessLevel::Restricted, AccessLevel::Restricted, true],
            'authenticated onto public' => [AccessLevel::Authenticated, AccessLevel::Public, AccessLevel::Public, false],

            /*
             * 🛑 The case that proves effective visibility is the MAXIMUM
             * of the two, per §12.3. A members-only project with a public
             * version is members-only, so a members component fits — and
             * an implementation reading the version alone would refuse it.
             */
            'members onto a public version of a members project' => [
                AccessLevel::Members, AccessLevel::Members, AccessLevel::Public, true,
            ],

            /*
             * And the mirror: a public project with a members version is
             * members-only, so a members component fits. An implementation
             * reading the PROJECT alone would refuse this one.
             */
            'members onto a members version of a public project' => [
                AccessLevel::Members, AccessLevel::Public, AccessLevel::Members, true,
            ],
        ];
    }

    /**
     * 🛑 §8.7.7's loosening is a separate audited action, and tightening
     * past a live mount is refused.
     *
     * Loosening can never declassify: every existing mount was validated
     * against a stricter ceiling. Tightening is the dangerous direction,
     * and it is refused rather than silently unpublishing somebody's
     * documentation.
     */
    public function test_tightening_a_ceiling_past_a_live_mount_is_refused(): void
    {
        $component = $this->makeComponent(AccessLevel::Public);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->mounts->attach($version, $component);

        try {
            $this->components->setMinAccess($component, AccessLevel::Members);
            $this->fail('tightening past a public mount must be refused');
        } catch (CompositionRefused $refused) {
            $this->assertSame(
                CompositionRejection::CeilingTighteningWouldOrphanMounts,
                $refused->rejection,
            );
        }

        $this->assertSame(AccessLevel::Public, $component->refresh()->min_access);
    }

    /** Loosening is permitted and re-snapshots every mount (§8.7.7). */
    public function test_loosening_a_ceiling_updates_every_mount_snapshot(): void
    {
        $component = $this->makeComponent(AccessLevel::Members);
        $version = $this->version(AccessLevel::Members, AccessLevel::Members);

        $mount = $this->mounts->attach($version, $component);

        $this->assertSame(AccessLevel::Members, $mount->min_access_snapshot);

        $this->components->setMinAccess($component, AccessLevel::Public);

        $this->assertSame(
            AccessLevel::Public,
            $mount->refresh()->min_access_snapshot,
            '🛑 §8.7.7 denormalises the ceiling into the manifest; a stale snapshot is a stale re-check',
        );
    }

    /**
     * 🛑 §8.7.8: "Mounting a component a team does not own MUST require an
     * explicit `component_grants` row."
     */
    public function test_mounting_another_teams_component_needs_a_grant(): void
    {
        $owner = $this->team('Platform');
        $other = $this->team('Marketing');
        $actor = $this->userIn($other);

        $component = $this->makeComponent(AccessLevel::Public, ownerTeamId: $owner->id);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        try {
            $this->mounts->attach($version, $component, actorId: $actor->id);
            $this->fail('🛑 §8.7.8: mounting is not implicitly organisation-wide');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::GrantMissing, $refused->rejection);
        }

        // And with the grant, it works.
        $grant = new ComponentGrant;
        $grant->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'component_id' => $component->id,
            'team_id' => $other->id,
            'capability' => 'mount',
        ])->save();

        $mount = $this->mounts->attach($version, $component, actorId: $actor->id);

        $this->assertTrue($mount->exists, 'the mount was not persisted');
    }

    /** A member of the owning team needs no grant: owning is the permission. */
    public function test_the_owning_team_needs_no_grant(): void
    {
        $owner = $this->team('Platform');
        $actor = $this->userIn($owner);

        $component = $this->makeComponent(AccessLevel::Public, ownerTeamId: $owner->id);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->assertTrue(
            $this->mounts->attach($version, $component, actorId: $actor->id)->exists,
            'the mount was not persisted',
        );
    }

    /**
     * 🛑 An organisation-owned component needs no grant.
     *
     * Every component created before grants existed has `owner_team_id`
     * null. A reading in which those became unmountable would have been a
     * migration that broke every installation — which is why the migration
     * makes null mean "organisation-owned" rather than "owned by nobody".
     */
    public function test_an_organisation_owned_component_needs_no_grant(): void
    {
        $actor = $this->userIn($this->team('Marketing'));

        $component = $this->makeComponent(AccessLevel::Public);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->assertTrue(
            $this->mounts->attach($version, $component, actorId: $actor->id)->exists,
            'the mount was not persisted',
        );
    }

    /** §8.7.3's three indexes, refused by name rather than by exception type. */
    public function test_the_three_unique_constraints_refuse_with_their_own_identifiers(): void
    {
        $first = $this->makeComponent(AccessLevel::Public);
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->mounts->attach($version, $first);

        try {
            $this->mounts->attach($version, $first);
            $this->fail('the same component twice on one version must be refused');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::ComponentAlreadyMounted, $refused->rejection);
        }
    }

    /**
     * 🛑 Phase 14 lifts Phase 13's blanket refusal, and this test is
     * what replaced it.
     *
     * Phase 13 refused every second mount with
     * `composition.multiple_mounts_not_yet_supported`, naming §8.7.6's nav
     * splicing, §8.7.14's collision policy and §8.7.15's shadowing refusal
     * as the reason — all three had to land together. They did, in Phase
     * 14, so a second mount at a **disjoint** prefix is now ordinary.
     *
     * The blanket refusal became §8.7.15's narrow one, which is the next
     * test. Keeping both assertions in one place is deliberate: "a second
     * mount is allowed" and "a shadowing second mount is not" are one
     * rule, and a reader who finds only the first would reasonably assume
     * there is no second.
     */
    public function test_a_second_component_at_a_disjoint_prefix_is_accepted(): void
    {
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->mounts->attach($version, $this->makeComponent(AccessLevel::Public));
        $this->mounts->attach(
            $version,
            $this->makeComponent(AccessLevel::Public),
            'guides',
            isPrimary: false,
        );

        $this->assertSame(2, $version->mounts()->count());
    }

    /**
     * 🛑 §8.7.15: "A new mount path that is a prefix of, or prefixed
     * by, an existing mount path in the same project version MUST be
     * **refused by default**."
     *
     * "By default" is the operative phrase: the override exists, it is
     * audited, and it moves the question to publish time where the file
     * manifests can say which paths actually disappeared.
     */
    public function test_a_second_component_that_shadows_an_existing_mount_is_refused(): void
    {
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        $this->mounts->attach($version, $this->makeComponent(AccessLevel::Public));
        $this->mounts->attach(
            $version,
            $this->makeComponent(AccessLevel::Public),
            'guides',
            isPrimary: false,
        );

        try {
            $this->mounts->attach(
                $version,
                $this->makeComponent(AccessLevel::Public),
                'guides/advanced',
                isPrimary: false,
            );

            $this->fail('§8.7.15 refuses a mount path prefixed by an existing one');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::MountPathShadows, $refused->rejection);
        }

        // And the override is what lets an operator mean it.
        $this->mounts->attach(
            $version,
            $this->makeComponent(AccessLevel::Public),
            'guides/advanced',
            isPrimary: false,
            shadowingOverride: true,
        );

        $this->assertSame(3, $version->mounts()->count());
    }

    /**
     * 🛑 §8.7.3's half an index cannot enforce, checked at publish.
     *
     * > "the two halves the index cannot enforce — that **at least one**
     * > exists, and that it sits at `mount_path=''` — MUST be enforced at
     * > publish time, which fails closed when either does not hold."
     */
    public function test_a_version_with_no_primary_mount_cannot_be_published(): void
    {
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);

        try {
            $this->mounts->assertPublishable($version);
            $this->fail('a version with no mounts must not publish');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::PrimaryMountMissing, $refused->rejection);
        }

        $this->mounts->attach($version, $this->makeComponent(AccessLevel::Public));

        // With one primary mount at the root, it passes.
        $this->mounts->assertPublishable($version);

        $this->addToAssertionCount(1);
    }

    /** A mount path that is not canonical is refused before it is stored. */
    public function test_a_non_canonical_mount_path_is_refused(): void
    {
        $version = $this->version(AccessLevel::Public, AccessLevel::Public);
        $component = $this->makeComponent(AccessLevel::Public);

        foreach (['/guides', 'guides/', 'guides//api', '../escape', 'Guides'] as $path) {
            try {
                $this->mounts->attach($version, $component, $path, isPrimary: false);
                $this->fail('"'.$path.'" must be refused');
            } catch (CompositionRefused $refused) {
                $this->assertSame(
                    CompositionRejection::MountPathNotCanonical,
                    $refused->rejection,
                    'for "'.$path.'"',
                );
            }
        }
    }

    // ---------------------------------------------------------------- helpers

    private function makeComponent(AccessLevel $minAccess, ?string $ownerTeamId = null): Component
    {
        return $this->components->register(
            organisationId: $this->organisation->id,
            key: 'c-'.bin2hex(random_bytes(4)),
            name: 'Component',
            minAccess: $minAccess,
            ownerTeamId: $ownerTeamId,
        );
    }

    private function version(AccessLevel $projectVisibility, AccessLevel $versionVisibility): ProjectVersion
    {
        $project = Project::query()->create([
            'slug' => 'p-'.bin2hex(random_bytes(4)),
            'name' => 'Project',
            'visibility' => $projectVisibility->value,
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => $versionVisibility->value,
        ])->save();

        return $version;
    }

    private function team(string $name): Team
    {
        $team = new Team;
        $team->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'name' => $name,
            'slug' => strtolower($name).'-'.bin2hex(random_bytes(3)),
        ])->save();

        return $team;
    }

    private function userIn(Team $team): User
    {
        $user = User::query()->create([
            'name' => 'Member',
            'email' => 'm-'.bin2hex(random_bytes(5)).'@example.com',
            'password' => 'x',
        ]);

        $member = new TeamMember;
        $member->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'team_id' => $team->id,
            'user_id' => $user->id,
        ])->save();

        return $user;
    }
}
