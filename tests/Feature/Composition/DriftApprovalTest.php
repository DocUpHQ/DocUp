<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Composition;

use App\Artifacts\Publisher;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Composition\Components;
use App\Composition\Mounts;
use App\Composition\Promotion;
use App\Composition\SelectorKind;
use App\Models\Build;
use App\Models\Component;
use App\Models\DriftEvent;
use App\Models\MountResolution;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §8.8.7's approval gate and §8.8.8's drift events.
 *
 * > "`publish_mode` MUST default to `auto` for channel-kind versions and
 * > `manual` for release-kind versions. A release-kind version MUST rewrite
 * > every mount to `pinned_build` at promotion, so a shipped release can
 * > never drift." (§8.8.7)
 *
 * > "Every selector resolution MUST be recorded as an append-only row, and
 * > every unpublished composition change as a drift event carrying the
 * > per-mount before/after ref, commit and build id." (§8.8.8)
 *
 * §18.25 is the assumption under test — that the gate survives contact with
 * operators rather than everything becoming `auto` — and its pre-decided
 * consequence is why an automatic publication records a drift event too.
 * The last test here is what keeps that assumption falsifiable.
 */
final class DriftApprovalTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Components $components;

    private Mounts $mounts;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');
        Cache::flush();

        $this->fixtures = sys_get_temp_dir().'/docup-drift-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Drift Co',
            'slug' => 'drift-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->components = new Components;
        $this->mounts = new Mounts;
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    /**
     * 🛑 The first publish of a `manual` version is never drift.
     *
     * There is nothing to drift from, and gating it would leave a
     * release-kind version unable to publish at all without approving a
     * change from nothing to something.
     */
    public function test_the_first_publish_of_a_manual_version_is_not_gated(): void
    {
        [$version, $component] = $this->releaseVersionMounting();

        $this->buildFor($component);

        $outcome = app(Publisher::class)->publishExistingBuild(
            $version,
            $this->latestBuildOf($component),
        );

        $this->assertTrue($outcome->published);
        $this->assertFalse($outcome->awaitingApproval);
        $this->assertSame(0, DriftEvent::query()->where('project_version_id', $version->id)->count());
    }

    /**
     * 🛑 A composition change on a `manual` version does not publish.
     *
     * The build is valid and stored; it is simply not the one being
     * served. §8.8.4 already has a state for that, and reusing it rather
     * than inventing one is what keeps "lost a race" and "awaiting an
     * approval" from needing two code paths.
     */
    public function test_a_composition_change_on_a_manual_version_is_recorded_and_withheld(): void
    {
        [$version, $component] = $this->releaseVersionMounting();

        $this->buildFor($component, commit: str_repeat('1', 40));
        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($component));

        $serving = $version->refresh()->getRawOriginal('published_manifest_id');

        // A second build of the same component: the composition has moved.
        $second = $this->buildFor($component, commit: str_repeat('2', 40));

        $outcome = app(Publisher::class)->publishExistingBuild($version->refresh(), $second);

        $this->assertFalse($outcome->published, 'a manual version does not publish its own drift');
        $this->assertTrue($outcome->awaitingApproval, 'and says why, distinctly from losing a race');
        $this->assertNull($outcome->manifest);

        $this->assertSame(
            $serving,
            $version->refresh()->getRawOriginal('published_manifest_id'),
            'the live composition is untouched',
        );

        /** @var DriftEvent $event */
        $event = DriftEvent::query()->where('project_version_id', $version->id)->sole();

        $this->assertSame('pending', $event->state);

        // 🛑 §8.8.8's "per-mount before/after ref, commit and build id".
        $changes = $event->changes_json['mounts'] ?? [];

        $this->assertIsArray($changes);
        $this->assertCount(1, $changes);
        $this->assertSame(str_repeat('1', 40), $changes[0]['before']['commit_sha']);
        $this->assertSame(str_repeat('2', 40), $changes[0]['after']['commit_sha']);
        $this->assertNotSame($changes[0]['before']['build_id'], $changes[0]['after']['build_id']);

        $this->assertSame('success_unpublished', $second->refresh()->state);
    }

    /** An approval opens the gate exactly once. */
    public function test_an_approval_lets_the_next_publish_through_and_is_then_spent(): void
    {
        [$version, $component] = $this->releaseVersionMounting();

        $this->buildFor($component, commit: str_repeat('1', 40));
        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($component));

        $second = $this->buildFor($component, commit: str_repeat('2', 40));
        app(Publisher::class)->publishExistingBuild($version->refresh(), $second);

        /** @var DriftEvent $event */
        $event = DriftEvent::query()->where('project_version_id', $version->id)->sole();

        (new Promotion)->approve($event);

        $outcome = app(Publisher::class)->publishExistingBuild($version->refresh(), $second);

        $this->assertTrue($outcome->published, 'the approval opened the gate');
        $this->assertNotNull($event->refresh()->manifest_id, 'and the approval names what it let through');

        // 🛑 Spent: a third build is gated again.
        $third = $this->buildFor($component, commit: str_repeat('3', 40));
        $next = app(Publisher::class)->publishExistingBuild($version->refresh(), $third);

        $this->assertFalse($next->published, 'the next change needs its own approval');
        $this->assertTrue($next->awaitingApproval);
    }

    /**
     * 🛑 §18.25's evidence trail: an automatic publication is recorded too.
     *
     * "Keep the drift event and audit record for every **automatic**
     * publication so the evidence trail survives either outcome." A table
     * holding only the gated cases could not tell anyone whether the gate
     * was being used or routed around.
     */
    public function test_an_automatic_publication_still_records_its_drift(): void
    {
        [$version, $component] = $this->releaseVersionMounting(publishMode: 'auto');

        $this->buildFor($component, commit: str_repeat('1', 40));
        app(Publisher::class)->publishExistingBuild($version, $this->latestBuildOf($component));

        $second = $this->buildFor($component, commit: str_repeat('2', 40));
        $outcome = app(Publisher::class)->publishExistingBuild($version->refresh(), $second);

        $this->assertTrue($outcome->published);

        /** @var DriftEvent $event */
        $event = DriftEvent::query()->where('project_version_id', $version->id)->sole();

        $this->assertSame('auto', $event->state);
        $this->assertNotNull($event->manifest_id, 'and it names the revision it describes');
    }

    /**
     * 🛑 §8.8.7's snapshot-on-promote: every mount becomes `pinned_build`.
     *
     * `pinned_build`, not `pinned_ref`, and the next assertion is why: a
     * later build of the same ref must not move the promoted version.
     */
    public function test_promotion_pins_every_mount_to_a_build(): void
    {
        [$version, $component] = $this->releaseVersionMounting();

        $first = $this->buildFor($component, commit: str_repeat('1', 40));

        $pinned = (new Promotion)->pinMounts($version);

        $this->assertSame(1, $pinned);

        $mount = $version->mounts()->sole();

        $this->assertSame(SelectorKind::PinnedBuild->value, $mount->selector_kind);
        $this->assertSame(Uuid::toText($first->id), $mount->selector_value);
        $this->assertNull($mount->mirror_fallback, 'a fallback on a pinned mount would read as configuration');

        // 🛑 The point of the pin: a later build of the same ref does not
        // move it. A `pinned_ref` would, because a tag can be force-pushed.
        $this->buildFor($component, commit: str_repeat('2', 40));

        app(Publisher::class)->publishExistingBuild($version->refresh(), $first);

        /** @var MountResolution $resolution */
        $resolution = MountResolution::query()
            ->where('project_version_id', $version->id)
            ->orderByDesc('created_at')
            ->firstOrFail();

        $this->assertSame($first->id, $resolution->build_id);
        $this->assertSame('pinned', $resolution->outcome->value);
    }

    /** Promoting twice is harmless, which is what makes it safe to retry. */
    public function test_promotion_is_idempotent(): void
    {
        [$version, $component] = $this->releaseVersionMounting();

        $this->buildFor($component);

        $promotion = new Promotion;

        $this->assertSame(1, $promotion->pinMounts($version));
        $this->assertSame(0, $promotion->pinMounts($version), 'nothing left to change');
    }

    // ---------------------------------------------------------------- helpers

    /** @return array{0: ProjectVersion, 1: Component} */
    private function releaseVersionMounting(string $publishMode = 'manual'): array
    {
        $component = $this->components->register(
            organisationId: $this->organisation->id,
            key: 'handbook-'.bin2hex(random_bytes(3)),
            name: 'Handbook',
            minAccess: AccessLevel::Public,
        );

        $project = Project::query()->create([
            'slug' => 'release-'.bin2hex(random_bytes(3)),
            'name' => 'Release',
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'v2.0',
            'kind' => 'release',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'publish_mode' => $publishMode,
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        $this->mounts->attach($version, $component);

        return [$version, $component];
    }

    private function buildFor(Component $component, ?string $commit = null): Build
    {
        $project = Project::query()->create([
            'slug' => 'staging-'.bin2hex(random_bytes(4)),
            'name' => 'Staging',
            'visibility' => 'public',
        ]);

        $staging = new ProjectVersion;
        $staging->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
        ])->save();

        $project->forceFill(['default_version_id' => $staging->id])->save();

        $this->mounts->attach($staging, $component);

        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><html><head></head><body>x</body></html>\n")
            ->toTarGz($this->fixtures.'/t-'.bin2hex(random_bytes(4)).'.tar.gz');

        $build = app(Publisher::class)->publishUpload($staging, $archive)->build;

        $this->assertInstanceOf(Build::class, $build);

        $build->forceFill(['commit_sha' => $commit ?? str_repeat('0', 40)])->save();

        DB::table('build_sources')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'build_id' => $build->id,
            'repository_id' => $this->repositoryId(),
            'component_source_id' => null,
            'ref' => 'v2.0',
            'commit_sha' => $commit ?? str_repeat('0', 40),
            'source_path' => '',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $build;
    }

    /** @return string raw 16 bytes */
    private function repositoryId(): string
    {
        $existing = DB::table('repositories')
            ->where('organisation_id', $this->organisation->id)
            ->value('id');

        if (is_string($existing)) {
            return $existing;
        }

        $id = Uuid::v7();

        DB::table('repositories')->insert([
            'id' => $id,
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/handbook.git',
            'normalised_url' => 'https://github.com/docup/handbook',
            'default_branch' => 'main',
            'provider_repo_id' => (string) random_int(1000, 99999),
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $id;
    }

    private function latestBuildOf(Component $component): Build
    {
        /** @var Build */
        return Build::query()
            ->where('component_id', $component->id)
            ->whereIn('state', ['published', 'success_unpublished'])
            ->orderByDesc('finished_at')
            ->orderByDesc('id')
            ->firstOrFail();
    }
}
