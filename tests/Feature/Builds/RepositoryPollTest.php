<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Automation\AutomationEngine;
use App\Builds\Jobs\RunBuild;
use App\Builds\RepositoryFanout;
use App\Models\BuildRequest;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use App\Versions\DiscoveredRef;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Versions\VersionOperations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * §8.5.3's `ls-remote` poll: the trigger for a repository whose webhook
 * could not be provisioned, and the only one an installation behind a
 * firewall the provider cannot reach ever gets.
 *
 * 🛑 **The refs are supplied rather than advertised**, for the reason
 * `VersionSyncTest` gives: what is under test is what a poll does with
 * refs, and driving it from a live repository would make the suite depend
 * on somebody else's tagging habits. The advertisement itself is
 * `RefResolver`'s and is exercised for real by `EndToEndBuildTest`.
 */
final class RepositoryPollTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private Repository $repository;

    private ProjectVersion $version;

    private RepositoryFanout $fanout;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();
        Storage::fake('artifacts');

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Polled Co',
            'slug' => 'polled-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'visibility' => 'public',
        ]);

        $this->repository = new Repository;
        $this->repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'gitea',
            'provider_host' => 'git.internal',
            'clone_url' => 'https://git.internal/docup/docs.git',
            'normalised_url' => 'https://git.internal/docup/docs',
            'default_branch' => 'main',

            // 🛑 The state that makes it eligible: no working webhook.
            'webhook_state' => 'manual_required',
            'state' => 'active',
        ])->save();

        $this->version = $this->makeVersion('main', 'branch', str_repeat('1', 40));
        $this->project->forceFill([
            'default_version_id' => $this->version->id,
            'preview_policy' => 'all_dependent_versions',
        ])->save();

        $this->attachComponent();

        $this->fanout = new RepositoryFanout(
            app(RefSync::class),
            new AutomationEngine(app(VersionOperations::class)),
        );
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /** A ref whose commit moved is built; one that did not is left alone. */
    public function test_a_poll_builds_only_the_refs_whose_commit_moved(): void
    {
        $this->makeVersion('v1.0.0', 'tag', str_repeat('2', 40));

        $outcome = $this->fanout->poll($this->repository, [
            new DiscoveredRef('main', RefKind::Branch, str_repeat('9', 40)),   // moved
            new DiscoveredRef('v1.0.0', RefKind::Tag, str_repeat('2', 40)),    // unchanged
        ]);

        $this->assertCount(1, $outcome->enqueued);
        $this->assertSame($this->version->id, $outcome->enqueued[0]->project_version_id);
        $this->assertSame('poll', $outcome->enqueued[0]->trigger, '§8.5.3: `poll` is its own trigger kind');

        Queue::assertPushed(RunBuild::class, 1);
    }

    /**
     * 🛑 A poll that finds nothing new enqueues nothing.
     *
     * §8.5.2's digest short-circuit would resolve an unneeded build to
     * `unchanged` in under a second, so building everything would be
     * correct — and would write one `build_requests` row per version per
     * tick for ever, which turns an operator's build history into noise.
     */
    public function test_a_poll_with_no_movement_enqueues_nothing(): void
    {
        $outcome = $this->fanout->poll($this->repository, [
            new DiscoveredRef('main', RefKind::Branch, str_repeat('1', 40)),
        ]);

        $this->assertSame([], $outcome->enqueued);
        $this->assertSame(0, BuildRequest::query()->count(), 'and no row, so the history stays readable');

        Queue::assertNothingPushed();
    }

    /** A ref the poll has never seen becomes a version and is built. */
    public function test_a_new_tag_found_by_polling_becomes_a_version_and_builds(): void
    {
        $outcome = $this->fanout->poll($this->repository, [
            new DiscoveredRef('main', RefKind::Branch, str_repeat('1', 40)),
            new DiscoveredRef('v2.0.0', RefKind::Tag, str_repeat('3', 40)),
        ]);

        $created = ProjectVersion::query()
            ->where('project_id', $this->project->id)
            ->where('ref_name', 'v2.0.0')
            ->sole();

        $this->assertSame('release', $created->kind, '§8.6.1: a tag is a release');
        $this->assertCount(1, $outcome->enqueued);
        $this->assertSame($created->id, $outcome->enqueued[0]->project_version_id);
    }

    /**
     * 🛑 A poll carries no file list, so §8.5.4 case (c) applies and a
     * path rule cannot be applied to it.
     */
    public function test_a_polled_change_is_marked_truncated(): void
    {
        $this->fanout->poll($this->repository, [
            new DiscoveredRef('main', RefKind::Branch, str_repeat('9', 40)),
        ]);

        $request = BuildRequest::query()->sole();

        $this->assertTrue(
            $request->payload_truncated,
            '§8.5.4 case (c): an advertisement says nothing about files, which is not the same as "nothing changed"',
        );
    }

    /**
     * 🛑 The command does not poll a repository whose webhook works.
     *
     * A poll beside a working webhook doubles the ref advertisements
     * against the provider for no new information, and providers
     * rate-limit — which would eventually cost the repositories that have
     * no other trigger the one they do have.
     */
    public function test_the_command_skips_repositories_with_a_working_webhook(): void
    {
        $this->repository->forceFill(['webhook_state' => 'provisioned'])->save();

        $this->assertSame(0, Artisan::call('docup:repositories:poll --json'));

        $this->assertStringContainsString(
            '"polled":0',
            Artisan::output(),
            'a poll beside a working webhook is a round trip the provider rate-limits us for',
        );
    }

    /** And it does poll one that needs it. */
    public function test_the_command_polls_a_repository_with_no_webhook(): void
    {
        $this->assertSame(0, Artisan::call('docup:repositories:poll --json'));

        $this->assertNotNull(
            $this->repository->refresh()->webhook_checked_at,
            'the check is stamped so the next tick reaches a different repository',
        );
    }

    private function makeVersion(string $ref, string $kind, string $sha): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => str_replace('/', '-', $ref),
            'kind' => $kind === 'tag' ? 'release' : 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => $ref,
            'ref_kind' => $kind,
            'ref_commit_sha' => $sha,
        ])->save();

        return $version;
    }

    private function attachComponent(): void
    {
        $component = new Component;
        $component->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'key' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'min_access' => AccessLevel::Public->value,
        ])->save();

        $source = new ComponentSource;
        $source->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'component_id' => $component->id,
            'repository_id' => $this->repository->id,
            'source_path' => '',
            'module' => 'ROOT',
            'priority' => 0,
            'state' => 'active',
        ])->save();

        $mount = new ComponentMount;
        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $this->version->id,
            'component_id' => $component->id,
            'mount_path' => '/',
            'selector_kind' => 'pinned_ref',
            'selector_value' => 'main',
            'is_required' => true,
            'is_primary' => true,
            'min_access_snapshot' => AccessLevel::Public->value,
        ])->save();
    }
}
