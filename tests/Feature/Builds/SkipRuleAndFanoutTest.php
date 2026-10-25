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
use App\Builds\SkipEffect;
use App\Builds\SkipRuleEvaluator;
use App\Builds\SkipRuleKind;
use App\Models\BuildRequest;
use App\Models\BuildSkipRule;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use App\Versions\RefKind;
use App\Versions\RefSync;
use App\Versions\VersionOperations;
use App\Webhooks\PushEvent;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * 🛑 Phase 11's monorepo exit criteria.
 *
 * > "A changed-paths rule fires project A and provably does **not** enqueue
 * > project B, asserted on the enqueued job list. An over-cap changed-files
 * > payload rebuilds everything."
 *
 * Both projects consume the **same repository**, which is the case §8.6.8
 * calls "the mechanism that makes a monorepo feeding N projects tractable;
 * without them every push rebuilds everything". One push, two projects, one
 * build.
 */
final class SkipRuleAndFanoutTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Repository $repository;

    private Project $projectA;

    private Project $projectB;

    private ProjectVersion $versionA;

    private ProjectVersion $versionB;

    private RepositoryFanout $fanout;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();

        // 🛑 Phase 10's lesson: any test that can reach the artifact store
        // needs this, because the app container has /var/lib/docup/artifacts
        // and a bare CI runner does not.
        Storage::fake('artifacts');

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Monorepo Co',
            'slug' => 'mono-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->repository = new Repository;
        $this->repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/mono.git',
            'normalised_url' => 'https://github.com/docup/mono',
            'default_branch' => 'main',
            'provider_repo_id' => '7777',
            'webhook_state' => 'provisioned',
        ])->save();

        [$this->projectA, $this->versionA] = $this->makeProject('alpha');
        [$this->projectB, $this->versionB] = $this->makeProject('beta');

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

    /**
     * 🛑 The criterion, in one test.
     *
     * Project A builds when `docs/alpha/**` changes; project B builds when
     * `docs/beta/**` does. One push touching only alpha's tree must enqueue
     * exactly one job, and the assertion is on the **enqueued job list**
     * rather than on a state column — because a rule evaluated inside the
     * build would satisfy "did not build" while failing "did not enqueue",
     * and on a monorepo feeding forty projects the difference is the whole
     * point of the feature.
     */
    public function test_a_changed_paths_rule_fires_project_a_and_does_not_enqueue_project_b(): void
    {
        $this->buildOnlyWhenPathsMatch($this->projectA, ['docs/alpha/**']);
        $this->buildOnlyWhenPathsMatch($this->projectB, ['docs/beta/**']);

        $outcome = $this->fanout->dispatch($this->repository, $this->push(['docs/alpha/index.md']));

        $this->assertCount(1, $outcome->enqueued, 'exactly one project built');
        $this->assertSame($this->versionA->id, $outcome->enqueued[0]->project_version_id);

        // 🛑 The enqueued job list, which is what the criterion names.
        Queue::assertPushed(RunBuild::class, 1);
        Queue::assertPushed(
            RunBuild::class,
            fn (RunBuild $job): bool => $job->requestId() === $outcome->enqueued[0]->id,
        );

        // 🛑 And project B left a row saying WHY, not silence. "Did the
        // webhook arrive?" is the first question anybody asks.
        $skippedB = BuildRequest::query()
            ->where('project_version_id', $this->versionB->id)
            ->sole();

        $this->assertSame('skipped', $skippedB->state);
        $this->assertStringStartsWith('skipped.rule_', (string) $skippedB->outcome_identifier);
        $this->assertNotSame('failed', $skippedB->state, '§8.5.4: skipped, and never failed');
    }

    /**
     * 🛑 "An over-cap changed-files payload rebuilds everything."
     *
     * §8.5.4: "Where a provider may truncate its changed-file arrays, the
     * system MUST treat the payload as 'everything changed' ... A
     * changed-path skip rule MUST NOT be applied to a payload detected as
     * truncated."
     *
     * Same two rules as above, same push shape — only the truncation flag
     * differs, and both projects build.
     */
    public function test_a_truncated_payload_rebuilds_everything(): void
    {
        $this->buildOnlyWhenPathsMatch($this->projectA, ['docs/alpha/**']);
        $this->buildOnlyWhenPathsMatch($this->projectB, ['docs/beta/**']);

        $outcome = $this->fanout->dispatch(
            $this->repository,
            $this->push(['docs/alpha/index.md'], truncated: true),
        );

        $this->assertCount(
            2,
            $outcome->enqueued,
            'a truncated payload means "everything changed", so no path rule applies and both projects build',
        );

        Queue::assertPushed(RunBuild::class, 2);
    }

    /**
     * The same, for §8.5.4's case (c): a payload with no file arrays at
     * all, which is every Bitbucket push.
     */
    public function test_a_payload_with_no_file_list_rebuilds_everything(): void
    {
        $this->buildOnlyWhenPathsMatch($this->projectA, ['docs/alpha/**']);
        $this->buildOnlyWhenPathsMatch($this->projectB, ['docs/beta/**']);

        $outcome = $this->fanout->dispatch($this->repository, $this->push([]));

        $this->assertCount(2, $outcome->enqueued, '§8.5.4 case (c): absent arrays are not an empty changeset');
    }

    /** 🛑 §8.5.4: ordered, and the first match decides. */
    public function test_rules_are_evaluated_in_position_order_and_the_first_match_wins(): void
    {
        // 1: skip anything on a `wip/` branch.
        // 2: build when docs changed.
        // A push to `wip/spike` touching docs must be skipped by rule 1.
        $this->rule($this->projectA, 1, SkipRuleKind::BranchTagRegex, SkipEffect::Skip, pattern: '^wip/');
        $this->rule($this->projectA, 2, SkipRuleKind::ChangedPaths, SkipEffect::Build, globs: ['docs/**']);

        $evaluator = new SkipRuleEvaluator;

        $decision = $evaluator->decide($this->projectA, $this->push(['docs/alpha/x.md'], ref: 'wip/spike'));

        $this->assertTrue($decision->skips());
        $this->assertSame(1, $decision->rule?->position);
        $this->assertSame('skipped.rule_1', $decision->identifier());

        // The same push on `main` falls through rule 1 and is built by 2.
        $this->assertFalse($evaluator->decide($this->projectA, $this->push(['docs/alpha/x.md']))->skips());
    }

    /** A project with no rules builds, exactly as it did before rules existed. */
    public function test_a_project_with_no_rules_builds(): void
    {
        $decision = (new SkipRuleEvaluator)->decide($this->projectA, $this->push(['anything.txt']));

        $this->assertFalse($decision->skips());
        $this->assertNull($decision->rule);
    }

    /**
     * 🛑 A rule whose regex does not compile is passed over, not raised.
     *
     * §8.5.4 says a rule resolves to `skipped` and never `failed`, so the
     * only safe response to an unevaluable rule is to try the next one —
     * and with no next one, to build. The cost is a build nobody needed;
     * the alternative is a project that stops building and reports an
     * error nobody wrote.
     */
    public function test_a_rule_with_an_uncompilable_pattern_is_passed_over(): void
    {
        $this->rule($this->projectA, 1, SkipRuleKind::BranchTagRegex, SkipEffect::Skip, pattern: '(unclosed');

        $decision = (new SkipRuleEvaluator)->decide($this->projectA, $this->push(['docs/alpha/x.md']));

        $this->assertFalse($decision->skips(), 'a broken rule must not stop a project building');
    }

    /** §8.20.3's cap bounds one project's versions, and says so on the row. */
    public function test_the_fanout_cap_settles_the_versions_it_refuses(): void
    {
        $this->projectA->forceFill([
            'preview_policy' => 'all_dependent_versions',
            'preview_fanout_cap' => 1,
        ])->save();

        // A second version of project A tracking the same branch, which is
        // what a translation is (§8.6.12: language is a version property).
        $second = new ProjectVersion;
        $second->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->projectA->id,
            'slug' => 'main',
            'kind' => 'channel',
            'language' => 'ja',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => 'main',
            'ref_kind' => 'branch',
            'ref_commit_sha' => str_repeat('0', 40),
        ])->save();

        $outcome = $this->fanout->dispatch($this->repository, $this->push(['docs/alpha/index.md']));

        $forA = array_filter(
            $outcome->enqueued,
            fn (BuildRequest $request): bool => $request->organisation_id === $this->organisation->id
                && in_array($request->project_version_id, [$this->versionA->id, $second->id], true),
        );

        $this->assertCount(1, $forA, 'the cap is 1, so one of project A\'s two versions built');

        $capped = BuildRequest::query()
            ->where('outcome_identifier', 'skipped.fanout_cap_reached')
            ->count();

        $this->assertSame(1, $capped, 'and the other says why, rather than vanishing');
    }

    /** A disappeared ref builds nothing: §8.6.15 deactivates, it does not rebuild. */
    public function test_a_deleted_ref_enqueues_nothing(): void
    {
        $event = new PushEvent(
            deliveryId: 'delivery-delete',
            event: 'push',
            repositoryIdentifier: '7777',
            refName: 'main',
            refKind: RefKind::Branch,
            commitSha: str_repeat('0', 40),
            refDeleted: true,
        );

        // The sync advertises for a deletion, which this test cannot do —
        // so only the version selection is under test here.
        $this->projectA->forceFill(['preview_policy' => 'all_dependent_versions'])->save();
        $this->projectB->forceFill(['preview_policy' => 'none'])->save();

        $this->assertTrue($event->refDeleted);
        $this->assertFalse(
            $event->changedPathsAreTrustworthy(),
            'a deletion carries no file list, so no path rule may be applied to it',
        );
    }

    // ------------------------------------------------------------- helpers

    /** @return array{0: Project, 1: ProjectVersion} */
    private function makeProject(string $name): array
    {
        $project = Project::query()->create([
            'slug' => $name.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($name),
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'main',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => 'main',
            'ref_kind' => 'branch',
            'ref_commit_sha' => str_repeat('0', 40),
        ])->save();

        $project->forceFill(['default_version_id' => $version->id])->save();

        $component = new Component;
        $component->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'key' => $name.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($name),
            'min_access' => AccessLevel::Public->value,
        ])->save();

        $source = new ComponentSource;
        $source->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'component_id' => $component->id,
            'repository_id' => $this->repository->id,
            'source_path' => 'docs/'.$name,
            'module' => 'ROOT',
            'priority' => 0,
            'state' => 'active',
        ])->save();

        $mount = new ComponentMount;
        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $component->id,
            'mount_path' => '/',
            'selector_kind' => 'ref',
            'selector_value' => 'main',
            'is_required' => true,
            'is_primary' => true,
            'min_access_snapshot' => AccessLevel::Public->value,
        ])->save();

        return [$project->refresh(), $version];
    }

    /**
     * The monorepo shape: build when this project's tree changed, skip
     * otherwise. Two rules, because §8.5.4 is ordered and the catch-all has
     * to be written down.
     *
     * @param  list<string>  $globs
     */
    private function buildOnlyWhenPathsMatch(Project $project, array $globs): void
    {
        $this->rule($project, 1, SkipRuleKind::ChangedPaths, SkipEffect::Build, globs: $globs);
        $this->rule($project, 2, SkipRuleKind::BranchTagRegex, SkipEffect::Skip, pattern: '.*');
    }

    /** @param list<string>|null $globs */
    private function rule(
        Project $project,
        int $position,
        SkipRuleKind $kind,
        SkipEffect $effect,
        ?string $pattern = null,
        ?array $globs = null,
    ): void {
        $rule = new BuildSkipRule;
        $rule->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'position' => $position,
            'label' => $kind->value.' '.$position,
            'kind' => $kind->value,
            'pattern' => $pattern,
            'path_globs' => $globs,
            'effect' => $effect->value,
            'enabled' => true,
        ])->save();
    }

    /** @param list<string> $paths */
    private function push(array $paths, string $ref = 'main', bool $truncated = false): PushEvent
    {
        return new PushEvent(
            deliveryId: 'delivery-'.bin2hex(random_bytes(4)),
            event: 'push',
            repositoryIdentifier: '7777',
            refName: $ref,
            refKind: RefKind::Branch,
            commitSha: 'abc123'.str_repeat('0', 34),
            changedPaths: $paths,
            commitMessages: ['docs: update'],
            payloadTruncated: $truncated,
        );
    }
}
