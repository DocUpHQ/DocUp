<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Builds\BuildGovernor;
use App\Builds\BuildTrigger;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Notifications\BuildFailed;
use App\Notifications\WebhookTriggeringDisabled;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

/**
 * 🛑 §8.5.17's governor, and Phase 08's exit criteria for it.
 *
 * > "The 26th consecutive default-version failure disables webhook
 * > triggering, leaves manual building available, and emails the owner.
 * > 🛑 Fifty consecutive **infrastructure** failures disable nothing."
 *
 * And the sentence those come from:
 *
 * > "🛑 Only user-caused classes (`user`, `config`, `contract`,
 * > `conflict`, `resource`) MUST count toward the consecutive-failure
 * > governor that disables **webhook** triggering (never manual) after 25
 * > consecutive default-version failures. Infrastructure failures MUST
 * > NEVER disable a tenant."
 *
 * 🛑 **The negative cases are the point.** A governor that disables a
 * project is easy; one that declines to, on fifty consecutive failures of
 * our own making, is the requirement — and it is the one an
 * implementation gets wrong by treating "failed" as one thing.
 */
final class BuildGovernorTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private ProjectVersion $otherVersion;

    private User $owner;

    private Component $component;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();

        $context = app(OrganisationContext::class);
        $context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Governed',
            'slug' => 'gov-'.bin2hex(random_bytes(4)),
        ]);

        $context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'gov-'.bin2hex(random_bytes(3)),
            'name' => 'Governed',
            'visibility' => 'public',
        ]);

        $this->component = Component::query()->create([
            'key' => 'gov-'.bin2hex(random_bytes(4)),
            'name' => 'Governed',
            'min_access' => 'public',
        ]);

        $this->version = $this->makeVersion('latest');
        $this->otherVersion = $this->makeVersion('feature');

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->owner = User::query()->create([
            'name' => 'Owner',
            'email' => 'owner-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->owner->id,
            'role' => Role::ProjectAdmin->value,
            'scope_type' => 'project',
            'scope_id' => $this->project->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    /** 🛑 The exit criterion: the 26th failure trips it, the 25th does not. */
    public function test_the_twenty_sixth_consecutive_user_failure_disables_webhook_triggering(): void
    {
        $governor = new BuildGovernor;

        for ($i = 0; $i < 25; $i++) {
            $governor->record($this->failedBuild($this->version, 'user', 'user.build_command_failed'));
        }

        $this->assertNull(
            $this->freshProject()->webhook_triggering_disabled_at,
            'twenty-five failures is the tolerance, not the trigger',
        );

        $governor->record($this->failedBuild($this->version, 'user', 'user.build_command_failed'));

        $this->assertNotNull($this->freshProject()->webhook_triggering_disabled_at);
        $this->assertSame(26, $this->freshProject()->consecutive_build_failures);

        Notification::assertSentTo($this->owner, WebhookTriggeringDisabled::class);
    }

    /** 🛑 "...leaves manual building available." */
    public function test_a_disabled_project_still_builds_manually(): void
    {
        $this->disableWebhooks();

        $manual = app(BuildTrigger::class)->record(version: $this->version, trigger: 'manual');
        $api = app(BuildTrigger::class)->record(version: $this->version, trigger: 'api');

        $this->assertSame('queued', $manual->state);
        $this->assertSame('queued', $api->state);
    }

    /** ...and refuses the webhook, with a stable identifier rather than silence. */
    public function test_a_disabled_project_refuses_a_webhook_trigger(): void
    {
        $this->disableWebhooks();

        $request = app(BuildTrigger::class)->record(
            version: $this->version,
            trigger: 'webhook',
            integrationId: Uuid::v7(),
            deliveryId: 'delivery-'.bin2hex(random_bytes(4)),
        );

        $this->assertSame('rejected', $request->state);
        $this->assertSame('rejected.webhook_triggering_disabled', $request->outcome_identifier);

        /*
         * 🛑 The row exists. Dropping the delivery would leave a provider's
         * webhook with no trace, and the first question anybody asks about
         * a project that stopped building is whether the hook arrived.
         */
        $this->assertDatabaseHas('build_requests', ['id' => $request->id]);
    }

    /** 🛑 "Fifty consecutive **infrastructure** failures disable nothing." */
    public function test_fifty_infrastructure_failures_disable_nothing(): void
    {
        $governor = new BuildGovernor;

        for ($i = 0; $i < 50; $i++) {
            $governor->record($this->failedBuild($this->version, 'infra', 'infra.runner_did_not_answer'));
        }

        $project = $this->freshProject();

        $this->assertNull($project->webhook_triggering_disabled_at);
        $this->assertSame(0, $project->consecutive_build_failures, 'our own outages must not even be counted');
        Notification::assertNotSentTo($this->owner, WebhookTriggeringDisabled::class);
    }

    /**
     * 🛑 ...and they do not RESET the counter either.
     *
     * The intuitive implementation resets on anything that is not a user
     * failure, and it is wrong: our own outage would launder somebody's
     * twenty-five consecutive broken configurations back to zero.
     */
    public function test_an_infrastructure_failure_does_not_launder_the_counter(): void
    {
        $governor = new BuildGovernor;

        for ($i = 0; $i < 10; $i++) {
            $governor->record($this->failedBuild($this->version, 'config', 'config.invalid'));
        }

        $governor->record($this->failedBuild($this->version, 'infra', 'infra.runner_lost'));

        $this->assertSame(10, $this->freshProject()->consecutive_build_failures);
    }

    /** A success is what clears it. */
    public function test_a_successful_build_resets_the_counter(): void
    {
        $governor = new BuildGovernor;

        for ($i = 0; $i < 10; $i++) {
            $governor->record($this->failedBuild($this->version, 'user', 'user.build_command_failed'));
        }

        $governor->record($this->succeededBuild($this->version));

        $this->assertSame(0, $this->freshProject()->consecutive_build_failures);
    }

    /** 🛑 "...after 25 consecutive **default-version** failures." */
    public function test_failures_of_another_version_are_not_counted(): void
    {
        $governor = new BuildGovernor;

        for ($i = 0; $i < 40; $i++) {
            $governor->record($this->failedBuild($this->otherVersion, 'user', 'user.build_command_failed'));
        }

        $project = $this->freshProject();

        $this->assertSame(0, $project->consecutive_build_failures);
        $this->assertNull($project->webhook_triggering_disabled_at);
    }

    /** 🛑 §8.18.2: every failed build of a tracked version is mailed. */
    public function test_a_failed_build_emails_the_owner(): void
    {
        (new BuildGovernor)->record($this->failedBuild($this->version, 'user', 'user.build_command_failed'));

        Notification::assertSentTo($this->owner, BuildFailed::class);
    }

    /** ...and an infrastructure failure is not the author's to be told about. */
    public function test_an_infrastructure_failure_does_not_email_the_author(): void
    {
        (new BuildGovernor)->record($this->failedBuild($this->version, 'infra', 'infra.runner_lost'));

        Notification::assertNotSentTo($this->owner, BuildFailed::class);
    }

    /** Re-enabling clears the counter too, or the next failure trips it again. */
    public function test_reenabling_resets_the_counter(): void
    {
        $this->disableWebhooks(26);

        (new BuildGovernor)->reenableWebhookTriggering($this->freshProject());

        $project = $this->freshProject();

        $this->assertNull($project->webhook_triggering_disabled_at);
        $this->assertSame(0, $project->consecutive_build_failures);
    }

    /**
     * The project as the database has it.
     *
     * A helper rather than `fresh()` at eleven call sites, because the
     * whole subject of this file is what the governor WROTE — reading a
     * stale in-memory model would make several of these tests pass
     * against a governor that did nothing at all.
     */
    private function freshProject(): Project
    {
        $project = $this->project->fresh();

        $this->assertInstanceOf(Project::class, $project);

        return $project;
    }

    private function disableWebhooks(int $count = 26): void
    {
        $this->project->forceFill([
            'webhook_triggering_disabled_at' => now(),
            'consecutive_build_failures' => $count,
        ])->save();
    }

    private function makeVersion(string $slug): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => $slug,
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        return $version;
    }

    private function failedBuild(ProjectVersion $version, string $class, string $identifier): Build
    {
        return $this->build($version, 'failed', $class, $identifier);
    }

    private function succeededBuild(ProjectVersion $version): Build
    {
        return $this->build($version, 'published', null, null);
    }

    private function build(ProjectVersion $version, string $state, ?string $class, ?string $identifier): Build
    {
        $build = new Build;

        $build->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $this->component->id,
            'content_key' => bin2hex(random_bytes(32)),
            'state' => $state,
            'kind' => 'full',
            'failure_class' => $class,
            'failure_identifier' => $identifier,
            'started_at' => now(),
            'finished_at' => now(),
        ])->save();

        return $build;
    }
}
