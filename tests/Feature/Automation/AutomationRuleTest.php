<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Automation;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Automation\AutomationAction;
use App\Automation\AutomationEngine;
use App\Automation\AutomationTrigger;
use App\Models\AutomationRule;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Support\Uuid;
use App\Versions\SyncOutcome;
use App\Versions\VersionOperations;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;

/**
 * §8.6.8's automation rules, and §8.6.15's `delete_version`.
 *
 * > "The system MUST support automation rules triggered by version
 * > **creation or disappearance**: activate, hide, make public or private,
 * > set as default, or trigger a build — filtered by branch/tag regex,
 * > changed-path globs, commit message or PR label."
 *
 * > 🛑 "removal MUST be an automation-rule action (`delete_version`)
 * > triggered by ref disappearance rather than by ref creation. Nothing may
 * > delete reader-visible URLs without either an explicit rule or an
 * > explicit action."
 */
final class AutomationRuleTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private AutomationEngine $engine;

    protected function setUp(): void
    {
        parent::setUp();

        // Phase 10's lesson: `delete_version` wipes artifacts, so this test
        // reaches the store and a bare CI runner has no /var/lib/docup.
        Storage::fake('artifacts');

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Rules Co',
            'slug' => 'rules-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'visibility' => 'public',
        ]);

        $this->engine = new AutomationEngine(app(VersionOperations::class));
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /** A rule filtered by tag regex activates matching versions and no others. */
    public function test_a_rule_activates_the_versions_its_regex_matches(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::Activate, [
            'ref_kind' => 'tag',
            'ref_pattern' => '^v\d+\.\d+\.\d+$',
        ]);

        $release = $this->version('v2.0.0', 'tag', active: false);
        $prerelease = $this->version('v2.1.0-rc1', 'tag', active: false);
        $branch = $this->version('main', 'branch', active: false);

        $fired = $this->engine->apply($this->project, new SyncOutcome(
            created: [$release, $prerelease, $branch],
        ));

        $this->assertCount(1, $fired);
        $this->assertTrue($release->refresh()->active);
        $this->assertFalse($prerelease->refresh()->active, 'the regex excludes a prerelease suffix');
        $this->assertFalse($branch->refresh()->active, 'ref_kind: tag excludes the branch');
    }

    /**
     * 🛑 §8.6.2's `hidden` is not `private`.
     *
     * A `hide` rule clears `listed` and leaves `active`, `published` and
     * `visibility` exactly as they were — which is what makes a hidden
     * version "serve by direct URL but absent from the flyout".
     */
    public function test_hide_clears_listed_and_touches_nothing_else(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::Hide, [
            'ref_pattern' => '^wip/',
        ]);

        $version = $this->version('wip/spike', 'branch', active: true);
        $version->forceFill(['published' => true])->save();

        $this->engine->apply($this->project, new SyncOutcome(created: [$version]));

        $version->refresh();

        $this->assertFalse($version->listed, '§8.6.2: hidden means absent from the flyout');
        $this->assertTrue($version->active, 'and still active, so its URLs resolve');
        $this->assertTrue($version->published, 'and still published, so they serve bytes');
        $this->assertSame(AccessLevel::Public, $version->visibility, 'hidden is not private');
    }

    /**
     * 🛑 §8.6.3's latch survives a `make_public` rule.
     *
     * > "A newly discovered version MUST inherit `private` whenever the
     * > project has ever had a non-public access rule ... **ever**."
     *
     * A rule that makes one version public must not unlatch the project, or
     * the next branch would be born public.
     */
    public function test_make_private_latches_the_project_and_make_public_does_not_unlatch_it(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::MakePrivate, [
            'ref_pattern' => '^internal/',
        ]);

        $internal = $this->version('internal/notes', 'branch');

        $this->engine->apply($this->project, new SyncOutcome(created: [$internal]));

        $this->assertSame(AccessLevel::Restricted, $internal->refresh()->visibility);
        $this->assertTrue($this->project->refresh()->has_ever_been_guarded, '§8.6.3: the latch is set');

        // Now a rule that makes something public.
        AutomationRule::query()->delete();
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::MakePublic, []);

        $this->engine->apply($this->project, new SyncOutcome(created: [$this->version('docs', 'branch')]));

        $this->assertTrue(
            $this->project->refresh()->has_ever_been_guarded,
            '🛑 §8.6.3 says **ever**: making one version public must not unlatch the project',
        );
    }

    /**
     * 🛑 §8.6.15: `delete_version` fires on disappearance and nowhere else.
     */
    public function test_delete_version_is_refused_on_creation_and_allowed_on_disappearance(): void
    {
        $this->assertFalse(
            AutomationAction::DeleteVersion->isValidFor(AutomationTrigger::VersionCreated),
            '🛑 §8.6.15: removal is triggered by ref disappearance, not by ref creation',
        );

        $this->assertTrue(
            AutomationAction::DeleteVersion->isValidFor(AutomationTrigger::VersionDisappeared),
        );

        // A rule written the wrong way round does not fire even if it is in
        // the table — a restore, a migration, a hand-edited row.
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::DeleteVersion, []);

        $version = $this->version('doomed', 'branch');

        $this->engine->apply($this->project, new SyncOutcome(created: [$version]));

        $this->assertNotNull(
            ProjectVersion::query()->find($version->id),
            'a delete_version rule on the wrong trigger is passed over, not run',
        );
    }

    /** The same action on the right trigger does remove the version. */
    public function test_delete_version_removes_a_disappeared_version(): void
    {
        $this->rule(1, AutomationTrigger::VersionDisappeared, AutomationAction::DeleteVersion, [
            'ref_pattern' => '^wip/',
        ]);

        $gone = $this->version('wip/abandoned', 'branch');
        $kept = $this->version('main', 'branch');

        $this->engine->apply($this->project, new SyncOutcome(disappeared: [$gone, $kept]));

        $this->assertNull(ProjectVersion::query()->find($gone->id));
        $this->assertNotNull(
            ProjectVersion::query()->find($kept->id),
            'the regex is what keeps `main` — a rule with no filter would have taken it too',
        );

        $this->assertSame(
            1,
            $this->auditCount('version.deleted'),
            'the one operation that destroys reader-visible URLs is audited',
        );
    }

    /**
     * 🛑 First match wins, because §8.6.8's actions are not commutative.
     *
     * `set_default` then `delete_version` would leave the project pointing
     * at nothing. An operator who genuinely wants two actions sets
     * `continue_matching`, which is a deliberate act rather than the
     * behaviour everybody gets by accident.
     */
    public function test_only_the_first_matching_rule_fires_unless_told_otherwise(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::Activate, []);
        $this->rule(2, AutomationTrigger::VersionCreated, AutomationAction::Hide, []);

        $version = $this->version('main', 'branch', active: false);

        $fired = $this->engine->apply($this->project, new SyncOutcome(created: [$version]));

        $this->assertCount(1, $fired);
        $this->assertTrue($version->refresh()->active);
        $this->assertTrue($version->listed, 'rule 2 did not fire');
    }

    /** And with `continue_matching`, both do, in order. */
    public function test_continue_matching_runs_the_rest_of_the_chain(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::Activate, [
            'continue_matching' => true,
        ]);
        $this->rule(2, AutomationTrigger::VersionCreated, AutomationAction::Hide, []);

        $version = $this->version('main', 'branch', active: false);

        $fired = $this->engine->apply($this->project, new SyncOutcome(created: [$version]));

        $this->assertCount(2, $fired);
        $this->assertSame(1, $fired[0]->rule->position, 'order matters and is asserted, not counted');
        $this->assertSame(2, $fired[1]->rule->position);

        $version->refresh();
        $this->assertTrue($version->active);
        $this->assertFalse($version->listed);
    }

    /**
     * 🛑 A filter that cannot be evaluated does not match.
     *
     * A rule filtered on changed paths, fired by a poll that carries none,
     * must NOT be treated as "no filter" — that would make a
     * `make_public` rule fire on a sync nobody meant to trigger it.
     */
    public function test_a_path_filtered_rule_does_not_fire_without_a_push(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::MakePublic, [
            'path_globs' => ['docs/**'],
        ]);

        $version = $this->version('main', 'branch');
        $version->forceFill(['visibility' => AccessLevel::Restricted->value])->save();

        $fired = $this->engine->apply($this->project, new SyncOutcome(created: [$version]));

        $this->assertSame([], $fired);
        $this->assertSame(
            AccessLevel::Restricted,
            $version->refresh()->visibility,
            'an unevaluable filter is not a satisfied one',
        );
    }

    /** `set_default` writes §8.6.14's stored pointer. */
    public function test_set_default_repoints_the_project(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::SetDefault, [
            'ref_kind' => 'tag',
        ]);

        $tag = $this->version('v3.0.0', 'tag');

        $this->engine->apply($this->project, new SyncOutcome(created: [$tag]));

        $this->assertSame($tag->id, $this->project->refresh()->default_version_id);
    }

    /** Every rule that fires leaves an audit event naming itself. */
    public function test_a_fired_rule_is_audited_with_its_identity(): void
    {
        $this->rule(1, AutomationTrigger::VersionCreated, AutomationAction::Activate, []);

        $this->engine->apply($this->project, new SyncOutcome(created: [$this->version('main', 'branch', active: false)]));

        $this->assertSame(1, $this->auditCount('automation.rule.fired'));
    }

    // ------------------------------------------------------------- helpers

    /** @param array<string, mixed> $attributes */
    private function rule(
        int $position,
        AutomationTrigger $trigger,
        AutomationAction $action,
        array $attributes,
    ): AutomationRule {
        $rule = new AutomationRule;

        $rule->forceFill(array_merge([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'position' => $position,
            'label' => $action->value.' '.$position,
            'trigger' => $trigger->value,
            'action' => $action->value,
            'ref_kind' => 'any',
            'enabled' => true,
            'continue_matching' => false,
        ], $attributes))->save();

        return $rule;
    }

    private function version(string $ref, string $kind, bool $active = true): ProjectVersion
    {
        $version = new ProjectVersion;

        $version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => str_replace('/', '-', $ref),
            'kind' => $kind === 'tag' ? 'release' : 'channel',
            'language' => 'en',
            'active' => $active,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => $ref,
            'ref_kind' => $kind,
            'ref_commit_sha' => str_repeat('a', 40),
        ])->save();

        return $version;
    }

    private function auditCount(string $action): int
    {
        return (int) DB::scalar('SELECT COUNT(*) FROM `audit_events` WHERE `action` = ?', [$action]);
    }
}
