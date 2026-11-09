<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Auth\OrganisationContext;
use App\Branding\CascadeLevel;
use App\Branding\ContrastVerdict;
use App\Branding\ResolvedTheme;
use App\Branding\ThemeDelivery;
use App\Branding\ThemeRevisions;
use App\Branding\ThemeTarget;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ThemeRevision;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\TestCase;
use Tests\Unit\Branding\ContrastGateTest;

/**
 * §8.14.5's gate and §8.14.6's lifecycle, where they meet a row.
 *
 * {@see ContrastGateTest} asserts the arithmetic. What is
 * here is what the arithmetic is allowed to do: refuse a publish, be overridden
 * by an operator, and leave an audit trail either way. Those are the three
 * things a unit test cannot see.
 */
final class ThemePublishTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('theme-assets');

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Publish Co',
            'slug' => 'pub-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'pub-'.bin2hex(random_bytes(4)),
            'name' => 'Published Project',
            'visibility' => 'public',
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 §8.14.5: "**refuse publication below 3:1**".
     *
     * `#979797` on the default white page background is 2.92:1, computed from
     * WCAG's own formula — the fixture §17's criterion names.
     */
    public function test_a_theme_below_three_to_one_cannot_be_published(): void
    {
        $revisions = $this->revisions();

        $draft = $revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.text.primary' => ['light' => '#979797', 'dark' => '#e7eaf0']],
        );

        /* The draft itself saves — §8.14.6 stages, it does not refuse. */
        $this->assertSame('draft', $draft->state);
        $this->assertSame(ContrastVerdict::Refuse->value, $draft->contrast_verdict);

        try {
            $revisions->publish($draft);
            $this->fail('a sub-3:1 theme was published');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::ContrastTooLow, $refused->rejection);
            $this->assertStringContainsString('2.92:1', $refused->getMessage());
        }

        $this->assertSame('draft', self::reload($draft)->state);
        $this->assertNull($this->publishedRevision());
    }

    /**
     * 🛑 §8.14.5: "operator override audited" — and an override with no reason
     * is not an override.
     */
    public function test_an_override_needs_a_reason_and_is_audited(): void
    {
        $revisions = $this->revisions();

        $draft = $revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.text.primary' => ['light' => '#979797', 'dark' => '#e7eaf0']],
        );

        try {
            $revisions->publish($draft, override: true);
            $this->fail('an override with no reason was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::ContrastTooLow, $refused->rejection);
            $this->assertStringContainsString('reason', $refused->getMessage());
        }

        $published = $revisions->publish(
            $draft,
            override: true,
            reason: 'Brand guideline signed off by legal; remediation tracked as ACME-4120.',
        );

        $this->assertSame('published', $published->state);
        $this->assertTrue($published->contrast_override);
        $this->assertStringContainsString('ACME-4120', (string) $published->contrast_override_reason);

        /*
         * 🛑 Two audit actions, not one. The publish is a publish; the
         * override is a separate, searchable fact — so an auditor asking
         * "which themes were shipped below the floor" has one action to
         * search for rather than a payload field to filter on.
         */
        $this->assertTrue($this->audited('branding.theme.published', (string) $published->id));
        $this->assertTrue($this->audited('branding.theme.contrast_overridden', (string) $published->id));
    }

    /** A 4.0:1 pair publishes, with the warning recorded on the revision. */
    public function test_a_four_to_one_pair_publishes_with_a_warning(): void
    {
        $revisions = $this->revisions();

        $published = $revisions->publish($revisions->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.text.secondary' => ['light' => '#7f7f7f', 'dark' => '#a9b2c1']],
        ));

        $this->assertSame('published', $published->state);
        $this->assertSame(ContrastVerdict::Warn->value, $published->contrast_verdict);
        $this->assertFalse($published->contrast_override);

        $report = $published->contrast;
        $this->assertIsArray($report);
        $this->assertSame('warn', $report['verdict']);
    }

    /**
     * 🛑 §8.14.6: publishing supersedes rather than deletes, and the unique
     * index permits exactly one published revision per scope.
     */
    public function test_publishing_supersedes_the_previous_revision(): void
    {
        $revisions = $this->revisions();

        $first = $revisions->publish($this->draftWith(['radius.small' => '2px']));
        $second = $revisions->publish($this->draftWith(['radius.small' => '6px']));

        $this->assertSame('superseded', self::reload($first)->state);
        $this->assertSame('published', self::reload($second)->state);
        $this->assertSame(1, $first->revision_number);
        $this->assertSame(2, $second->revision_number);

        $this->assertSame(
            1,
            ThemeRevision::query()
                ->where('scope_type', 'project')
                ->where('scope_id', $this->project->id)
                ->where('state', 'published')
                ->count(),
        );
    }

    /**
     * 🛑 §8.14.1's per-path locking, both halves.
     *
     * The write is refused loudly, **and** a value written before the lock
     * existed is dropped at resolution — which is the half that makes locking
     * usable after the fact.
     */
    public function test_a_locked_token_is_refused_on_write_and_dropped_on_read(): void
    {
        /* The project overrides the brand colour first. */
        $projectRevisions = $this->revisions();
        $projectRevisions->publish($this->draftWith([
            'color.brand.primary' => ['light' => '#6d28d9', 'dark' => '#c4b5fd'],
        ]));

        $this->assertSame('#6d28d9', $this->resolved()->serialised('color.brand.primary'));

        /* Then the organisation locks it. */
        $organisationRevisions = ThemeRevisions::make((string) $this->organisation->id);
        $organisationRevisions->publish($organisationRevisions->draft(
            level: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
            tokens: ['color.brand.primary' => ['light' => '#0f6b35', 'dark' => '#5bd98d']],
            locks: ['color.brand.primary'],
        ));

        /*
         * 🛑 The project's existing override is dropped on read, with no
         * migration and nothing deleted. Without this, locking would mean
         * finding and rewriting every deeper revision.
         */
        $resolved = $this->resolved();
        $this->assertSame('#0f6b35', $resolved->serialised('color.brand.primary'));
        $this->assertSame(CascadeLevel::Organisation, $resolved->origin('color.brand.primary'));
        $this->assertTrue($resolved->locks->locks('color.brand.primary'));

        /* And a new project write is refused with the reason. */
        try {
            $this->draftWith(['color.brand.primary' => ['light' => '#b3261e', 'dark' => '#ff8f85']]);
            $this->fail('a locked token was written at project scope');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::PathLocked, $refused->rejection);
            $this->assertSame('color.brand.primary', $refused->path);
        }
    }

    /** A group name locks its members and is stored expanded. */
    public function test_a_group_lock_is_stored_as_exact_token_names(): void
    {
        $organisationRevisions = ThemeRevisions::make((string) $this->organisation->id);

        $revision = $organisationRevisions->draft(
            level: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
            tokens: [],
            locks: ['Typography'],
        );

        $this->assertContains('font.body', $revision->locks);
        $this->assertContains('font.mono', $revision->locks);
        $this->assertNotContains('Typography', $revision->locks);
    }

    /** Every draft and publish writes an audit event (§9.4's baseline). */
    public function test_drafting_is_audited(): void
    {
        $draft = $this->draftWith(['radius.small' => '3px']);

        $this->assertTrue($this->audited('branding.theme.drafted', (string) $draft->id));
    }

    /**
     * 🛑 §8.14.3's structured content refuses raw HTML below installation
     * scope, which is §8.14.8's rule reaching a row.
     */
    public function test_raw_head_html_is_refused_at_project_scope(): void
    {
        try {
            $this->revisions()->draft(
                level: CascadeLevel::Project,
                scopeId: (string) $this->project->id,
                organisationId: (string) $this->organisation->id,
                tokens: [],
                chrome: ['head_html' => '<script>alert(1)</script>'],
            );
            $this->fail('raw HTML was accepted at project scope');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::TenantScriptRefused, $refused->rejection);
        }
    }

    /**
     * 🛑 And at installation scope it is still refused while
     * `DOCUP_ALLOW_RAW_HTML_BRANDING` is unset — §20.4's flag defaults closed.
     */
    public function test_raw_head_html_is_refused_at_installation_scope_without_the_flag(): void
    {
        config()->set('docup.unsafe.allow_raw_html_branding', false);

        try {
            ThemeRevisions::make()->draft(
                level: CascadeLevel::Installation,
                scopeId: null,
                organisationId: null,
                tokens: [],
                chrome: ['head_html' => '<script>console.log(1)</script>'],
            );
            $this->fail('raw HTML was accepted with the flag unset');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::TenantScriptRefused, $refused->rejection);
            $this->assertStringContainsString('DOCUP_ALLOW_RAW_HTML_BRANDING', $refused->getMessage());
        }
    }

    /** With the flag set, installation scope may carry it — and only that scope. */
    public function test_raw_head_html_is_admitted_at_installation_scope_behind_the_flag(): void
    {
        config()->set('docup.unsafe.allow_raw_html_branding', true);

        $revision = ThemeRevisions::make()->draft(
            level: CascadeLevel::Installation,
            scopeId: null,
            organisationId: null,
            tokens: [],
            chrome: ['head_html' => '<meta name="operator" content="acme">'],
        );

        $this->assertSame('<meta name="operator" content="acme">', $revision->chrome['head_html']);

        /* Still refused one rung down, flag or no flag. */
        try {
            $this->revisions()->draft(
                level: CascadeLevel::Project,
                scopeId: (string) $this->project->id,
                organisationId: (string) $this->organisation->id,
                tokens: [],
                chrome: ['head_html' => '<meta name="tenant" content="acme">'],
            );
            $this->fail('the flag widened raw HTML to project scope');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::TenantScriptRefused, $refused->rejection);
        }
    }

    // ------------------------------------------------------------- the fixtures

    /**
     * One revision, re-read from the database.
     *
     * 🛑 Through a typed helper rather than `->fresh()` or a bare
     * `findOrFail()`, because both widen to a union Larastan cannot narrow —
     * and a test asserting `->state` on a union is a test that would compile
     * against a collection.
     */
    private static function reload(ThemeRevision $revision): ThemeRevision
    {
        $reloaded = ThemeRevision::query()->whereKey($revision->getKey())->first();

        if (! $reloaded instanceof ThemeRevision) {
            throw new \RuntimeException('the revision under test disappeared');
        }

        return $reloaded;
    }

    private function revisions(): ThemeRevisions
    {
        return ThemeRevisions::make((string) $this->organisation->id, (string) $this->project->id);
    }

    /** @param array<string, mixed> $tokens */
    private function draftWith(array $tokens): ThemeRevision
    {
        return $this->revisions()->draft(
            level: CascadeLevel::Project,
            scopeId: (string) $this->project->id,
            organisationId: (string) $this->organisation->id,
            tokens: $tokens,
        );
    }

    private function resolved(): ResolvedTheme
    {
        return ThemeDelivery::make((string) $this->organisation->id, (string) $this->project->id)
            ->deliver(new ThemeTarget(
                organisationId: (string) $this->organisation->id,
                projectId: (string) $this->project->id,
            ))->theme;
    }

    private function publishedRevision(): ?ThemeRevision
    {
        $revision = ThemeRevision::query()
            ->where('scope_type', 'project')
            ->where('scope_id', $this->project->id)
            ->where('state', 'published')
            ->first();

        return $revision instanceof ThemeRevision ? $revision : null;
    }

    private function audited(string $action, string $subjectId): bool
    {
        return DB::table('audit_events')
            ->where('action', $action)
            ->where('subject_id', Uuid::tryToBytes($subjectId) ?? str_repeat("\xff", 16))
            ->exists();
    }
}
