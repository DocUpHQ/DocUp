<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\SessionStamps;
use App\Http\Middleware\EnforceSessionLifetime;
use App\Http\Middleware\RequireRecentAuthentication;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * Session hardening (§8.13.3) and step-up re-authentication (§8.13.5).
 *
 * 🛑 These tests deliberately bypass {@see TestCase::actingAs()}, which stamps a
 * fresh session for every other feature test. A control that the test harness
 * quietly satisfies is a control nobody is testing — so each case here sets the
 * stamps by hand to the state it wants to assert about.
 */
final class SessionSecurityTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $user;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Session Fixture',
            'slug' => 'session-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);
        // Referenced by URL rather than held: the session controls under test
        // do not care which project it is.
        Project::query()->create(['slug' => 'docs', 'name' => 'Docs']);
        $this->context->spanAllOrganisations();

        $this->user = User::query()->create([
            'name' => 'Session User',
            'email' => 'session-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->user->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => Role::OrgAdmin->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->forget();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    private function url(string $suffix = ''): string
    {
        return "/o/{$this->organisation->slug}/projects/docs".$suffix;
    }

    // --------------------------------------------------- §8.13.3 session limits

    /** 🛑 15-minute idle timeout. */
    public function test_an_idle_session_is_ended(): void
    {
        $stale = now()->subMinutes(EnforceSessionLifetime::IDLE_MINUTES + 1)->getTimestamp();

        $this->withSession([
            SessionStamps::AUTHENTICATED_AT => now()->subMinutes(20)->getTimestamp(),
            SessionStamps::LAST_ACTIVITY_AT => $stale,
            SessionStamps::CONFIRMED_AT => $stale,
        ])->actingAsWithoutStamps();

        $this->get($this->url())->assertRedirect(route('login'));
    }

    /**
     * 🛑 12-hour absolute lifetime, renewed by nothing.
     *
     * The case Laravel's own `session.lifetime` cannot express: the user has
     * been active one second ago, so the idle timer is satisfied, and the
     * session must still end. Without this a session lives for ever as long as
     * somebody keeps clicking — which is exactly what a stolen cookie gives an
     * attacker.
     */
    public function test_a_session_past_its_absolute_lifetime_is_ended_even_when_active(): void
    {
        $this->withSession([
            SessionStamps::AUTHENTICATED_AT => now()->subHours(EnforceSessionLifetime::ABSOLUTE_HOURS + 1)->getTimestamp(),
            SessionStamps::LAST_ACTIVITY_AT => now()->getTimestamp(),
            SessionStamps::CONFIRMED_AT => now()->getTimestamp(),
        ])->actingAsWithoutStamps();

        $this->get($this->url())->assertRedirect(route('login'));
    }

    /**
     * 🛑 Fail closed: an authenticated session with no stamp is ended.
     *
     * The alternative is a session that is immortal precisely because something
     * forgot to stamp it — the worst direction for the bug to lean, and the
     * reason the stamps live in one place.
     */
    public function test_a_session_with_no_stamp_is_ended(): void
    {
        $this->actingAsWithoutStamps();

        $this->get($this->url())->assertRedirect(route('login'));
    }

    public function test_a_fresh_session_is_served(): void
    {
        $this->actingAs($this->user)->get($this->url())->assertOk();
    }

    /** An expired API request gets 401 rather than a redirect to an HTML form. */
    public function test_an_expired_api_session_gets_401(): void
    {
        $this->withSession([
            SessionStamps::AUTHENTICATED_AT => now()->subHours(13)->getTimestamp(),
            SessionStamps::LAST_ACTIVITY_AT => now()->getTimestamp(),
        ])->actingAsWithoutStamps();

        $this->getJson("/api/v1/organisations/{$this->organisation->slug}/projects")
            ->assertStatus(401);
    }

    // ------------------------------------------------------- §8.13.5 step-up

    /**
     * 🛑 Visibility is on §8.13.5's 5-minute list, because §8.2.10 makes it the
     * kill switch. A session confirmed 10 minutes ago is inside the routine
     * window and still refused here.
     */
    public function test_a_sensitive_mutation_needs_confirmation_within_five_minutes(): void
    {
        $this->withSession([
            SessionStamps::AUTHENTICATED_AT => now()->getTimestamp(),
            SessionStamps::LAST_ACTIVITY_AT => now()->getTimestamp(),
            SessionStamps::CONFIRMED_AT => now()->subMinutes(RequireRecentAuthentication::SENSITIVE_MINUTES + 5)->getTimestamp(),
        ])->actingAsWithoutStamps();

        $this->patchJson($this->url('/visibility'), ['visibility' => 'public'])
            ->assertStatus(403)
            ->assertJsonPath('reason', 'step_up_required');
    }

    public function test_a_sensitive_mutation_is_allowed_when_just_confirmed(): void
    {
        $this->actingAs($this->user)
            ->patch($this->url('/visibility'), ['visibility' => 'public'])
            ->assertRedirect();

        $this->context->for($this->organisation->id);

        $this->assertSame('public', Project::query()->where('slug', 'docs')->firstOrFail()->visibility->value);
    }

    /**
     * 🛑 The step-up refusal is 403, not 401.
     *
     * 401 would send an API client into a re-login loop it cannot complete: the
     * credentials are valid and the session is live. What is missing is an
     * interactive confirmation only a human at a browser can give, and saying
     * so is the difference between a client that surfaces the problem and one
     * that retries for ever.
     */
    public function test_the_step_up_refusal_is_not_401(): void
    {
        $this->withSession([
            SessionStamps::AUTHENTICATED_AT => now()->getTimestamp(),
            SessionStamps::LAST_ACTIVITY_AT => now()->getTimestamp(),
            SessionStamps::CONFIRMED_AT => now()->subHour()->getTimestamp(),
        ])->actingAsWithoutStamps();

        $response = $this->patchJson($this->url('/visibility'), ['visibility' => 'public']);

        $this->assertSame(403, $response->getStatusCode());
    }

    /** The §8.13.5 sensitive list is asked of capabilities, not route names. */
    public function test_the_sensitive_list_covers_the_specified_capabilities(): void
    {
        foreach (
            [
                Capability::InstallationIdpManage,
                Capability::InstallationAuditExport,
                Capability::ProjectVisibilityUpdate,
                Capability::TokenMint,
            ] as $capability
        ) {
            $this->assertTrue(
                RequireRecentAuthentication::isSensitive($capability),
                "[{$capability->value}] is named by §8.13.5 but is not on the 5-minute list"
            );
        }

        $this->assertFalse(RequireRecentAuthentication::isSensitive(Capability::ProjectView));
    }

    /**
     * Authenticate without the harness's stamps, so each test above controls
     * the session state it is asserting about.
     *
     * 🛑 `be()`, not `parent::actingAs()`. The parent here is Tests\TestCase,
     * whose actingAs() override stamps a FRESH session — so calling it
     * overwrote the stale stamps these tests had just set, and every expiry
     * case passed the control it was meant to be exercising. The tests
     * reported 200 and looked like a middleware bug for several rounds.
     *
     * A reminder that a convenience in the test harness can silently disable
     * the thing under test, which is why these cases set the session by hand
     * rather than trusting any helper.
     */
    private function actingAsWithoutStamps(): void
    {
        $this->be($this->user);
    }
}
