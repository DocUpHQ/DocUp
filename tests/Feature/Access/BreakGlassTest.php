<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Access;

use App\Access\AccessReason;
use App\Access\AccessRequest;
use App\Access\AccessSurface;
use App\Access\BreakGlass;
use App\Access\BreakGlassRefused;
use App\Access\BreakGlassRejection;
use App\Access\EffectiveAccess;
use App\Access\ReaderContext;
use App\Access\ReaderPolicy;
use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\SessionStamps;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Notifications\BreakGlassOpened;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\Session;
use Tests\TestCase;

/**
 * 🛑 §8.12.20's break-glass read override, and §17's exit criterion:
 * "Break-glass requires MFA, step-up and a reason, is rate-limited to 3/hour
 * and alerts."
 *
 * > "An installation-owner **break-glass** read override MUST exist behind MFA,
 * > step-up re-authentication and a mandatory reason, rate-limited to 3/hour,
 * > raising an operator alert and audited."
 *
 * Five requirements in one sentence, and this file asserts each of them refuses
 * when unmet — plus the three things about the *decision* side that keep the
 * override honest: it is distinguishable from an ordinary allow, it can never
 * be publicly cached, and it cannot override an outage.
 */
final class BreakGlassTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private User $owner;

    protected function setUp(): void
    {
        parent::setUp();

        Notification::fake();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Break Glass Fixture',
            'slug' => 'bg-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'name' => 'Handbook',
            'slug' => 'handbook-'.bin2hex(random_bytes(4)),
            'visibility' => 'members',
        ]);

        $this->owner = $this->ownerWithEverything();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // -------------------------------------------- §8.12.20's five preconditions

    /** 🛑 A fully-qualified owner opens a window, and everything is recorded. */
    public function test_an_installation_owner_with_mfa_and_step_up_may_open_a_window(): void
    {
        $grant = app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());

        $this->assertTrue($grant->isOpen());
        $this->assertSame($this->project->id, $grant->project_id);
        $this->assertSame($this->owner->id, $grant->user_id);

        /* The window is §8.13.3's dashboard idle timeout, argued in the service. */
        $this->assertSame(
            BreakGlass::WINDOW_MINUTES * 60,
            $grant->expires_at->getTimestamp() - $grant->opened_at->getTimestamp(),
        );

        /* 🛑 Audited (§8.12.20), with the reason in the chain and not only in the row. */
        $event = DB::table('audit_events')
            ->where('action', 'authz.break_glass.opened')
            ->orderByDesc('id')
            ->first();

        $this->assertNotNull($event);
        $this->assertStringContainsString($this->reason(), (string) ($event->payload ?? ''));

        /* 🛑 And alerted (§8.12.20). */
        Notification::assertSentTo($this->owner, BreakGlassOpened::class);
    }

    /**
     * 🛑 §8.12.20 says "installation-**owner**", and
     * `installation_security_admin` deliberately does not hold it.
     *
     * §8.13.2 makes that role a separation of duty over "IdP configuration and
     * audit export" — the power to change who can get in and to read the record
     * of who did. One person who can both read everything and export the record
     * of it is not a separation.
     */
    public function test_only_an_installation_owner_may_open_a_window(): void
    {
        foreach ([Role::InstallationSecurityAdmin, Role::OrgAdmin, Role::ProjectAdmin] as $role) {
            $user = $this->userWith($role, mfa: true);

            $this->stepUp();

            $this->refuses(
                $user,
                BreakGlassRejection::NotAnInstallationOwner,
                $role->value.' opened a break-glass window',
            );
        }
    }

    /**
     * 🛑 §8.12.20's "behind MFA" is about **enrolment** on the account doing the
     * override, not about the installation's policy.
     *
     * An owner on an installation that has not switched MFA on would otherwise
     * pass a check written as "is MFA required and satisfied".
     */
    public function test_an_owner_without_a_second_factor_is_refused(): void
    {
        $user = $this->userWith(Role::InstallationOwner, mfa: false);

        $this->stepUp();

        $this->refuses($user, BreakGlassRejection::MfaNotEnrolled);
    }

    /**
     * 🛑 §8.12.20's "step-up re-authentication", in §8.13.5's **five-minute**
     * window — not the routine fifteen.
     *
     * Reading every document on the installation is at least as sensitive as
     * the mutations §8.13.5 reserves the short window for.
     */
    public function test_a_stale_step_up_is_refused(): void
    {
        /* No confirmation at all. */
        Session::forget(SessionStamps::CONFIRMED_AT);
        $this->refuses($this->owner, BreakGlassRejection::StepUpRequired);

        /* And one just outside the five-minute window. */
        Session::put(SessionStamps::CONFIRMED_AT, time() - (5 * 60 + 1));
        $this->refuses($this->owner, BreakGlassRejection::StepUpRequired);

        /* Inside it, and the window opens. */
        Session::put(SessionStamps::CONFIRMED_AT, time() - 60);
        $this->assertTrue(
            app(BreakGlass::class)->open($this->owner, $this->project, $this->reason())->isOpen(),
        );
    }

    /**
     * 🛑 §8.12.20's "mandatory reason", where mandatory means more than NOT
     * NULL.
     *
     * A single character satisfies a database constraint. What a review needs
     * six months later is a sentence, so the floor is a length **and** a count
     * of distinct words — `aaaa…` passes any length test, and
     * `incident incident incident incident` passes any word count that does not
     * ask for distinct ones.
     */
    public function test_a_reason_must_be_a_reason(): void
    {
        $thin = [
            '',
            'x',
            'incident',
            str_repeat('a', 60),
            str_repeat('incident ', 8),
            '.........................................',
            'need access need access need access need',
        ];

        foreach ($thin as $reason) {
            $this->stepUp();

            $this->refuses(
                $this->owner,
                BreakGlassRejection::ReasonTooThin,
                json_encode($reason).' was accepted as a reason',
                $reason,
            );
        }

        /* And one that says something. */
        $this->stepUp();
        $this->assertTrue(app(BreakGlass::class)->open(
            $this->owner,
            $this->project,
            'Investigating ticket SEC-4120: a reader reports seeing another tenant content.',
        )->isOpen());
    }

    public function test_an_over_long_reason_is_refused(): void
    {
        $this->stepUp();

        $this->refuses(
            $this->owner,
            BreakGlassRejection::ReasonTooLong,
            'a reason over the column width was accepted',
            $this->reason().str_repeat(' and more detail', 40),
        );
    }

    /**
     * 🛑 §8.12.20's "rate-limited to 3/hour", counted from the **grants table**
     * and not a cache bucket.
     *
     * A Valkey counter resets on a flush, an eviction or a restart, so "3 per
     * hour" would be an honest claim only while the cache happened to be
     * healthy — and the one time the limit matters is an incident, which is
     * also when somebody is restarting things.
     */
    public function test_three_an_hour_and_no_more(): void
    {
        $breakGlass = app(BreakGlass::class);

        /* Three different projects, because a second window on one is refused. */
        for ($i = 0; $i < BreakGlass::MAX_PER_HOUR; $i++) {
            $this->stepUp();
            $breakGlass->open($this->owner, $this->anotherProject(), $this->reason());
        }

        $this->assertSame(BreakGlass::MAX_PER_HOUR, $breakGlass->openedInTheLastHour($this->owner));

        $this->stepUp();
        $this->refuses($this->owner, BreakGlassRejection::RateLimited);

        /*
         * 🛑 An hour later the budget is back, because the window slides — and
         * the step-up has to be fresh **as of then**.
         *
         * The first version of this test reused the step-up from a moment ago
         * and was refused for staleness, which is correct: the rate-limit
         * window slides with the clock and the five-minute confirmation window
         * does not travel with it. Two independent controls, and the test now
         * says so rather than passing because one of them happened to fire.
         */
        $later = now()->addHour()->addMinute()->getTimestamp();

        Session::put(SessionStamps::CONFIRMED_AT, $later - 60);

        $this->assertTrue($breakGlass->open(
            $this->owner,
            $this->anotherProject(),
            $this->reason(),
            $later,
        )->isOpen());

        /* And without a fresh confirmation at that later moment, it is not. */
        Session::put(SessionStamps::CONFIRMED_AT, time());

        try {
            $breakGlass->open($this->owner, $this->anotherProject(), $this->reason(), $later);
            $this->fail('a step-up from an hour earlier was accepted');
        } catch (BreakGlassRefused $refused) {
            $this->assertSame(BreakGlassRejection::StepUpRequired, $refused->rejection);
        }
    }

    /**
     * 🛑 A second window on the same project is refused rather than silently
     * reused.
     *
     * Otherwise the rate limit is sidestepped by re-opening, and two reasons
     * attach to one window — which makes neither reviewable.
     */
    public function test_a_second_window_on_the_same_project_is_refused(): void
    {
        app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());

        $this->stepUp();
        $this->refuses($this->owner, BreakGlassRejection::AlreadyOpen);
    }

    /**
     * 🛑 **Every refused attempt is audited**, not only the successful ones.
     *
     * A sequence of refusals is exactly the signal an operator wants, and it is
     * the signal somebody who has taken an owner's session would produce while
     * working out which precondition they cannot meet.
     */
    public function test_a_refused_attempt_is_audited(): void
    {
        $before = DB::table('audit_events')->count();

        Session::forget(SessionStamps::CONFIRMED_AT);

        try {
            app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());
        } catch (BreakGlassRefused) {
            // expected
        }

        $this->assertGreaterThan($before, DB::table('audit_events')->count());

        $event = DB::table('audit_events')
            ->where('action', BreakGlassRejection::StepUpRequired->auditAction())
            ->first();

        $this->assertNotNull($event, '🛑 a refused break-glass attempt left no trace');
    }

    // ------------------------------------------------------ closing the window

    public function test_closing_a_window_ends_it_and_is_recorded(): void
    {
        $grant = app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());

        app(BreakGlass::class)->close($grant, $this->owner);

        $this->assertFalse($grant->refresh()->isOpen());
        $this->assertNull(app(BreakGlass::class)->activeFor($this->owner->id, $this->project->id));

        $this->assertNotNull(
            DB::table('audit_events')->where('action', 'authz.break_glass.closed')->first(),
        );
    }

    /** And a window that has run out is not open, with nothing closed. */
    public function test_an_expired_window_is_not_active(): void
    {
        $grant = app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());

        $later = $grant->expires_at->getTimestamp() + 1;

        $this->assertNull(
            app(BreakGlass::class)->activeFor($this->owner->id, $this->project->id, $later),
        );
        $this->assertFalse($grant->isOpen($later));
        $this->assertNull($grant->closed_at, 'expiry is not a close');
    }

    /** 🛑 A window is scoped to one project and reaches no other. */
    public function test_a_window_reaches_only_its_own_project(): void
    {
        app(BreakGlass::class)->open($this->owner, $this->project, $this->reason());

        $other = $this->anotherProject();

        $this->assertNotNull(app(BreakGlass::class)->activeFor($this->owner->id, $this->project->id));
        $this->assertNull(app(BreakGlass::class)->activeFor($this->owner->id, $other->id));
    }

    // ------------------------------------------------------- the decision side

    /**
     * 🛑 The override admits a reader the lattice refuses — and says so.
     *
     * `allow:break_glass`, not `allow:allowed`. §8.12.20 requires the
     * activation audited and alerted, which presumes every *use* is
     * distinguishable afterwards; an override that looked like an ordinary
     * allow would satisfy the feature and defeat the requirement.
     */
    public function test_the_override_admits_and_is_distinguishable(): void
    {
        /* Without it: a `restricted` resource refuses an anonymous reader. */
        $refused = EffectiveAccess::decide($this->request(ReaderContext::anonymous()));

        $this->assertFalse($refused->allowed);

        /* With it: allowed, and the header names the override. */
        $allowed = EffectiveAccess::decide($this->request(
            new ReaderContext(breakGlassId: str_repeat("\x11", 16)),
        ));

        $this->assertTrue($allowed->allowed);
        $this->assertSame(AccessReason::BreakGlass, $allowed->reason);
        $this->assertSame('allow:break_glass', $allowed->header());
        $this->assertTrue($allowed->reason->isOverride());

        /*
         * 🛑 No satisfying leaf. No credential admitted this request, and
         * naming one would record the override as though an identity had
         * satisfied a requirement — which is the one thing §8.12.7's
         * satisfiability invariant is about.
         */
        $this->assertNull($allowed->satisfiedBy);

        /* And the established level is what the override actually confers. */
        $this->assertSame(AccessLevel::Restricted, $allowed->established);
    }

    /**
     * 🛑 **An override is never publicly cacheable.**
     *
     * §9.3.2 forbids a public cache directive on private content, and an
     * override's allow is the most private response this system produces: one
     * cached copy would serve, to everybody, a document one person was briefly
     * permitted to read.
     */
    public function test_an_override_is_never_publicly_cacheable(): void
    {
        $decision = EffectiveAccess::decide($this->request(
            new ReaderContext(breakGlassId: str_repeat("\x11", 16)),
            visibility: AccessLevel::Public,
        ));

        $this->assertTrue($decision->allowed);
        $this->assertFalse(
            $decision->rulePubliclyCacheable,
            '🛑 §9.3.2: an override must never carry a public cache directive',
        );
    }

    /**
     * 🛑 The override cannot override an **outage**, and that is deliberate.
     *
     * §8.12.19's degraded binding means the installation cannot establish who
     * anybody is, so every answer it could give about identity would be wrong —
     * including an allow. §8.12.21's stale search generation means the index is
     * a copy of authorisation facts the live rows have already contradicted.
     * Neither is a policy refusal, so there is nothing there for an owner to
     * override, and an override that worked through them would turn "I cannot
     * tell" into "yes".
     */
    public function test_the_override_does_not_defeat_a_degraded_binding_or_a_stale_index(): void
    {
        $reader = new ReaderContext(breakGlassId: str_repeat("\x11", 16));

        $degraded = EffectiveAccess::decide($this->request($reader, degraded: true));

        $this->assertFalse($degraded->allowed, '🛑 an override served through an outage');
        $this->assertSame(AccessReason::BindingDegraded, $degraded->reason);
        $this->assertSame(503, $degraded->status);

        $stale = EffectiveAccess::decide($this->request(
            $reader,
            surface: AccessSurface::Search,
            searchGeneration: 1,
            policyGeneration: 2,
        ));

        $this->assertFalse($stale->allowed, '🛑 an override served from a stale index');
        $this->assertSame(AccessReason::SearchGenerationStale, $stale->reason);
    }

    /** `isAllow()` counts the override, or every consumer of it would deny. */
    public function test_the_reason_counts_as_an_allow(): void
    {
        $this->assertTrue(AccessReason::BreakGlass->isAllow());
        $this->assertTrue(AccessReason::BreakGlass->isOverride());
        $this->assertFalse(AccessReason::Allowed->isOverride());
    }

    // ------------------------------------------------------------- fixtures

    private function reason(): string
    {
        return 'Investigating incident SEC-4120 reported by the platform team today.';
    }

    /**
     * @throws \Throwable
     */
    private function refuses(
        User $actor,
        BreakGlassRejection $expected,
        string $message = '',
        ?string $reason = null,
    ): void {
        try {
            app(BreakGlass::class)->open($actor, $this->project, $reason ?? $this->reason());
            $this->fail($message === '' ? 'the window opened' : $message);
        } catch (BreakGlassRefused $refused) {
            $this->assertSame($expected, $refused->rejection, $message);
        }
    }

    /** A step-up confirmation inside §8.13.5's five-minute window. */
    private function stepUp(): void
    {
        Session::put(SessionStamps::CONFIRMED_AT, time());
    }

    private function ownerWithEverything(): User
    {
        $owner = $this->userWith(Role::InstallationOwner, mfa: true);

        $this->stepUp();

        return $owner;
    }

    private function userWith(Role $role, bool $mfa): User
    {
        $user = User::query()->create([
            'name' => ucfirst($role->value),
            'email' => $role->value.'-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        if ($mfa) {
            /*
             * 🛑 `two_factor_confirmed_at`, which is what
             * `MfaEnforcement::isEnrolled()` reads — a secret that was set and
             * never confirmed is an enrolment nobody completed.
             */
            $user->forceFill(['two_factor_confirmed_at' => now()])->save();
        }

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $role === Role::InstallationOwner ? null : $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => $role === Role::InstallationOwner ? 'installation' : 'organisation',
            'scope_id' => $role === Role::InstallationOwner ? null : $this->organisation->id,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        return $user;
    }

    private function anotherProject(): Project
    {
        return Project::query()->create([
            'organisation_id' => $this->organisation->id,
            'name' => 'Other',
            'slug' => 'other-'.bin2hex(random_bytes(5)),
            'visibility' => 'members',
        ]);
    }

    /**
     * One decision request against a `restricted` resource with an empty
     * policy, which refuses everybody who is not overriding.
     */
    private function request(
        ReaderContext $reader,
        AccessLevel $visibility = AccessLevel::Restricted,
        bool $degraded = false,
        AccessSurface $surface = AccessSurface::Proxy,
        int $searchGeneration = 0,
        int $policyGeneration = 0,
    ): AccessRequest {
        return new AccessRequest(
            projectId: str_repeat("\x01", 16),
            projectVisibility: $visibility,
            versionVisibility: AccessLevel::Public,
            /*
             * §12.3's `inherit` sentinel — "take the project's value", resolved
             * before the comparison. So the mount neither narrows nor widens
             * and the project's own visibility is what the lattice demands.
             */
            mountExposure: 'inherit',
            policy: ReaderPolicy::absent(),
            reader: $reader,
            versionSlug: 'latest',
            path: 'index.html',
            surface: $surface,
            policyGeneration: $policyGeneration,
            searchGeneration: $searchGeneration,
            bindingDegraded: $degraded,
        );
    }
}
