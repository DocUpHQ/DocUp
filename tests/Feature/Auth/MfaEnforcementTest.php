<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Auth;

use App\Auth\MfaEnforcement;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\RoleResolver;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\DB;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\TwoFactorAuthenticatable;
use Tests\TestCase;

/**
 * 🛑 §17's Phase 26a exit criterion for MFA.
 *
 * > "Organisation-level MFA enforcement blocks a non-enrolled member above
 * > `project_writer`."
 *
 * Every clause of that sentence is a separate way to get this wrong, and each
 * gets its own test:
 *
 * | Clause | The wrong version |
 * |---|---|
 * | **organisation-level** | enforcing installation-wide, so one tenant's choice locks out everybody |
 * | **blocks** | showing a warning, or a 403 the person cannot act on |
 * | **non-enrolled** | counting a secret as enrolment, locking out somebody who closed the QR tab |
 * | **above `project_writer`** | holding out a writer, or letting an admin past |
 *
 * ## 🛑 And the gate must not block the remedy
 *
 * The most expensive failure here is not a leak; it is an installation whose
 * administrators cannot reach the page that would let them in. So the enrolment
 * page, Fortify's two-factor endpoints, the password confirmation they redirect
 * through, and logout all have their own tests — a gate that blocks everything
 * is a gate that has to be removed by hand from the database.
 */
final class MfaEnforcementTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);

        $this->organisation = Organisation::query()->create([
            'name' => 'Mfa Co',
            'slug' => 'mfa-'.bin2hex(random_bytes(3)),
        ]);

        Config::set('docup.mfa.required', false);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    // ------------------------------------------- §17's exit criterion

    /**
     * 🛑 **The criterion: organisation-level enforcement blocks a non-enrolled
     * member above `project_writer`.**
     *
     * Asserted end to end, through a real dashboard request, because the
     * requirement is about what happens to a person rather than what a
     * predicate returns.
     */
    public function test_organisation_enforcement_blocks_a_non_enrolled_admin(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        $this->actingAs($admin)
            ->get('/o/'.$this->organisation->slug.'/projects')
            ->assertRedirect(route('mfa.enrol'));
    }

    /**
     * 🛑 And a `project_writer` is **not** blocked, which is the other half of
     * "above `project_writer`".
     *
     * Without this the first test passes against a gate that holds out
     * everybody — and an installation that turned enforcement on would lock out
     * the people §8.13.4 deliberately exempts, who are the ones with no
     * administrative reach and the most of them.
     */
    public function test_a_project_writer_is_not_blocked(): void
    {
        $writer = $this->member(Role::ProjectWriter, project: true);

        $this->require();

        $this->assertNotBlocked($writer);
    }

    /** And neither is a reader. */
    public function test_a_project_reader_is_not_blocked(): void
    {
        $reader = $this->member(Role::ProjectReader, project: true);

        $this->require();

        $this->assertNotBlocked($reader);
    }

    /**
     * 🛑 A `project_admin` on one project **is** blocked.
     *
     * The case {@see RoleResolver::rolesFor()} cannot see: it
     * includes project-scope assignments only when it is handed a project, so
     * asking it "what roles does this person hold" misses exactly this person —
     * silently, because nothing about the check would look wrong.
     * {@see RoleResolver::rolesAnywhere()} exists for this test.
     */
    public function test_a_project_scoped_admin_is_blocked(): void
    {
        $admin = $this->member(Role::ProjectAdmin, project: true);

        $this->require();

        $this->assertBlocked($admin);
    }

    /** With enforcement off, nobody is blocked — §8.13.4 says "enforceable". */
    public function test_nobody_is_blocked_with_enforcement_off(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->actingAs($admin)
            ->get('/o/'.$this->organisation->slug.'/projects')
            ->assertSuccessful();
    }

    /**
     * 🛑 An **enrolled** admin passes, and "enrolled" means a confirmed
     * secret.
     *
     * Both halves in one test, because the pair is the requirement: a secret
     * alone is somebody who opened the QR screen and closed the tab, and
     * treating that as enrolment would lock them out with a secret no
     * authenticator holds — remediable only by an operator clearing a column.
     */
    public function test_enrolment_means_a_confirmed_secret(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        /* A secret and no confirmation: still blocked. */
        $admin->forceFill(['two_factor_secret' => 'pending'])->save();

        $this->actingAs($this->reload($admin))
            ->get('/o/'.$this->organisation->slug.'/projects')
            ->assertRedirect(route('mfa.enrol'));

        $admin->forceFill(['two_factor_confirmed_at' => now()])->save();

        $this->actingAs($this->reload($admin))
            ->get('/o/'.$this->organisation->slug.'/projects')
            ->assertSuccessful();
    }

    // ------------------------------------------- the two scopes

    /**
     * 🛑 One organisation's switch does not reach another organisation's
     * people.
     *
     * The failure this prevents is the expensive one: a single tenant turning
     * on a posture that holds out every administrator on a shared
     * installation.
     */
    public function test_one_organisations_switch_does_not_reach_another(): void
    {
        $other = Organisation::query()->create([
            'name' => 'Globex',
            'slug' => 'globex-'.bin2hex(random_bytes(3)),
        ]);

        $outsider = $this->member(Role::OrgAdmin, organisation: $other);

        $this->require();  // on `$this->organisation` only

        $this->assertFalse(app(MfaEnforcement::class)->blocks($outsider));
    }

    /**
     * 🛑 The installation switch **dominates**: an organisation cannot opt out
     * of it.
     *
     * The reverse ordering would make the tenant switch a vulnerability with a
     * checkbox — an `org_admin` opting their own organisation out of the
     * operator's security posture.
     */
    public function test_the_installation_switch_dominates(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        /* The organisation says no, explicitly. */
        MfaEnforcement::setForOrganisation($this->organisation, false);

        Config::set('docup.mfa.required', true);

        $this->assertTrue(
            app(MfaEnforcement::class)->blocks($admin),
            '🛑 §8.13.4: an organisation cannot turn off what the installation requires',
        );
    }

    /**
     * 🛑 And an installation-scope role with no organisation at all is covered
     * by the installation switch.
     *
     * {@see RoleResolver::organisationIdsFor()} returns nothing for
     * such a person, so the per-organisation path cannot see them — which is
     * one of the reasons §8.13.4 asks for both scopes rather than either.
     */
    public function test_an_installation_owner_is_covered_by_the_installation_switch(): void
    {
        $owner = User::factory()->create();

        DB::table('role_assignments')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => null,
            'subject_type' => 'user',
            'subject_id' => $owner->id,
            'scope_type' => 'installation',
            'scope_id' => null,
            'role' => Role::InstallationOwner->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $enforcement = app(MfaEnforcement::class);

        $this->require();

        $this->assertFalse(
            $enforcement->blocks($owner),
            'an organisation switch has nothing to attach to for an installation-scope role',
        );

        Config::set('docup.mfa.required', true);

        $this->assertTrue($enforcement->blocks($owner));
    }

    // ------------------------------------------- the remedy stays reachable

    /**
     * 🛑 **The gate must not block the remedy.** The single most expensive
     * failure available here.
     *
     * An installation whose administrators cannot reach the enrolment page has
     * to be repaired by somebody editing the database, and they will reach for
     * `DOCUP_MFA_REQUIRED=false` instead — after which §8.13.4 is satisfied by
     * a configuration key nobody can turn on.
     */
    public function test_the_enrolment_page_is_reachable_while_blocked(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        $this->actingAs($admin)
            ->get(route('mfa.enrol'))
            ->assertSuccessful();
    }

    /**
     * And Fortify's two-factor endpoints, which are the mutation rather than
     * the page. A gate that allowed the form and blocked its submission would
     * read as a broken page.
     */
    public function test_the_two_factor_endpoints_are_reachable_while_blocked(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        /*
         * 🛑 `assertStatus` on anything but a redirect to enrolment. Fortify
         * answers 423 here because `confirmPassword => true` sends the person
         * through the confirm-password screen first — which is itself a correct
         * answer, and emphatically not this middleware's redirect.
         */
        $response = $this->actingAs($admin)->post('/user/two-factor-authentication');

        $this->assertNotSame(
            route('mfa.enrol'),
            $response->headers->get('Location'),
            '🛑 enrolling must not be blocked by the gate that demands enrolment',
        );
    }

    /**
     * Password confirmation, which §8.13.5 and `config/fortify.php` put in
     * front of enrolment. Blocking it would make enrolment a loop: enrol →
     * confirm → blocked → enrol.
     */
    public function test_password_confirmation_is_reachable_while_blocked(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        $this->actingAs($admin)
            ->get('/user/confirm-password')
            ->assertSuccessful();
    }

    /**
     * 🛑 And logout. A person who cannot enrol on this device has to be able to
     * get out; holding them in a session they cannot use is not a security
     * control.
     */
    public function test_logout_is_reachable_while_blocked(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        $this->actingAs($admin)
            ->post('/logout')
            ->assertRedirect();

        $this->assertGuest();
    }

    /**
     * 🛑 A client with nobody behind it gets a 403 and a code, not a redirect.
     *
     * A redirect to an HTML page is useless to a script, and following it would
     * make a 200 of a refusal — the shape of bug where a CI job reports success
     * because it fetched a sign-in page.
     */
    public function test_a_json_client_is_refused_rather_than_redirected(): void
    {
        $admin = $this->member(Role::OrgAdmin);

        $this->require();

        $this->actingAs($admin)
            ->getJson('/o/'.$this->organisation->slug.'/projects')
            ->assertStatus(403)
            ->assertJsonPath('code', 'mfa_enrolment_required');
    }

    // ------------------------------------------- the Phase 02 gap

    /**
     * 🛑 **`User` uses `TwoFactorAuthenticatable`, and this test is the reason
     * it is a test.**
     *
     * Phase 02 enabled `Features::twoFactorAuthentication()`, published the
     * columns and wired the challenge view — and left the trait off.
     * {@see RedirectIfTwoFactorAuthenticatable} gates
     * the challenge on `in_array(TwoFactorAuthenticatable::class,
     * class_uses_recursive($user))`, so an enrolled user would have been issued
     * a secret, shown a QR code, and then signed in with a password alone for
     * ever.
     *
     * Asserted **by name** rather than behaviourally, because the behavioural
     * version is "a challenge appears", and a challenge can be made to appear
     * by other means while the trait is still missing — at which point
     * `recoveryCodes()` and `twoFactorQrCodeSvg()` are still absent and
     * enrolment still cannot complete.
     */
    public function test_the_user_model_is_two_factor_authenticatable(): void
    {
        $this->assertContains(
            TwoFactorAuthenticatable::class,
            class_uses_recursive(User::class),
            '🛑 §8.13.4: without the trait Fortify never challenges, however enrolled the user is',
        );
    }

    // ------------------------------------------------------------- fixtures

    /**
     * The row as it now stands.
     *
     * `fresh()` is typed nullable, which Larastan refuses to pass to
     * `actingAs()` — and `findOrFail` says what this means: the row exists,
     * because this test just wrote to it.
     */
    private function reload(User $user): User
    {
        return User::query()->findOrFail($user->id);
    }

    /**
     * 🛑 Blocked or not, asserted on `/` rather than on a dashboard page.
     *
     * The capability layer and the MFA gate both answer with a refusal, and on
     * a tenant page they are indistinguishable: §8.2.2 makes a member without
     * `organisation.view` a **404**, so a `project_writer` asking for
     * `/o/<slug>/projects` is refused whether or not this middleware ran. `/`
     * carries no capability requirement and redirects to login, so the two
     * destinations tell the two layers apart — which is what makes these tests
     * about §8.13.4 rather than about §12.2.
     */
    private function assertBlocked(User $user): void
    {
        $this->actingAs($user)->get('/')->assertRedirect(route('mfa.enrol'));
    }

    private function assertNotBlocked(User $user): void
    {
        $this->actingAs($user)->get('/')->assertRedirect(route('login'));
    }

    /** Turn enforcement on for this organisation only. */
    private function require(): void
    {
        $this->context->for($this->organisation->id);

        MfaEnforcement::setForOrganisation($this->organisation, true);

        $this->context->forget();
    }

    /**
     * A user holding one role, at organisation or project scope.
     *
     * 🛑 The scope matters: a `project_admin` is reachable only through a
     * project-scope assignment, and that is the case the role resolver's
     * narrower query cannot see.
     */
    private function member(Role $role, bool $project = false, ?Organisation $organisation = null): User
    {
        $organisation ??= $this->organisation;

        $this->context->for($organisation->id);

        $user = User::factory()->create();

        $scopeId = $organisation->id;
        $scopeType = 'organisation';

        if ($project) {
            $row = Project::query()->create([
                'organisation_id' => $organisation->id,
                'slug' => 'p-'.bin2hex(random_bytes(3)),
                'name' => 'A project',
                'visibility' => 'public',
            ]);

            $scopeId = $row->id;
            $scopeType = 'project';
        }

        DB::table('role_assignments')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => $scopeType,
            'scope_id' => $scopeId,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->context->forget();

        return $user;
    }
}
