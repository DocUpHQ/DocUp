<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\Exceptions\InvitationRejected;
use App\Auth\Exceptions\TokenRejected;
use App\Auth\Invitations;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Auth\Scope;
use App\Models\Invitation;
use App\Models\Organisation;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * Invitations (§8.2.4) and dashboard API tokens (§8.13.6).
 *
 * Both carry a §9.1.4 secret, so the first thing each half asserts is that the
 * plaintext never reaches the database.
 */
final class InvitationAndTokenTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private User $admin;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Invite Fixture',
            'slug' => 'invite-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->admin = $this->user('admin');

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $this->admin->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => Role::OrgAdmin->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    private function user(string $label): User
    {
        return User::query()->create([
            'name' => ucfirst($label),
            'email' => $label.'-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);
    }

    // ----------------------------------------------------------- invitations

    /** 🛑 §9.1.4: only the hash is stored, so a stolen dump yields no codes. */
    public function test_the_invitation_code_is_never_stored(): void
    {
        $invitee = $this->user('invitee');

        [$invitation, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        $this->assertNotSame('', $code);

        /** @var object{token_hash: string}|null $row */
        $row = DB::selectOne('SELECT `token_hash` FROM `invitations` WHERE `id` = ?', [$invitation->id]);

        $this->assertNotNull($row);
        $this->assertSame(hash('sha256', $code), $row->token_hash);
        $this->assertStringNotContainsString($code, (string) json_encode($row));
    }

    public function test_accepting_creates_the_pre_staged_role_assignment(): void
    {
        $invitee = $this->user('invitee');

        [, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::ProjectWriter,
            $this->admin,
            Scope::Organisation,
        );

        $assignment = app(Invitations::class)->accept($code, $invitee);

        $this->assertSame(Role::ProjectWriter, $assignment->role);
        // §10.1: the source lets §8.13.7 reconciliation tell which rows it owns,
        // so an invite-sourced grant is not stripped by IdP reconciliation.
        $this->assertSame('invite', $assignment->source);
    }

    /** 🛑 §8.2.4: single-use. */
    public function test_an_invitation_cannot_be_accepted_twice(): void
    {
        $invitee = $this->user('invitee');

        [, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        app(Invitations::class)->accept($code, $invitee);

        $this->expectException(InvitationRejected::class);
        $this->expectExceptionMessageMatches('/already been accepted/');

        app(Invitations::class)->accept($code, $invitee);
    }

    /**
     * 🛑 §8.2.4: email-bound. Without this an invitation code is a bearer token
     * for a role — forward the email to anyone and they hold it.
     */
    public function test_someone_else_cannot_accept_an_invitation(): void
    {
        $invitee = $this->user('invitee');
        $stranger = $this->user('stranger');

        [, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgAdmin,
            $this->admin,
        );

        $this->expectException(InvitationRejected::class);

        app(Invitations::class)->accept($code, $stranger);
    }

    /**
     * 🛑 A wrong recipient and an unknown code must be indistinguishable.
     *
     * Otherwise an attacker holding a leaked code learns whether it is live and
     * whose address it is bound to, turning a useless string into a target.
     */
    public function test_a_wrong_recipient_is_indistinguishable_from_an_unknown_code(): void
    {
        $invitee = $this->user('invitee');
        $stranger = $this->user('stranger');

        [, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        $wrongRecipient = null;
        $unknownCode = null;

        try {
            app(Invitations::class)->accept($code, $stranger);
        } catch (InvitationRejected $e) {
            $wrongRecipient = $e->getMessage();
        }

        try {
            app(Invitations::class)->accept('docup_inv_not-a-real-code', $stranger);
        } catch (InvitationRejected $e) {
            $unknownCode = $e->getMessage();
        }

        $this->assertNotNull($wrongRecipient);
        $this->assertSame($unknownCode, $wrongRecipient, 'the two cases are distinguishable');
    }

    public function test_an_expired_invitation_is_rejected(): void
    {
        $invitee = $this->user('invitee');

        [$invitation, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        $invitation->forceFill(['expires_at' => now()->subMinute()])->save();

        $this->expectException(InvitationRejected::class);
        $this->expectExceptionMessageMatches('/expired/');

        app(Invitations::class)->accept($code, $invitee);
    }

    public function test_a_revoked_invitation_is_rejected(): void
    {
        $invitee = $this->user('invitee');

        [$invitation, $code] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        app(Invitations::class)->revoke($invitation, $this->admin);

        $this->expectException(InvitationRejected::class);
        $this->expectExceptionMessageMatches('/revoked/');

        app(Invitations::class)->accept($code, $invitee);
    }

    /** §8.2.4 fixes the expiry at 14 days. */
    public function test_an_invitation_expires_in_fourteen_days(): void
    {
        $invitee = $this->user('invitee');

        [$invitation] = app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        $this->assertNotNull($invitation->expires_at);
        // Compared as dates rather than via diffInDays, which truncates: an
        // expiry 13.99 days out reads as 13, and the assertion then fails on
        // arithmetic rather than on behaviour.
        $this->assertSame(
            now()->addDays(Invitations::EXPIRY_DAYS)->toDateString(),
            $invitation->expires_at->toDateString(),
        );
    }

    /**
     * 🛑 §8.22.5: the invitee's email must NOT reach the hashed payload. It is
     * personal data, and a hashed email can never be erased.
     */
    public function test_the_invitees_email_is_not_in_the_audit_payload(): void
    {
        $invitee = $this->user('invitee');

        app(Invitations::class)->issue(
            $this->organisation,
            $invitee->email,
            Role::OrgMember,
            $this->admin,
        );

        /** @var list<object{payload: string}> $rows */
        $rows = DB::select('SELECT `payload` FROM `audit_events` WHERE `action` = ?', ['organisation.invitation.issued']);

        $this->assertNotEmpty($rows);

        foreach ($rows as $row) {
            $this->assertStringNotContainsString($invitee->email, $row->payload);
            $this->assertStringNotContainsString('@', $row->payload);
        }
    }

    /** §8.13.4 / §8.2.4: enrolment is forced where the granted role demands it. */
    public function test_mfa_enrolment_is_derived_from_the_granted_role(): void
    {
        $invitee = $this->user('invitee');

        [$writer] = app(Invitations::class)->issue($this->organisation, $invitee->email, Role::ProjectWriter, $this->admin);
        [$admin] = app(Invitations::class)->issue($this->organisation, $invitee->email, Role::OrgAdmin, $this->admin);

        $this->assertFalse($writer->forcesMfaEnrolment());
        $this->assertTrue($admin->forcesMfaEnrolment());
    }

    // ---------------------------------------------------------------- tokens

    public function test_the_token_plaintext_is_never_stored(): void
    {
        [$token, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'CI',
            [Capability::ProjectView],
        );

        $this->assertStringStartsWith('docup_pat_', $plaintext);

        /** @var object{token_hash: string}|null $row */
        $row = DB::selectOne('SELECT `token_hash` FROM `api_tokens` WHERE `id` = ?', [$token->id]);

        $this->assertNotNull($row);
        $this->assertSame(hash('sha256', $plaintext), $row->token_hash);
    }

    public function test_a_minted_token_can_be_found_by_its_plaintext(): void
    {
        [$token, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'CI',
            [Capability::ProjectView],
        );

        $found = app(ApiTokens::class)->find($plaintext);

        $this->assertNotNull($found);
        $this->assertSame($token->id, $found->id);
        $this->assertTrue($found->grants(Capability::ProjectView));
    }

    /**
     * 🛑 §8.13.6: "No token MUST hold installation-scope administrative
     * capability, validated at mint." At mint, because such a token is
     * dangerous the moment it exists — it only has to leak once.
     */
    public function test_a_token_cannot_hold_installation_administrative_capability(): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => null,
            'subject_type' => 'user',
            'subject_id' => $this->admin->id,
            'scope_type' => 'installation',
            'scope_id' => null,
            'role' => Role::InstallationOwner->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/8\.13\.6/');

        app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'Too powerful',
            [Capability::InstallationUserManage],
        );
    }

    /**
     * 🛑 A token may not exceed its minter, or `token.mint` is an escalation
     * primitive: grant a token more than you hold, then act as the token.
     */
    public function test_a_token_cannot_exceed_its_minters_capabilities(): void
    {
        $member = $this->user('member');

        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $member->id,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'role' => Role::OrgMember->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/do not hold it/');

        // org_member holds project.view and project.create, never project.delete.
        app(ApiTokens::class)->mint($member, $this->organisation, 'Escalation', [Capability::ProjectDelete]);
    }

    public function test_a_token_must_grant_something(): void
    {
        $this->expectException(TokenRejected::class);

        app(ApiTokens::class)->mint($this->admin, $this->organisation, 'Empty', []);
    }

    /** §8.13.6: capped at 365 days. */
    public function test_token_lifetime_is_capped(): void
    {
        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/capped at 365/');

        app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'Forever',
            [Capability::ProjectView],
            now()->addDays(366),
        );
    }

    public function test_the_default_lifetime_is_ninety_days(): void
    {
        [$token] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'Default',
            [Capability::ProjectView],
        );

        $this->assertNotNull($token->expires_at);
        $this->assertSame(
            now()->addDays(ApiTokens::DEFAULT_LIFETIME_DAYS)->toDateString(),
            $token->expires_at->toDateString(),
        );
    }

    /**
     * 🛑 A revoked token must be indistinguishable from one that never existed.
     * Otherwise an attacker sorting stolen tokens learns which are worth effort.
     */
    public function test_a_revoked_token_is_not_found(): void
    {
        [$token, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'Doomed',
            [Capability::ProjectView],
        );

        app(ApiTokens::class)->revoke($token, $this->admin);

        $this->assertNull(app(ApiTokens::class)->find($plaintext));
        $this->assertNull(app(ApiTokens::class)->find('docup_pat_never-existed'));
    }

    public function test_an_expired_token_is_not_found(): void
    {
        [$token, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'Stale',
            [Capability::ProjectView],
        );

        $token->forceFill(['expires_at' => now()->subMinute()])->save();

        $this->assertNull(app(ApiTokens::class)->find($plaintext));
    }

    /** Invitations are tenant-scoped like everything else (§8.2.1). */
    public function test_invitations_are_invisible_from_another_organisation(): void
    {
        $invitee = $this->user('invitee');

        app(Invitations::class)->issue($this->organisation, $invitee->email, Role::OrgMember, $this->admin);

        $this->context->spanAllOrganisations();

        $other = Organisation::query()->create([
            'name' => 'Other',
            'slug' => 'other-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($other->id);

        $this->assertSame(0, Invitation::query()->count());
    }
}
