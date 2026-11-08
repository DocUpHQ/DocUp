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
use App\Egress\IpAddressClassifier;
use App\Http\Middleware\OnlyFromLoopback;
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

    /**
     * An address every unbound token is presented from.
     *
     * 🛑 §8.13.6's CIDR binding made `find()`'s address parameter
     * mandatory in Phase 26b, so these tests have to name one — which is
     * the point. An optional parameter would have let a caller recreate the
     * state that phase found: the column written at mint and read by nothing.
     */
    private const string OFFICE = '203.0.113.20';

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

        $found = app(ApiTokens::class)->find($plaintext, self::OFFICE);

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

        $this->assertNull(app(ApiTokens::class)->find($plaintext, self::OFFICE));
        $this->assertNull(app(ApiTokens::class)->find('docup_pat_never-existed', self::OFFICE));
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

        $this->assertNull(app(ApiTokens::class)->find($plaintext, self::OFFICE));
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
    // ------------------------------------- §8.13.6 overlap rotation and binding

    /**
     * 🛑 **§17's exit criterion for Phase 26b**: "A token rotated with overlap
     * serves both values until the old one's expiry and neither afterwards."
     *
     * ## The reading of "and neither afterwards"
     *
     * Taken literally, "neither afterwards" would mean the successor dies with
     * the predecessor — which would make rotation pointless, since the whole
     * purpose is a secret that outlives the one it replaces. The criterion is
     * about the **family**: both work during the overlap, the old one stops at
     * its own expiry, and once both expiries have passed nothing in the family
     * works. All three states are asserted here, in order.
     *
     * The predecessor is deliberately not revoked, which is what makes the
     * middle state exist at all: a deployment holding the old secret in three
     * places keeps working while they are updated one at a time.
     */
    public function test_a_rotated_token_serves_both_values_through_the_overlap_and_neither_after(): void
    {
        $tokens = app(ApiTokens::class);

        [$old, $oldPlaintext] = $tokens->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
            expiresAt: now()->addDays(10),
        );

        [$new, $newPlaintext] = $tokens->rotate($old, $this->admin);

        /* 1. During the overlap: both. */
        $this->assertNotNull($tokens->find($oldPlaintext, self::OFFICE), 'the old secret stopped working at once');
        $this->assertNotNull($tokens->find($newPlaintext, self::OFFICE), 'the new secret does not work');

        /* 2. One second after the OLD one's expiry: only the successor. */
        $this->travelTo($old->expires_at->copy()->addSecond());

        $this->assertNull(
            $tokens->find($oldPlaintext, self::OFFICE),
            '🛑 §17: the old value must stop at its own expiry',
        );
        $this->assertNotNull(
            $tokens->find($newPlaintext, self::OFFICE),
            '🛑 the successor must outlive it, or rotation achieves nothing',
        );

        /* 3. After the successor's expiry too: neither. */
        $this->travelTo($new->expires_at->copy()->addSecond());

        $this->assertNull($tokens->find($oldPlaintext, self::OFFICE));
        $this->assertNull($tokens->find($newPlaintext, self::OFFICE), '🛑 §17: and neither afterwards');

        $this->travelBack();
    }

    /**
     * 🛑 Rotation does not revoke the predecessor, and this is asserted
     * separately because it is the one thing a well-meaning edit would "fix".
     *
     * Revoking here turns a rotate into a replace and reintroduces exactly the
     * outage rotation exists to avoid.
     */
    public function test_rotation_does_not_revoke_the_predecessor(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
            expiresAt: now()->addDays(10),
        );

        $expiry = $old->expires_at->copy();

        app(ApiTokens::class)->rotate($old, $this->admin);

        $old->refresh();

        $this->assertNull($old->revoked_at, 'rotation revoked the predecessor');

        /*
         * To the second. The column is `datetime(3)`, so a refreshed model
         * loses the microseconds the in-memory Carbon carried — comparing
         * instants would fail on a difference that is not a change. A second is
         * finer than any shortening a rotation could plausibly make.
         */
        $this->assertSame(
            $expiry->format('Y-m-d H:i:s'),
            $old->expires_at->format('Y-m-d H:i:s'),
            'rotation moved the predecessor\'s expiry',
        );

        $this->assertTrue($old->isUsable());
    }

    /** The successor carries the family's capabilities, scope, name and binding. */
    public function test_rotation_carries_the_whole_credential_forward(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
            scope: Scope::Organisation,
            cidrAllowlist: '203.0.113.0/24',
        );

        [$new] = app(ApiTokens::class)->rotate($old, $this->admin);

        $this->assertSame($old->capabilities, $new->capabilities);
        $this->assertSame($old->scope_type, $new->scope_type);
        $this->assertSame($old->scope_id, $new->scope_id);
        $this->assertSame($old->name, $new->name);

        /*
         * 🛑 The binding above all. A rotation that dropped it would silently
         * widen where the credential works, which is the one change a rotation
         * must never make.
         */
        $this->assertSame('203.0.113.0/24', $new->cidr_allowlist);
    }

    /** The lineage is recorded, which is what bounds the family at two. */
    public function test_rotation_records_the_lineage(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        [$new] = app(ApiTokens::class)->rotate($old, $this->admin);

        $this->assertSame($old->id, $new->rotated_from_id);
        $this->assertSame($new->id, $old->successor()->first()?->id);
    }

    /**
     * 🛑 Only the holder may rotate, because rotation returns a **plaintext**.
     *
     * Rotating another user's token would hand the rotator a credential that
     * acts as them, and the audit chain would show the owner acting. Revocation
     * needs no secret and is the operation an administrator actually wants.
     */
    public function test_only_the_holder_may_rotate(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        $someoneElse = $this->user('intruder');

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/holder of a token/');

        app(ApiTokens::class)->rotate($old, $someoneElse);
    }

    /**
     * 🛑 A revoked token cannot be rotated — rotating one would resurrect a
     * credential somebody deliberately turned off.
     */
    public function test_a_revoked_token_cannot_be_rotated(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        app(ApiTokens::class)->revoke($old, $this->admin);

        $this->expectException(TokenRejected::class);

        app(ApiTokens::class)->rotate($old->refresh(), $this->admin);
    }

    /** And an expired one has no continuity left to preserve. */
    public function test_an_expired_token_cannot_be_rotated(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        $old->forceFill(['expires_at' => now()->subMinute()])->save();

        $this->expectException(TokenRejected::class);

        app(ApiTokens::class)->rotate($old, $this->admin);
    }

    /**
     * 🛑 Once only, so a family never holds more than two live secrets.
     *
     * Without this, rotating repeatedly leaves three or four working
     * credentials and an operator with no idea how many are out there — the
     * state rotation exists to end.
     */
    public function test_a_token_may_be_rotated_only_once(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        app(ApiTokens::class)->rotate($old, $this->admin);

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/already been rotated/');

        app(ApiTokens::class)->rotate($old->refresh(), $this->admin);
    }

    /** An overlap window may shorten the predecessor's life. */
    public function test_an_overlap_window_shortens_the_predecessor(): void
    {
        [$old, $oldPlaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
            expiresAt: now()->addDays(30),
        );

        $overlap = now()->addHours(2);

        app(ApiTokens::class)->rotate($old, $this->admin, overlapUntil: $overlap);

        $this->assertNotNull(app(ApiTokens::class)->find($oldPlaintext, self::OFFICE));

        $this->travelTo($overlap->copy()->addSecond());

        $this->assertNull(app(ApiTokens::class)->find($oldPlaintext, self::OFFICE));

        $this->travelBack();
    }

    /**
     * 🛑 And may only **shorten**.
     *
     * Extending the predecessor's expiry during a rotation prolongs the secret
     * being replaced, and rotating in a circle would reach past §8.13.6's
     * 365-day cap one window at a time.
     */
    public function test_an_overlap_window_may_not_extend_the_predecessor(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
            expiresAt: now()->addDays(10),
        );

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/only end sooner/');

        app(ApiTokens::class)->rotate($old, $this->admin, overlapUntil: now()->addDays(300));
    }

    /**
     * 🛑 Rotation re-applies every one of §8.13.6's mint prohibitions, so it
     * **fails when the holder has lost a capability** since the token was
     * minted.
     *
     * Correct rather than inconvenient: carrying a capability forward onto a
     * new secret for somebody who no longer holds it is exactly the escalation
     * `exceedsMinter()` exists to stop, with a delay in front of it. This is
     * also the test that proves rotation goes through the one mint path rather
     * than inserting a row of its own.
     */
    public function test_rotation_refuses_a_capability_the_holder_has_lost(): void
    {
        [$old] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'deploy',
            [Capability::ProjectView],
        );

        /* The role goes away; the token's capability does not. */
        DB::table('role_assignments')
            ->where('subject_id', $this->admin->id)
            ->delete();

        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/do not hold it/');

        app(ApiTokens::class)->rotate($old, $this->admin);
    }

    /**
     * 🛑 §8.13.6's "optional CIDR binding", **which nothing enforced until
     * Phase 26b**.
     *
     * The column was written at mint and read by nothing, so a token bound to
     * an office range was usable from anywhere — the same shape of defect as
     * `reader_groups` earlier in this phase, and the reason both halves are
     * asserted here.
     */
    public function test_a_bound_token_is_refused_from_another_address(): void
    {
        [, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'office only',
            [Capability::ProjectView],
            cidrAllowlist: '203.0.113.0/24, 198.51.100.7',
        );

        /* Inside the range, and the single host. */
        $this->assertNotNull(app(ApiTokens::class)->find($plaintext, '203.0.113.20'));
        $this->assertNotNull(app(ApiTokens::class)->find($plaintext, '198.51.100.7'));

        /* Outside it. */
        $this->assertNull(app(ApiTokens::class)->find($plaintext, '192.0.2.1'));
        $this->assertNull(app(ApiTokens::class)->find($plaintext, '198.51.100.8'));
    }

    /**
     * 🛑 A bound token presented from an address nobody resolved fails
     * **closed**.
     *
     * A binding compared against an unknown address is a binding that admits
     * whoever the proxy happens to be, which is the `ip_allowlist` defect this
     * phase fixed in `336b19a` arriving by a different route.
     */
    public function test_a_bound_token_is_refused_when_no_address_is_known(): void
    {
        [, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'office only',
            [Capability::ProjectView],
            cidrAllowlist: '203.0.113.0/24',
        );

        $this->assertNull(app(ApiTokens::class)->find($plaintext, null));
        $this->assertNull(app(ApiTokens::class)->find($plaintext, ''));
    }

    /**
     * 🛑 And an **unbound** token works from anywhere, including from nowhere.
     *
     * Null or empty means unbound, not an empty allowlist. Conflating the two
     * would have made every token on every existing installation stop working
     * the moment the binding was enforced.
     */
    public function test_an_unbound_token_works_from_anywhere(): void
    {
        [, $plaintext] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'CI',
            [Capability::ProjectView],
        );

        $this->assertNotNull(app(ApiTokens::class)->find($plaintext, '192.0.2.1'));
        $this->assertNotNull(app(ApiTokens::class)->find($plaintext, null));
    }

    /**
     * 🛑 An IPv4-mapped IPv6 address never matches an IPv4 binding, and
     * **this test exists because I nearly made it do so.**
     *
     * The first version asserted the opposite — that
     * `::ffff:203.0.113.20` should be admitted by `203.0.113.0/24`, since RFC
     * 4291 §2.5.5.2 makes them the same address. It failed, and the failure
     * led to `provider-013` in the permanent abuse corpus (§9.4), which
     * decided this in Phase 23 with the reason recorded:
     *
     * > "an allowlist that normalised the mapped form would admit from a family
     * > the operator never entered".
     *
     * 🛑 That is right, and the asymmetry with
     * {@see IpAddressClassifier} — which **does** normalise
     * `::ffff:` forms — is the point rather than an inconsistency. A
     * **deny** list must recognise every spelling of a forbidden address or an
     * attacker picks the one it misses. An **allow** list must refuse every
     * spelling the operator did not enter, because there the fail-closed
     * direction is refusal.
     *
     * So a token bound to IPv4 ranges refuses a client that arrives in mapped
     * form. That fails closed, and an operator who needs both lists both —
     * as {@see OnlyFromLoopback} does.
     */
    public function test_an_ipv4_mapped_address_never_matches_an_ipv4_binding(): void
    {
        $tokens = app(ApiTokens::class);

        [, $plaintext] = $tokens->mint(
            $this->admin,
            $this->organisation,
            'office only',
            [Capability::ProjectView],
            cidrAllowlist: '203.0.113.0/24',
        );

        /* The dotted quad the operator entered. */
        $this->assertNotNull($tokens->find($plaintext, '203.0.113.20'));

        /* The same address, spelled in the family they did not enter. */
        $this->assertNull(
            $tokens->find($plaintext, '::ffff:203.0.113.20'),
            '🛑 provider-013: an allowlist must not normalise the mapped form',
        );

        $this->assertNull($tokens->find($plaintext, '::ffff:192.0.2.1'));

        /*
         * 🛑 And the operator's remedy, asserted so that the documentation
         * is not the only place it is written down: list both spellings.
         */
        [, $both] = $tokens->mint(
            $this->admin,
            $this->organisation,
            'dual stack',
            [Capability::ProjectView],
            cidrAllowlist: '203.0.113.0/24,::ffff:203.0.113.0/120',
        );

        $this->assertNotNull($tokens->find($both, '203.0.113.20'));
        $this->assertNotNull($tokens->find($both, '::ffff:203.0.113.20'));
        $this->assertNull($tokens->find($both, '::ffff:192.0.2.1'));
    }

    /**
     * The binding is canonicalised at mint, so the stored form and the compared
     * form are the same string.
     */
    public function test_the_binding_is_canonicalised_at_mint(): void
    {
        [$token] = app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'office only',
            [Capability::ProjectView],
            /* Host bits set, duplicated, oddly spaced. */
            cidrAllowlist: ' 203.0.113.20/24 ,203.0.113.0/24,  10.0.0.1 ',
        );

        $this->assertSame('203.0.113.0/24,10.0.0.1/32', $token->cidr_allowlist);
    }

    /**
     * 🛑 An unparseable binding is refused at mint rather than stored.
     *
     * An unparseable range matches nothing and `find()` fails closed, so the
     * token would be bound to the empty set and every request with it would get
     * exactly the 401 a stolen token gets. Safe, and undiagnosable.
     */
    public function test_an_unparseable_binding_is_refused_at_mint(): void
    {
        foreach (['not-an-address', '10.0.0.0/33', '203.0.113.0/', 'example.test'] as $nonsense) {
            try {
                app(ApiTokens::class)->mint(
                    $this->admin,
                    $this->organisation,
                    'office only',
                    [Capability::ProjectView],
                    cidrAllowlist: $nonsense,
                );
                $this->fail('"'.$nonsense.'" was accepted as a CIDR binding');
            } catch (TokenRejected $rejected) {
                $this->assertStringContainsString('not an address or a CIDR range', $rejected->getMessage());
            }
        }
    }

    /** The list is capped, because every entry is compared on every request. */
    public function test_the_binding_list_is_capped(): void
    {
        $this->expectException(TokenRejected::class);
        $this->expectExceptionMessageMatches('/at most/');

        app(ApiTokens::class)->mint(
            $this->admin,
            $this->organisation,
            'too many',
            [Capability::ProjectView],
            cidrAllowlist: implode(',', array_map(
                static fn (int $n): string => '203.0.'.$n.'.0/24',
                range(1, ApiTokens::MAX_CIDR_ENTRIES + 1),
            )),
        );
    }
}
