<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Exceptions\InvitationRejected;
use App\Models\Invitation;
use App\Models\Organisation;
use App\Models\RoleAssignment;
use App\Models\User;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Issues and accepts invitations (§8.2.4).
 *
 * §8.2.4: single-use, hashed, email-bound, 14-day expiry, with the role
 * assignment pre-staged and MFA enrolment forced on acceptance where policy
 * demands it.
 *
 * The sole creator of {@see Invitation} rows, which is why that model has no
 * `$fillable`: an invitation carries a pre-staged role, so a mass-assignable
 * `role` column would be privilege escalation one careless controller away.
 */
final class Invitations
{
    /** §8.2.4 fixes this at 14 days. */
    public const EXPIRY_DAYS = 14;

    /**
     * Issue an invitation and return the **plaintext code**, once.
     *
     * 🛑 The code is returned and never stored. Only its SHA-256 hash reaches
     * the database (§9.1.4), so a stolen dump yields no usable invitations and
     * the code cannot be recovered to be re-sent — re-sending means issuing a
     * new one, which is the correct behaviour for a single-use credential
     * anyway.
     *
     * @return array{0: Invitation, 1: string} the record and the plaintext code
     */
    public function issue(
        Organisation $organisation,
        string $email,
        Role $role,
        User $invitedBy,
        Scope $scope = Scope::Organisation,
        ?string $scopeId = null,
    ): array {
        $scopeId = $scope === Scope::Installation ? null : ($scopeId ?? $organisation->id);

        if ($scope->requiresSubjectId() && $scopeId === null) {
            throw InvitationRejected::scopeNeedsSubject($scope);
        }

        $code = SecretToken::generate('docup_inv');

        return DB::transaction(function () use ($organisation, $email, $role, $invitedBy, $scope, $scopeId, $code): array {
            $invitation = new Invitation;

            $invitation->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisation->id,
                'email' => mb_strtolower(trim($email)),
                'token_hash' => SecretToken::hash($code),
                'token_hash_prefix' => SecretToken::prefix($code),
                'role' => $role->value,
                'scope_type' => $scope->value,
                'scope_id' => $scopeId,
                'invited_by' => $invitedBy->id,
                'expires_at' => now()->addDays(self::EXPIRY_DAYS),
            ])->save();

            // §8.22.4: the mutation and its audit row in one transaction.
            // 🛑 §8.22.5: the email does NOT go in the payload. It is personal
            // data, the payload is hashed, and a hashed email can never be
            // erased — the whole point of actor_labels being separate.
            Audit::record(
                action: 'organisation.invitation.issued',
                actorType: ActorType::User,
                organisationId: $organisation->id,
                actorId: $invitedBy->id,
                subjectType: 'invitation',
                subjectId: $invitation->id,
                payload: ['role' => $role->value, 'scope' => $scope->value],
            );

            return [$invitation, $code];
        });
    }

    /**
     * Accept an invitation, creating the pre-staged role assignment.
     *
     * 🛑 Email-bound (§8.2.4): the accepting user's address must match. Without
     * that check an invitation code is a bearer token for a role — forward the
     * email to anyone and they hold it. The comparison is case-insensitive
     * because addresses are stored lowercased, and `hash_equals` because it is
     * still a credential comparison.
     *
     * @throws InvitationRejected
     */
    public function accept(string $code, User $user): RoleAssignment
    {
        $invitation = Invitation::query()
            ->where('token_hash_prefix', SecretToken::prefix($code))
            ->get()
            ->first(fn (Invitation $candidate): bool => SecretToken::matches($code, $candidate->token_hash));

        if (! $invitation instanceof Invitation) {
            throw InvitationRejected::unknownCode();
        }

        if (! $invitation->isOpen()) {
            throw InvitationRejected::notOpen($invitation);
        }

        if (! hash_equals($invitation->email, mb_strtolower(trim($user->email)))) {
            throw InvitationRejected::wrongRecipient();
        }

        return DB::transaction(function () use ($invitation, $user): RoleAssignment {
            $assignment = new RoleAssignment;

            $assignment->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $invitation->scope_type === Scope::Installation
                    ? null
                    : $invitation->organisation_id,
                'subject_type' => 'user',
                'subject_id' => $user->id,
                'scope_type' => $invitation->scope_type->value,
                'scope_id' => $invitation->scope_id,
                'role' => $invitation->role->value,
                // §10.1: recorded so §8.13.7 reconciliation can tell which rows
                // it owns. An invite-sourced grant must not be stripped by IdP
                // reconciliation that only manages its own.
                'source' => 'invite',
            ])->save();

            // 🛑 Single-use (§8.2.4): stamped inside the same transaction as the
            // grant. Stamped afterwards, a crash between the two would leave a
            // live invitation that had already granted its role — reusable, and
            // granting again each time.
            $invitation->forceFill(['accepted_at' => now()])->save();

            Audit::record(
                action: 'organisation.invitation.accepted',
                actorType: ActorType::User,
                organisationId: $invitation->organisation_id,
                actorId: $user->id,
                subjectType: 'role_assignment',
                subjectId: $assignment->id,
                payload: [
                    'role' => $invitation->role->value,
                    'scope' => $invitation->scope_type->value,
                    'mfa_required' => $invitation->forcesMfaEnrolment(),
                ],
            );

            return $assignment;
        });
    }

    /** Revoke an unaccepted invitation. */
    public function revoke(Invitation $invitation, User $actor): void
    {
        DB::transaction(function () use ($invitation, $actor): void {
            $invitation->forceFill(['revoked_at' => now()])->save();

            Audit::record(
                action: 'organisation.invitation.revoked',
                actorType: ActorType::User,
                organisationId: $invitation->organisation_id,
                actorId: $actor->id,
                subjectType: 'invitation',
                subjectId: $invitation->id,
            );
        });
    }
}
