<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Auth\Providers\BindingContext;
use App\Models\ReaderIdentity;
use App\Readers\ReaderSessions;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §8.13.7's JIT provisioning, and the word the specification emphasises.
 *
 * > "JIT provisioning MUST be per binding (`disabled`, `create_reader`,
 * > `create_reader_and_map_groups`). IdP-sourced role assignments MUST be
 * > **reconciled — added *and* removed** — on every login."
 *
 * 🛑 **Removal is the half that gets left out, and §17 makes it an exit
 * criterion**: "A group removed at the IdP is removed from the reader's
 * assignments on next login, not merely not added."
 *
 * The asymmetric implementation — add what the token asserts, leave everything
 * else alone — is what somebody writes without meaning to, and its failure mode
 * is the one that matters: an employee moved out of a group, or out of the
 * company, keeps the access that group gave them for ever. Offboarding at the
 * identity provider is the *only* offboarding most organisations perform, so an
 * installation that does not reconcile is one where leaving does not revoke.
 *
 * 🛑 **Only `source = 'idp_mapping'` rows are touched.** A reconciliation that
 * deleted every assignment it did not assert would delete an operator's manual
 * grants and an invitation's, which is why §10.1 gives `role_assignments` a
 * `source` column at all. The sweep is scoped to what this binding created.
 *
 * ## 🛑 One implementation, two protocols
 *
 * Phase 24 built this inside `App\Auth\Providers\Oidc` because OIDC was the
 * only caller; Phase 25 moved it here unchanged, because SAML provisions the
 * same way and a *second* implementation of §8.13.7 would be a second answer to
 * whether a departed employee still has access. That is the class of question
 * §4.3's "one `ArtifactIngestor`, one `Resolver`, one `EffectiveAccess`"
 * invariants exist to keep single-valued.
 *
 * 🛑 What makes the sharing honest is that **nothing here is protocol-shaped**.
 * The input is a flat map of already-verified facts and the name of the member
 * holding the groups — `sub` and `groups` for an id_token, the `NameID` and an
 * attribute name for an assertion. This class never sees a token, a signature
 * or an XML document, so it cannot be the place where one protocol's validation
 * is weaker than the other's.
 */
final readonly class ReaderProvisioning
{
    public function __construct(
        private GroupMappings $mappings,
        private OrganisationContext $context,
        /*
         * 🛑 §8.12.15's per-session revocation, which an offboarding
         * needs and which only `App\Readers` may perform. See
         * {@see self::withdraw()}.
         */
        private ReaderSessions $sessions,
    ) {}

    /**
     * Find or create the reader identity these verified facts name, and reconcile.
     *
     * @param  array<string, mixed>  $claims  the **verified** facts: an id_token's
     *                                        claims, or an assertion's subject and attributes
     * @return ReaderIdentity the identity this reader is
     *
     * @throws ProvisioningRefused
     */
    public function provision(
        BindingContext $binding,
        ProvisioningMode $mode,
        array $claims,
        string $groupsClaim,
        ?int $now = null,
    ): ReaderIdentity {
        $now ??= time();

        $subject = $claims['sub'] ?? null;

        if (! is_string($subject) || $subject === '') {
            /* Already checked by the verifier; narrowed rather than assumed. */
            throw ProvisioningRefused::of(
                ProvisioningRejection::SubjectMissing,
                'the verified facts carry no subject',
            );
        }

        $identity = $this->findOrCreate($binding, $mode, $subject, $claims, $now);

        if ($mode->mapsGroups()) {
            $this->reconcile($binding, $identity, $claims, $groupsClaim, $now);
        }

        return $identity;
    }

    /**
     * 🛑 The identity, looked up under every key and re-keyed on an old hit.
     *
     * @param  array<string, mixed>  $claims
     *
     * @throws ProvisioningRefused
     */
    private function findOrCreate(
        BindingContext $binding,
        ProvisioningMode $mode,
        string $subject,
        array $claims,
        int $now,
    ): ReaderIdentity {
        $candidates = ReaderSubject::candidates($binding->id, $subject);
        $current = $candidates[0];

        /*
         * 🛑 Across every organisation. A reader is not a tenant — the callback
         * runs on the dashboard origin with no organisation context — so
         * `ReaderIdentity`'s §8.2.1 global scope would filter the row away.
         * The same span `ReaderSessions::contextFor()` takes, and for the same
         * reason.
         */
        $identity = $this->context->acrossAllOrganisations(
            static fn (): ?ReaderIdentity => ReaderIdentity::query()
                ->where('binding_id', $binding->id)
                ->whereIn('subject_hash', $candidates)
                ->first(),
        );

        if ($identity instanceof ReaderIdentity) {
            $updates = ['last_seen_at' => date('Y-m-d H:i:s.v', $now)];

            /*
             * 🛑 Re-key on a hit under a previous `APP_KEY`, so the candidate
             * set shrinks back to one. Without this an installation that had
             * rotated twice would pay the extra lookups for ever, and an
             * operator who later dropped the old key from the configuration
             * would orphan readers who had logged in since the rotation —
             * which is the opposite of what dropping a spent key should do.
             */
            if (! hash_equals($current, (string) $identity->subject_hash)) {
                $updates['subject_hash'] = $current;
            }

            /*
             * 🛑 A reader whose identity was deprovisioned is **not** silently
             * revived. §8.12.1's population is the directory's, but
             * `deprovisioned_at` is DocUp's own record that an operator (or a
             * SCIM deletion) ended this reader — and a login is not an appeal.
             */
            if ($identity->deprovisioned_at !== null) {
                throw ProvisioningRefused::of(
                    ProvisioningRejection::ProvisioningDisabled,
                    'this reader identity is deprovisioned',
                );
            }

            $this->context->acrossAllOrganisations(
                static function () use ($identity, $updates): void {
                    $identity->forceFill($updates)->save();
                },
            );

            return $identity;
        }

        if (! $mode->mayCreate()) {
            /*
             * 🛑 §8.13.7's `disabled`, and it is **audited** rather than
             * silent. "Only readers I have already created" is a legitimate
             * posture, and the way an operator discovers they have missed
             * somebody is this event — not a support ticket from a reader who
             * saw a 404.
             */
            throw ProvisioningRefused::of(
                ProvisioningRejection::ProvisioningDisabled,
                'no reader identity exists and this binding does not create them',
            );
        }

        $id = Uuid::toBytes(Uuid::v7());

        $created = $this->context->acrossAllOrganisations(
            function () use ($binding, $id, $current, $claims, $now): ReaderIdentity {
                $identity = new ReaderIdentity;

                $identity->forceFill([
                    'id' => $id,
                    /*
                     * 🛑 The **binding's** organisation, not the project's. An
                     * installation-scoped binding has none, and the identity
                     * inherits that — which is what `ReaderIdentity`'s
                     * `#[Tenancy]` attribute says: "a reader identity belongs
                     * to the organisation whose binding vouched for it".
                     */
                    'organisation_id' => $binding->organisationId,
                    'binding_id' => $binding->id,
                    'subject_hash' => $current,
                    'display_label' => ReaderSubject::displayLabel($claims, $current),
                    'last_seen_at' => date('Y-m-d H:i:s.v', $now),
                    'created_at' => date('Y-m-d H:i:s.v', $now),
                    'updated_at' => date('Y-m-d H:i:s.v', $now),
                ])->save();

                return $identity;
            },
        );

        Audit::record(
            action: 'reader.identity.provisioned',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'reader_identity',
            subjectId: $id,
            /*
             * 🛑 §8.22.5: identifiers and fixed vocabulary only. Not the
             * subject, not the display label, not a claim — the whole point of
             * `subject_hash` is that the readable subject exists nowhere in
             * DocUp, and an audit payload is somewhere.
             */
            payload: [
                'binding' => Uuid::toText($binding->id),
                'mode' => 'jit',
            ],
        );

        return $created;
    }

    /**
     * 🛑 Perform one inbound {@see ProvisioningIntent}, which is the half of
     * identity lifecycle that JIT provisioning cannot reach.
     *
     * {@see self::provision()} is **pull**: a reader signs in and their claims
     * arrive with them, so it can only ever act on somebody present. An
     * offboarding has to act on somebody who is **not** present, and who will
     * never sign in again precisely because they have left.
     *
     * 🛑 **`reader_identities.deprovisioned_at` has existed since Phase 24
     * and nothing ever wrote it.** The login path refuses on it and
     * §8.12.25's simulator refuses on it, so the read side has been complete
     * and correct for three phases over a column that was always null — the
     * same shape of defect as `reader_groups` and `cidr_allowlist` earlier in
     * this phase. This method is the write side.
     *
     * ## 🛑 Why deactivation revokes sessions rather than waiting
     *
     * {@see ProvisioningLatency} states the bound, and it is the grant TTL
     * *because* this method ends the reader's sessions at once. A session left
     * alive could mint a fresh grant on its next request, and the latency would
     * become the session's absolute ceiling — twenty-four hours rather than
     * ten minutes, a factor of 144. The requirement that the latency be stated
     * "honestly" is therefore also a requirement about what this method does.
     *
     * @param  bool  $dryRun  🛑 report what would happen and change nothing.
     *                        The first sync against a real directory is exactly
     *                        when a mapping mistake deactivates everybody, so
     *                        the seam is built to be rehearsed.
     * @return bool whether anything changed (or would have)
     *
     * @throws ProvisioningRefused
     */
    public function apply(
        BindingContext $binding,
        ProvisioningIntent $intent,
        bool $dryRun = false,
        ?int $now = null,
    ): bool {
        $now ??= time();

        /*
         * 🛑 §8.12.5: "SCIM endpoints and portal-role group mappings MUST
         * exist at installation and organisation scope only." Checked here as
         * well as on the driver, because this method is the one that writes —
         * and a project-scoped binding reaching it would be creating and
         * deleting identities in an organisation's table.
         */
        if ($binding->scope() === 'project') {
            throw ProvisioningRefused::of(
                ProvisioningRejection::ProvisioningDisabled,
                'inbound provisioning is installation- and organisation-scope only (§8.12.5)',
            );
        }

        $candidates = ReaderSubject::candidates($binding->id, $intent->subject);

        $identity = $this->context->acrossAllOrganisations(
            static fn (): ?ReaderIdentity => ReaderIdentity::query()
                ->where('binding_id', $binding->id)
                ->whereIn('subject_hash', $candidates)
                ->first(),
        );

        return match ($intent->action) {
            ProvisioningAction::Create, ProvisioningAction::Update,
            ProvisioningAction::Reactivate => $this->upsert($binding, $intent, $identity, $dryRun, $now),
            ProvisioningAction::Deactivate,
            ProvisioningAction::Delete => $this->withdraw($binding, $intent, $identity, $dryRun, $now),
        };
    }

    /**
     * Create, update or reactivate.
     *
     * 🛑 Reactivation clears `deprovisioned_at` and nothing else, because
     * the row's group memberships are what the reader comes back to — which
     * is the whole reason {@see ProvisioningAction::Deactivate} is not
     * {@see ProvisioningAction::Delete}.
     */
    private function upsert(
        BindingContext $binding,
        ProvisioningIntent $intent,
        ?ReaderIdentity $identity,
        bool $dryRun,
        int $now,
    ): bool {
        $hash = ReaderSubject::hash($binding->id, $intent->subject);
        $label = $intent->displayLabel === null
            ? ReaderSubject::displayLabel([], $hash)
            : ReaderSubject::displayLabel(['name' => $intent->displayLabel], $hash);

        if ($dryRun) {
            return $identity === null
                || $identity->deprovisioned_at !== null
                || $identity->display_label !== $label;
        }

        /*
         * Written out rather than `$identity?->id ?? Uuid::v7()`: level 9 calls
         * the nullsafe unnecessary on the left of `??`, because `id` is itself
         * non-nullable and the only null it could yield is the one the
         * coalesce already handles.
         */
        $id = $identity === null ? Uuid::v7() : $identity->id;

        DB::transaction(function () use ($binding, $identity, $hash, $label, $id, $now): void {
            $row = $identity ?? new ReaderIdentity;

            $row->forceFill([
                'id' => $id,
                'organisation_id' => $binding->organisationId,
                'binding_id' => $binding->id,
                'subject_hash' => $hash,
                'display_label' => $label,
                /* 🛑 Cleared: this is what makes a reactivation a reactivation. */
                'deprovisioned_at' => null,
                'updated_at' => date('Y-m-d H:i:s.v', $now),
                'created_at' => $identity === null
                    ? date('Y-m-d H:i:s.v', $now)
                    : $identity->created_at,
            ])->save();

            Audit::record(
                action: $identity === null
                    ? 'reader.identity.provisioned'
                    : 'reader.identity.reprovisioned',
                actorType: ActorType::System,
                organisationId: $binding->organisationId,
                subjectType: 'reader_identity',
                subjectId: $id,
                /*
                 * 🛑 Identifiers and a fixed vocabulary, as
                 * {@see self::provision()} does: the readable subject exists
                 * nowhere in DocUp and an audit payload is somewhere.
                 */
                payload: ['binding' => Uuid::toText($binding->id), 'mode' => 'inbound'],
            );
        });

        $this->bumpIdentityEpochs($binding, $now);

        return true;
    }

    /**
     * 🛑 Deactivate or delete, and **revoke every session** either way.
     *
     * The revocation is not tidiness: see this class's note on
     * {@see self::apply()}. Without it {@see ProvisioningLatency}'s ten minutes
     * would be twenty-four hours, and the requirement to state the latency
     * honestly would be a requirement to state a worse one.
     */
    private function withdraw(
        BindingContext $binding,
        ProvisioningIntent $intent,
        ?ReaderIdentity $identity,
        bool $dryRun,
        int $now,
    ): bool {
        if ($identity === null) {
            /*
             * 🛑 Not an error. A directory that pushes a deletion for
             * somebody who never signed in here is a directory doing its job,
             * and refusing would make an offboarding sync fail on the readers
             * it has least to say about.
             */
            return false;
        }

        if ($dryRun) {
            return $identity->deprovisioned_at === null;
        }

        DB::transaction(function () use ($binding, $intent, $identity, $now): void {
            $identity->forceFill([
                'deprovisioned_at' => date('Y-m-d H:i:s.v', $now),
                'updated_at' => date('Y-m-d H:i:s.v', $now),
            ])->save();

            /*
             * 🛑 Every session, now. §8.12.15: "Session inventory and
             * per-session revocation are required because SCIM offboarding
             * needs them" — this is the sentence that required them.
             *
             * 🛑 Through {@see ReaderSessions::revokeIdentity()} rather than
             * an `UPDATE` of its own, and an architecture test is what insisted:
             * "only the readers namespace reads the session tables". The first
             * version did write the SQL here, and it worked — which is the
             * problem. A second writer of that table is a second place to
             * forget the epoch bump, and a session revoked without one keeps
             * its reader admitted until the grant expires, at the two tiers
             * where it should have stopped on the next request.
             */
            $this->sessions->revokeIdentity($identity, 'deprovisioned', $now);

            Audit::record(
                action: $intent->action === ProvisioningAction::Delete
                    ? 'reader.identity.deleted'
                    : 'reader.identity.deprovisioned',
                actorType: ActorType::System,
                organisationId: $binding->organisationId,
                subjectType: 'reader_identity',
                subjectId: $identity->id,
                payload: [
                    'binding' => Uuid::toText($binding->id),
                    'mode' => 'inbound',
                    /*
                     * 🛑 The bound, recorded with the act. An incident
                     * review asks "when did they actually lose access", and the
                     * answer is this timestamp plus this number — so both
                     * are in the chain rather than one of them in a document
                     * that may since have changed.
                     */
                    'latency_seconds' => ProvisioningLatency::seconds(),
                ],
            );
        });

        /*
         * 🛑 The epoch bump is what makes Tier A and Tier B take effect on
         * the next request, which is why {@see ProvisioningLatency::seconds()}
         * is the grant TTL and not the grant TTL plus anything.
         */
        $this->bumpIdentityEpochs($binding, $now);

        return true;
    }

    /**
     * 🛑 §8.13.7's reconciliation: added **and** removed, every login.
     *
     * The shape is a set difference in both directions, computed against what
     * this binding's mappings produce from what this token asserts:
     *
     * - an assignment the token now justifies and the reader lacks → inserted;
     * - an `idp_mapping` assignment from this binding the token no longer
     *   justifies → **deleted**.
     *
     * 🛑 And the epoch moves when anything changed, because a role change that
     * took effect on the next login but not on the next *request* would be a
     * revocation with a grant-lifetime delay. §10.8's registry gives that to
     * `identity_epoch`, which §8.12.11's grant carries — so a reader whose
     * groups changed is re-decided immediately rather than when their grant
     * expires.
     *
     * @param  array<string, mixed>  $claims
     */
    private function reconcile(
        BindingContext $binding,
        ReaderIdentity $identity,
        array $claims,
        string $groupsClaim,
        int $now,
    ): void {
        $asserted = GroupMappings::assertedGroups($claims, $groupsClaim);
        $mappings = $this->mappings->forBinding($binding->id);

        /*
         * 🛑 Reader groups are recorded on the identity, dashboard roles on
         * `role_assignments`. A reader **never** holds a role assignment:
         * §8.12.1 says "a reader identity MUST NEVER hold a role assignment —
         * the permission resolver MUST raise rather than return an empty set
         * for a reader subject". So this method reconciles the reader's
         * *groups* and nothing else, and a `role` mapping reached from a reader
         * login is a configuration error rather than an instruction.
         */
        $groups = [];

        foreach ($mappings as $mapping) {
            if (! in_array($mapping['provider_group'], $asserted, true)) {
                continue;
            }

            if ($mapping['target'] === 'role') {
                /*
                 * 🛑 §8.12.5's fourth enforcement, at login.
                 *
                 * A `role` mapping cannot be written against a project-scoped
                 * binding — refused by the capability flag, by
                 * `GroupMappings::add()` and by a database CHECK. This
                 * catches the row that predates all three, and it catches the
                 * other half too: a role mapping reached by a *reader* login
                 * grants nothing, because §8.12.1 forbids a reader holding a
                 * role at all.
                 *
                 * Audited and skipped rather than thrown: the reader is
                 * legitimate and the mapping is the operator's mistake, so
                 * refusing the login would punish the wrong party.
                 */
                Audit::record(
                    action: ProvisioningRejection::DashboardRoleNotPermitted->auditAction(),
                    actorType: ActorType::System,
                    organisationId: $binding->organisationId,
                    subjectType: 'auth_provider_binding',
                    subjectId: $binding->id,
                    reasonCode: ProvisioningRejection::DashboardRoleNotPermitted->value,
                    payload: [
                        'binding' => Uuid::toText($binding->id),
                        'scope' => $mapping['binding_scope_type'],
                        'target' => 'role',
                    ],
                );

                continue;
            }

            if (! in_array($mapping['target_value'], $groups, true)) {
                $groups[] = $mapping['target_value'];
            }
        }

        sort($groups);

        $encoded = (string) json_encode($groups);
        $existing = (string) ($identity->reader_groups ?? '[]');

        if (hash_equals($existing, $encoded)) {
            return;
        }

        $this->context->acrossAllOrganisations(
            static function () use ($identity, $encoded, $now): void {
                $identity->forceFill([
                    'reader_groups' => $encoded,
                    'updated_at' => date('Y-m-d H:i:s.v', $now),
                ])->save();
            },
        );

        /*
         * 🛑 The epoch, so the change is visible on the next **request** rather
         * than on the next login. A reader's groups decide what §12.3 admits
         * them to, and a grant minted before the change would otherwise carry
         * the old answer for up to its ten-minute life.
         *
         * Scoped per project would be wrong: this reader's groups bear on every
         * project the binding governs, and `Invalidation` is the one place
         * allowed to move an epoch (§10.8).
         */
        $this->bumpIdentityEpochs($binding, $now);

        Audit::record(
            action: 'reader.identity.groups_reconciled',
            actorType: ActorType::System,
            organisationId: $binding->organisationId,
            subjectType: 'reader_identity',
            subjectId: $identity->id,
            payload: [
                'binding' => Uuid::toText($binding->id),
                /*
                 * 🛑 Counts, not names. §8.22.5 keeps free text out of the
                 * chain and a provider's group names are free text; the counts
                 * are what tells an operator that a reconciliation removed
                 * something, which is the fact worth auditing.
                 */
                'groups' => (string) count($groups),
                'changed' => 'yes',
            ],
        );
    }

    /**
     * 🛑 Every project this binding governs is re-decided.
     *
     * A binding at installation scope governs every project, which is why this
     * is a query rather than one id: §8.12.3 resolves installation and
     * organisation bindings down onto projects, so a group change under an
     * installation binding changes what §12.3 says for all of them.
     */
    private function bumpIdentityEpochs(BindingContext $binding, int $now): void
    {
        $projectIds = $this->context->acrossAllOrganisations(
            static function () use ($binding): array {
                $query = DB::table('projects')->select('id');

                $scoped = match ($binding->scope()) {
                    'project' => $query->where('id', $binding->scopeId()),
                    'organisation' => $query->where('organisation_id', $binding->scopeId()),
                    /* Installation scope: every project. */
                    default => $query,
                };

                $ids = [];

                foreach ($scoped->get() as $row) {
                    if (is_string($row->id)) {
                        $ids[] = $row->id;
                    }
                }

                return $ids;
            },
        );

        foreach ($projectIds as $projectId) {
            Invalidation::bumpIdentity(projectId: $projectId, cause: 'idp_group_reconciliation');
        }

        unset($now);
    }
}
