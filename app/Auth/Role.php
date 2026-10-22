<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * The ten fixed dashboard roles (§8.13.1).
 *
 * Fixed, not operator-defined. §12.1 requires a capability matrix enumerable
 * from code, which custom roles would make unenumerable, and §8.13.1 names
 * exactly these ten. An installation that needs a different split assigns two
 * roles — that is what additive union is for.
 *
 * 🛑 `project_reader` is a **dashboard** role: it means "may see this project in
 * the dashboard". It is not reader access to documentation, which is decided by
 * `EffectiveAccess` (§12.3) from project visibility, reader policy and bindings,
 * and never from a role assignment. §10.1 keeps `reader_identities` physically
 * disjoint from `users` for this reason — readers never hold role assignments at
 * all. The names are similar and the systems are not.
 */
enum Role: string
{
    case InstallationOwner = 'installation_owner';
    case InstallationSecurityAdmin = 'installation_security_admin';
    case InstallationAuditor = 'installation_auditor';
    case OrgAdmin = 'org_admin';
    case OrgMember = 'org_member';
    case OrgAuditor = 'org_auditor';
    case ProjectAdmin = 'project_admin';
    case ProjectMaintainer = 'project_maintainer';
    case ProjectWriter = 'project_writer';
    case ProjectReader = 'project_reader';

    /** The scope a role is assignable at. */
    public function scope(): Scope
    {
        return match ($this) {
            self::InstallationOwner,
            self::InstallationSecurityAdmin,
            self::InstallationAuditor => Scope::Installation,
            self::OrgAdmin,
            self::OrgMember,
            self::OrgAuditor => Scope::Organisation,
            self::ProjectAdmin,
            self::ProjectMaintainer,
            self::ProjectWriter,
            self::ProjectReader => Scope::Project,
        };
    }

    /**
     * The capabilities this role confers (§12.2).
     *
     * 🛑 Note what `InstallationOwner` does **not** hold:
     * `installation.idp.manage` and `installation.audit.export`. §8.13.2 makes
     * that a separation of duty, and the reason is worth stating where someone
     * might be tempted to "fix" the omission — an owner who can repoint the
     * identity provider at a directory they control *and* export and prune the
     * record of having done so is a single point of total compromise. On a
     * one-person installation the same human holds both roles, which is fine and
     * unavoidable; §8.13.2 asks `doctor` to surface the combination, not to
     * prevent it.
     *
     * @return list<Capability>
     */
    public function capabilities(): array
    {
        return match ($this) {
            self::InstallationOwner => [
                Capability::InstallationSettingsUpdate,
                Capability::InstallationUserManage,
                Capability::InstallationOrganisationCreate,
                Capability::OrganisationView,
                Capability::OrganisationUpdate,
                Capability::OrganisationDelete,
                Capability::OrganisationMemberInvite,
                Capability::OrganisationMemberRemove,
                Capability::OrganisationRoleAssign,
                Capability::OrganisationTeamManage,
                Capability::ProjectView,
                Capability::ProjectCreate,
                Capability::ProjectUpdate,
                Capability::ProjectVersionPublish,
                Capability::ProjectDelete,
                Capability::ProjectRoleAssign,
                Capability::ProjectVisibilityUpdate,
                Capability::ProjectVersionRollback,
                Capability::ProjectInheritanceOverride,
                Capability::AuditRead,
                Capability::TokenMint,
                Capability::TokenRevoke,
            ],

            // Reading the audit log is not the separated duty; exporting it is.
            // Revocation without minting is deliberate: incident response needs
            // to kill a credential, not create one.
            self::InstallationSecurityAdmin => [
                Capability::InstallationIdpManage,
                Capability::InstallationAuditExport,
                Capability::OrganisationView,
                Capability::ProjectView,
                Capability::AuditRead,
                Capability::TokenRevoke,
            ],

            self::InstallationAuditor => [
                Capability::OrganisationView,
                Capability::ProjectView,
                Capability::AuditRead,
            ],

            self::OrgAdmin => [
                Capability::OrganisationView,
                Capability::OrganisationUpdate,
                Capability::OrganisationDelete,
                Capability::OrganisationMemberInvite,
                Capability::OrganisationMemberRemove,
                Capability::OrganisationRoleAssign,
                Capability::OrganisationTeamManage,
                Capability::ProjectView,
                Capability::ProjectCreate,
                Capability::ProjectUpdate,
                Capability::ProjectVersionPublish,
                Capability::ProjectDelete,
                Capability::ProjectRoleAssign,
                Capability::ProjectVisibilityUpdate,
                Capability::ProjectVersionRollback,
                Capability::ProjectInheritanceOverride,
                Capability::AuditRead,
                Capability::TokenMint,
                Capability::TokenRevoke,
            ],

            self::OrgMember => [
                Capability::OrganisationView,
                Capability::ProjectView,
                Capability::ProjectCreate,
            ],

            self::OrgAuditor => [
                Capability::OrganisationView,
                Capability::ProjectView,
                Capability::AuditRead,
            ],

            self::ProjectAdmin => [
                Capability::ProjectView,
                Capability::ProjectUpdate,
                Capability::ProjectVersionPublish,
                Capability::ProjectDelete,
                Capability::ProjectRoleAssign,
                Capability::ProjectVisibilityUpdate,
                Capability::ProjectVersionRollback,
                Capability::AuditRead,
                Capability::TokenMint,
                Capability::TokenRevoke,
            ],

            self::ProjectMaintainer => [
                Capability::ProjectView,
                Capability::ProjectUpdate,
                Capability::ProjectVersionPublish,
                // Maintainer is where rollback begins. See the capability's own
                // note: withdrawing what readers are currently being served is
                // a different decision from shipping a change.
                Capability::ProjectVersionRollback,
            ],

            /*
             * Phase 03 is what Phase 02's note here was waiting for. It read:
             * "`project_writer` and `project_reader` differ only once there is
             * something to write: publishing, versions and builds arrive in
             * Phase 03 and later, and §4.3 forbids inventing a capability
             * before the thing it governs exists."
             *
             * Publishing exists now, so the two roles finally differ by
             * something other than requiresMfa(). A writer publishes; only a
             * maintainer and above can roll back.
             */
            self::ProjectWriter => [
                Capability::ProjectView,
                Capability::ProjectVersionPublish,
            ],

            self::ProjectReader => [
                Capability::ProjectView,
            ],
        };
    }

    /**
     * Whether holding this role obliges MFA enrolment (§8.13.4).
     *
     * §8.13.4 words it as "required above `project_writer`", so writer and
     * reader are the exceptions and everything else is included. `org_member`
     * counts because it carries `project.create`, and the creator of a project
     * administers it — a role that can manufacture administrative scope is
     * above a writer however modest its own capability list looks.
     */
    public function requiresMfa(): bool
    {
        return match ($this) {
            self::ProjectWriter, self::ProjectReader => false,
            default => true,
        };
    }

    /** Whether this role confers the given capability directly. */
    public function can(Capability $capability): bool
    {
        return in_array($capability, $this->capabilities(), true);
    }
}
