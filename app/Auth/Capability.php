<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

/**
 * Namespaced dashboard capabilities (§12.2).
 *
 * 🛑 §12.2 requires these to be **enumerable from code**, because auditors ask
 * for the capability matrix and a matrix assembled by reading policy classes is
 * a matrix nobody can trust. {@see Role::capabilities()} maps fixed roles onto
 * these, and `docup:capabilities` renders the table.
 *
 * An enum, not free strings: a typo in a free-string capability check fails
 * **open** if the check is `!in_array(...)` and closed if it is `in_array(...)`,
 * and which one it is depends on the call site. A missing enum case does not
 * compile.
 *
 * §12.2 also says plugins contribute capabilities. They cannot contribute enum
 * cases, so when plugins arrive this enum becomes the *core* contribution to a
 * registry rather than the whole set. That is a deliberate deferral: Phase 02
 * has no plugin system, and a registry with one contributor is harder to read
 * than an enum without being more capable. The seam is {@see Role::capabilities()},
 * which is already the only thing that maps roles to capabilities.
 *
 * Naming is `<area>.<noun>.<verb>`, and the areas are deliberately coarse —
 * capabilities granular enough to express every UI affordance produce a matrix
 * too large to audit, which defeats the point of having one.
 */
enum Capability: string
{
    // ---------------------------------------------------------------- installation
    case InstallationSettingsUpdate = 'installation.settings.update';
    case InstallationUserManage = 'installation.user.manage';
    case InstallationOrganisationCreate = 'installation.organisation.create';

    /**
     * 🛑 §8.13.2 holds these two apart from {@see self::InstallationSettingsUpdate}
     * as a separation of duty: the owner runs the installation, the security
     * admin controls who may assert an identity and who may read the record of
     * what happened. An owner who can silently repoint the IdP at a directory
     * they control, and then export and prune the audit log, is a single point
     * of total compromise.
     *
     * On a fresh single-operator install one person holds both, which is
     * unavoidable and fine — §8.13.2 requires `doctor` to *surface* the
     * combination rather than prevent it.
     */
    case InstallationIdpManage = 'installation.idp.manage';
    case InstallationAuditExport = 'installation.audit.export';

    // ---------------------------------------------------------------- organisation
    case OrganisationView = 'organisation.view';
    case OrganisationUpdate = 'organisation.update';
    case OrganisationDelete = 'organisation.delete';
    case OrganisationMemberInvite = 'organisation.member.invite';
    case OrganisationMemberRemove = 'organisation.member.remove';
    case OrganisationRoleAssign = 'organisation.role.assign';
    case OrganisationTeamManage = 'organisation.team.manage';

    // --------------------------------------------------------------------- project
    case ProjectView = 'project.view';
    case ProjectCreate = 'project.create';
    case ProjectUpdate = 'project.update';
    case ProjectDelete = 'project.delete';
    case ProjectRoleAssign = 'project.role.assign';

    /**
     * Separate from {@see self::ProjectUpdate} because §8.2.10 makes
     * `projects.visibility` the operator's single kill switch, and §8.12.13
     * treats a change to it as an access-stopping event requiring an epoch
     * bump. Someone trusted to edit a project's description is not necessarily
     * trusted to publish it to the world.
     */
    case ProjectVisibilityUpdate = 'project.visibility.update';

    /**
     * §8.2.9: the single audited flag that opts a project out of
     * organisation-level role inheritance. It is the only escape from additive
     * inheritance, which is why it is its own capability and not folded into
     * project administration.
     */
    case ProjectInheritanceOverride = 'project.inheritance.override';

    // ------------------------------------------------------- versions and builds

    /**
     * Publish an artifact tree to a project version (§8.8.4, §8.21.6).
     *
     * 🛑 This is the capability Phase 02 deliberately did not invent. Its note
     * on `project_writer` reads: "publishing, versions and builds arrive in
     * Phase 03 and later, and §4.3 forbids inventing a capability before the
     * thing it governs exists". It exists now, so this does.
     *
     * Publishing is the writer's job, which is what finally distinguishes
     * `project_writer` from `project_reader`.
     */
    case ProjectVersionPublish = 'project.version.publish';

    /**
     * Roll a version back to an earlier manifest, pinning it (§8.8.5).
     *
     * Held higher than publishing, from `project_maintainer` up. Publishing adds
     * something; a rollback **withdraws content that readers are currently
     * being served** and leaves a pin that blocks the next automatic publish
     * until a human clears it. The person who can ship a documentation change is
     * not automatically the person who decides a release should disappear.
     */
    case ProjectVersionRollback = 'project.version.rollback';

    // ----------------------------------------------------------------------- audit
    case AuditRead = 'audit.read';

    // ---------------------------------------------------------------------- tokens
    case TokenMint = 'token.mint';
    case TokenRevoke = 'token.revoke';

    /**
     * A one-line description, for the generated operator table (§12.2).
     *
     * Kept beside the case rather than in the documentation, because a matrix
     * whose descriptions live in another file drifts from the code that
     * enforces it.
     */
    public function describe(): string
    {
        return match ($this) {
            self::InstallationSettingsUpdate => 'Change installation-wide settings.',
            self::InstallationUserManage => 'Create, suspend and delete user accounts.',
            self::InstallationOrganisationCreate => 'Create organisations.',
            self::InstallationIdpManage => 'Configure identity providers. Held apart from the owner role (§8.13.2).',
            self::InstallationAuditExport => 'Export the audit log. Held apart from the owner role (§8.13.2).',
            self::OrganisationView => 'View an organisation and its projects.',
            self::OrganisationUpdate => 'Change organisation settings.',
            self::OrganisationDelete => 'Delete an organisation.',
            self::OrganisationMemberInvite => 'Invite people to an organisation.',
            self::OrganisationMemberRemove => 'Remove members from an organisation.',
            self::OrganisationRoleAssign => 'Assign organisation-scoped roles.',
            self::OrganisationTeamManage => 'Create teams and manage their membership.',
            self::ProjectView => 'View a project in the dashboard.',
            self::ProjectCreate => 'Create projects within an organisation.',
            self::ProjectUpdate => 'Change project settings other than visibility.',
            self::ProjectDelete => 'Delete a project.',
            self::ProjectRoleAssign => 'Assign project-scoped roles.',
            self::ProjectVisibilityUpdate => 'Change who may read a project (§8.2.10 kill switch).',
            self::ProjectInheritanceOverride => 'Opt a project out of organisation role inheritance (§8.2.9).',
            self::ProjectVersionPublish => 'Publish an artifact tree to a project version.',
            self::ProjectVersionRollback => 'Roll a version back to an earlier revision, pinning it (§8.8.5).',
            self::AuditRead => 'Read the audit log.',
            self::TokenMint => 'Mint dashboard API tokens.',
            self::TokenRevoke => 'Revoke dashboard API tokens.',
        };
    }

    /**
     * 🛑 §8.13.6: no API token may ever hold installation-scope administrative
     * capability, validated at mint.
     *
     * Asked of the capability rather than checked against a list at the mint
     * site, so a capability added later is covered by the rule the moment it
     * exists. A list at the call site is a list someone forgets to extend.
     */
    public function isInstallationAdministrative(): bool
    {
        return match ($this) {
            self::InstallationSettingsUpdate,
            self::InstallationUserManage,
            self::InstallationOrganisationCreate,
            self::InstallationIdpManage,
            self::InstallationAuditExport => true,
            default => false,
        };
    }
}
