<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit;

use App\Auth\Capability;
use App\Auth\Role;
use App\Auth\Scope;
use PHPUnit\Framework\TestCase;

/**
 * The §12.2 capability matrix, asserted rather than described.
 *
 * Pure enums, so no application container is needed. These are unit tests in
 * the strict sense and they are the cheapest place to catch a role model that
 * has drifted from the specification.
 */
final class RoleCapabilityTest extends TestCase
{
    /**
     * 🛑 §8.13.2 — the separation of duty, and the single most important
     * assertion in this file.
     *
     * An `installation_owner` who could also repoint the identity provider and
     * export the audit log would be a single point of total compromise: assert
     * an identity of their choosing, then remove the record of having done so.
     * The omission looks like an oversight to anyone reading the role's
     * capability list, so it gets a test that says otherwise.
     */
    public function test_the_installation_owner_cannot_manage_idp_or_export_audit(): void
    {
        $owner = Role::InstallationOwner;

        $this->assertFalse(
            $owner->can(Capability::InstallationIdpManage),
            'installation_owner must not hold installation.idp.manage (§8.13.2 separation of duty)'
        );
        $this->assertFalse(
            $owner->can(Capability::InstallationAuditExport),
            'installation_owner must not hold installation.audit.export (§8.13.2 separation of duty)'
        );
    }

    /** The other half: the separated duties must actually be held by someone. */
    public function test_the_security_admin_holds_both_separated_duties(): void
    {
        $admin = Role::InstallationSecurityAdmin;

        $this->assertTrue($admin->can(Capability::InstallationIdpManage));
        $this->assertTrue($admin->can(Capability::InstallationAuditExport));
    }

    /**
     * §8.13.1 names exactly ten roles. Asserted as a set, so both adding an
     * eleventh and quietly dropping one fail here — a specification-conformance
     * check, not a snapshot of the current code.
     */
    public function test_exactly_the_ten_specified_roles_exist(): void
    {
        $expected = [
            'installation_owner',
            'installation_security_admin',
            'installation_auditor',
            'org_admin',
            'org_member',
            'org_auditor',
            'project_admin',
            'project_maintainer',
            'project_writer',
            'project_reader',
        ];

        $actual = array_map(static fn (Role $r): string => $r->value, Role::cases());

        sort($expected);
        sort($actual);

        $this->assertSame($expected, $actual, 'the role set must match §8.13.1 exactly');
    }

    /**
     * No capability may exist that no role can ever hold.
     *
     * An unreachable capability is worse than a missing one: the UI gates on it,
     * the gate always denies, and the feature appears broken rather than
     * forbidden. §12.2 requires the matrix to be enumerable, and a matrix with
     * an empty column is a matrix with a bug in it.
     */
    public function test_every_capability_is_reachable_by_some_role(): void
    {
        $held = [];

        foreach (Role::cases() as $role) {
            foreach ($role->capabilities() as $capability) {
                $held[$capability->value] = true;
            }
        }

        $orphans = [];

        foreach (Capability::cases() as $capability) {
            if (! isset($held[$capability->value])) {
                $orphans[] = $capability->value;
            }
        }

        $this->assertSame([], $orphans, 'these capabilities are held by no role: '.implode(', ', $orphans));
    }

    /** Every role's scope must agree with the chain in §8.13.1. */
    public function test_each_role_is_scoped_where_its_name_says(): void
    {
        foreach (Role::cases() as $role) {
            $expected = match (true) {
                str_starts_with($role->value, 'installation_') => Scope::Installation,
                str_starts_with($role->value, 'org_') => Scope::Organisation,
                str_starts_with($role->value, 'project_') => Scope::Project,
                default => null,
            };

            $this->assertNotNull($expected, "role [{$role->value}] has an unrecognised name prefix");
            $this->assertSame($expected, $role->scope(), "role [{$role->value}] is scoped wrongly");
        }
    }

    /**
     * §8.13.4: MFA is required above `project_writer`. So exactly two roles are
     * exempt, and anything else becoming exempt is a weakening that should have
     * to be argued for.
     */
    public function test_mfa_is_required_for_every_role_above_project_writer(): void
    {
        $exempt = [];

        foreach (Role::cases() as $role) {
            if (! $role->requiresMfa()) {
                $exempt[] = $role->value;
            }
        }

        sort($exempt);

        $this->assertSame(
            ['project_reader', 'project_writer'],
            $exempt,
            'only writer and reader are below the §8.13.4 MFA threshold'
        );
    }

    /**
     * 🛑 §8.13.6: no API token may hold installation-scope administrative
     * capability. The mint path asks the capability, so the classification has
     * to be right or the rule silently stops applying.
     */
    public function test_every_installation_capability_is_classified_administrative(): void
    {
        foreach (Capability::cases() as $capability) {
            if (! str_starts_with($capability->value, 'installation.')) {
                continue;
            }

            $this->assertTrue(
                $capability->isInstallationAdministrative(),
                "[{$capability->value}] is installation-scoped but is not classified administrative, "
                .'so §8.13.6 would not stop a token from holding it'
            );
        }
    }

    /** No capability outside the installation namespace should be classified as one. */
    public function test_no_non_installation_capability_is_classified_administrative(): void
    {
        foreach (Capability::cases() as $capability) {
            if (str_starts_with($capability->value, 'installation.')) {
                continue;
            }

            $this->assertFalse(
                $capability->isInstallationAdministrative(),
                "[{$capability->value}] is not installation-scoped but claims to be administrative"
            );
        }
    }

    /** §12.2 renders this matrix for operators, so every row needs its text. */
    public function test_every_capability_describes_itself(): void
    {
        foreach (Capability::cases() as $capability) {
            $this->assertNotSame('', trim($capability->describe()), "[{$capability->value}] has no description");
        }
    }

    /** Capability strings are namespaced `<area>.<noun>.<verb>` (§12.2). */
    public function test_capability_strings_are_namespaced(): void
    {
        foreach (Capability::cases() as $capability) {
            $this->assertMatchesRegularExpression(
                '/^[a-z]+(\.[a-z_]+){1,2}$/',
                $capability->value,
                "[{$capability->value}] is not a namespaced capability string"
            );
        }
    }

    /**
     * The installation singleton carries no scope id; everything else must name
     * its subject. The migration enforces the pairing, and this pins the rule
     * the migration is written against.
     */
    public function test_only_the_installation_scope_omits_a_subject_id(): void
    {
        $this->assertFalse(Scope::Installation->requiresSubjectId());

        foreach ([Scope::Organisation, Scope::Collection, Scope::Project] as $scope) {
            $this->assertTrue($scope->requiresSubjectId(), "[{$scope->value}] must name its subject");
        }
    }
}
