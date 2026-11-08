<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Role;
use App\Auth\Scope;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The sole reader and writer of `provider_group_mappings` (§10.6).
 *
 * §8.12.5 is the requirement and it asks for the same rule in two places:
 *
 * > "Project-scoped bindings MUST NOT produce any dashboard role, enforced
 * > **both** as a driver capability flag **and** as a validation invariant on
 * > group mappings."
 *
 * So the refusal exists three times over, and the repetition is the point:
 *
 * 1. {@see AuthComponent::mayMapDashboardRoles()} — the
 *    capability flag, checked before a mapping is written at all;
 * 2. {@see self::add()} — the validation invariant, which refuses a `role`
 *    mapping on a project-scoped binding whatever the driver says;
 * 3. a database CHECK (`provider_group_mappings_project_scope_no_role`) — which
 *    survives a future writer who read neither.
 *
 * 🛑 And a fourth at login, in {@see ReaderProvisioning}, because a row written
 * before any of the three existed must not grant anything. §17 makes it an
 * exit criterion: "A project-scoped binding attempting to map a dashboard role
 * is rejected at validation **and** by the driver capability flag."
 *
 * ## Why the rule matters this much
 *
 * §8.12.5's own sentence says it: "A project admin controls their own IdP;
 * find-or-create-by-email would let any tenant mint an installation owner."
 * A project admin configures a binding against a directory they control — so
 * if a project-scoped binding could map a group to `installation_owner`, the
 * project admin would only have to add themselves to a group in their own
 * directory. That is not a privilege escalation bug; it is a privilege
 * escalation *feature*, and the only defence is that the capability does not
 * exist at project scope.
 */
final readonly class GroupMappings
{
    /**
     * 🛑 A cap, for the reason every other list in this schema has one.
     *
     * A provider can assert hundreds of groups and every mapping is compared
     * against every asserted group on every login. 200 keeps reconciliation
     * linear in something small.
     */
    public const int MAX_PER_BINDING = 200;

    /**
     * Add a mapping.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @param  string  $bindingScopeType  installation, organisation or project
     * @param  string  $providerGroup  the claim value as the provider sends it
     * @param  string|null  $scopeId  raw 16 bytes; required for a role
     * @return string the new row's id, raw 16 bytes
     *
     * @throws BindingRefused
     */
    public function add(
        string $bindingId,
        string $bindingScopeType,
        ?string $organisationId,
        string $providerGroup,
        string $target,
        string $targetValue,
        ?Scope $scope = null,
        ?string $scopeId = null,
    ): string {
        if ($target !== 'role' && $target !== 'group') {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'a mapping targets a `role` or a `group`',
            );
        }

        if ($providerGroup === '' || mb_strlen($providerGroup) > 255) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'the provider group name is empty or longer than 255 characters',
            );
        }

        if ($target === 'role') {
            /*
             * 🛑 §8.12.5's validation invariant. The driver capability flag is
             * checked by the caller; this is the second enforcement the
             * requirement asks for by name, and it is here rather than there
             * because a mapping can be written by an API that never loaded a
             * driver.
             */
            if ($bindingScopeType === 'project') {
                throw BindingRefused::of(
                    BindingRejection::DashboardRoleNotPermitted,
                    '🛑 §8.12.5: a project-scoped binding may not map a dashboard role',
                );
            }

            /*
             * §12.1's roles are code-enumerable, so the mapping is validated
             * against the enum rather than against a list copied into this
             * file. A `role` column ENUM in the database would be a third copy.
             */
            if (Role::tryFrom($targetValue) === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`'.$targetValue.'` is not one of §12.1\'s roles',
                );
            }

            if ($scope === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    'a mapped role needs a scope, because §12.1 resolves roles over the scope chain',
                );
            }

            /*
             * 🛑 An installation-scoped role mapping is the most dangerous row
             * in this table, so it is only writable from an installation-scoped
             * binding. An organisation-scoped binding mapping to
             * `installation_owner` would be the same escalation the project
             * rule forbids, one rung up.
             */
            if ($scope === Scope::Installation && $bindingScopeType !== 'installation') {
                throw BindingRefused::of(
                    BindingRejection::DashboardRoleNotPermitted,
                    'only an installation-scoped binding may map an installation-scope role',
                );
            }

            if ($scope !== Scope::Installation && $scopeId === null) {
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    'a role mapped at '.$scope->value.' scope needs the id of that scope',
                );
            }
        } elseif ($scope !== null) {
            /*
             * A reader group is not scoped: it is a fact about the reader, and
             * §12.3's rules are what give it meaning per project. A scope here
             * would be a scope nothing reads.
             */
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'a reader group mapping carries no scope',
            );
        }

        $live = DB::table('provider_group_mappings')->where('binding_id', $bindingId)->count();

        if ($live >= self::MAX_PER_BINDING) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'a binding may hold at most '.self::MAX_PER_BINDING.' group mappings',
            );
        }

        $id = Uuid::toBytes(Uuid::v7());

        DB::table('provider_group_mappings')->insert([
            'id' => $id,
            'organisation_id' => $organisationId,
            'binding_id' => $bindingId,
            'binding_scope_type' => $bindingScopeType,
            'provider_group' => $providerGroup,
            'target' => $target,
            'target_value' => $targetValue,
            'scope_type' => $scope?->value,
            'scope_id' => $scope === Scope::Installation ? null : $scopeId,
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        return $id;
    }

    /**
     * Every mapping for a binding.
     *
     * 🛑 **Not cached.** A group mapping decides who holds a dashboard role, so
     * a stale read is a stale privilege — and unlike §12.3's policy, there is
     * no epoch to key a cache on. This is read once per login, which is not a
     * hot path: §8.12.11's grant is what keeps the *serving* path free of
     * database work, and a login is already making several round trips to
     * somebody else's identity provider.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @return list<array{
     *     provider_group: string,
     *     target: string,
     *     target_value: string,
     *     scope_type: ?string,
     *     scope_id: ?string,
     *     binding_scope_type: string,
     * }>
     */
    public function forBinding(string $bindingId): array
    {
        $out = [];

        $rows = DB::table('provider_group_mappings')
            ->where('binding_id', $bindingId)
            ->orderBy('provider_group')
            ->get(['provider_group', 'target', 'target_value', 'scope_type', 'scope_id', 'binding_scope_type']);

        foreach ($rows as $row) {
            $out[] = [
                'provider_group' => (string) $row->provider_group,
                'target' => (string) $row->target,
                'target_value' => (string) $row->target_value,
                'scope_type' => is_string($row->scope_type) ? $row->scope_type : null,
                'scope_id' => is_string($row->scope_id) ? $row->scope_id : null,
                'binding_scope_type' => (string) $row->binding_scope_type,
            ];
        }

        return $out;
    }

    /** Remove one mapping. */
    public function remove(string $id): bool
    {
        return DB::table('provider_group_mappings')->where('id', $id)->delete() === 1;
    }

    /**
     * 🛑 The groups a token asserts, from the claim the binding names.
     *
     * The claim's name is configuration because providers disagree: Keycloak
     * sends `groups`, Entra sends `roles`, Okta sends whatever the
     * administrator called it. A constant here would work against one provider.
     *
     * Two shapes are accepted — a list of strings, and a single string — because
     * both occur in the wild, and a provider sending one group as a bare string
     * is not a provider DocUp should refuse. Anything else yields no groups,
     * which fails closed: a reader with no groups gets whatever a rule gives
     * readers with no groups.
     *
     * @param  array<string, mixed>  $claims
     * @return list<string>
     */
    public static function assertedGroups(array $claims, string $claimName): array
    {
        $value = $claims[$claimName] ?? null;

        if (is_string($value)) {
            return $value === '' ? [] : [$value];
        }

        if (! is_array($value)) {
            return [];
        }

        $groups = [];

        foreach ($value as $group) {
            if (is_string($group) && $group !== '' && ! in_array($group, $groups, true)) {
                /*
                 * 🛑 Capped in length as well as in count. A provider asserting
                 * a 10 KB group name is either broken or probing, and the
                 * column is 255 characters, so a longer name can never match a
                 * stored mapping anyway.
                 */
                if (mb_strlen($group) <= 255) {
                    $groups[] = $group;
                }
            }
        }

        return $groups;
    }
}
