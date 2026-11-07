<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\RoleResolver;
use App\Credentials\EnvelopeCipher;
use App\Credentials\SealedSecret;
use App\Models\Project;
use App\Support\Uuid;
use App\Tls\CertificateStore;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * §8.12.3's binding resolution: the only class that reads or writes
 * `auth_provider_bindings`.
 *
 * > "Bindings MUST be scoped at installation, organisation or project level
 * > with **most-specific-of-type** resolution, so one installation Okta binding
 * > serves 200 projects while project 201 brings its own Entra tenant."
 *
 * ## 🛑 "Most specific **of type**", which is not "most specific"
 *
 * The three words carry the whole design. Resolution is per **driver type**, so
 * a project that configures its own `password` binding keeps the installation's
 * `oidc` one — it does not shadow it. Plain most-specific-wins would mean
 * configuring anything at project scope silently removed everything the
 * installation offered, and the first reader to notice would be one who could
 * no longer sign in.
 *
 * So the resolved set is: for each type, the project's if it has one, else the
 * organisation's, else the installation's.
 *
 * ## 🛑 Secrets are opened per binding and never cached
 *
 * The resolved **set** is cached on the project's authz epoch, because it is a
 * query on the hot path. The opened secrets are not: §8.12.2's "envelope-
 * encrypted secrets no API or UI ever returns" is a statement about where the
 * plaintext may exist, and a cache is a place it must not. So the cache holds
 * rows and {@see self::contextFor()} opens on demand.
 */
final readonly class Bindings
{
    public function __construct(private EnvelopeCipher $cipher) {}

    /**
     * 🛑 Every binding that bears on a project, most specific of each type.
     *
     * Cached on the project's `authz_epoch`, which §10.8 bumps on a "policy,
     * rule, **binding**, visibility change" — so a binding edit takes effect on
     * the next request with no purge, exactly as a policy edit does. The epoch
     * is in the key, so a bump addresses a key that has never been written and
     * there is no stale entry to read.
     *
     * 🛑 `DB::table`, not Eloquent: the serving path declares no tenant context
     * and an installation-scoped binding has a NULL `organisation_id`, which
     * §8.2.1's global scope would filter away — the same reason
     * {@see RoleResolver} queries `role_assignments` directly.
     *
     * @param  string  $projectId  raw 16 bytes
     * @param  string|null  $organisationId  raw 16 bytes
     * @return list<array<string, mixed>> the resolved rows, one per type
     */
    public function forProject(string $projectId, ?string $organisationId, int $authzEpoch): array
    {
        $key = 'authz:bindings:'.bin2hex($projectId).':'.$authzEpoch;

        /** @var list<array<string, mixed>> $rows */
        $rows = Cache::remember($key, 300, function () use ($projectId, $organisationId): array {
            $candidates = DB::table('auth_provider_bindings')
                ->where(function ($query) use ($projectId, $organisationId): void {
                    $query->where(function ($q): void {
                        $q->where('scope_type', 'installation');
                    })->orWhere(function ($q) use ($projectId): void {
                        $q->where('scope_type', 'project')->where('scope_id', $projectId);
                    });

                    if ($organisationId !== null) {
                        $query->orWhere(function ($q) use ($organisationId): void {
                            $q->where('scope_type', 'organisation')->where('scope_id', $organisationId);
                        });
                    }
                })
                ->get([
                    'id', 'scope_type', 'scope_id', 'organisation_id', 'realm', 'type', 'name',
                    'config', 'config_version', 'shareable', 'state', 'epoch',
                    'envelope_version', 'kek_fingerprint', 'wrapped_key', 'ciphertext',
                ]);

            /*
             * 🛑 Most specific **of type**, decided by a rank rather than by an
             * ordered query — so the rule is readable here and does not depend
             * on a `CASE` expression in SQL that a future index change could
             * reorder.
             */
            $rank = ['installation' => 0, 'organisation' => 1, 'project' => 2];
            $best = [];

            foreach ($candidates as $row) {
                $type = (string) $row->type;
                $scope = (string) $row->scope_type;
                $weight = $rank[$scope] ?? -1;

                if ($weight < 0) {
                    /*
                     * A scope this code has not been taught. Skipped rather
                     * than ranked, because an unranked scope that sorted first
                     * would silently become the most specific.
                     */
                    continue;
                }

                $existing = $best[$type] ?? null;

                if ($existing === null || $weight > $existing['weight']) {
                    $best[$type] = ['weight' => $weight, 'row' => (array) $row];
                }
            }

            return array_values(array_map(
                static fn (array $entry): array => $entry['row'],
                $best,
            ));
        });

        return $rows;
    }

    /**
     * One resolved row as a driver sees it, with its secrets opened.
     *
     * 🛑 **Opened here and nowhere else**, and a failure to open is a
     * **degraded** binding rather than an exception.
     *
     * The direction is §8.12.19's: a binding whose envelope will not open —
     * `APP_KEY` rotated without `APP_PREVIOUS_KEYS`, a restored database
     * without its key — cannot authenticate anybody, and the choice is between
     * denying with a 503 that names the binding and crashing the request. A
     * crash is a 500 with no explanation on every page of a project; a
     * degraded binding is §8.12.19's own answer, with a health page.
     *
     * @param  array<string, mixed>  $row
     */
    public function contextFor(array $row): BindingContext
    {
        $id = is_string($row['id'] ?? null) ? $row['id'] : '';
        $type = is_string($row['type'] ?? null) ? $row['type'] : '';
        $state = BindingState::tryFrom(is_string($row['state'] ?? null) ? $row['state'] : '')
            /*
             * 🛑 An unrecognised state is `disabled`, the safest of the five: a
             * column value this code has not been taught must authenticate
             * nobody, and `degraded` would raise an operator alert for a row
             * that may simply be from a future version.
             */
            ?? BindingState::Disabled;

        $config = [];

        if (is_string($row['config'] ?? null)) {
            $decoded = json_decode((string) $row['config'], true, 8);
            $config = is_array($decoded) ? $decoded : [];
        }

        $secrets = [];

        if (is_string($row['ciphertext'] ?? null) && $row['ciphertext'] !== '') {
            try {
                $secrets = $this->cipher->open(
                    new SealedSecret(
                        is_numeric($row['envelope_version'] ?? null) ? (int) $row['envelope_version'] : 0,
                        is_string($row['kek_fingerprint'] ?? null) ? $row['kek_fingerprint'] : '',
                        is_string($row['wrapped_key'] ?? null) ? $row['wrapped_key'] : '',
                        (string) $row['ciphertext'],
                    ),
                    self::aad($id),
                );
            } catch (\Throwable) {
                /*
                 * 🛑 Degraded, not thrown. See the method note: §8.12.19 has an
                 * answer for a provider that cannot currently work, and it is a
                 * 503 naming the binding rather than a 500 naming nothing.
                 */
                $state = BindingState::Degraded;
                $secrets = [];
            }
        }

        return new BindingContext(
            id: $id,
            type: $type,
            name: is_string($row['name'] ?? null) ? $row['name'] : '',
            config: $config,
            secrets: $secrets,
            state: $state,
            shareable: (bool) ($row['shareable'] ?? false),
            projectId: ($row['scope_type'] ?? null) === 'project' && is_string($row['scope_id'] ?? null)
                ? $row['scope_id']
                : null,
            organisationId: is_string($row['organisation_id'] ?? null) ? $row['organisation_id'] : null,
            epoch: is_numeric($row['epoch'] ?? null) ? (int) $row['epoch'] : 0,
        );
    }

    /**
     * Create a binding, in `draft`.
     *
     * 🛑 §8.12.19's default, and the reason it is not a parameter: a binding
     * that could be created `active` would be a binding created without the
     * probe and the test login the requirement demands. The only way to
     * `active` is through {@see self::transition()}, which checks both.
     *
     * @param  array<string, mixed>  $config  non-secret
     * @param  array<string, string>  $secrets  sealed before storage; never
     *                                          returned by anything afterwards
     * @param  'installation'|'organisation'|'project'  $scopeType
     *
     * @throws BindingRefused
     */
    public function create(
        string $scopeType,
        ?string $scopeId,
        string $type,
        string $name,
        array $config = [],
        array $secrets = [],
        ?string $organisationId = null,
        bool $shareable = false,
        ?string $actorId = null,
    ): string {
        /*
         * 🛑 §8.12.4's two gates — the driver's own capability and the
         * installation's restriction — before anything is written.
         */
        $driver = DriverRegistry::permittedAt($type, $scopeType);

        $normalised = $driver->validate($config);

        $id = Uuid::toBytes(Uuid::v7());

        $row = [
            'id' => $id,
            'organisation_id' => $organisationId,
            'scope_type' => $scopeType,
            'scope_id' => $scopeId,
            'type' => $type,
            'name' => mb_substr($name, 0, 120),
            'config' => (string) json_encode($normalised),
            'config_version' => 1,
            'shareable' => $shareable,
            'state' => BindingState::Draft->value,
            'epoch' => 1,
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ];

        if ($secrets !== []) {
            $sealed = $this->cipher->seal($secrets, self::aad($id));

            $row['envelope_version'] = $sealed->version;
            $row['kek_fingerprint'] = $sealed->kekFingerprint;
            $row['wrapped_key'] = $sealed->wrappedKey;
            $row['ciphertext'] = $sealed->ciphertext;
        }

        DB::table('auth_provider_bindings')->insert($row);

        Audit::record(
            action: 'authz.binding.created',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'auth_provider_binding',
            subjectId: $id,
            /*
             * 🛑 §8.22.5: identifiers and fixed vocabulary. The config is not
             * here — a client id is non-secret but it is still somebody's
             * tenant identifier, and the audit chain is not the place to copy
             * a configuration into.
             */
            payload: ['type' => $type, 'scope' => $scopeType, 'state' => BindingState::Draft->value],
        );

        return $id;
    }

    /**
     * 🛑 §8.12.19's progression, enforced.
     *
     * Three refusals, each with its own reason code and each one an operator
     * would otherwise reach for:
     *
     * - a transition the state machine does not allow
     *   ({@see BindingState::mayTransitionTo()});
     * - `verifying → active` **without a passed probe**;
     * - `verifying → active` **without a human test login**.
     *
     * The last two are the requirement's "and": "MUST NOT leave `verifying`
     * until an automated probe passes **and** a human completes a test login".
     *
     * @throws BindingRefused
     */
    public function transition(
        string $bindingId,
        BindingState $next,
        ?string $actorId = null,
        ?string $cause = null,
    ): void {
        $row = DB::table('auth_provider_bindings')
            ->where('id', $bindingId)
            ->first(['organisation_id', 'state', 'probe', 'verified_by', 'verified_at', 'type']);

        if ($row === null) {
            throw BindingRefused::of(BindingRejection::UnknownDriver, 'no such binding');
        }

        $current = BindingState::tryFrom((string) $row->state) ?? BindingState::Disabled;

        if (! $current->mayTransitionTo($next)) {
            throw BindingRefused::of(
                BindingRejection::TransitionNotPermitted,
                $current->value.' → '.$next->value.' is not a permitted transition (§8.12.19)',
            );
        }

        if ($next === BindingState::Active) {
            $probe = is_string($row->probe) ? json_decode((string) $row->probe, true, 8) : null;

            if (! is_array($probe) || ($probe['passed'] ?? false) !== true) {
                throw BindingRefused::of(
                    BindingRejection::TransitionNotPermitted,
                    'a binding may not become active until its probe passes (§8.12.19)',
                );
            }

            if ($row->verified_by === null || $row->verified_at === null) {
                throw BindingRefused::of(
                    BindingRejection::TransitionNotPermitted,
                    'a binding may not become active until a human completes a test login (§8.12.19)',
                );
            }
        }

        DB::table('auth_provider_bindings')->where('id', $bindingId)->update([
            'state' => $next->value,
            /*
             * 🛑 Entering `active` clears the failure counter, so the five
             * failures that degraded a binding last month do not degrade it
             * again on its first blip this month.
             */
            'probe_failures' => $next === BindingState::Active ? 0 : DB::raw('`probe_failures`'),
            'epoch' => DB::raw('`epoch` + 1'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        Audit::record(
            action: 'authz.binding.state_changed',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: is_string($row->organisation_id) ? $row->organisation_id : null,
            actorId: $actorId,
            subjectType: 'auth_provider_binding',
            subjectId: $bindingId,
            payload: [
                'from' => $current->value,
                'to' => $next->value,
                'cause' => $cause ?? 'operator',
            ],
        );
    }

    /**
     * 🛑 §8.12.19's human half: record that somebody completed a test login.
     *
     * Its own method, and it takes a `User`'s id rather than a boolean, because
     * "who said this provider works" is the question an incident asks and a
     * boolean cannot answer.
     */
    public function recordTestLogin(string $bindingId, string $userId): void
    {
        DB::table('auth_provider_bindings')->where('id', $bindingId)->update([
            'verified_by' => $userId,
            'verified_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        Audit::record(
            action: 'authz.binding.test_login',
            actorType: ActorType::User,
            actorId: $userId,
            subjectType: 'auth_provider_binding',
            subjectId: $bindingId,
            payload: ['result' => 'passed'],
        );
    }

    /**
     * Run a binding's probe and record the verdict.
     *
     * 🛑 **Consecutive** failures degrade it, and the counter resets on a pass.
     * One failed probe is a network and {@see BindingState::DEGRADE_AFTER_FAILURES}
     * is a provider — degrading on the first would make every transient DNS
     * blip take a project's documentation offline with a 503, which is the
     * behaviour operators disable a feature to escape.
     */
    public function probe(string $bindingId): ProbeResult
    {
        $row = DB::table('auth_provider_bindings')
            ->where('id', $bindingId)
            ->first([
                'id', 'scope_type', 'scope_id', 'organisation_id', 'type', 'name',
                'config', 'shareable', 'state', 'epoch',
                'envelope_version', 'kek_fingerprint', 'wrapped_key', 'ciphertext',
            ]);

        if ($row === null) {
            return ProbeResult::fail('no such binding');
        }

        $driver = DriverRegistry::for((string) $row->type);

        if ($driver === null) {
            return ProbeResult::fail('no driver is registered for type "'.$row->type.'"');
        }

        $context = $this->contextFor((array) $row);
        $result = $driver->probe($context);

        $state = BindingState::tryFrom((string) $row->state) ?? BindingState::Disabled;

        $failures = $result->passed
            ? 0
            : (int) DB::table('auth_provider_bindings')->where('id', $bindingId)->value('probe_failures') + 1;

        DB::table('auth_provider_bindings')->where('id', $bindingId)->update([
            'probe' => (string) json_encode($result->toArray()),
            'probe_failures' => $failures,
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        /*
         * 🛑 The two automatic transitions, and they are the only two.
         *
         * `active → degraded` on repeated failure, and `degraded → verifying`
         * on a pass. Note what the second is **not**: it is not
         * `degraded → active`. §8.12.19 requires a human test login to reach
         * `active`, and a provider that recovered has unproven configuration
         * again — the probe says the installation can reach it, not that a
         * person can get in.
         */
        if ($state === BindingState::Active && ! $result->passed && $failures >= BindingState::DEGRADE_AFTER_FAILURES) {
            $this->forceState($bindingId, BindingState::Degraded, 'probe_failed');
        }

        if ($state === BindingState::Degraded && $result->passed) {
            $this->forceState($bindingId, BindingState::Verifying, 'probe_recovered');
        }

        return $result;
    }

    /**
     * Delete a binding, refusing if anything references it.
     *
     * 🛑 §8.12.19: "A referenced binding MUST NOT be deletable." The database
     * refuses it too — `reader_credentials.binding_id` and
     * `reader_identities.binding_id` are both `RESTRICT` — and this is the half
     * that gives the operator a sentence instead of a constraint violation.
     *
     * @throws BindingRefused
     */
    public function delete(string $bindingId, ?string $actorId = null): void
    {
        $credentials = DB::table('reader_credentials')->where('binding_id', $bindingId)->count();
        $identities = DB::table('reader_identities')->where('binding_id', $bindingId)->count();

        if ($credentials > 0 || $identities > 0) {
            throw BindingRefused::of(
                BindingRejection::StillReferenced,
                'this binding has '.$credentials.' credential(s) and '.$identities
                .' identity(ies); revoke them first (§8.12.19)',
            );
        }

        $organisationId = DB::table('auth_provider_bindings')
            ->where('id', $bindingId)
            ->value('organisation_id');

        DB::table('auth_provider_bindings')->where('id', $bindingId)->delete();

        Audit::record(
            action: 'authz.binding.deleted',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: is_string($organisationId) ? $organisationId : null,
            actorId: $actorId,
            subjectType: 'auth_provider_binding',
            subjectId: $bindingId,
            payload: ['result' => 'deleted'],
        );
    }

    /**
     * Seal a binding's secrets, replacing whatever was there.
     *
     * 🛑 Bumps `config_version` and `epoch`, so a cached resolution and a
     * cached driver instance are both addressed differently on the next
     * request — no purge, the mechanism §10.8 uses throughout.
     *
     * @param  array<string, string>  $secrets
     */
    public function setSecrets(string $bindingId, array $secrets, ?string $actorId = null): void
    {
        $sealed = $this->cipher->seal($secrets, self::aad($bindingId));

        DB::table('auth_provider_bindings')->where('id', $bindingId)->update([
            'envelope_version' => $sealed->version,
            'kek_fingerprint' => $sealed->kekFingerprint,
            'wrapped_key' => $sealed->wrappedKey,
            'ciphertext' => $sealed->ciphertext,
            'config_version' => DB::raw('`config_version` + 1'),
            'epoch' => DB::raw('`epoch` + 1'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        Audit::record(
            action: 'authz.binding.secrets_set',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            actorId: $actorId,
            subjectType: 'auth_provider_binding',
            subjectId: $bindingId,
            /*
             * 🛑 The **keys** only, never a value. An operator needs to know
             * which secrets a binding holds; nobody needs the chain to hold
             * one.
             */
            payload: ['keys' => implode(',', array_keys($secrets))],
        );
    }

    /** A state change the state machine did not authorise, for the two automatic ones. */
    private function forceState(string $bindingId, BindingState $next, string $cause): void
    {
        DB::table('auth_provider_bindings')->where('id', $bindingId)->update([
            'state' => $next->value,
            'epoch' => DB::raw('`epoch` + 1'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        Audit::record(
            action: 'authz.binding.state_changed',
            actorType: ActorType::System,
            subjectType: 'auth_provider_binding',
            subjectId: $bindingId,
            payload: ['to' => $next->value, 'cause' => $cause],
        );
    }

    /**
     * 🛑 The envelope's additional authenticated data, binding a ciphertext to
     * its row.
     *
     * The argument {@see CertificateStore::aad()} makes: without it, a
     * ciphertext moved between two rows opens cleanly, and a binding would
     * authenticate readers with another binding's secret — with every row in
     * the database looking correct.
     */
    public static function aad(string $bindingId): string
    {
        return 'auth_provider_binding|'.bin2hex($bindingId);
    }

    /**
     * Every binding in scope for a project, as driver contexts.
     *
     * The one method the serving path calls.
     *
     * @return list<BindingContext>
     */
    public function contextsFor(Project|string $project, ?string $organisationId = null, int $authzEpoch = 0): array
    {
        $projectId = $project instanceof Project ? $project->id : $project;
        $organisationId ??= $project instanceof Project ? $project->organisation_id : null;

        return array_map(
            fn (array $row): BindingContext => $this->contextFor($row),
            $this->forProject($projectId, $organisationId, $authzEpoch),
        );
    }
}
