<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\AccessLevel;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;
use Illuminate\Support\Facades\DB;

/**
 * A documentation project (§8.2, §10.4).
 *
 * 🛑 `visibility` is the §8.2.10 kill switch, stored on the §12.3 lattice and
 * authoritative at decision time rather than being a listing flag. A project at
 * `members` serves nothing publicly however permissive a version or a
 * reader-policy rule is, which is why §12.3 evaluates it first.
 *
 * Reading this model is tenant-filtered by {@see BelongsToOrganisation}, which
 * is also what makes §8.2.2's "404, never 403" fall out for free: a project in
 * another organisation is not visible, so route binding finds nothing and the
 * framework renders 404 without any code choosing to.
 *
 * The property annotations are not decoration. Without them PHPStan infers
 * `visibility` from the `$attributes` defaults below and concludes it is a
 * string, so `$this->visibility === AccessLevel::Public` "always evaluates to
 * false" — it cannot see through the cast declared in casts(). The runtime
 * behaviour was correct; the analysis was not, and on a column §8.2.10 calls
 * the kill switch, an analyser that cannot reason about it is worth fixing.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $slug
 * @property string $name
 * @property string|null $description
 * @property AccessLevel $visibility
 * @property bool $inherit_organisation_roles
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
#[Fillable(['slug', 'name', 'description', 'visibility'])]
final class Project extends Model
{
    use BelongsToOrganisation;

    /*
     * 🛑 Aliased, because `parent::resolveRouteBinding()` does NOT reach the
     * trait.
     *
     * Trait methods are flattened into the using class, so `parent::` from here
     * resolves to Eloquent's Model, not to HasUuidKey — the UUID handling would
     * have been bypassed entirely and every identifier lookup would have fallen
     * through to the slug branch. Nothing would have crashed; direct identifier
     * access would simply have stopped working, which is exactly the silent
     * failure ADR 0006 is about. PHPStan level 9 caught it.
     */
    use HasUuidKey {
        resolveRouteBinding as resolveRouteBindingByUuid;
    }
    use SoftDeletes;

    /**
     * 🛑 Mirrors the column defaults, so a freshly created instance agrees with
     * the row that was just written.
     *
     * Without these the database applies its defaults but the in-memory model
     * holds null until something calls refresh(), so `$project->visibility`
     * right after create() is null rather than Restricted. Nothing would have
     * crashed — a null compares unequal to AccessLevel::Public, so the failure
     * leans safe — but code reading its own freshly created project would have
     * seen a visibility the row does not have, and §8.2.10 makes this column
     * the kill switch. A kill switch that reads null is one nobody can reason
     * about.
     *
     * @var array<string, mixed>
     */
    protected $attributes = [
        'visibility' => 'restricted',
        'inherit_organisation_roles' => true,

        // 🛑 §8.5.10: "Fork-PR builds MUST be off by default."
        'fork_builds_enabled' => false,
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'visibility' => AccessLevel::class,
            'inherit_organisation_roles' => 'boolean',
            'fork_builds_enabled' => 'boolean',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * Resolve a route parameter by slug **or** by UUID.
     *
     * 🛑 §8.2.2 names "the UI, the API **and** direct identifier access" as
     * three routes that must all answer 404. Accepting both forms on one route
     * is what makes that testable with one endpoint rather than three — and it
     * is safe for the same reason the whole requirement works: resolution runs
     * through the §8.2.1 global scope, so neither form can reach outside the
     * declared tenant. Knowing the key does not help.
     *
     * Order matters only for clarity: a slug can never look like a UUID, so the
     * two namespaces cannot collide.
     *
     * @param  mixed  $field  `mixed` for contravariance with UrlRoutable
     */
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        if (! is_string($value) || $value === '') {
            return null;
        }

        // Try the identifier form first; HasUuidKey returns null rather than
        // throwing for anything that is not a UUID, which is what keeps an
        // invalid key a 404 instead of a 500 (ADR 0006).
        $byUuid = $this->resolveRouteBindingByUuid($value, $field);

        if ($byUuid !== null) {
            return $byUuid;
        }

        return self::query()->where('slug', $value)->first();
    }

    /**
     * Set the §8.2.9 organisation-role inheritance flag, auditing the change.
     *
     * 🛑 Deliberately a method and deliberately NOT in `$fillable`. §8.2.9
     * calls this "a single audited flag" and "the only escape from additive
     * inheritance" — the one switch that removes an organisation's
     * administrators from a project. Mass-assignable, it would be flippable by
     * any request that happened to forward an unexpected field, and the audit
     * event §8.2.9 requires would depend on whoever wrote the controller
     * remembering.
     *
     * §8.22.4 puts the mutation and its audit row in one transaction, so a
     * flipped flag with no record, or a record with no flip, cannot happen.
     *
     * @param  string|null  $actorId  raw 16 bytes, or null when the system did it
     */
    public function setOrganisationRoleInheritance(bool $inherits, ?string $actorId = null): void
    {
        $was = (bool) $this->inherit_organisation_roles;

        if ($was === $inherits) {
            return;
        }

        DB::transaction(function () use ($inherits, $was, $actorId): void {
            $this->inherit_organisation_roles = $inherits;
            $this->save();

            Audit::record(
                action: 'project.role_inheritance.changed',
                actorType: $actorId === null ? ActorType::System : ActorType::User,
                organisationId: $this->organisation_id,
                actorId: $actorId,
                subjectType: 'project',
                subjectId: $this->id,
                // Identifiers and booleans only (§8.22.5).
                payload: ['from' => $was, 'to' => $inherits],
            );
        });
    }

    /**
     * Whether this project is readable without any credential.
     *
     * 🛑 A convenience for presentation only. It is NOT an access decision:
     * §4.3/7 and §12.3 require every reader access decision to go through the
     * single `EffectiveAccess` function, which also weighs reader policy,
     * version visibility, mount exposure and component access. A project being
     * `public` is necessary for public reading and nowhere near sufficient.
     */
    public function isPubliclyVisible(): bool
    {
        return $this->visibility === AccessLevel::Public;
    }
}
