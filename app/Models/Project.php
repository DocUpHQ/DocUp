<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\AccessLevel;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

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
    use HasUuidKey;
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
    ];

    /**
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'visibility' => AccessLevel::class,
            'inherit_organisation_roles' => 'boolean',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
            'deleted_at' => 'datetime:Y-m-d H:i:s.v',
        ];
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
