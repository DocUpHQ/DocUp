<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Concerns;

use App\Auth\OrganisationContext;
use App\Models\Organisation;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Scope;

/**
 * The §8.2.1 global tenancy scope.
 *
 * Every model carrying `organisation_id` uses this, and the architecture test
 * in `tests/Arch/TenancyTest.php` fails CI for any model declared
 * `OrganisationScoped` that does not.
 *
 * 🛑 Two halves, and both matter:
 *
 * - **Reads** are filtered by a global scope, so a bare `Project::all()` can
 *   never return another tenant's rows.
 * - **Writes** have `organisation_id` filled in on create, so a row cannot be
 *   written into the wrong tenant by omission. A scope that only filtered reads
 *   would leave every insert path to remember, and §14's threat model is about
 *   the path somebody forgets.
 *
 * §8.2.2 requires cross-tenant access to return **404, never 403**, through the
 * UI, the API and direct identifier access alike. This scope is what delivers
 * that for free: a row outside the context is not visible, so route binding
 * finds nothing and the framework renders 404 without any code deciding to. A
 * 403 would confirm the row exists, which is itself the leak.
 *
 * @phpstan-require-extends Model
 */
trait BelongsToOrganisation
{
    public static function bootBelongsToOrganisation(): void
    {
        static::addGlobalScope(new class implements Scope
        {
            public function apply(Builder $builder, Model $model): void
            {
                $context = app(OrganisationContext::class);

                // An explicitly installation-wide unit of work is not filtered.
                // Undeclared throws inside require(), which is the point.
                if ($context->spansAllOrganisations()) {
                    return;
                }

                $builder->where(
                    $model->qualifyColumn('organisation_id'),
                    $context->require(),
                );
            }
        });

        // Fill the tenant on insert rather than trusting every call site.
        static::creating(function (Model $model): void {
            $context = app(OrganisationContext::class);

            if ($model->getAttribute('organisation_id') !== null) {
                return;
            }

            // Spanning all organisations is a legitimate read posture but never
            // a legitimate way to create a tenant-scoped row: there is no
            // tenant to put it in. require() throws, which is correct — the
            // caller must name one.
            $model->setAttribute('organisation_id', $context->require());
        });
    }

    /**
     * The owning organisation.
     *
     * @return BelongsTo<Organisation, $this>
     */
    public function organisation(): BelongsTo
    {
        /** @var BelongsTo<Organisation, $this> */
        return $this->belongsTo(Organisation::class);
    }
}
