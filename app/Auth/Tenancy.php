<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use Attribute;

/**
 * Declares a model's tenancy posture (§8.2.1).
 *
 * An attribute rather than an interface or a static method, for two reasons
 * that matter to the architecture test in `tests/Arch/TenancyTest.php`:
 *
 * - It is readable by reflection **without instantiating the model**, so the
 *   test needs no database and no container.
 * - It cannot be inherited by accident. A posture declared on a parent class
 *   would silently apply to a subclass whose table is completely different,
 *   and `Attribute::IS_REPEATABLE` is deliberately not set so each model states
 *   its own.
 *
 * Usage:
 *
 *     #[Tenancy(TenancyPosture::OrganisationScoped)]
 *     final class Project extends Model { ... }
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class Tenancy
{
    public function __construct(
        public TenancyPosture $posture,

        /**
         * Why, when the posture is not the obvious one.
         *
         * 🛑 Required by the architecture test for anything other than
         * `OrganisationScoped`. A model that opts out of tenancy filtering is
         * either correct or a cross-tenant leak, and the difference is entirely
         * in the author's reasoning — so the reasoning is mandatory and travels
         * with the code rather than living in a commit message nobody will find.
         */
        public ?string $because = null,
    ) {}
}
