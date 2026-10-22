<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Auth\Capability;
use App\Auth\RoleResolver;
use App\Models\Project;
use App\Models\User;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;

/**
 * Registers the §12.2 capability matrix with Laravel's authorisation layer.
 *
 * 🛑 §12.1: "Laravel `Gate` and policies are the only call site." Every
 * capability becomes a gate ability named by its own string, so a check reads
 * `$user->can('project.visibility.update', $project)` and there is exactly one
 * place that decides.
 *
 * Defined in a loop over the enum rather than written out, which is what makes
 * §12.2's "enumerable from code" true in both directions: a capability added to
 * the enum is immediately checkable, and one removed stops being checkable
 * rather than silently always-denying.
 */
final class AuthServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        $resolver = $this->app->make(RoleResolver::class);

        foreach (Capability::cases() as $capability) {
            Gate::define(
                $capability->value,
                /**
                 * @param  Project|string|null  $target  a project, an organisation id, or
                 *                                       null for an installation-level check
                 */
                static function (User $user, Project|string|null $target = null) use ($resolver, $capability): bool {
                    if ($target instanceof Project) {
                        return $resolver->allows($user, $capability, $target);
                    }

                    return $resolver->allows($user, $capability, null, $target);
                },
            );
        }

        /*
         * 🛑 No Gate::before() short-circuit for any role.
         *
         * The obvious convenience is `if ($user->isInstallationOwner()) return
         * true;` — and it would quietly break §8.13.2, which holds IdP
         * configuration and audit export away from the owner as a separation of
         * duty. A before-callback returning true for an owner grants exactly the
         * two capabilities the specification spent a requirement withholding,
         * and the capability matrix would still LOOK correct because the
         * omission is in Role::capabilities() while the grant happens here.
         *
         * Every check goes through the matrix. There are no exceptions, and this
         * comment exists so that adding one is a deliberate act.
         */
    }
}
