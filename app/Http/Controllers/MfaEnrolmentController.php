<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Auth\MfaEnforcement;
use App\Auth\Role;
use App\Http\Middleware\RequireMfaEnrolment;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * §8.13.4's enrolment page: where {@see RequireMfaEnrolment}
 * sends somebody who has to set up TOTP before they can carry on.
 *
 * 🛑 **This page enrols nobody.** Fortify's own endpoints do all of it —
 * `two-factor.enable`, `two-factor.confirm`, `two-factor.qr-code`,
 * `two-factor.recovery-codes` — and that is the whole reason Phase 02 chose
 * Fortify: the secret generation, the window tolerance, the recovery codes and
 * the challenge throttle are a security surface with known-good answers, and
 * this is a page that posts to them. A controller of our own that generated a
 * secret would be a second implementation of the part nobody should write
 * twice.
 *
 * 🛑 **It says *why* they are here**, naming the role. A page that said only
 * "two-factor authentication is required" sends a person to ask an
 * administrator why, and §8.13.4's requirement is per-role — so the answer is
 * knowable and worth printing. The alternative is a support conversation for
 * every person on the installation, once.
 */
final class MfaEnrolmentController
{
    public function __invoke(Request $request, MfaEnforcement $enforcement): Response|RedirectResponse
    {
        /** @var User $user */
        $user = $request->user();

        $required = $enforcement->isRequiredFor($user);

        /*
         * 🛑 Somebody already enrolled, or not obliged to be, is sent on rather
         * than shown a page about a problem they do not have. They can still
         * enrol voluntarily through the profile surface — §8.13.4 makes MFA
         * *enforceable*, never exclusive to the enforced.
         */
        if (! $required && MfaEnforcement::isEnrolled($user)) {
            return redirect()->route('projects.index');
        }

        return Inertia::render('Auth/TwoFactorEnrol', [
            'required' => $required,
            'enrolled' => MfaEnforcement::isEnrolled($user),
            /*
             * 🛑 The reason, in the operator's own vocabulary: §12.1's role
             * names. Only the roles that oblige enrolment are listed, because
             * listing them all would invite the reader to work out which one it
             * was — and they would guess `project_reader`.
             */
            'because' => array_values(array_map(
                static fn (Role $role): string => $role->value,
                array_filter(
                    $enforcement->rolesObliging($user),
                    static fn (Role $role): bool => $role->requiresMfa(),
                ),
            )),
            'installationWide' => MfaEnforcement::installationRequires(),
        ]);
    }
}
