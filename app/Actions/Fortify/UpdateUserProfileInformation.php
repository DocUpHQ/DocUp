<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Actions\Fortify;

use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;
use Laravel\Fortify\Contracts\UpdatesUserProfileInformation;

final class UpdateUserProfileInformation implements UpdatesUserProfileInformation
{
    /**
     * Validate and update the given user's profile information.
     *
     * @param  array<string, string>  $input
     *
     * @throws ValidationException
     */
    public function update(User $user, array $input): void
    {
        Validator::make($input, [
            'name' => ['required', 'string', 'max:255'],

            'email' => [
                'required',
                'string',
                'email',
                'max:255',
                Rule::unique('users')->ignore($user->id),
            ],
        ])->validateWithBag('updateProfileInformation');

        /*
         * 🛑 The published stub branched on `$user instanceof MustVerifyEmail`
         * and called updateVerifiedUser(). DocUp's User does NOT implement that
         * contract, because email verification is deliberately disabled in
         * config/fortify.php — Phase 02 has no mail templates (§8.18), and
         * enabling verification would hold every invited member at an
         * unsendable email.
         *
         * PHPStan reported the condition as always false. The branch is removed
         * rather than suppressed: dead code in an identity path is code someone
         * will later read as a safeguard that is running.
         */
        $user->forceFill([
            'name' => $input['name'],
            'email' => $input['email'],
        ])->save();
    }

    // 🛑 updateVerifiedUser() removed. It was only reachable from the
    // MustVerifyEmail branch above, which can never be true here, and it called
    // sendEmailVerificationNotification() — a notification Phase 02 has no
    // template for (§8.18). Left in place it would have been read as "changing
    // your email re-verifies it", which is not what this installation does.
}
