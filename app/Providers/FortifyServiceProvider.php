<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Actions\Fortify\ResetUserPassword;
use App\Actions\Fortify\UpdateUserPassword;
use App\Actions\Fortify\UpdateUserProfileInformation;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use Inertia\Inertia;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\Fortify;

/**
 * Wires Fortify to DocUp's Inertia front end (§8.13.3–§8.13.5).
 *
 * 🛑 **Fortify owns `/login` and `/user/confirm-password`, not routes/web.php.**
 *
 * Phase 01 registered its own `/login`, and Fortify registers one too. Both
 * were live at once, both named `login`, so `route('login')` resolved to
 * whichever was registered last — and the §8.13.3 and §8.13.5 middleware both
 * redirect by name. The same collision existed on `password.confirm`, which
 * step-up redirects to. Duplicate route names do not error in Laravel; they
 * just make the destination a matter of registration order, which is the worst
 * kind of bug to have in an authentication path.
 *
 * So the routes are Fortify's and the *views* are ours, supplied through the
 * callbacks below. Fortify keeps the POST handlers — the password check, the
 * throttling, the two-factor challenge — which is the entire reason for using
 * it rather than hand-rolling §8.13.5.
 */
final class FortifyServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        /*
         * No createUsersUsing(): registration is disabled in config/fortify.php
         * because §8.2.4 makes invitations the way people join a self-hosted
         * installation. Registering a handler for a feature that is off would
         * suggest the route exists.
         */
        Fortify::updateUserProfileInformationUsing(UpdateUserProfileInformation::class);
        Fortify::updateUserPasswordsUsing(UpdateUserPassword::class);
        Fortify::resetUserPasswordsUsing(ResetUserPassword::class);
        Fortify::redirectUserForTwoFactorAuthenticationUsing(RedirectIfTwoFactorAuthenticatable::class);

        $this->registerViews();
        $this->registerRateLimiters();
    }

    /**
     * Inertia responses for Fortify's GET routes.
     *
     * Fortify defaults to `view('auth.login')`, which this application does not
     * have — it is Inertia, not Blade. Without these callbacks every
     * authentication page would 500 on a missing view, and the first time
     * anyone noticed would be a locked-out operator.
     */
    private function registerViews(): void
    {
        Fortify::loginView(fn () => Inertia::render('Auth/Login', [
            'installationName' => config('app.name', 'DocUp'),
            'locale' => app()->getLocale(),
            // §9.5.2: every user-visible string comes from a message file.
            't' => __('auth.login'),
        ]));

        // §8.13.5 step-up lands here.
        Fortify::confirmPasswordView(fn () => Inertia::render('Auth/ConfirmPassword', [
            'installationName' => config('app.name', 'DocUp'),
            't' => __('auth.confirm'),
        ]));

        // §8.13.4: the TOTP challenge after a correct password.
        Fortify::twoFactorChallengeView(fn () => Inertia::render('Auth/TwoFactorChallenge', [
            'installationName' => config('app.name', 'DocUp'),
            't' => __('auth.two_factor'),
        ]));

        Fortify::requestPasswordResetLinkView(fn () => Inertia::render('Auth/ForgotPassword', [
            'installationName' => config('app.name', 'DocUp'),
            't' => __('auth.forgot'),
        ]));

        Fortify::resetPasswordView(fn (Request $request) => Inertia::render('Auth/ResetPassword', [
            'installationName' => config('app.name', 'DocUp'),
            't' => __('auth.reset'),
            'token' => $request->route('token'),
            'email' => $request->string('email')->toString(),
        ]));
    }

    private function registerRateLimiters(): void
    {
        /*
         * 🛑 Keyed on the submitted username AND the IP, not on one or the
         * other. Keyed on IP alone, one office behind a single address locks
         * itself out; keyed on username alone, an attacker locks a known
         * account out at will, which turns a brute-force defence into a
         * denial-of-service tool pointed at whoever they choose.
         */
        RateLimiter::for('login', function (Request $request): Limit {
            $throttleKey = Str::transliterate(
                Str::lower((string) $request->input(Fortify::username())).'|'.$request->ip()
            );

            return Limit::perMinute(5)->by($throttleKey);
        });

        /*
         * The two-factor challenge is keyed on the pending login id, which
         * exists only in the session between a correct password and a correct
         * code. Six-digit codes are brute-forceable in a way passwords are not
         * — 5 attempts a minute against a million possibilities is the whole
         * defence.
         */
        RateLimiter::for('two-factor', function (Request $request): Limit {
            return Limit::perMinute(5)->by((string) $request->session()->get('login.id'));
        });

        /*
         * Passkeys are disabled pending §18 (see config/fortify.php), but the
         * limiter is registered anyway: Fortify resolves it when the feature is
         * enabled, and a missing limiter then fails at the first attempt rather
         * than at configuration time. Cheap insurance against enabling the
         * feature and discovering the gap in production.
         */
        RateLimiter::for('passkeys', function (Request $request): Limit {
            $credentialId = $request->input('credential.id');

            return Limit::perMinute(10)->by(
                (is_string($credentialId) && $credentialId !== '' ? $credentialId : $request->session()->getId())
                .'|'.$request->ip()
            );
        });
    }
}
