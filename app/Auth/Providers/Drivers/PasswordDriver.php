<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;
use App\Auth\Providers\ReaderThrottle;
use Illuminate\Support\Facades\Hash;

/**
 * §8.12.17's `password`: one shared password for everybody a binding admits.
 *
 * > §8.12.16: "password (Argon2id `m=19456,t=2,p=1` — 🛑 Laravel's
 * > `ArgonHasher` default of `m=1024` is roughly 19× below the OWASP floor and
 * > MUST be overridden)"
 *
 * 🛑 **One password per binding, not per reader.** That is a deliberate
 * narrowing, not a simplification: a per-reader password is an account system,
 * and §4.2 excludes reader account management. What this driver is for is the
 * common case an IdP is overkill for — a client portal whose password is in the
 * engagement email.
 *
 * ## 🛑 The subject problem, and what it costs
 *
 * Everybody who knows the password is the same reader, so there is no identity
 * to log. §20.3 aggregates an allow "per session, version and hour" keyed on a
 * subject, and this driver's subject is the **binding**, not the person — so
 * two readers behind one password share one row.
 *
 * That is honest rather than ideal, and it is why §8.12.17 still classifies this
 * as identity-bearing: §8.12.7's invariant asks whether a requirement can be
 * satisfied *without presenting a credential*, and this one cannot. It does not
 * ask whether the credential identifies a person.
 */
final readonly class PasswordDriver implements AuthComponent
{
    public function __construct(private ReaderThrottle $throttle) {}

    public static function type(): string
    {
        return 'password';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    public static function allowsProjectScope(): bool
    {
        return true;
    }

    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /** @param  array<string, mixed>  $config */
    public function validate(array $config): array
    {
        $hint = $config['hint'] ?? null;

        /*
         * 🛑 A hint is the only configuration, and it is optional. It is shown
         * on the credential page — "the password is in your onboarding email" —
         * and is therefore `content` rather than a secret.
         *
         * 🛑 There is no `min_length` or `complexity` key, deliberately. The
         * operator chooses the password and the Argon2 floor is what protects
         * it; a complexity rule here would be theatre on a secret that is
         * typed once into a form and then pasted into an email.
         */
        return $hint === null ? [] : ['hint' => mb_substr((string) $hint, 0, 200)];
    }

    public function probe(BindingContext $binding): ProbeResult
    {
        $hash = $binding->secret('password_hash');

        if ($hash === null || $hash === '') {
            /*
             * 🛑 §8.12.19 exists for exactly this: a `password` binding with
             * nothing sealed denies everybody, and without a probe the operator
             * discovers it from a reader. "Could this provider work" is a
             * question a driver with no provider can still answer.
             */
            return ProbeResult::fail('no password is set, so this binding would deny everybody');
        }

        /*
         * 🛑 Verify the stored hash is at or above §8.12.16's floor — not just
         * that the *configuration* is, which is what `docup:doctor` checks.
         *
         * The difference matters: a hash written before an operator raised
         * `ARGON_MEMORY` is still below the floor, and `doctor` would report a
         * healthy configuration over it. `needsRehash()` is what notices.
         */
        if (! str_starts_with($hash, '$argon2id$')) {
            return ProbeResult::fail('the stored password hash is not Argon2id');
        }

        try {
            if (Hash::needsRehash($hash)) {
                return ProbeResult::fail(
                    'the stored password hash is below the configured Argon2id parameters; '
                    .'re-enter the password to rehash it',
                    ['hash_algorithm' => 'argon2id'],
                );
            }
        } catch (\Throwable) {
            return ProbeResult::fail('the stored password hash could not be inspected');
        }

        return ProbeResult::pass('an Argon2id password is set at the configured parameters');
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $submitted = $presented->password;

        if ($submitted === null || $submitted === '') {
            /* No password typed: the ordinary state of a first visit. */
            return AttemptResult::unsatisfied();
        }

        $hash = $binding->secret('password_hash');

        if ($hash === null || $hash === '') {
            /*
             * 🛑 A credential **was** presented, so this is a rejection rather
             * than an absence — the reader typed something and it did not work,
             * and §8.12.23's case (a) lets them be challenged again. That the
             * cause is the operator's missing configuration is the probe's
             * business, not the response's.
             */
            return AttemptResult::rejected();
        }

        /*
         * 🛑 §8.12.16's lockout, checked **before** the comparison so a
         * locked-out client's guess is never compared at all. Checking after
         * would leak through timing the very thing the lockout protects.
         */
        $key = 'binding:'.bin2hex($binding->id);

        if (! $this->throttle->permits($key, $presented->remoteAddress)) {
            return AttemptResult::rejected();
        }

        /*
         * 🛑 `Hash::check`, which is `password_verify`, which is
         * constant-time over the digest. §8.12.16's "timing-safe comparison"
         * is satisfied by the primitive rather than by a wrapper — and writing
         * `hash_equals(Hash::make($submitted), $hash)` instead would be
         * *wrong*, because Argon2 salts every hash and two hashes of one
         * password never match.
         */
        if (! Hash::check($submitted, $hash)) {
            $this->throttle->fail($key, $presented->remoteAddress);

            return AttemptResult::rejected();
        }

        $this->throttle->succeed($key, $presented->remoteAddress);

        /*
         * 🛑 The subject is the **binding**, not the person. See the class
         * note: everybody who knows the password is one reader, and inventing
         * a per-request subject would make §20.3's aggregation count visits
         * instead of readers while implying it knew who they were.
         */
        return AttemptResult::satisfiedBy(
            AccessLeaf::Binding,
            subject: 'password:'.bin2hex($binding->id),
        );
    }

    /**
     * 🛑 §8.12.16's floor, as the constants a test asserts.
     *
     * Here rather than only in `config/hashing.php` so that the *requirement's*
     * numbers are in the code that depends on them: §9.4 asks for a test on
     * every 🛑 requirement, and a test reading the config would assert the
     * config against itself.
     *
     * @return array{memory: int, time: int, threads: int}
     */
    public static function owaspFloor(): array
    {
        return ['memory' => 19456, 'time' => 2, 'threads' => 1];
    }
}
