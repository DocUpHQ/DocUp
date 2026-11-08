<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\HasUuidKey;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Support\Carbon;
use Laravel\Fortify\Actions\RedirectIfTwoFactorAuthenticatable;
use Laravel\Fortify\TwoFactorAuthenticatable;

/**
 * A person who can sign in to the dashboard.
 *
 * `final` on purpose. DocUp has no single-table inheritance anywhere in the
 * data model (SPEC 10), so a subclassed model would be a surprise rather
 * than a design; behaviour that varies belongs in a concern or a service, not
 * in a subclass that silently changes what a type means.
 *
 * 🛑 The key is a raw-binary UUIDv7 via {@see HasUuidKey}, per ADR 0006. The
 * `password` cast is `hashed`, which routes through the SPEC 8.12.16 Argon2id
 * parameters in `config/hashing.php` - never Laravel's m=1024 default.
 *
 * Authentication itself is Phase 02 (SPEC 8.13). Phase 01 gives the table and
 * the model so the first administrator can exist before sign-in does.
 *
 * 🛑 **`TwoFactorAuthenticatable` is not decoration (Phase 26a).** Phase 02
 * enabled `Features::twoFactorAuthentication()`, published the columns and
 * wired the challenge view — and left the trait off, which made the whole
 * feature unreachable:
 * {@see RedirectIfTwoFactorAuthenticatable} gates the
 * challenge on `in_array(TwoFactorAuthenticatable::class,
 * class_uses_recursive($user))`, so a user who enrolled would have been issued
 * a secret, shown a QR code, and then signed in with a password alone for ever.
 * A silent no-op in the authentication path, which is the class of defect
 * §9.4's level-9 namespaces exist for.
 *
 * @property-read string $id raw 16 bytes, per ADR 0006 — never the canonical form
 * @property string $name
 * @property string $email
 * @property string|null $two_factor_secret encrypted by Fortify, never read here
 * @property string|null $two_factor_recovery_codes encrypted by Fortify
 * @property Carbon|null $two_factor_confirmed_at 🛑 §8.13.4's
 *                                                only proof of
 *                                                enrolment: a
 *                                                secret alone is
 *                                                somebody who
 *                                                abandoned the QR
 *                                                screen
 */
#[Tenancy(
    TenancyPosture::Installation,
    because: 'A person is an installation-level identity who may hold roles in several '
        .'organisations. Scoping this table by organisation would turn one human into '
        .'several accounts, each unable to see the others. Their MEMBERSHIP is org-scoped '
        .'(team_members, role_assignments); their identity is not.'
)]
#[Fillable(['name', 'email', 'password'])]
#[Hidden(['password', 'remember_token'])]
final class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, HasUuidKey, Notifiable, TwoFactorAuthenticatable;

    /**
     * The attributes that should be cast.
     *
     * Protected because Eloquent declares this extension point protected;
     * see the exemption and its reason in tests/Arch/PresetsTest.php.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
            /*
             * 🛑 Not `encrypted`. Fortify encrypts and decrypts the two secret
             * columns itself through `Fortify::currentEncrypter()`, so a cast
             * here would encrypt an already-encrypted value on write and hand
             * the decrypter ciphertext it cannot read — breaking enrolment with
             * a `DecryptException` that names neither the cast nor the trait.
             */
            'two_factor_confirmed_at' => 'datetime',
        ];
    }
}
