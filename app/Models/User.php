<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Concerns\HasUuidKey;
use Database\Factories\UserFactory;
use Illuminate\Database\Eloquent\Attributes\Fillable;
use Illuminate\Database\Eloquent\Attributes\Hidden;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;

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
 */
#[Fillable(['name', 'email', 'password'])]
#[Hidden(['password', 'remember_token'])]
final class User extends Authenticatable
{
    /** @use HasFactory<UserFactory> */
    use HasFactory, HasUuidKey, Notifiable;

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
        ];
    }
}
