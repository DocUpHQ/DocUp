<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Database\Seeders;

use App\Models\User;
use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;

/**
 * Development seed data.
 *
 * 🛑 Refuses to run outside local and testing environments. The account below
 * has a known password, and `db:seed --force` is a command operators do reach
 * for on a real installation - during a restore, or while following a runbook
 * written for staging. A seeder that plants known credentials in production is
 * a backdoor whatever the intent was, so the guard is here rather than in the
 * documentation.
 *
 * Real first-administrator creation is `docup:install` (SPEC 8.1.8), which
 * reads a password interactively and never accepts one as an argument.
 */
final class DatabaseSeeder extends Seeder
{
    use WithoutModelEvents;

    /**
     * Seed the application's database.
     *
     * @throws \RuntimeException when run outside local or testing
     */
    public function run(): void
    {
        if (! app()->environment(['local', 'testing'])) {
            throw new \RuntimeException(
                'DatabaseSeeder plants a known-password account and refuses to run in "'
                .app()->environment().'". Use `php artisan docup:install` instead (SPEC 8.1.8).'
            );
        }

        User::factory()->create([
            'name' => 'Test User',
            'email' => 'test@example.com',
        ]);
    }
}
