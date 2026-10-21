<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use Database\Seeders\DatabaseSeeder;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Schema;
use Tests\TestCase;

/**
 * The remaining Phase 01 exit criteria: the login page renders, it renders in a
 * second locale, and the framework landmines SPEC 9.3.8 names are closed.
 */
final class BedrockTest extends TestCase
{
    // The seeder test below inserts a row. Rolled back per test so the suite
    // is re-runnable: without this the second run fails on the unique email,
    // which looks like a broken seeder rather than a dirty database.
    use DatabaseTransactions;

    public function test_the_root_path_redirects_to_the_login_page(): void
    {
        $this->get('/')->assertRedirectToRoute('login');
    }

    public function test_the_login_page_renders(): void
    {
        $this->get('/login')
            ->assertOk()
            ->assertSee('Sign in')
            // Inertia serialises the component name into JSON, where the
            // slash is escaped as Auth\/Login. Assert on the escaped form.
            ->assertSee('Auth\/Login', escape: false);
    }

    /** SPEC 9.5.2 / Phase 01 exit criterion: the UI renders in a second locale. */
    public function test_the_login_page_renders_in_a_second_locale(): void
    {
        $response = $this->get('/login?locale=fr')->assertOk();

        $response->assertSee('Connexion');
        $response->assertSee('Se connecter');
        $response->assertSee('lang="fr"', escape: false);

        // ...and the English strings are genuinely gone, not merely joined by
        // the French ones, which is what a half-applied locale looks like.
        $response->assertDontSee('>Sign in<', escape: false);
    }

    public function test_an_unknown_locale_falls_back_rather_than_erroring(): void
    {
        $this->get('/login?locale=../../etc/passwd')->assertOk()->assertSee('Sign in');
        $this->get('/login?locale=zz')->assertOk()->assertSee('Sign in');
    }

    public function test_every_user_facing_string_comes_from_a_message_file(): void
    {
        // SPEC 9.5.2: all UI strings in message files from the first string.
        // If a component hard-codes copy, the locale test above cannot catch it
        // unless we also assert the message files are the source.
        $en = require lang_path('en/auth.php');
        $fr = require lang_path('fr/auth.php');

        $this->assertSame(
            array_keys($en['login']),
            array_keys($fr['login']),
            'the locales have diverged: a key exists in one and not the other',
        );

        foreach ($en['login'] as $key => $value) {
            $this->assertNotSame(
                $value,
                $fr['login'][$key],
                "lang/fr/auth.php key [login.{$key}] is still the English string",
            );
        }
    }

    /**
     * 🛑 SPEC 8.12.16 / 9.3.8: Laravel's ArgonHasher defaults to m=1024 KiB,
     * roughly 19x below the OWASP password-storage floor of 19456 KiB. Phase 00
     * verified the weak default is still current, so this must be overridden and
     * must not regress.
     */
    public function test_argon2id_parameters_meet_the_owasp_floor(): void
    {
        $this->assertGreaterThanOrEqual(19456, (int) config('hashing.argon.memory'));
        $this->assertGreaterThanOrEqual(2, (int) config('hashing.argon.time'));
        $this->assertGreaterThanOrEqual(1, (int) config('hashing.argon.threads'));
    }

    public function test_the_unsafe_mode_registry_defaults_entirely_closed(): void
    {
        // 🛑 SPEC 8.22.11: no security control sits behind a flag that defaults
        // open. Every entry in the registry must be falsy out of the box.
        foreach ((array) config('docup.unsafe') as $flag => $value) {
            $this->assertFalse(
                (bool) $value,
                "unsafe mode [{$flag}] does not default closed (SPEC 8.22.11)",
            );
        }
    }

    public function test_the_data_class_annotation_register_exists(): void
    {
        // SPEC 8.22.7: created in Phase 01, before any domain model, so the
        // first table anyone adds is already covered by the coverage check.
        $this->assertTrue(
            Schema::hasTable('data_class_annotations'),
        );

        foreach (['table_name', 'column_name', 'classification', 'erasure', 'retention_class'] as $column) {
            $this->assertTrue(
                Schema::hasColumn('data_class_annotations', $column),
                "data_class_annotations is missing [{$column}]",
            );
        }
    }

    public function test_hashing_actually_uses_argon2id(): void
    {
        $hash = Hash::driver('argon2id')->make('correct horse battery staple');

        $this->assertStringStartsWith('$argon2id$', $hash);
        $this->assertTrue(Hash::driver('argon2id')->check('correct horse battery staple', $hash));
    }

    /**
     * 🛑 The development seeder plants an account with a known password, so it
     * must refuse to run anywhere that is not local or testing. `db:seed
     * --force` is a command an operator genuinely reaches for on a real
     * installation, and nothing in the framework stops it.
     */
    public function test_the_development_seeder_refuses_to_run_in_production(): void
    {
        $this->app->detectEnvironment(fn (): string => 'production');

        try {
            $this->expectException(\RuntimeException::class);
            $this->expectExceptionMessageMatches('/refuses to run in "production"/');

            (new DatabaseSeeder)->run();
        } finally {
            // Restore it explicitly: a leaked environment would silently change
            // what every later test in this process is asserting about.
            $this->app->detectEnvironment(fn (): string => 'testing');
        }
    }

    public function test_the_development_seeder_does_run_in_testing(): void
    {
        // The other half of the pair. A test that only proved the refusal would
        // still pass if the seeder refused everywhere and seeded nothing.
        (new DatabaseSeeder)->run();

        $this->assertDatabaseHas('users', ['email' => 'test@example.com']);
    }
}
