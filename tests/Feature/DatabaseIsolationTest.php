<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * 🛑 The suite must not be pointed at the development database.
 *
 * This exists because it already happened. PHPUnit's `<env>` elements do not
 * override a variable that is already set in the environment, and PHPUnit 13
 * removed the attribute that used to make them - so the app container's
 * `DB_DATABASE=docup` and `APP_ENV=local` simply won. Every test in Phase 01
 * ran against the developer's
 * own database while `phpunit.xml` said `docup_test`, and nothing failed -
 * the schemas are identical, so the tests passed and proved what they claimed
 * to prove, just not in isolation.
 *
 * What makes it worth a permanent test rather than a fixed config and a note:
 * the damage is latent and arrives later. Phase 01's tests only read schema
 * and insert a row or two. The first test to use `RefreshDatabase` would have
 * dropped every table in the developer's database, and the commit that added
 * that trait would have looked completely innocent.
 *
 * So this asserts the outcome - which database am I actually connected to -
 * rather than the setting that is supposed to produce it. A configuration
 * comment cannot fail a build.
 */
final class DatabaseIsolationTest extends TestCase
{
    public function test_the_suite_runs_against_a_test_database(): void
    {
        $database = (string) DB::connection()->getDatabaseName();

        // The naming rule is the check. Anything that is not clearly a test
        // database is treated as the developer's, because guessing wrong in
        // that direction destroys data and guessing wrong in this direction
        // only fails a build.
        $this->assertTrue(
            str_ends_with($database, '_test') || str_ends_with($database, '_testing'),
            "The test suite is connected to [{$database}], which is not a test database.\n"
            ."Every write in this suite is landing in it, and the first use of\n"
            ."RefreshDatabase would drop it.\n\n"
            ."Cause: PHPUnit's <env> elements cannot overwrite a variable that is\n"
            ."already set, and PHPUnit 13 removed the attribute that used to make\n"
            ."them. The app container sets DB_DATABASE, so the pinning lives in\n"
            .'tests/bootstrap.php. Look there, not in phpunit.xml.'
        );
    }

    public function test_the_application_is_in_the_testing_environment(): void
    {
        // Same failure, different symptom. With APP_ENV left at "local" every
        // environment-gated guard in the codebase is evaluated for the wrong
        // environment - including the SPEC 8.1.8 seeder guard, which would
        // then let the development seeder run in a context it should refuse.
        $this->assertSame(
            'testing',
            $this->app->environment(),
            'APP_ENV reached the application as ['.$this->app->environment().'] rather than [testing]; '
            .'environment-gated behaviour is being tested under the wrong environment.'
        );
    }

    public function test_the_connection_is_mysql_not_sqlite(): void
    {
        // SPEC 9.1 keys are BINARY(16) with BIN_TO_UUID() generated columns and
        // SPEC 8.16 search is FULLTEXT. On SQLite the key tests would pass
        // while proving nothing about production, which is the specific
        // failure ADR 0006 was written to prevent.
        $this->assertSame('mysql', DB::connection()->getDriverName());
    }
}
