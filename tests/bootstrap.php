<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| Test environment pinning
|--------------------------------------------------------------------------
|
| 🛑 This file exists because `phpunit.xml` cannot do this job.
|
| PHPUnit's `<env>` elements do not overwrite a variable that is already
| present in the environment. PHPUnit 9 had a `force="true"` attribute for
| exactly that; PHPUnit 13 has REMOVED it - `namedValueType` in
| `vendor/phpunit/phpunit/phpunit.xsd` declares only `name` and `value`. An
| XML file carrying `force="true"` still validates, and the attribute is
| silently ignored, which is the worst of the available behaviours.
|
| Both places this suite runs have the variables already set: the application
| container exports `APP_ENV=local` and `DB_DATABASE=docup`, and a developer's
| shell can export anything at all. The consequence, before this file existed,
| was a suite that reported itself green while connected to the DEVELOPER'S
| OWN DATABASE. Nothing failed, because the two schemas are identical.
|
| The cost of leaving it is not the stray rows. It is that the first test to
| use `RefreshDatabase` would have dropped every table in that database, and
| the commit adding the trait would have looked entirely innocent.
|
| So the values that decide WHICH database and WHICH environment are pinned
| here, before the autoloader, before Laravel, before anything can read them.
| `tests/Feature/DatabaseIsolationTest.php` then asserts the result, because a
| comment cannot fail a build.
|
| DB_HOST is deliberately absent: the container reaches MySQL at `db` and CI
| reaches it at `127.0.0.1`, so the host must stay environment-provided. This
| file pins only what must never be inherited.
*/

/*
|--------------------------------------------------------------------------
| Parallel testing is not supported yet
|--------------------------------------------------------------------------
|
| 🛑 Refused loudly rather than left to fail strangely.
|
| `pest --parallel` gives each process its own database (docup_test_1,
| docup_test_2, …). Two things break:
|
|  1. This file pins DB_DATABASE, so all 28 processes would share one database
|     and interfere with each other. Observed: 113 failures that look like
|     application bugs and are not.
|  2. Even token-aware, the per-process databases cannot be hardened. The
|     §8.22.1 append-only triggers need SUPER while binary logging is on, which
|     the application's database user must never hold — so
|     tests/Feature/AuditAppendOnlyTest.php would fail on every parallel
|     database, or worse, pass against an unhardened schema and prove nothing.
|
| CLAUDE.md rule 5 asks for --parallel on full-suite runs. It is not available
| until the hardening can be applied per test database, which needs a
| privileged setup hook. Recorded in the build log as owed; the serial suite is
| the supported run.
*/
if (getenv('TEST_TOKEN') !== false || getenv('LARAVEL_PARALLEL_TESTING') !== false) {
    fwrite(STDERR, <<<'MESSAGE'

        Parallel testing is not supported in DocUp yet.

        Each parallel process gets its own database, and the SPEC 8.22.1
        append-only triggers cannot be installed on one: CREATE TRIGGER needs
        SUPER while binary logging is enabled, and the application user must
        never hold it. A parallel run would either fail on
        AuditAppendOnlyTest or silently test an unhardened audit log.

        Run the suite serially:

            ./vendor/bin/pest

        MESSAGE);

    exit(1);
}

$pinned = [
    'APP_ENV' => 'testing',
    'DB_CONNECTION' => 'mysql',
    'DB_DATABASE' => 'docup_test',
];

foreach ($pinned as $name => $value) {
    // All three, because Laravel's Env repository reads $_SERVER and $_ENV
    // while third-party code and PHP extensions read getenv(). Setting one
    // and not the others produces a disagreement that is very hard to see.
    $_ENV[$name] = $value;
    $_SERVER[$name] = $value;
    putenv($name.'='.$value);
}

/*
| A test database whose name does not say it is one is how this went wrong in
| the first place, so refuse to start rather than discover it later. This is a
| guard on the constant above, not on configuration: it fires if someone edits
| this file to point the suite somewhere dangerous.
*/
if (! str_ends_with($pinned['DB_DATABASE'], '_test')) {
    fwrite(STDERR, "tests/bootstrap.php: DB_DATABASE must end in _test.\n");
    exit(1);
}

require __DIR__.'/../vendor/autoload.php';
