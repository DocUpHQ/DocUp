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
