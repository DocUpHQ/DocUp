<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use Tests\TestCase;

/**
 * 🛑 Phase 06's exit criterion: "The runner's environment contains no
 * database credentials and no `APP_KEY`, asserted by test."
 *
 * This is that test, and it asserts against the **compose file** rather than
 * against a running container. Both would be worth having; the file is the
 * one that fails in CI, where no runner is running, and it is the artefact an
 * operator edits. A comment saying "no credentials here" is worth nothing the
 * day somebody adds one to debug something.
 *
 * §11.2 is the requirement behind it: the runner zone holds "runtime socket,
 * git credentials" and the app zone holds "database and cache credentials,
 * signing keys". Neither holds both, so a compromise of the one process with
 * the container-runtime socket yields no tenant data, no envelope key and no
 * route to the database.
 */
final class RunnerIsolationTest extends TestCase
{
    /**
     * One service's block, as text.
     *
     * Text rather than a parsed document because `symfony/yaml` is not a
     * dependency and adding one to read a file in a test would be the wrong
     * trade — `ComposeFilesTest` already reads this file the same way, and
     * what is being asserted is the presence or absence of lines an operator
     * would recognise.
     */
    private function service(string $name): string
    {
        $compose = (string) file_get_contents(base_path('compose.yaml'));

        $start = strpos($compose, "
  {$name}:
");

        $this->assertNotFalse($start, "compose.yaml declares no `{$name}` service");

        // To the next top-level service or the top-level `volumes:` key.
        $next = strlen($compose);

        foreach (['app', 'db', 'cache', 'worker', 'runner'] as $other) {
            if ($other === $name) {
                continue;
            }

            $at = strpos($compose, "
  {$other}:
", $start + 1);

            if ($at !== false && $at < $next) {
                $next = $at;
            }
        }

        $volumes = strpos($compose, '
volumes:', $start + 1);

        if ($volumes !== false && $volumes < $next) {
            $next = $volumes;
        }

        return substr($compose, $start, $next - $start);
    }

    /**
     * The environment variable names a service block declares.
     *
     * @return list<string>
     */
    private function environmentNames(string $block): array
    {
        $environment = strpos($block, '
    environment:
');

        if ($environment === false) {
            return [];
        }

        $names = [];

        foreach (explode('
', substr($block, $environment + 1)) as $line) {
            // A six-space indent is a key inside `environment:`; anything
            // shallower has left the block.
            if (preg_match('/^      ([A-Za-z_][A-Za-z0-9_]*):/', $line, $matches) === 1) {
                $names[] = $matches[1];
            } elseif (trim($line) !== '' && ! str_starts_with($line, '      ') && ! str_starts_with($line, '    environment:')) {
                break;
            }
        }

        return $names;
    }

    /**
     * 🛑 The exit criterion itself.
     *
     * Every name is checked, not just `APP_KEY`: `DB_PASSWORD` alone would be
     * enough to reach the database, and so would a `DATABASE_URL`. The list
     * is of **prefixes and names that confer access**, so a new one has to be
     * added deliberately rather than slipping in under a name the test did
     * not think of.
     */
    public function test_the_runner_holds_no_database_credentials_and_no_app_key(): void
    {
        $forbidden = [];

        foreach ($this->environmentNames($this->service('runner')) as $name) {
            if (str_starts_with($name, 'DB_')
                || str_starts_with($name, 'DATABASE_')
                || str_starts_with($name, 'REDIS_')
                || in_array($name, ['APP_KEY', 'APP_PREVIOUS_KEYS', 'DOCUP_AUDIT_KEY', 'QUEUE_CONNECTION'], true)) {
                $forbidden[] = $name;
            }
        }

        $this->assertSame(
            [],
            $forbidden,
            'the runner must hold no credentials (§11.2, Phase 06 exit criterion): '.implode(', ', $forbidden),
        );
    }

    /**
     * 🛑 The runner's `.env` is masked, and this is the assertion that makes
     * the one above mean anything.
     *
     * The environment block carries no `DB_*` and no `APP_KEY` — and every
     * service in this file bind-mounts the project directory, where Laravel's
     * dotenv loader finds `/app/.env` and reads the database password
     * straight off the filesystem. Measured during Phase 06: a runner with a
     * spotless compose environment answered `CAN READ DB PASSWORD`.
     *
     * So the environment block is necessary and not sufficient, and a test
     * that checked only the block would have certified exactly the hole it
     * was written to prevent.
     */
    public function test_the_runner_cannot_read_the_dotenv_file(): void
    {
        $this->assertStringContainsString(
            '/dev/null:/app/.env',
            $this->service('runner'),
            'the runner reads the project .env unless it is masked, whatever its environment block says',
        );
    }

    /**
     * 🛑 §8.5.13: "No request-handling or queue-worker process MUST hold a
     * container-runtime socket. The runner is the sole holder."
     *
     * Asserted in both directions, because only one of them is obvious. The
     * runner must have the socket — a runner without it cannot do its job and
     * would fail loudly. Every *other* service must not, and that is the
     * direction a mistake takes: a socket mounted into the application
     * container to make something work locally, left there.
     */
    public function test_only_the_runner_mounts_the_container_runtime_socket(): void
    {
        $holders = [];

        foreach (['app', 'db', 'cache', 'worker', 'runner'] as $name) {
            if (str_contains($this->service($name), 'docker.sock')) {
                $holders[] = $name;
            }
        }

        $this->assertSame(['runner'], $holders, 'the runner is the sole runtime-socket holder (§8.5.13)');
    }

    /**
     * The worker is in the app zone and therefore keeps its credentials.
     *
     * A control for the test above: if the credential assertions were passing
     * because the parser was returning nothing, this would fail too.
     */
    public function test_the_worker_does_hold_database_credentials(): void
    {
        $names = $this->environmentNames($this->service('worker'));

        $this->assertContains('DB_PASSWORD', $names);
        $this->assertContains('APP_KEY', $names);
    }

    /**
     * 🛑 The runner and the worker both mount the spool, and nothing else
     * does except the application.
     *
     * The spool is the §8.5.13 exchange. A fourth service mounting it would
     * be a path into the runner's instruction stream from somewhere nobody
     * has thought about.
     */
    public function test_only_the_application_worker_and_runner_share_the_spool(): void
    {
        $mounting = [];

        foreach (['app', 'db', 'cache', 'worker', 'runner'] as $name) {
            if (str_contains($this->service($name), '- spool:/var/lib/docup/spool')) {
                $mounting[] = $name;
            }
        }

        sort($mounting);

        $this->assertSame(['app', 'runner', 'worker'], $mounting);
    }

    /**
     * 🛑 The Docker client is in the runner image and nowhere else.
     *
     * §8.5.13 is about who may call the runtime. Keeping the client out of
     * the application image means a request-handling process could not use
     * the socket even if one were mounted into it by mistake — which is the
     * mistake the test above exists to catch, and this is the second lock on
     * the same door.
     */
    public function test_the_docker_client_is_only_in_the_runner_image(): void
    {
        $application = (string) file_get_contents(base_path('deploy/Dockerfile'));

        $this->assertStringNotContainsString('docker-ce-cli', $application);
        $this->assertStringNotContainsString('docker-cli', $application);

        $runner = (string) file_get_contents(base_path('deploy/Dockerfile.runner'));

        $this->assertStringContainsString('docker-ce-cli', $runner);
    }
}
