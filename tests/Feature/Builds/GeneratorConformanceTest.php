<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\BuildEnvironment;
use App\Builds\Runner\DockerRunnerDriver;
use App\Builds\Runner\Spool;
use App\Builds\Runner\Workspace;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\SandboxPolicy;
use App\Builds\Stage;
use App\Builds\Toolchain\ToolchainPlan;
use App\Builds\Toolchain\ToolchainPresets;
use App\Config\ConfigParser;
use App\Config\HtmlContext;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\GeneratorFixtures;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * 🛑 Phase 09's first exit criterion: "**Each of six generators builds from
 * ≤12 lines of configuration.**"
 *
 * Everything below the configuration file is real: the shipped preset, the
 * shipped image, the §8.4.10 script the runner writes into the workspace,
 * the §8.5.8 hardening, and the tar the §8.21.6 publish path would ingest.
 *
 * 🛑 **The clone is the one thing left out, and deliberately.** The fetcher
 * refuses `file://`, `http://` and `git://` (§8.3.4), which is correct and
 * means there is no way to serve six fixture repositories to it without a
 * certificate authority the fetch image trusts. Cloning is separately proven
 * against five real providers in ADR 0010 and ADR 0011, and
 * {@see EndToEndBuildTest} runs the whole pipeline against a real public
 * repository. What is under test here is the half those do not cover: that a
 * preset plus twelve lines of YAML produces a site.
 *
 * 🛑 **Runs in the `runner` container**, which is the only process §8.5.13
 * lets hold the runtime socket.
 */
final class GeneratorConformanceTest extends TestCase
{
    use RequiresBuildImages;

    /**
     * 🛑 The budget, counted rather than claimed.
     *
     * This one needs no Docker, so it runs everywhere — which matters,
     * because it is the half of the criterion that a passing build does not
     * prove. A fixture whose configuration grew to forty lines would still
     * build.
     */
    public function test_every_fixture_is_within_the_configuration_budget(): void
    {
        foreach (GeneratorFixtures::all() as $toolchain => $files) {
            $lines = substr_count(rtrim($files['.docup.yaml'], "\n")."\n", "\n");

            $this->assertLessThanOrEqual(
                GeneratorFixtures::CONFIGURATION_BUDGET,
                $lines,
                $toolchain.' needs '.$lines.' lines of configuration; §17 budgets '
                    .GeneratorFixtures::CONFIGURATION_BUDGET,
            );

            // And it must be a configuration this installation accepts.
            $config = ConfigParser::parse($files['.docup.yaml'], '.docup.yaml');

            $this->assertSame($toolchain, $config->declaredToolchain());
        }
    }

    /**
     * The three that need no package manager: seconds, not minutes.
     *
     * @param  string  $toolchain  the preset under test
     */
    #[DataProvider('offlineGenerators')]
    public function test_an_offline_generator_builds_from_twelve_lines(string $toolchain): void
    {
        $this->assertGeneratorBuilds($toolchain);
    }

    /**
     * The four that install from the §8.5.9 allowlist.
     *
     * 🛑 These are the first builds in DocUp's history to install
     * dependencies while running repository code, which is the combination
     * Phase 07's CONNECT proxy and nftables backstop exist to contain. A
     * failure here is as likely to be the egress policy as the generator,
     * which is why the failure message carries the log.
     *
     * @param  string  $toolchain  the preset under test
     */
    #[DataProvider('networkGenerators')]
    public function test_a_network_generator_builds_from_twelve_lines(string $toolchain): void
    {
        $this->assertGeneratorBuilds($toolchain);
    }

    /** @return iterable<string, array{string}> */
    public static function offlineGenerators(): iterable
    {
        foreach (GeneratorFixtures::offline() as $toolchain) {
            yield $toolchain => [$toolchain];
        }
    }

    /** @return iterable<string, array{string}> */
    public static function networkGenerators(): iterable
    {
        foreach (array_keys(GeneratorFixtures::all()) as $toolchain) {
            if (! in_array($toolchain, GeneratorFixtures::offline(), true)) {
                yield $toolchain => [$toolchain];
            }
        }
    }

    /**
     * 🛑 §8.4.11: "MUST fail loudly rather than silently falling back to a
     * full clone."
     *
     * The failing half, which is the half that matters: a sparse checkout
     * that quietly did not apply is a build reading files it was told to
     * exclude, and it looks identical to one that worked. So the fetcher is
     * asked to narrow to a directory that does not exist at this commit, and
     * must exit 64 rather than hand back a full worktree.
     *
     * The *succeeding* half is measured across all five providers by
     * `deploy/verify-sparse.sh` and recorded in ADR 0012; it is not in the
     * suite because five clones of real repositories is a two-minute
     * verification rather than a test.
     */
    public function test_a_sparse_checkout_that_narrows_nothing_is_refused(): void
    {
        $this->requireBuildImages(['docup/fetch:1']);

        $driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));
        $volume = $driver->createWorkspace($buildId);

        try {
            $probe = $driver->run($this->fetchSpec($buildId, $volume, 'probe', []), credential: '');

            $this->assertTrue($probe->succeeded(), 'the probe pass failed: '.$this->tail($probe->log));

            $refused = $driver->run(
                $this->fetchSpec($buildId, $volume, 'checkout', ['no-such-directory-in-this-repository']),
                credential: '',
            );

            $this->assertFalse($refused->succeeded(), '🛑 §8.4.11: a sparse checkout that narrowed nothing must fail: '.$this->tail($refused->log));
            $this->assertSame(64, $refused->exitCode, 'the fetcher must say WHY, with its own exit code');
        } finally {
            $driver->destroyWorkspace($volume);
        }
    }

    /**
     * One pass of the fetcher, built the way the pipeline builds it.
     *
     * A method rather than the closure this was: `[...$sparse]` inside an
     * array literal is a `non-empty-array` to PHPStan and
     * `RunSpecification` takes a `list<string>`, and a closure parameter
     * cannot carry the `@param` that would say so. The pipeline's own call
     * site spreads and passes for exactly that reason.
     *
     * @param  list<string>  $sparse
     */
    private function fetchSpec(string $buildId, string $volume, string $mode, array $sparse): RunSpecification
    {
        return new RunSpecification(
            buildId: $buildId,
            stage: Stage::Fetch,
            imageKey: 'fetch',
            command: [
                'https://github.com/mkdocs/mkdocs',
                'master',
                '/workspace/source',
                '.',
                $mode,
                ...$sparse,
            ],
            environment: [],
            volume: $volume,
            workdir: '/workspace',
            timeoutSeconds: Stage::Fetch->timeoutSeconds(),
            egress: SandboxPolicy::fromConfig()->egressFor(Stage::Fetch),
            acceptsStdin: true,
            pass: $mode,
        );
    }

    private function assertGeneratorBuilds(string $toolchain): void
    {
        $preset = ToolchainPresets::get($toolchain);
        $image = $this->imageReferenceFor($preset->image);

        $this->requireBuildImages([$image]);

        $files = GeneratorFixtures::all()[$toolchain];
        $driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));
        $volume = $driver->createWorkspace($buildId);

        try {
            $this->seedWorkspace(Workspace::pathFor($volume).'/source', $files);

            $plan = ToolchainPlan::resolve(
                config: ConfigParser::parse($files['.docup.yaml'], '.docup.yaml'),
                sourcePath: '',
                presentFiles: array_keys($files),
                htmlContext: HtmlContext::fromCloneUrl('https://github.com/docup/fixture.git', 'main'),
            );

            $this->assertSame($toolchain, $plan->preset->key);

            $environment = array_merge(
                (new BuildEnvironment('docs.example.invalid', 'fixture', 'https://github.com/docup/fixture.git', 'main', str_repeat('0', 40), 'main'))->forContainer(),
                $plan->environment(),
            );

            $script = $plan->environmentScript();

            if ($script !== null) {
                $install = $driver->run(new RunSpecification(
                    buildId: $buildId,
                    stage: Stage::Environment,
                    imageKey: $preset->image,
                    command: [],
                    environment: $environment,
                    volume: $volume,
                    workdir: $plan->sourceDir,
                    timeoutSeconds: Stage::Environment->timeoutSeconds(),
                    egress: SandboxPolicy::fromConfig()->egressFor(Stage::Environment),
                    script: $script,
                    shell: $plan->semantics->shell(),
                ));

                $this->assertTrue(
                    $install->succeeded(),
                    $toolchain.' could not install its dependencies: '.$this->tail($install->log),
                );
            }

            $build = $driver->run(new RunSpecification(
                buildId: $buildId,
                stage: Stage::Build,
                imageKey: $preset->image,
                command: [],
                environment: $environment,
                volume: $volume,
                workdir: $plan->sourceDir,
                timeoutSeconds: Stage::Build->timeoutSeconds(),
                egress: SandboxPolicy::fromConfig()->egressFor(Stage::Build),
                exportPath: BuildEnvironment::OUTPUT_PATH,
                script: $plan->buildScript(),
                shell: $plan->semantics->shell(),
            ));

            $this->assertTrue(
                $build->succeeded(),
                $toolchain.' did not build: '.$this->tail($build->log),
            );

            /*
             * The §8.21.6 hand-off, which `RunnerCommand` does after a
             * successful stage with an `exportPath`. Done here rather than
             * inside `run()` because the driver's job ends at the container:
             * what it exports and where is the runner loop's decision, and
             * keeping it there is what lets a different `RunnerDriver`
             * (§11.4 names `gvisor`, `kubernetes` and `external`) answer it
             * differently.
             */
            $archive = Spool::fromConfig()->output($buildId.'-build');

            $this->assertTrue(
                $driver->exportDirectory($volume, BuildEnvironment::OUTPUT_PATH, $archive),
                $toolchain.' produced no exportable output directory',
            );

            /*
             * 🛑 §8.4.5's whole contract in one assertion:
             * "anything written to `$DOCUP_OUTPUT/{html,pdf,epub,htmlzip}/`
             * is published; `html/index.html` is mandatory". Seven
             * generators, one directory, one mandatory file — "This one
             * contract is why ten unrelated generators work from twelve
             * lines of YAML."
             */
            $this->assertTrue(
                $this->archiveContains($archive, 'html/index.html'),
                $toolchain.' produced no html/index.html in $DOCUP_OUTPUT (§8.4.5)',
            );
        } finally {
            $driver->destroyWorkspace($volume);
            @unlink(Spool::fromConfig()->output($buildId.'-build'));
        }
    }

    /** @param  array<string, string>  $files */
    private function seedWorkspace(string $root, array $files): void
    {
        foreach ($files as $path => $contents) {
            $target = $root.'/'.$path;
            $directory = dirname($target);

            if (! is_dir($directory)) {
                mkdir($directory, 0o750, true);
            }

            file_put_contents($target, $contents);
        }

        /*
         * 🛑 Owned by the container's user. Every build container runs as
         * uid 10001 with every capability dropped (§8.5.8), so it does not
         * have `CAP_DAC_OVERRIDE` and root-owned files are simply
         * unreadable — the failure Phase 07 spent an afternoon on.
         */
        $this->chownTree($root);
    }

    private function chownTree(string $path): void
    {
        @chown($path, 10001);
        @chgrp($path, 10001);

        foreach ((array) scandir($path) as $entry) {
            if (! is_string($entry) || $entry === '.' || $entry === '..') {
                continue;
            }

            $child = $path.'/'.$entry;

            if (is_dir($child)) {
                $this->chownTree($child);

                continue;
            }

            @chown($child, 10001);
            @chgrp($child, 10001);
        }
    }

    /** Is this path in the exported ustar archive? */
    private function archiveContains(string $archive, string $path): bool
    {
        if (! is_file($archive)) {
            return false;
        }

        $handle = fopen($archive, 'rb');

        if ($handle === false) {
            return false;
        }

        try {
            while (($header = fread($handle, 512)) !== false && strlen($header) === 512) {
                $name = rtrim(substr($header, 0, 100), "\0");

                if ($name === '') {
                    break;
                }

                $prefix = rtrim(substr($header, 345, 155), "\0");
                $full = ltrim(($prefix === '' ? '' : $prefix.'/').$name, './');

                if ($full === $path || str_ends_with($full, '/'.$path)) {
                    return true;
                }

                $size = (int) octdec(trim(substr($header, 124, 12)) ?: '0');
                fseek($handle, (int) (ceil($size / 512) * 512), SEEK_CUR);
            }
        } finally {
            fclose($handle);
        }

        return false;
    }

    private function imageReferenceFor(string $key): string
    {
        $images = (array) config('builds.images');
        $entry = $images[$key] ?? [];

        return is_array($entry) && is_string($entry['reference'] ?? null) ? $entry['reference'] : $key;
    }

    /**
     * The last lines of a stage's log, for a failure message.
     *
     * `RunOutcome::$log` is a list of records when the runner streamed them
     * and a list of plain strings when it refused before any container
     * started — which is how a `docker run` failure reaches here, and
     * exactly the case worth printing.
     *
     * @param  list<array<string, mixed>|string>  $log
     */
    private function tail(array $log, int $lines = 120): string
    {
        $text = [];

        foreach (array_slice($log, -$lines) as $record) {
            if (is_string($record)) {
                $text[] = $record;

                continue;
            }

            $text[] = is_string($record['text'] ?? null) ? $record['text'] : (string) json_encode($record);
        }

        return "\n".implode("\n", $text);
    }
}
