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
use Tests\Feature\Composition\SinglePassPlanTest;
use Tests\Support\RequiresBuildImages;
use Tests\Support\SinglePassFixture;
use Tests\TestCase;

/**
 * 🛑 Phase 15's exit criteria, in the real sandbox.
 *
 * > "An Antora site builds from three content sources with working
 * > cross-source `xref`s. 🛑 A contributing repository's own
 * > `antora-playbook.yml` or `mkdocs.yml` `!include` **cannot** add a
 * > fourth source or redirect an existing one — asserted by a fixture that
 * > tries."
 *
 * Both halves are one build, deliberately: the fixture that composes three
 * sources is the same fixture that ships a hostile playbook, so the
 * assertion "three components, not four" is made against a site that was
 * genuinely built rather than against a generated file nobody ran.
 *
 * 🛑 **Runs in the `runner` container**, which is the only process §8.5.13
 * lets hold the runtime socket.
 *
 * What is NOT under test here is the clone: §8.3.4 refuses `file://`, so
 * the three sources are seeded into the workspace exactly as
 * {@see GeneratorConformanceTest} seeds one. What the pipeline does with
 * several of them — one fetch per slot, into one volume — is
 * {@see SinglePassPlanTest}'s, which needs no
 * container.
 */
final class SinglePassCompositionTest extends TestCase
{
    use RequiresBuildImages;

    /**
     * 🛑 "An Antora site builds from three content sources with working
     * cross-source `xref`s."
     *
     * The `xref` assertion is on the **built HTML**, not on the exit code.
     * Antora resolves an unresolvable `xref:` into a page that still
     * builds — it emits the target text wrapped in a broken-xref class and
     * carries on — so a build that exits zero proves nothing about whether
     * the three sources can see each other. The link is what proves it.
     */
    public function test_three_sources_build_as_one_site_with_cross_source_xrefs(): void
    {
        $archive = $this->composeAndBuild(SinglePassFixture::threeSources());

        try {
            // Each component writes its own directory, named by its own
            // `antora.yml` — which is why DocUp's slot names never reach
            // the output and the mount path never enters the container.
            foreach (['handbook', 'reference', 'glossary'] as $component) {
                $this->assertTrue(
                    $this->archiveContains($archive, 'html/'.$component.'/index.html'),
                    $component.' is missing from the composed site',
                );
            }

            // §8.4.5's mandatory root, which Antora writes only because the
            // generated playbook named a start page (§8.7.12).
            $this->assertTrue($this->archiveContains($archive, 'html/index.html'));

            /*
             * 🛑 The cross-source reference, resolved. The handbook's page
             * carries `xref:glossary::terms.adoc[…]`, and a resolved xref
             * is an `<a href>` into the glossary's directory. Antora marks
             * an unresolved one with the `xref unresolved` class, which is
             * what this asserts the absence of — the positive and the
             * negative together, because either alone can pass for the
             * wrong reason.
             */
            $page = (string) $this->fileFromArchive($archive, 'html/handbook/index.html');

            $this->assertNotSame('', $page, 'the handbook page is missing');
            $this->assertStringContainsString('../glossary/terms.html', $page, 'the xref did not resolve');
            $this->assertStringNotContainsString('unresolved', $page, 'Antora reported a broken xref');
        } finally {
            @unlink($archive);
        }
    }

    /**
     * 🛑 "A contributing repository's own `antora-playbook.yml` ... cannot
     * add a fourth source or redirect an existing one — asserted by a
     * fixture that tries."
     *
     * The fixture's third source ships a playbook naming a fourth content
     * source that exists on disk, so the only thing standing between it
     * and the site is that DocUp's playbook is the one Antora reads. If
     * the guarantee were "Antora ignores other playbooks" this test would
     * pass for the wrong reason — so the fourth source is a *valid*
     * component that would build perfectly if it were included.
     */
    public function test_a_contributing_repository_cannot_add_a_fourth_source(): void
    {
        $archive = $this->composeAndBuild(SinglePassFixture::withAHostilePlaybook());

        try {
            $this->assertTrue(
                $this->archiveContains($archive, 'html/handbook/index.html'),
                'the composed site did not build at all',
            );

            $this->assertFalse(
                $this->archiveContains($archive, 'html/intruder/index.html'),
                '🛑 a contributing repository added a fourth content source (§8.7.12)',
            );

            // And it did not redirect an existing one either: the component
            // its playbook tried to re-point is still the one DocUp named.
            $this->assertTrue(
                $this->archiveContains($archive, 'html/glossary/terms.html'),
                '🛑 a contributing repository redirected an existing source (§8.7.12)',
            );
        } finally {
            @unlink($archive);
        }
    }

    // ---------------------------------------------------------------- harness

    /**
     * Generate the playbook from the plan, then run the real stages.
     *
     * @param  array{sources: array<string, array<string, string>>, primary: string, config: string}  $fixture
     * @return string the exported archive's path
     */
    private function composeAndBuild(array $fixture): string
    {
        $preset = ToolchainPresets::get('antora');
        $this->requireBuildImages([$this->imageReferenceFor($preset->image)]);

        $driver = new DockerRunnerDriver;
        $buildId = bin2hex(random_bytes(16));
        $volume = $driver->createWorkspace($buildId);

        try {
            $root = Workspace::pathFor($volume);
            $slots = [];

            foreach ($fixture['sources'] as $slot => $files) {
                $this->seedWorkspace($root.'/source/'.$slot, $files);
                $slots[] = $slot;
            }

            $plan = ToolchainPlan::resolve(
                config: ConfigParser::parse($fixture['config'], '.docup.yaml'),
                sourcePath: '',
                presentFiles: ['antora-playbook.yml'],
                htmlContext: HtmlContext::fromCloneUrl('https://github.com/docup/fixture.git', 'main'),
            )->composedWith(SinglePassFixture::composition($slots, $fixture['config']));

            $this->assertSame('antora', $plan->preset->key);

            $environment = array_merge(
                (new BuildEnvironment(
                    'docs.example.invalid',
                    'fixture',
                    'https://github.com/docup/fixture.git',
                    'main',
                    str_repeat('0', 40),
                    'main',
                ))->forContainer(),
                $plan->environment(),
            );

            $script = $plan->environmentScript();

            $this->assertIsString($script, 'a composed plan always has an environment stage: it writes the playbook');

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
                'the composition stage failed: '.$this->tail($install->log),
            );

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

            $this->assertTrue($build->succeeded(), 'the composed build failed: '.$this->tail($build->log));

            $archive = Spool::fromConfig()->output($buildId.'-build');

            $this->assertTrue(
                $driver->exportDirectory($volume, BuildEnvironment::OUTPUT_PATH, $archive),
                'the composed build produced no exportable output directory',
            );

            return $archive;
        } finally {
            $driver->destroyWorkspace($volume);
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

        // 🛑 Owned by the container's user: every build container runs as
        // uid 10001 with every capability dropped (§8.5.8), so root-owned
        // files are simply unreadable.
        $this->chownTree($root);
    }

    private function chownTree(string $root): void
    {
        @chmod($root, 0o755);
        @chown($root, 10001);
        @chgrp($root, 10001);

        $items = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST,
        );

        foreach ($items as $item) {
            $path = (string) $item;
            @chmod($path, is_dir($path) ? 0o755 : 0o644);
            @chown($path, 10001);
            @chgrp($path, 10001);
        }
    }

    private function archiveContains(string $archive, string $path): bool
    {
        return $this->fileFromArchive($archive, $path) !== null;
    }

    /** One file's bytes out of an exported tar, or null. */
    private function fileFromArchive(string $archive, string $path): ?string
    {
        if (! is_file($archive)) {
            return null;
        }

        $handle = fopen($archive, 'rb');

        if ($handle === false) {
            return null;
        }

        try {
            while (($header = fread($handle, 512)) !== false && strlen($header) === 512) {
                $name = rtrim(substr($header, 0, 100), "\0");

                if ($name === '') {
                    break;
                }

                $prefix = rtrim(substr($header, 345, 155), "\0");
                $full = ltrim(($prefix === '' ? '' : $prefix.'/').$name, './');
                $size = (int) octdec(trim(substr($header, 124, 12)) ?: '0');

                if ($full === $path || str_ends_with($full, '/'.$path)) {
                    return $size > 0 ? (string) fread($handle, $size) : '';
                }

                fseek($handle, (int) (ceil($size / 512) * 512), SEEK_CUR);
            }
        } finally {
            fclose($handle);
        }

        return null;
    }

    private function imageReferenceFor(string $key): string
    {
        $images = (array) config('builds.images');
        $entry = $images[$key] ?? [];

        return is_array($entry) && is_string($entry['reference'] ?? null) ? $entry['reference'] : $key;
    }

    /**
     * The last lines of a runner log, for a failure message.
     *
     * @param  list<string|array<string, mixed>>  $log
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
