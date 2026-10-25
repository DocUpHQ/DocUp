<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Docs\DogfoodPlan;
use Tests\Support\RequiresBuildImages;
use Tests\TestCase;

/**
 * 🛑 Phase 17's second exit criterion, run rather than claimed.
 *
 * > "The same content builds with plain `mkdocs build`."
 *
 * The point of the parallel build is that the manual survives DocUp being
 * broken, so this is deliberately **not** a DocUp build: no plan, no
 * sandbox hardening, no toolchain preset, no `$DOCUP_OUTPUT`. One
 * `mkdocs build --strict` over the committed tree, the way somebody with a
 * checkout and a bad day would run it.
 *
 * `--strict` rather than a bare build, because the failure this guards
 * against is silent: MkDocs warns about a broken internal link and exits
 * zero, so a fallback manual whose links had rotted would still "build".
 *
 * 🛑 Runs in the `runner` container, which is the only process §8.5.13 lets
 * hold the runtime socket.
 */
final class PlainManualBuildTest extends TestCase
{
    use RequiresBuildImages;

    private ?string $staged = null;

    protected function setUp(): void
    {
        parent::setUp();

        $this->requireBuildImages(['docup/build-mkdocs:1']);
    }

    protected function tearDown(): void
    {
        if (is_string($this->staged) && is_dir($this->staged)) {
            $this->execute(['rm', '-rf', $this->staged]);
        }

        parent::tearDown();
    }

    /**
     * 🛑 The whole manual, one plain build, every page present.
     */
    public function test_the_manual_builds_without_docup(): void
    {
        $manual = $this->stageTheManual();

        /*
         * 🛑 One command, and its output is the assertion. `--strict` turns
         * a broken internal link into a failure — a bare build warns and
         * exits zero — and the `find` that follows catches what `--strict`
         * does not: a nav entry whose page was removed, which builds a
         * smaller site perfectly happily.
         */
        [$status, $output] = $this->execute([
            'docker', 'run', '--rm',
            // Read-only: a fallback build that needed to write into the
            // checkout would be one more thing to go wrong on the bad day.
            '--volume', $manual.':/manual:ro',
            '--workdir', '/manual',
            // No network. The fallback exists for when things are broken,
            // and one that needed to reach a package index would not be one.
            '--network', 'none',
            'docup/build-mkdocs:1',
            'sh', '-c',
            'mkdocs build --strict --site-dir /tmp/site && cd /tmp/site && find . -name index.html | sort',
        ]);

        $this->assertSame(0, $status, "mkdocs build --strict failed:\n".$output);

        foreach (DogfoodPlan::sourcePages() as $page) {
            // `docs/author/docs/builds.md` is served at
            // `author/docs/builds/index.html` by MkDocs' directory URLs.
            $expected = './'.preg_replace('#^docs/|\.md$#', '', $page);
            $expected = str_ends_with($expected, '/index') ? substr($expected, 0, -6) : $expected;

            $this->assertStringContainsString(
                rtrim($expected, '/').'/index.html',
                $output,
                $page.' is missing from the plain build',
            );
        }
    }

    /**
     * The manual, where a nested `docker run` can mount it.
     *
     * 🛑 `base_path()` is `/app` **inside** this container and means nothing
     * to the daemon, which resolves a bind source on the host. §8.5.13's
     * workspace root is the one path compose bind-mounts at the same
     * location on both sides, which is why the runner's own sandboxes live
     * there — so the manual is copied there rather than mounted from a path
     * only this process can see.
     */
    private function stageTheManual(): string
    {
        $root = rtrim((string) config('builds.workspace_root'), '/');
        $manual = $root.'/manual-'.bin2hex(random_bytes(4));

        mkdir($manual.'/docs', 0o755, true);
        copy(base_path('mkdocs.yml'), $manual.'/mkdocs.yml');

        foreach (DogfoodPlan::guides() as $guide) {
            $target = $manual.'/'.$guide['directory'].'/docs';
            mkdir($target, 0o755, true);

            foreach ($guide['pages'] as $page) {
                copy(base_path($guide['directory'].'/docs/'.$page.'.md'), $target.'/'.$page.'.md');
            }
        }

        $this->staged = $manual;

        return $manual;
    }

    /**
     * @param  list<string>  $argv
     * @return array{0: int, 1: string}
     */
    private function execute(array $argv): array
    {
        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            return [-1, 'could not start '.implode(' ', $argv)];
        }

        $output = '';

        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                $output .= (string) stream_get_contents($pipe);
                fclose($pipe);
            }
        }

        return [proc_close($process), $output];
    }
}
