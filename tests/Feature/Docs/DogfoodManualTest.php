<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Docs;

use App\Docs\DogfoodPlan;
use App\Docs\GeneratedBlocks;
use Illuminate\Support\Facades\Artisan;
use Symfony\Component\Yaml\Yaml;
use Tests\Feature\Builds\PlainManualBuildTest;
use Tests\TestCase;

/**
 * 🛑 Phase 17's second exit criterion, in the half that needs no container.
 *
 * > "The same content builds with plain `mkdocs build`."
 *
 * {@see PlainManualBuildTest} runs the build. What is
 * here is the half a passing build does not prove: that the plain build and
 * the composed one cover the **same pages**. A fallback manual missing a
 * guide still builds, and the day anybody needs it is the day DocUp is
 * broken and nobody is checking.
 */
final class DogfoodManualTest extends TestCase
{
    /**
     * 🛑 The fallback's navigation names every page the composition serves.
     *
     * Both directions. A page in `docs/` and not in the root `mkdocs.yml` is
     * unreachable in the fallback; a page in the nav and not on disk fails
     * `mkdocs build --strict`, which is a worse way to find out.
     */
    public function test_the_plain_build_covers_every_page_the_composition_serves(): void
    {
        $composed = DogfoodPlan::sourcePages();
        $fallback = $this->navPagesOfTheRootConfig();

        sort($composed);
        sort($fallback);

        $this->assertSame(
            $composed,
            $fallback,
            'mkdocs.yml and DogfoodPlan disagree about which pages the manual has',
        );
    }

    /** And every page named actually exists. */
    public function test_every_page_in_the_plan_exists(): void
    {
        foreach (DogfoodPlan::sourcePages() as $page) {
            $this->assertFileExists(base_path($page));
        }
    }

    /**
     * 🛑 Each guide is independently buildable, which is what makes it a
     * repository rather than a directory.
     *
     * The composed site builds each guide on its own, in its own sandbox,
     * from its own `.docup.yaml` — so a guide whose configuration only works
     * when the others are present is not a component at all.
     */
    public function test_each_guide_is_a_self_contained_docset(): void
    {
        foreach (DogfoodPlan::guides() as $guide) {
            $config = base_path($guide['directory'].'/.docup.yaml');
            $mkdocs = base_path($guide['directory'].'/mkdocs.yml');

            $this->assertFileExists($config, $guide['key'].' has no .docup.yaml');
            $this->assertFileExists($mkdocs, $guide['key'].' has no mkdocs.yml');

            /** @var array{toolchain?: string, nav?: list<array<string, string>>} $parsed */
            $parsed = Yaml::parseFile($config);

            $this->assertSame('mkdocs', $parsed['toolchain'] ?? null);

            /*
             * 🛑 Every href in the declared nav is component-relative.
             * §8.7.6 drops an absolute or root-relative href during
             * normalisation rather than prefixing it into nonsense, so one
             * written here would vanish from the composed navigation with no
             * error anywhere.
             */
            foreach ($parsed['nav'] ?? [] as $entry) {
                foreach ($entry as $label => $href) {
                    $this->assertStringStartsNotWith('/', (string) $href, $guide['key'].': '.$label);
                    $this->assertStringStartsNotWith('http', (string) $href, $guide['key'].': '.$label);
                }
            }
        }
    }

    /**
     * 🛑 No page links across guides with a relative path.
     *
     * A cross-repository relative link has no spelling that is correct in
     * both places — it is wrong the moment a component is mounted somewhere
     * else, and `/_/x/<component>/` is dead in the plain build. This is
     * Phase 17's first real finding and the assertion that keeps it fixed.
     */
    public function test_no_guide_links_into_another_guide_with_a_relative_path(): void
    {
        $offenders = [];

        foreach (DogfoodPlan::sourcePages() as $page) {
            $body = (string) file_get_contents(base_path($page));

            if (preg_match_all('#\]\((\.\./[^)]*)\)#', $body, $matches) > 0) {
                foreach ($matches[1] as $link) {
                    $offenders[] = $page.' → '.$link;
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            'a relative link out of a component cannot be correct in both the composed site and the fallback: '
                .implode(', ', $offenders),
        );
    }

    /**
     * 🛑 The generated blocks are current.
     *
     * §8.7.13's matrix is the one that matters: an operator switches
     * composition modes on it, and a stale copy of a contract is worse than
     * an absent one.
     */
    public function test_every_generated_block_is_up_to_date(): void
    {
        $this->assertSame(
            0,
            Artisan::call('docup:docs:render', ['--check' => true]),
            'run `php artisan docup:docs:render` and commit: '.Artisan::output(),
        );
    }

    /** And every block the register names has its markers in place. */
    public function test_every_generated_block_has_its_markers(): void
    {
        foreach (GeneratedBlocks::all() as $page => $blocks) {
            $contents = (string) file_get_contents(base_path($page));

            foreach (array_keys($blocks) as $block) {
                $this->assertStringContainsString('<!-- BEGIN GENERATED: '.$block.' -->', $contents);
                $this->assertStringContainsString('<!-- END GENERATED: '.$block.' -->', $contents);
            }
        }
    }

    /**
     * The nav of the root `mkdocs.yml`, flattened to page paths relative to
     * the repository root.
     *
     * @return list<string>
     */
    private function navPagesOfTheRootConfig(): array
    {
        /** @var array{docs_dir?: string, nav?: list<mixed>} $config */
        $config = Yaml::parseFile(base_path('mkdocs.yml'));

        $root = ($config['docs_dir'] ?? 'docs').'/';

        return array_map(
            static fn (string $page): string => $root.$page,
            $this->flatten($config['nav'] ?? []),
        );
    }

    /**
     * @param  array<array-key, mixed>  $nav
     * @return list<string>
     */
    private function flatten(array $nav): array
    {
        $pages = [];

        foreach ($nav as $entry) {
            if (is_string($entry)) {
                $pages[] = $entry;

                continue;
            }

            if (! is_array($entry)) {
                continue;
            }

            foreach ($entry as $value) {
                if (is_string($value)) {
                    $pages[] = $value;
                } elseif (is_array($value)) {
                    $pages = array_merge($pages, $this->flatten($value));
                }
            }
        }

        return $pages;
    }
}
