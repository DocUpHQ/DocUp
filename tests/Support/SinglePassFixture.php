<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

use App\Builds\BuildEnvironment;
use App\Builds\Toolchain\ToolchainPlan;
use App\Composition\SinglePass\AntoraPlaybook;
use App\Composition\SinglePass\GeneratedComposition;
use App\Composition\SinglePass\SourceSlot;
use App\Config\ConfigParser;
use Symfony\Component\Yaml\Yaml;

/**
 * Three repositories that make one manual, for §17 Phase 15's exit criteria.
 *
 * Deliberately **not** in {@see GeneratorFixtures}: those are the §17 Phase
 * 09 "twelve lines of configuration" corpus, one per generator, and their
 * budget is asserted. These are three sources that only mean anything
 * together.
 *
 * 🛑 The shape mirrors what the pipeline produces rather than what a test
 * finds convenient: one directory per slot under `/workspace/source`,
 * named as {@see SourceSlot} names them, and a
 * playbook DocUp generates from the plan rather than one the fixture
 * ships.
 */
final class SinglePassFixture
{
    /**
     * A handbook, a reference and a glossary, cross-referencing each other.
     *
     * @return array{sources: array<string, array<string, string>>, primary: string, config: string}
     */
    public static function threeSources(): array
    {
        return [
            'primary' => 'handbook',
            'config' => self::config(),
            'sources' => [
                'handbook' => self::component(
                    'handbook',
                    "= Handbook\n\nThe front page.\n\n"
                        // 🛑 The cross-source reference the criterion is about.
                        ."See the xref:glossary::terms.adoc[glossary] for the words.\n",
                ),
                'reference' => self::component('reference', "= Reference\n\nThe API.\n"),
                'glossary' => self::component('glossary', "= Glossary\n\nThe words.\n", [
                    'docs/modules/ROOT/pages/terms.adoc' => "= Terms\n\nA term.\n",
                ]),
            ],
        ];
    }

    /**
     * 🛑 The same three, where one ships a playbook that tries to add a
     * fourth source and redirect an existing one.
     *
     * The fourth source is a **valid** component sitting on disk, so the
     * only thing keeping it out of the site is that DocUp's playbook is
     * the one Antora reads. A fixture whose fourth source could not have
     * built would pass this test for the wrong reason.
     *
     * @return array{sources: array<string, array<string, string>>, primary: string, config: string}
     */
    public static function withAHostilePlaybook(): array
    {
        $fixture = self::threeSources();

        $fixture['sources']['glossary']['antora-playbook.yml'] = Yaml::dump([
            'site' => ['start_page' => 'intruder::index.adoc'],
            'content' => [
                'sources' => [
                    // A fourth source, which exists and would build.
                    ['url' => BuildEnvironment::REPOSITORY_PATH.'/intruder', 'branches' => 'HEAD', 'start_path' => 'docs'],
                    // And an attempt to re-point an existing one at itself.
                    ['url' => BuildEnvironment::REPOSITORY_PATH.'/intruder', 'branches' => 'HEAD', 'start_path' => 'docs'],
                ],
            ],
            'ui' => ['bundle' => ['url' => 'https://example.invalid/ui.zip']],
        ], 6, 2);

        $fixture['sources']['intruder'] = self::component('intruder', "= Intruder\n\nShould not be here.\n");

        return $fixture;
    }

    /**
     * The composition DocUp would generate for these slots.
     *
     * Built through the real {@see AntoraPlaybook} so the test exercises
     * the generator rather than a copy of it — the file under test is the
     * one the pipeline writes.
     *
     * @param  list<string>  $slots  directory names under `/workspace/source`
     */
    public static function composition(array $slots, string $config): GeneratedComposition
    {
        $entries = [];
        $prepare = [];

        foreach ($slots as $slot) {
            if ($slot === 'intruder') {
                // Present on disk, absent from the plan. That is the whole
                // of the 🛑 criterion: DocUp's playbook decides.
                continue;
            }

            $path = BuildEnvironment::REPOSITORY_PATH.'/'.$slot;

            $entries[] = ['url' => $path, 'branches' => 'HEAD', 'start_path' => 'docs'];

            $prepare[] = 'if [ ! -d '.ToolchainPlan::quote($path.'/.git').' ]; then '
                .'( cd '.ToolchainPlan::quote($path).' '
                .'&& export GIT_AUTHOR_DATE="@${SOURCE_DATE_EPOCH} +0000" '
                .'&& export GIT_COMMITTER_DATE="@${SOURCE_DATE_EPOCH} +0000" '
                .'&& git init --quiet --initial-branch=main . '
                .'&& git -c user.email=build@docup.invalid -c user.name=DocUp add --all '
                .'&& git -c user.email=build@docup.invalid -c user.name=DocUp '
                .'commit --quiet --no-gpg-sign -m "DocUp build snapshot" ); fi';
        }

        $playbook = [
            'site' => ['start_page' => (string) ConfigParser::parse($config, '.docup.yaml')->antoraStartPage()],
            'content' => ['sources' => $entries],
            'ui' => ['bundle' => [
                'url' => (string) config('builds.antora.ui_bundle'),
                'snapshot' => true,
            ]],
        ];

        return new GeneratedComposition(
            filename: AntoraPlaybook::FILENAME,
            contents: Yaml::dump($playbook, 6, 2),
            prepare: $prepare,
        );
    }

    /** The primary component's `.docup.yaml`, which owns the site root (§8.7.3). */
    public static function config(): string
    {
        return "version: 2\ntoolchain: antora\nantora:\n  start_page: handbook::index.adoc\n";
    }

    /**
     * One Antora component: its descriptor, its nav and its index page.
     *
     * @param  array<string, string>  $extra
     * @return array<string, string>
     */
    private static function component(string $name, string $index, array $extra = []): array
    {
        return array_merge([
            'docs/antora.yml' => "name: {$name}\nversion: ~\nnav:\n  - modules/ROOT/nav.adoc\n",
            'docs/modules/ROOT/nav.adoc' => '* xref:index.adoc['.ucfirst($name)."]\n",
            'docs/modules/ROOT/pages/index.adoc' => $index,
        ], $extra);
    }
}
