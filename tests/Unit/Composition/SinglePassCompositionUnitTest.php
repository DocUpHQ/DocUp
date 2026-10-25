<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Builds\Toolchain\ToolchainPresets;
use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;
use App\Composition\SinglePass\AntoraPlaybook;
use App\Composition\SinglePass\Composer;
use App\Composition\SinglePass\GeneratedComposition;
use App\Config\ConfigParser;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Yaml\Yaml;
use Tests\Feature\Builds\SinglePassCompositionTest;

/**
 * 🛑 §8.7.12's generated playbook, examined rather than run.
 *
 * {@see SinglePassCompositionTest} proves the
 * composition builds a site in the real sandbox. These are the properties
 * that make the sentence "a contributing repository cannot redirect
 * sources or add a fourth repository" true, and each one is easier to
 * break than to notice: a path inside a checkout, a mount path in the
 * playbook, a shell escape in the materialising command.
 */
final class SinglePassCompositionUnitTest extends TestCase
{
    /**
     * 🛑 The generated file lives OUTSIDE every checkout.
     *
     * The whole guarantee rests on this: a repository that could contain
     * the playbook's path could ship a file that is mistaken for it, or
     * overwrite it between the composition stage and the build stage.
     */
    public function test_the_playbook_is_written_outside_every_checkout(): void
    {
        $composition = new GeneratedComposition('antora-playbook.yml', 'site: {}');

        $this->assertSame('/workspace/composition/antora-playbook.yml', $composition->path());
        $this->assertStringStartsNotWith('/workspace/source', $composition->path());
    }

    /**
     * 🛑 The bytes travel base64-encoded, so the playbook's own content
     * can never be read as shell syntax.
     *
     * A playbook contains paths, quotes and newlines. Written with a
     * heredoc or an echo, a source path containing a quote would end the
     * argument; base64's alphabet is closed, and there is no sequence of
     * its characters that does.
     */
    public function test_the_playbook_reaches_the_sandbox_as_base64(): void
    {
        $contents = "site:\n  title: \"it's \$(whoami) `id`\"\n";
        $commands = (new GeneratedComposition('antora-playbook.yml', $contents))->commands();

        $joined = implode("\n", $commands);

        $this->assertStringContainsString(base64_encode($contents), $joined);
        $this->assertStringContainsString('base64 -d', $joined);

        // The dangerous substrings are present only inside the encoding,
        // never as syntax.
        $this->assertStringNotContainsString('$(whoami)', $joined);
        $this->assertStringNotContainsString('`id`', $joined);
    }

    /**
     * 🛑 The playbook names local paths and nothing remote.
     *
     * §8.5.1 pins every contributing ref before any repository code runs,
     * and a playbook naming a URL would fetch something nothing had
     * pinned. The preset refuses `--fetch` for the same reason; this is
     * the other half.
     */
    public function test_the_generated_playbook_names_only_local_checkouts(): void
    {
        $playbook = $this->generate();

        $this->assertIsArray($playbook['content']['sources']);
        $this->assertCount(2, $playbook['content']['sources']);

        foreach ($playbook['content']['sources'] as $source) {
            $this->assertStringStartsWith('/workspace/source/', (string) $source['url']);
            $this->assertSame('HEAD', $source['branches']);
        }
    }

    /**
     * 🛑 §8.7.10 does not stop applying because the mode changed.
     *
     * A mount path under `base_url_mode='relative'` must not enter a build
     * container, and `single_pass` suspends only the one-component-per-
     * build assumption. Antora decides a page's URL from the component's
     * own `antora.yml`, so the mount path is not needed and is not sent.
     */
    public function test_no_mount_path_reaches_the_playbook(): void
    {
        $encoded = Yaml::dump($this->generate(), 6, 2);

        $this->assertStringNotContainsString('guides/advanced', $encoded);
        $this->assertStringNotContainsString('mount', $encoded);
    }

    /**
     * 🛑 The primary must say what the site root is, and a missing answer
     * is a refusal rather than a guess.
     *
     * Every wrong guess produces a site whose front page is somebody
     * else's section, which looks deliberate.
     */
    public function test_a_missing_start_page_is_refused(): void
    {
        try {
            (new AntoraPlaybook)->generate(
                [SlotFactory::make('handbook', '', true)],
                ConfigParser::parse("version: 2\ntoolchain: antora\n", '.docup.yaml'),
                'https://example.invalid/ui.zip',
            );

            $this->fail('a composed Antora site with no start page must be refused');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::SinglePassStartPageMissing, $refused->rejection);
        }
    }

    /**
     * 🛑 A preset DocUp cannot write a source list for is **refused**, not
     * quietly built under the other mode's rules.
     *
     * Falling back to `mount` would give a project a different 404 chain,
     * a different cross-reference mechanism and a different failure
     * domain from the one its operator chose — §8.7.13's "single largest
     * specification risk in the composition area".
     */
    public function test_an_uncomposable_preset_is_refused(): void
    {
        foreach (ToolchainPresets::names() as $name) {
            if ($name === 'antora') {
                continue;
            }

            try {
                (new Composer)->compose(
                    ToolchainPresets::get($name),
                    [SlotFactory::make('handbook', '', true)],
                    ConfigParser::parse("version: 2\n", '.docup.yaml'),
                    'https://example.invalid/ui.zip',
                );

                $this->fail($name.' must be refused in single_pass until it can be composed');
            } catch (CompositionRefused $refused) {
                $this->assertSame(CompositionRejection::SinglePassUnsupportedToolchain, $refused->rejection);

                // 🛑 And the refusal carries the documented reason, so an
                // operator reading a build log learns why rather than that.
                $this->assertStringContainsString(
                    substr(Composer::PRECEDENCE[$name], 0, 40),
                    $refused->getMessage(),
                );
            }
        }
    }

    /** One throwaway git repository per slot, because Antora reads repositories. */
    public function test_each_slot_is_prepared_as_its_own_repository(): void
    {
        $composition = $this->composition();
        $prepare = implode("\n", $composition->prepare);

        $this->assertStringContainsString('/workspace/source/handbook', $prepare);
        $this->assertStringContainsString('/workspace/source/glossary', $prepare);
        $this->assertSame(2, substr_count($prepare, 'git init --quiet'));

        // 🛑 Fixed dates, so the commit — and therefore Antora's output —
        // is the same on every build of the same sources (§18.13).
        $this->assertStringContainsString('SOURCE_DATE_EPOCH', $prepare);
    }

    /** @return array<string, mixed> */
    private function generate(): array
    {
        /** @var array<string, mixed> $decoded */
        $decoded = Yaml::parse($this->composition()->contents);

        return $decoded;
    }

    private function composition(): GeneratedComposition
    {
        return (new AntoraPlaybook)->generate(
            [
                SlotFactory::make('handbook', 'docs', true),
                SlotFactory::make('glossary', 'docs', false),
            ],
            ConfigParser::parse(
                "version: 2\ntoolchain: antora\nantora:\n  start_page: handbook::index.adoc\n",
                '.docup.yaml',
            ),
            'https://example.invalid/ui.zip',
        );
    }
}
