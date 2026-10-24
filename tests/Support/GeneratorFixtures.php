<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

/**
 * The smallest real site each shipped generator can build, and the
 * `.docup.yaml` that drives it.
 *
 * 🛑 Phase 09's first exit criterion is "**Each of six generators builds
 * from ≤12 lines of configuration**", and the configuration is the thing
 * being measured — so each fixture's `.docup.yaml` is here in full, as
 * source, where its line count can be counted by a test rather than
 * claimed. `ConfigurationBudget` is that count.
 *
 * 🛑 **These are DocUp's own fixtures, not somebody's repository.** §18.12
 * asks a different and harder question — "can the hardened sandbox run the
 * real generator ecosystem", with a ten-repository conformance suite of real
 * projects, Sphinx autodoc importing project code, MkDocs plugin ecosystems
 * and all — and it stays unverified. What these prove is the contract: a
 * preset is a data file, the output contract is one directory, and twelve
 * lines of YAML is enough to reach it.
 */
final class GeneratorFixtures
{
    /** 🛑 §17's budget, asserted against every fixture's `.docup.yaml`. */
    public const CONFIGURATION_BUDGET = 12;

    /**
     * Every fixture, keyed by toolchain.
     *
     * @return array<string, array<string, string>> toolchain => path => contents
     */
    public static function all(): array
    {
        return [
            'mkdocs' => self::mkdocs(),
            'sphinx' => self::sphinx(),
            'mdbook' => self::mdbook(),
            'docusaurus' => self::docusaurus(),
            'vitepress' => self::vitepress(),
            'starlight' => self::starlight(),
            'antora' => self::antora(),
        ];
    }

    /**
     * The ones that need no package manager, and therefore no egress.
     *
     * Separated because they are seconds where the Node ones are minutes:
     * a developer iterating on the pipeline runs these, and CI runs all of
     * them.
     *
     * @return list<string>
     */
    public static function offline(): array
    {
        return ['mkdocs', 'sphinx', 'mdbook'];
    }

    /** @return array<string, string> */
    private static function mkdocs(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: mkdocs
            mkdocs:
              configuration: mkdocs.yml
              fail_on_warning: true
            YAML,

            'mkdocs.yml' => "site_name: Fixture\nnav:\n  - Home: index.md\n",
            'docs/index.md' => "# Fixture\n\nBuilt by DocUp.\n",
        ];
    }

    /** @return array<string, string> */
    private static function sphinx(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: sphinx
            sphinx:
              builder: dirhtml
              configuration: docs/conf.py
            YAML,

            // `html_theme` is left at the default: the point of the fixture
            // is the pipeline, and a theme is a dependency question §18.12
            // owns.
            'docs/conf.py' => "project = 'Fixture'\nextensions = []\nexclude_patterns = ['_build']\n",
            'docs/index.rst' => "Fixture\n=======\n\nBuilt by DocUp.\n",
        ];
    }

    /** @return array<string, string> */
    private static function mdbook(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: mdbook
            YAML,

            'book.toml' => "[book]\ntitle = \"Fixture\"\nsrc = \"src\"\n",
            'src/SUMMARY.md' => "# Summary\n\n- [Home](./index.md)\n",
            'src/index.md' => "# Fixture\n\nBuilt by DocUp.\n",
        ];
    }

    /** @return array<string, string> */
    private static function docusaurus(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: docusaurus
            build:
              os: ubuntu-24.04
              tools:
                nodejs: "22"
            YAML,

            // Exact versions, not ranges. §18.13's determinism note says the
            // fragment cache depends on the resolved tree being stable, and
            // a fixture that floated would also make this test's duration
            // depend on what npm published this morning.
            'package.json' => json_encode([
                'name' => 'docup-fixture',
                'private' => true,
                'dependencies' => [
                    '@docusaurus/core' => '3.10.2',
                    '@docusaurus/preset-classic' => '3.10.2',
                    'react' => '18.3.1',
                    'react-dom' => '18.3.1',
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",

            'docusaurus.config.js' => <<<'JS'
            module.exports = {
              title: 'Fixture',
              url: 'https://example.invalid',
              baseUrl: '/',
              presets: [['classic', { docs: { routeBasePath: '/' }, blog: false }]],
            };
            JS,

            'docs/intro.md' => "---\nslug: /\n---\n\n# Fixture\n\nBuilt by DocUp.\n",
        ];
    }

    /** @return array<string, string> */
    private static function vitepress(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: vitepress
            build:
              os: ubuntu-24.04
              tools:
                nodejs: "22"
            YAML,

            'package.json' => json_encode([
                'name' => 'docup-fixture',
                'private' => true,
                'type' => 'module',
                'devDependencies' => ['vitepress' => '1.5.0'],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",

            'docs/.vitepress/config.mjs' => "export default { title: 'Fixture', description: 'Built by DocUp' }\n",
            'docs/index.md' => "# Fixture\n\nBuilt by DocUp.\n",
        ];
    }

    /** @return array<string, string> */
    private static function starlight(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: starlight
            build:
              os: ubuntu-24.04
              tools:
                nodejs: "22"
            YAML,

            'package.json' => json_encode([
                'name' => 'docup-fixture',
                'private' => true,
                'type' => 'module',
                'dependencies' => [
                    '@astrojs/starlight' => '0.29.2',
                    'astro' => '4.16.18',
                ],
            ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",

            'astro.config.mjs' => <<<'JS'
            import { defineConfig } from 'astro/config';
            import starlight from '@astrojs/starlight';

            export default defineConfig({ integrations: [starlight({ title: 'Fixture' })] });
            JS,

            'src/content/config.ts' => <<<'TS'
            import { defineCollection } from 'astro:content';
            import { docsSchema } from '@astrojs/starlight/schema';

            export const collections = { docs: defineCollection({ schema: docsSchema() }) };
            TS,

            'src/content/docs/index.md' => "---\ntitle: Fixture\n---\n\nBuilt by DocUp.\n",
        ];
    }

    /**
     * Antora, whose content sources are **git repositories**.
     *
     * 🛑 This is the fixture that exposes a real conflict with §8.5.7, which
     * removes `.git` before the build stage so that a build container holds
     * no remote URL and no credential cache. Antora's playbook reads content
     * from a repository rather than from a directory, so a worktree with no
     * `.git` is not a content source it can use. Recorded rather than worked
     * around — see the build log.
     *
     * @return array<string, string>
     */
    private static function antora(): array
    {
        return [
            '.docup.yaml' => <<<'YAML'
            version: 2
            toolchain: antora
            build:
              os: ubuntu-24.04
              tools:
                nodejs: "22"
            YAML,

            // 🛑 `ui.bundle.url` is required by Antora and is a REMOTE
            // fetch — gitlab.com, which is on §8.5.9's allowlist because it
            // is a git host. That it works at all is a result: an Antora
            // build reaches the network during the build stage, through the
            // CONNECT proxy, with the nftables backstop behind it.
            'antora-playbook.yml' => <<<'YAML'
            site:
              title: Fixture
              # 🛑 §8.4.5 makes `html/index.html` mandatory, and Antora emits
              # pages under `<component>/<version>/` with nothing at the root
              # unless a start page is named. Antora's own documentation calls
              # this out; here it is the difference between a site and a
              # `contract.no_output_directory`.
              start_page: fixture::index.adoc
            content:
              sources:
                - url: .
                  start_path: docs
            ui:
              bundle:
                url: https://gitlab.com/antora/antora-ui-default/-/jobs/artifacts/HEAD/raw/build/ui-bundle.zip?job=bundle-stable
                snapshot: true
            YAML,

            'docs/antora.yml' => "name: fixture\nversion: ~\nnav:\n  - modules/ROOT/nav.adoc\n",
            'docs/modules/ROOT/nav.adoc' => "* xref:index.adoc[Home]\n",
            'docs/modules/ROOT/pages/index.adoc' => "= Fixture\n\nBuilt by DocUp.\n",
        ];
    }
}
