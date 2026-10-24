<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Config;

use App\Builds\FailureCatalogue;
use App\Config\BuildJobs;
use App\Config\ConfigDiscovery;
use App\Config\ConfigParser;
use App\Config\ConfigRefused;
use App\Config\ConfigRejection;
use App\Config\YamlGate;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * §8.4's contract, and Phase 09's first three exit criteria.
 *
 * > "An unknown key, a 200 MB YAML bomb, a 40-deep nesting and a YAML alias
 * > expansion each fail with a **documented identifier in under a second**.
 * > 🛑 A configuration file naming a project, a domain or a visibility level
 * > is **rejected by the schema**."
 *
 * 🛑 **"In under a second" is asserted, not assumed.** It is the half of the
 * criterion that fails silently: a parser that eventually refuses a 200 MB
 * file has still read 200 MB, and a build worker that spends a minute on one
 * hostile configuration is a denial of service with a correct error message
 * at the end of it. The timing assertions here are generous by two orders of
 * magnitude against what {@see YamlGate} actually costs, because
 * a tight bound on a shared CI runner is a flaky test rather than a stronger
 * guarantee — what they catch is a future change that moves a cap after the
 * parse.
 */
final class ConfigContractTest extends TestCase
{
    /** The smallest file the schema accepts, for building cases on top of. */
    private const MINIMAL = "version: 2\ntoolchain: mkdocs\n";

    public function test_the_minimal_configuration_is_accepted(): void
    {
        $config = ConfigParser::parse(self::MINIMAL, '.docup.yaml');

        $this->assertSame('mkdocs', $config->declaredToolchain());
        $this->assertSame('.docup.yaml', $config->filename);
        $this->assertSame(hash('sha256', self::MINIMAL), $config->digest);
    }

    /**
     * 🛑 §8.4.2: "a **key- and value-compatible superset** of
     * `.readthedocs.yaml` v2: every key below is preserved verbatim, and so
     * are its accepted *values*."
     *
     * A real Read the Docs file, unmodified, exercising the value forms the
     * specification names one by one — the literal `all` for formats and
     * submodules, `ubuntu-lts-latest`, `latest` per tool, both `python.install`
     * forms, and `dirhtml`.
     */
    public function test_an_unmodified_read_the_docs_file_is_accepted(): void
    {
        $yaml = <<<'YAML'
        version: 2
        formats: all
        build:
          os: ubuntu-lts-latest
          tools:
            python: latest
            nodejs: "22"
          apt_packages:
            - graphviz
          jobs:
            post_checkout:
              - git fetch --unshallow || true
            pre_install:
              - echo preparing
            build:
              html:
                - sphinx-build -b html docs _build
        python:
          install:
            - requirements: docs/requirements.txt
            - path: .
              method: pip
              extra_requirements:
                - docs
        sphinx:
          builder: dirhtml
          configuration: docs/conf.py
          fail_on_warning: true
        submodules:
          include: all
          recursive: true
        search:
          ranking:
            api/v1/*: -5
          ignore:
            - changelog.html
        YAML;

        $config = ConfigParser::parse($yaml, '.readthedocs.yaml');

        $this->assertSame('sphinx', $config->declaredToolchain());
        $this->assertSame('dirhtml', $config->sphinxBuilder());
        $this->assertTrue($config->failOnWarning('sphinx'));
        $this->assertSame(['pdf', 'epub', 'htmlzip'], $config->formats());
        $this->assertSame(['graphviz'], $config->aptPackages());
        $this->assertCount(2, $config->pythonInstall());
        $this->assertSame(['git fetch --unshallow || true'], $config->jobs()->hook('post_checkout'));
    }

    /** The retired Read the Docs spelling of `dirhtml`, still accepted. */
    public function test_the_legacy_htmldir_builder_is_normalised(): void
    {
        $config = ConfigParser::parse("version: 2\nsphinx:\n  builder: htmldir\n", '.readthedocs.yaml');

        $this->assertSame('dirhtml', $config->sphinxBuilder());
    }

    // ---------------------------------------------------------------- caps

    public function test_an_oversized_file_is_refused_on_its_size_alone(): void
    {
        // 🛑 Not a 200 MB string in PHP memory — a file one byte over the
        // cap proves the same boundary and the timing assertion below is
        // what proves nothing read the whole of it.
        $yaml = "version: 2\n# ".str_repeat('x', ConfigRejection::MAX_BYTES);

        $this->assertRefusedQuickly($yaml, ConfigRejection::TooLarge);
    }

    /**
     * 🛑 The billion-laughs shape: a few hundred bytes that expand to
     * gigabytes. Refused on sight of the alias, before any expansion.
     */
    public function test_a_yaml_alias_bomb_is_refused_before_expansion(): void
    {
        $yaml = "version: 2\na: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n"
            ."b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            ."c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            ."d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n"
            ."e: [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n";

        $this->assertRefusedQuickly($yaml, ConfigRejection::AliasesForbidden);
    }

    public function test_forty_deep_nesting_is_refused(): void
    {
        $yaml = "version: 2\n";

        for ($depth = 0; $depth < 40; $depth++) {
            $yaml .= str_repeat('  ', $depth).'k'.$depth.":\n";
        }

        $yaml .= str_repeat('  ', 40)."leaf: 1\n";

        $this->assertRefusedQuickly($yaml, ConfigRejection::TooDeep);
    }

    /** Flow collections nest too, and on one line. */
    public function test_forty_deep_flow_nesting_is_refused(): void
    {
        $yaml = "version: 2\ndeep: ".str_repeat('[', 40).str_repeat(']', 40)."\n";

        $this->assertRefusedQuickly($yaml, ConfigRejection::TooDeep);
    }

    public function test_a_second_document_is_refused(): void
    {
        $this->assertRefusedQuickly(
            "version: 2\n---\nversion: 2\n",
            ConfigRejection::MultipleDocuments,
        );
    }

    /**
     * 🛑 The caps must not refuse legitimate files, which is the half a
     * cap-focused test suite forgets. A shell script in a `build.jobs` hook
     * is indented text, not structure; counting its indentation as nesting
     * would reject a real configuration and send somebody to patch the
     * check out.
     */
    public function test_a_deeply_indented_shell_script_in_a_hook_is_accepted(): void
    {
        $script = '';

        for ($depth = 1; $depth <= 20; $depth++) {
            $script .= str_repeat(' ', 8 + $depth * 2)."echo level {$depth}\n";
        }

        $yaml = "version: 2\ntoolchain: mkdocs\nbuild:\n  jobs:\n    post_build:\n      - |\n".$script;

        $config = ConfigParser::parse($yaml, '.docup.yaml');

        $this->assertNotSame([], $config->jobs()->hook('post_build'));
    }

    /** `&&` and `*` are ordinary characters in a command, not YAML nodes. */
    public function test_ampersands_and_asterisks_inside_commands_are_not_aliases(): void
    {
        $yaml = "version: 2\nbuild:\n  commands:\n"
            ."    - make -j2 && make html\n"
            ."    - rm -rf build/*\n"
            ."    - find . -name '*.pyc' -delete\n";

        $config = ConfigParser::parse($yaml, '.docup.yaml');

        $this->assertCount(3, $config->commands());
    }

    // ------------------------------------------------------------ contract

    public function test_an_unknown_key_is_refused_with_its_name(): void
    {
        $refused = $this->refusal("version: 2\nnot_a_real_key: 1\n");

        $this->assertSame(ConfigRejection::UnknownKey, $refused->rejection);
        $this->assertContains('not_a_real_key', $refused->offendingKeys);
    }

    public function test_an_unknown_nested_key_names_its_path(): void
    {
        $refused = $this->refusal("version: 2\nbuild:\n  nonsense: 1\n");

        $this->assertSame(ConfigRejection::UnknownKey, $refused->rejection);
        $this->assertContains('build.nonsense', $refused->offendingKeys);
    }

    /**
     * 🛑 Phase 09's third exit criterion, and §8.4.8's invariant: "The
     * configuration file MUST NOT accept any key naming a project, mount
     * path, domain, authentication policy, visibility, version channel or
     * retention policy, and the schema MUST set `additionalProperties:
     * false`."
     *
     * Every forbidden word is tried, not a representative three. The list is
     * the one the parser uses for its better message, so this test is also
     * what stops that list quietly becoming a list of keys that work.
     */
    #[DataProvider('projectScopedKeys')]
    public function test_a_project_scoped_key_is_rejected_by_the_schema(string $key): void
    {
        $refused = $this->refusal("version: 2\n{$key}: something\n");

        $this->assertSame(ConfigRejection::ProjectScopedKey, $refused->rejection);
        $this->assertContains($key, $refused->offendingKeys);
        $this->assertStringContainsString($key, $refused->userMessage());
    }

    /** @return iterable<string, array{string}> */
    public static function projectScopedKeys(): iterable
    {
        foreach (ConfigParser::PROJECT_SCOPED_KEYS as $key) {
            yield $key => [$key];
        }
    }

    /** §8.4.4: "MUST NOT be combinable with `build.apt_packages`". */
    public function test_commands_with_apt_packages_is_refused(): void
    {
        $refused = $this->refusal(
            "version: 2\nbuild:\n  apt_packages: [graphviz]\n  commands:\n    - make html\n",
        );

        $this->assertSame(ConfigRejection::CommandsWithAptPackages, $refused->rejection);
    }

    /** Either alone is fine; it is only the pair that is refused. */
    public function test_commands_alone_and_apt_packages_alone_are_both_accepted(): void
    {
        $this->assertTrue(
            ConfigParser::parse("version: 2\nbuild:\n  commands:\n    - make html\n", '.docup.yaml')->hasCommands(),
        );

        $this->assertSame(
            ['graphviz'],
            ConfigParser::parse("version: 2\ntoolchain: mkdocs\nbuild:\n  apt_packages: [graphviz]\n", '.docup.yaml')
                ->aptPackages(),
        );
    }

    /** §8.4.14: parseable, and not runnable in v1. */
    public function test_conda_is_accepted_by_the_schema_and_refused_by_name(): void
    {
        $refused = $this->refusal("version: 2\nconda:\n  environment: environment.yml\n");

        $this->assertSame(ConfigRejection::CondaUnsupported, $refused->rejection);

        // 🛑 The sentence must name the alternatives, or the author has a
        // refusal and nowhere to go.
        $this->assertStringContainsString('python.install', $refused->userMessage());
        $this->assertStringContainsString('build.commands', $refused->userMessage());
    }

    /**
     * A typo inside `conda` is still a typo, not an unsupported feature.
     *
     * 🛑 The schema sees it as `environment` being absent rather than as
     * `enviroment` being unknown — `required` is evaluated before
     * `additionalProperties` and the validator stops there — so the refusal
     * names the key that should have been written. Either view points at the
     * same three characters; what matters is that it is not reported as
     * "conda is not supported", which would send the author away from a
     * configuration that would otherwise have been refused for a reason they
     * can act on.
     */
    public function test_a_misspelled_conda_key_is_a_typo_rather_than_an_unsupported_feature(): void
    {
        $refused = $this->refusal("version: 2\nconda:\n  enviroment: environment.yml\n");

        $this->assertSame(ConfigRejection::MissingKey, $refused->rejection);
        $this->assertContains('conda.environment', $refused->offendingKeys);
    }

    public function test_a_traversing_path_is_refused(): void
    {
        $refused = $this->refusal("version: 2\nsphinx:\n  configuration: ../../etc/passwd\n");

        $this->assertSame(ConfigRejection::InvalidValue, $refused->rejection);
    }

    public function test_an_absolute_path_is_refused(): void
    {
        $refused = $this->refusal("version: 2\nsphinx:\n  configuration: /etc/passwd\n");

        $this->assertSame(ConfigRejection::InvalidValue, $refused->rejection);
    }

    public function test_an_unknown_build_os_is_refused(): void
    {
        $refused = $this->refusal("version: 2\ntoolchain: mkdocs\nbuild:\n  os: ubuntu --privileged\n");

        $this->assertSame(ConfigRejection::InvalidValue, $refused->rejection);
    }

    // ------------------------------------------------------- discovery &c.

    /** §8.4.1's order, and the fetcher's, are the same list. */
    public function test_the_fetcher_walks_the_same_discovery_order(): void
    {
        $script = (string) file_get_contents(base_path('deploy/fetch-entrypoint.sh'));

        $this->assertStringContainsString(
            'for candidate in '.implode(' ', ConfigDiscovery::CANDIDATES).';',
            $script,
            'deploy/fetch-entrypoint.sh must walk §8.4.1 in the same order ConfigDiscovery declares',
        );
    }

    /**
     * 🛑 Every hook name the pipeline honours is a key the schema accepts.
     *
     * The failure this catches is silent in the worst way: a hook the schema
     * rejects is a loud error, but a hook the schema **accepts** and the
     * pipeline never reads is an author's commands quietly not running.
     */
    public function test_every_hook_name_is_in_the_schema(): void
    {
        $schema = json_decode((string) file_get_contents(ConfigParser::schemaPath()), true, 32, JSON_THROW_ON_ERROR);

        $this->assertIsArray($schema);
        $declared = array_keys($schema['properties']['build']['properties']['jobs']['properties']);

        sort($declared);

        $this->assertSame(BuildJobs::hookNames(), $declared);
    }

    /** Every refusal has a sentence; a build that stops with none is a gap. */
    public function test_every_rejection_has_a_message(): void
    {
        foreach (ConfigRejection::identifiers() as $identifier) {
            $this->assertTrue(
                FailureCatalogue::has($identifier),
                $identifier.' has no entry in FailureCatalogue',
            );
        }
    }

    // ----------------------------------------------------------- helpers

    private function refusal(string $yaml): ConfigRefused
    {
        try {
            ConfigParser::parse($yaml, '.docup.yaml');
        } catch (ConfigRefused $refused) {
            return $refused;
        }

        $this->fail('the configuration was accepted');
    }

    private function assertRefusedQuickly(string $yaml, ConfigRejection $expected): void
    {
        $started = hrtime(true);
        $refused = $this->refusal($yaml);
        $elapsed = (hrtime(true) - $started) / 1_000_000_000;

        $this->assertSame($expected, $refused->rejection);
        $this->assertLessThan(1.0, $elapsed, 'the refusal took '.$elapsed.'s; the criterion is under a second');
    }
}
