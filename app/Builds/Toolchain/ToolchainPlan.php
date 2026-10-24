<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Toolchain;

use App\Builds\BuildEnvironment;
use App\Builds\BuildPipeline;
use App\Config\BuildJobs;
use App\Config\ConfigRefused;
use App\Config\ConfigRejection;
use App\Config\DocupConfig;
use App\Config\HtmlContext;
use App\Config\ShellSemantics;

/**
 * One preset, one configuration file and one checkout, resolved into the two
 * scripts a build runs.
 *
 * This is where §8.4's halves meet: the preset supplies the predefined
 * pipeline (§11.4), the configuration supplies the hooks and replacements
 * (§8.4.3) or discards the pipeline entirely (§8.4.4), and §8.4.10 decides
 * what shell they run under. Keeping the join here means
 * {@see ToolchainPreset} stays data and {@see BuildPipeline} stays
 * a sequence of stages.
 *
 * 🛑 **Repository values reach the script as environment variables, never as
 * text spliced into a command.** A quoted `"$DOCUP_CONFIGURATION"` is one
 * word whatever is in it. The exceptions are §8.4.2's `python.install`
 * entries, where the count is unbounded so a variable per entry is not
 * available — those are single-quote escaped by {@see quote()}, which is the
 * same guarantee reached a different way.
 */
final readonly class ToolchainPlan
{
    /** Scratch inside the workspace: doctrees, caches, anything not published. */
    public const WORK_PATH = '/workspace/work';

    private function __construct(
        public ToolchainPreset $preset,
        public DocupConfig $config,
        public BuildJobs $jobs,
        public ShellSemantics $semantics,
        public string $sourceDir,
        public ?string $configuration,
        public HtmlContext $htmlContext,
    ) {}

    /**
     * Resolve a plan, or refuse with a §8.4 identifier.
     *
     * @param  string  $sourcePath  the component's `source_path`, relative
     * @param  list<string>  $presentFiles  what the fetcher saw, relative to `source_path`
     *
     * @throws ConfigRefused
     */
    public static function resolve(
        DocupConfig $config,
        string $sourcePath,
        array $presentFiles,
        HtmlContext $htmlContext,
        ShellSemantics $semantics = ShellSemantics::Strict,
    ): self {
        $declared = $config->declaredToolchain();

        /*
         * §8.4.4: `build.commands` "MUST discard the predefined pipeline
         * entirely", so a file carrying it needs no preset at all — which is
         * how a generator nobody has written a preset for still works today.
         * It is checked before the toolchain so that `build.commands` plus a
         * `toolchain:` is the commands, not a confusing half of each.
         */
        if ($declared === null && ! $config->hasCommands()) {
            /*
             * 🛑 Inferred only when the answer is unambiguous: exactly one
             * preset's marker files are in the checkout.
             *
             * Not a convenience. A repository holding `mkdocs.yml` and
             * nothing else has said which generator it uses as plainly as a
             * `toolchain:` key would, and refusing it would lose a case
             * Phase 06 already built for no gain in safety — the generator
             * is decided by a file in the repository either way. What is
             * refused is the case where guessing would be guessing: zero
             * matches, or several. A repository with both `mkdocs.yml` and
             * `docusaurus.config.js` gets a refusal naming both, because
             * picking one would produce a different site from the one its
             * author expected with no line anywhere saying why. The
             * inference is narrated by the pipeline either way.
             */
            $matches = ToolchainPresets::suggestionsFor($presentFiles);

            if (count($matches) !== 1) {
                throw ConfigRefused::of(
                    ConfigRejection::NoToolchain,
                    $matches === []
                        ? 'no generator could be inferred from the checkout'
                        : 'the checkout matches several generators: '.implode(', ', $matches),
                );
            }

            $declared = $matches[0];
        }

        $preset = ToolchainPresets::get($declared ?? 'mkdocs');

        $configuration = $config->hasCommands()
            ? null
            : $preset->resolveConfiguration($config, $presentFiles);

        if ($configuration === null && $preset->configurationRequired && ! $config->hasCommands()) {
            throw ConfigRefused::of(
                ConfigRejection::MissingGeneratorConfiguration,
                $preset->name.' needs one of: '.implode(', ', $preset->configurationCandidates),
            );
        }

        $relative = trim($sourcePath, '/');

        return new self(
            preset: $preset,
            config: $config,
            jobs: $config->jobs(),
            semantics: $semantics,
            sourceDir: BuildEnvironment::REPOSITORY_PATH.($relative === '' ? '' : '/'.$relative),
            configuration: $configuration,
            htmlContext: $htmlContext,
        );
    }

    /**
     * The variables both stages receive, on top of §8.4.6's scoped set.
     *
     * 🛑 Every name is `DOCUP_*` or comes from the preset's own file. Nothing
     * here is project-scoped (§8.4.6, §8.7.10): a configuration path, a
     * builder name and a strict flag are facts about the component's source.
     *
     * @return array<string, string>
     */
    public function environment(): array
    {
        $configuration = $this->configuration === null
            ? ''
            : $this->sourceDir.'/'.ltrim($this->configuration, '/');

        return array_merge(
            $this->preset->environment,
            $this->htmlContext->forEnvironment(),
            [
                'DOCUP_SOURCE_DIR' => $this->sourceDir,
                'DOCUP_WORK_DIR' => self::WORK_PATH,
                'DOCUP_TOOLCHAIN' => $this->preset->key,
                'DOCUP_CONFIGURATION' => $configuration,
                'DOCUP_CONFIGURATION_DIR' => $configuration === '' ? $this->sourceDir : dirname($configuration),
                'DOCUP_BUILDER' => $this->config->sphinxBuilder(),

                /*
                 * Unquoted at the point of use, so that an empty value adds
                 * no argument at all. Safe only because the value is the
                 * preset's own literal, never a repository's.
                 */
                'DOCUP_STRICT' => $this->config->failOnWarning($this->preset->configurationKey)
                    ? $this->preset->strictFlag
                    : '',
            ],
        );
    }

    /**
     * §8.5.6's `environment` stage, or null when it has no work.
     *
     * 🛑 Null rather than an empty script, because the difference is a
     * container start on every build. Phase 06 recorded this stage as
     * `skipped.toolchain_prebaked`, which was honest then; a preset with no
     * dependencies to install and a repository with no hooks is still that
     * case, and saying so beats a container that runs `true`.
     */
    public function environmentScript(): ?string
    {
        $lines = [];

        /*
         * 🛑 §8.5.7: "All user-defined hooks **including `post_checkout`**
         * MUST run in the build sandbox, never the fetcher." This is the
         * first sandboxed stage, so this is where it goes. Read the Docs
         * runs it in the credentialed context, and §8.5.7 says plainly that
         * doing so "voids the entire credential separation".
         */
        $lines = array_merge($lines, $this->section('post_checkout', $this->jobs->hook('post_checkout')));
        $lines = array_merge($lines, $this->section(
            'system_dependencies',
            $this->jobs->stepsFor('system_dependencies', []),
        ));
        $lines = array_merge($lines, $this->section(
            'create_environment',
            $this->preset->stepCommands('create_environment', $this->jobs),
        ));
        $lines = array_merge($lines, $this->section(
            'install',
            $this->jobs->stepsFor('install', array_merge(
                $this->preset->steps['install'] ?? [],
                $this->pythonInstallCommands(),
            )),
        ));

        return $lines === [] ? null : $this->wrap($lines);
    }

    /** §8.5.6's `build` stage. Always present: it is what produces the site. */
    public function buildScript(): string
    {
        if ($this->config->hasCommands()) {
            /*
             * §8.4.4: the author owns every step. No preset commands, no
             * per-format wrapper, and `$DOCUP_OUTPUT/html` is theirs to
             * create — `collect` will tell them if they did not (§8.4.5).
             */
            return $this->wrap($this->section('commands', $this->config->commands()));
        }

        $lines = $this->section('pre_build', $this->jobs->hook('pre_build'));

        foreach ($this->formats() as $format) {
            $lines = array_merge($lines, $this->section(
                'build:'.$format,
                $this->preset->formatCommands($format, $this->jobs),
            ));
        }

        return $this->wrap(array_merge($lines, $this->section('post_build', $this->jobs->hook('post_build'))));
    }

    /**
     * The §8.4.5 formats this build emits.
     *
     * `html` always, because `html/index.html` is mandatory. The offline
     * formats are §8.4.2's `formats` key intersected with what the preset can
     * actually produce — Phase 12 owns PDF, EPUB and htmlzip, so today that
     * intersection is empty for every shipped preset and a repository asking
     * for `formats: all` gets its HTML rather than a refusal.
     *
     * @return list<string>
     */
    public function formats(): array
    {
        $formats = ['html'];

        foreach ($this->config->formats() as $format) {
            if ($format !== 'html' && $this->preset->supportsFormat($format)) {
                $formats[] = $format;
            }
        }

        return $formats;
    }

    /**
     * §8.4.2's `python.install`, as pip invocations.
     *
     * @return list<string>
     */
    private function pythonInstallCommands(): array
    {
        $commands = [];

        foreach ($this->config->pythonInstall() as $entry) {
            $requirements = $entry['requirements'] ?? null;

            if (is_string($requirements)) {
                $commands[] = 'python -m pip install --no-input -r '.self::quote($requirements);

                continue;
            }

            $path = $entry['path'] ?? null;

            if (! is_string($path)) {
                continue;
            }

            $extras = [];

            foreach (is_array($entry['extra_requirements'] ?? null) ? $entry['extra_requirements'] : [] as $extra) {
                if (is_string($extra)) {
                    $extras[] = $extra;
                }
            }

            $target = $extras === [] ? $path : $path.'['.implode(',', $extras).']';

            $commands[] = match ($entry['method'] ?? 'pip') {
                'setuptools' => 'python '.self::quote(rtrim($path, '/').'/setup.py').' install',
                'uv' => 'uv pip install --no-input '.self::quote($target),
                default => 'python -m pip install --no-input '.self::quote($target),
            };
        }

        return $commands;
    }

    /**
     * One named group of commands, each echoed before it runs.
     *
     * 🛑 **Echoed, not `set -x`.** `set -x` prints each command *after*
     * expansion, which would put the value of every variable the line touches
     * into the build log — including §8.5.25's component secrets, which are
     * in the environment precisely so they are not in the file. Echoing the
     * literal text shows the author what ran without showing anybody what it
     * ran with. §8.5.21 redacts the log as well; neither measure is a reason
     * to drop the other.
     *
     * @param  list<string>  $commands
     * @return list<string>
     */
    private function section(string $name, array $commands): array
    {
        if ($commands === []) {
            return [];
        }

        $lines = ['', 'printf \'\\n--- '.$name.' ---\\n\''];

        foreach ($commands as $command) {
            $lines[] = 'printf \'$ %s\\n\' '.self::quote($command);
            $lines[] = $command;
        }

        return $lines;
    }

    /**
     * §8.4.10's prologue, and the scratch directory the presets assume.
     *
     * @param  list<string>  $lines
     */
    private function wrap(array $lines): string
    {
        $header = [
            '#!'.$this->semantics->shell(),
            '# Generated by DocUp (§8.4.10). Do not edit: this file is written',
            '# into the workspace by the runner and is read-only to the build.',
            $this->semantics->prologue(),
            'mkdir -p "$DOCUP_WORK_DIR" "$DOCUP_OUTPUT"',
            'cd "$DOCUP_SOURCE_DIR"',
        ];

        return implode("\n", array_merge($header, $lines))."\n";
    }

    /**
     * POSIX single-quote escaping.
     *
     * The one correct way: a single-quoted string ends at the next `'`, and
     * `'\''` closes, escapes and reopens. Nothing inside is interpreted —
     * no `$`, no backtick, no backslash — which is the property that makes
     * this safe where double quotes are not.
     */
    public static function quote(string $value): string
    {
        return "'".str_replace("'", "'\\''", $value)."'";
    }
}
