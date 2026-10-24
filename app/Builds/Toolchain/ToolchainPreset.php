<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Toolchain;

use App\Config\BuildJobs;
use App\Config\DocupConfig;

/**
 * One generator, as data.
 *
 * §11.4 names this the highest-leverage seam in the system: "🛑 **declarative
 * YAML toolchain presets** — the highest-leverage seam, where a new generator
 * is a data file plus a fixture, not code." This class is the loaded form of
 * one of those files and contains no generator-specific logic at all; if it
 * ever grows a `match ($this->key)` the seam has been lost.
 *
 * 🛑 **A preset's commands are DocUp-authored and a repository cannot supply
 * one.** {@see ToolchainPresets} reads only from the shipped directory, and
 * `ArchitectureTest` asserts there is no other loader. The `toolchain:` key in
 * a `.docup.yaml` selects a preset by name from a closed enum in the published
 * schema; it does not define one. Without that, "a new generator is a data
 * file" would read "a new generator is a data file anybody can post".
 *
 * 🛑 **Values from the repository are passed as environment variables, never
 * interpolated into a command string.** A quoted `"$DOCUP_CONFIGURATION"` is
 * one word whatever is in it; the same value spliced into a command would be
 * re-parsed by the shell. The build container is already running the
 * repository's own code with no credentials and no route anywhere (§8.5.8,
 * §8.5.9), so this buys no privilege — but a preset that is injectable is a
 * preset whose rendered argv cannot be reasoned about, and §8.5.13 requires
 * exactly that reasoning.
 */
final readonly class ToolchainPreset
{
    /**
     * @param  string  $key  the name `toolchain:` selects, and the file's stem
     * @param  string  $image  a KEY in `config('builds.images')`, never a reference
     * @param  list<string>  $detect  files whose presence indicates this generator
     * @param  array<string, string>  $environment  preset-wide additions
     * @param  array<string, list<string>>  $steps  `create_environment`, `install`
     * @param  array<string, list<string>>  $formats  commands per §8.4.5 format
     * @param  string  $configurationKey  the `.docup.yaml` section holding `configuration`
     * @param  list<string>  $configurationCandidates  looked for when the key is absent
     * @param  string  $strictFlag  what `fail_on_warning: true` adds
     * @param  string  $determinism  §18.13's per-preset note
     */
    public function __construct(
        public string $key,
        public string $name,
        public string $image,
        public array $detect,
        public array $environment,
        public array $steps,
        public array $formats,
        public string $configurationKey,
        public array $configurationCandidates,
        public bool $configurationRequired,
        public string $strictFlag,
        public string $determinism,
    ) {}

    /**
     * The commands for one predefined step, with §8.4.3's hooks applied.
     *
     * @return list<string>
     */
    public function stepCommands(string $step, BuildJobs $jobs): array
    {
        return $jobs->stepsFor($step, $this->steps[$step] ?? []);
    }

    /**
     * The commands that produce one §8.4.5 format.
     *
     * @return list<string>
     */
    public function formatCommands(string $format, BuildJobs $jobs): array
    {
        return $jobs->buildStepFor($format, $this->formats[$format] ?? []);
    }

    /** Can this preset emit the format at all, before any hook is applied? */
    public function supportsFormat(string $format): bool
    {
        return ($this->formats[$format] ?? []) !== [];
    }

    /**
     * Where this generator's own configuration file is, relative to the
     * component's source path.
     *
     * The author's `sphinx.configuration` wins; otherwise the preset's
     * candidates are tried in order against what the fetcher reported. A
     * preset that requires one and finds none is a `config` failure with a
     * message naming the candidates, rather than a generator exiting with
     * something about a missing module.
     *
     * @param  list<string>  $presentFiles  paths the fetcher saw, relative to source_path
     */
    public function resolveConfiguration(DocupConfig $config, array $presentFiles): ?string
    {
        $declared = $config->generatorConfiguration($this->configurationKey);

        if ($declared !== null && $declared !== '') {
            return $declared;
        }

        foreach ($this->configurationCandidates as $candidate) {
            if (in_array($candidate, $presentFiles, true)) {
                return $candidate;
            }
        }

        return null;
    }

    /**
     * Does the checkout look like this generator's?
     *
     * 🛑 Used to select only when **exactly one** preset matches, and
     * narrated when it is. A repository holding `mkdocs.yml` and nothing
     * else has named its generator as plainly as a `toolchain:` key would;
     * a repository holding two markers has not, and
     * {@see ToolchainPlan::resolve()} refuses that case by name rather than
     * picking the first. The list also makes `config.no_toolchain`
     * actionable, by telling an author which value to write.
     *
     * @param  list<string>  $presentFiles
     */
    public function looksLike(array $presentFiles): bool
    {
        foreach ($this->detect as $marker) {
            if (in_array($marker, $presentFiles, true)) {
                return true;
            }
        }

        return false;
    }
}
