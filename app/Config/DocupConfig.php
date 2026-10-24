<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * A validated `.docup.yaml`, read through accessors rather than by index.
 *
 * Everything here has already passed {@see ConfigParser}, so each accessor
 * narrows a value the schema has guaranteed the shape of. That is the only
 * reason the casts below are safe, and it is why this class has no public
 * constructor path that bypasses the parser in production code.
 *
 * 🛑 **Nothing here reads a key the schema does not declare.** §8.4.8's
 * invariant is enforced by `additionalProperties: false`, and a reader that
 * reached for `$this->raw['project']` would be the one place that invariant
 * could be undone without anybody editing the schema.
 */
final readonly class DocupConfig
{
    /**
     * @param  string  $filename  which of §8.4.1's names this came from
     * @param  array<array-key, mixed>  $raw  the schema-validated structure
     * @param  string  $digest  sha256 of the file's bytes, for §8.5.2
     */
    public function __construct(
        public string $filename,
        public array $raw,
        public string $digest,
    ) {}

    /**
     * An empty configuration, for a repository that has none.
     *
     * 🛑 Not a default *file* — a repository with no configuration has not
     * chosen anything, and the toolchain is inferred from what is in the
     * checkout. The digest is the digest of nothing, which is what §8.5.2
     * needs it to be: stable, and different from any real file's.
     */
    public static function absent(): self
    {
        return new self('', [], hash('sha256', ''));
    }

    public function isPresent(): bool
    {
        return $this->filename !== '';
    }

    /**
     * §8.4.2's generator selection, Read the Docs' rules plus DocUp's key.
     *
     * The explicit `toolchain:` wins; otherwise a `sphinx` or `mkdocs` key
     * selects as Read the Docs selects, which is what keeps an unmodified
     * `.readthedocs.yaml` working. `build.commands` selects nothing, because
     * §8.4.4 says it "MUST discard the predefined pipeline entirely" — there
     * is no generator to name.
     */
    public function declaredToolchain(): ?string
    {
        $explicit = $this->raw['toolchain'] ?? null;

        if (is_string($explicit) && $explicit !== '') {
            return $explicit;
        }

        if (isset($this->raw['sphinx'])) {
            return 'sphinx';
        }

        if (isset($this->raw['mkdocs'])) {
            return 'mkdocs';
        }

        return null;
    }

    /** §8.4.4: the author owns every step, and there is no predefined pipeline. */
    public function hasCommands(): bool
    {
        return $this->commands() !== [];
    }

    /** @return list<string> */
    public function commands(): array
    {
        return $this->stringList($this->path('build', 'commands'));
    }

    /** §8.4.3's hooks, with the append/replace semantics applied by the caller. */
    public function jobs(): BuildJobs
    {
        $jobs = $this->path('build', 'jobs');

        return BuildJobs::fromConfig(is_array($jobs) ? $jobs : []);
    }

    /** @return list<string> */
    public function aptPackages(): array
    {
        return $this->stringList($this->path('build', 'apt_packages'));
    }

    /**
     * §8.4.2's `build.os`, or null.
     *
     * 🛑 Returned as the author wrote it, never resolved to an image here.
     * §8.5.14 makes the image an allowlist lookup, and resolving a name to a
     * reference in a value object is how a repository-supplied string ends up
     * one refactor away from `docker run`.
     */
    public function os(): ?string
    {
        $os = $this->path('build', 'os');

        return is_string($os) ? $os : null;
    }

    /** @return array<string, string> */
    public function tools(): array
    {
        $tools = $this->path('build', 'tools');

        if (! is_array($tools)) {
            return [];
        }

        $resolved = [];

        foreach ($tools as $name => $version) {
            if (is_string($name) && is_string($version)) {
                $resolved[$name] = $version;
            }
        }

        return $resolved;
    }

    /**
     * §8.4.2's `formats`, with the literal `all` expanded.
     *
     * @return list<string>
     */
    public function formats(): array
    {
        $formats = $this->raw['formats'] ?? null;

        if ($formats === 'all') {
            return ['pdf', 'epub', 'htmlzip'];
        }

        return $this->stringList($formats);
    }

    /**
     * §8.4.2's `python.install`, as written.
     *
     * @return list<array<string, mixed>>
     */
    public function pythonInstall(): array
    {
        $install = $this->path('python', 'install');

        if (! is_array($install)) {
            return [];
        }

        $entries = [];

        foreach ($install as $entry) {
            if (! is_array($entry)) {
                continue;
            }

            // Re-keyed to string keys only. The schema guarantees these are
            // objects, so a numeric key cannot occur — but the guarantee
            // lives in a JSON file and the type here should not depend on
            // somebody having read it.
            $normalised = [];

            foreach ($entry as $key => $value) {
                if (is_string($key)) {
                    $normalised[$key] = $value;
                }
            }

            $entries[] = $normalised;
        }

        return $entries;
    }

    /**
     * §8.4.11's checkout narrowing.
     *
     * @return list<string>
     */
    public function sparse(): array
    {
        return $this->stringList($this->raw['sparse'] ?? null);
    }

    /** The generator's own configuration file, where the schema names one. */
    public function generatorConfiguration(string $toolchain): ?string
    {
        $configuration = $this->path($toolchain, 'configuration');

        return is_string($configuration) ? $configuration : null;
    }

    public function failOnWarning(string $toolchain): bool
    {
        return $this->path($toolchain, 'fail_on_warning') === true;
    }

    /** `html`, `dirhtml` or `singlehtml`; `htmldir` is the retired spelling. */
    public function sphinxBuilder(): string
    {
        $builder = $this->path('sphinx', 'builder');

        if ($builder === 'htmldir') {
            return 'dirhtml';
        }

        return is_string($builder) ? $builder : 'html';
    }

    /**
     * §8.4.8's one advisory key, read **once** at attach time.
     *
     * Named `suggested` because that is all it is: the repository proposes,
     * the project disposes, and nothing in the serving path ever reads it.
     */
    public function suggestedMountPath(): ?string
    {
        $path = $this->raw['suggested_mount_path'] ?? null;

        return is_string($path) ? $path : null;
    }

    /**
     * §8.16.3's per-page ranking and ignore list, untouched.
     *
     * @return array<string, mixed>
     */
    public function search(): array
    {
        $search = $this->raw['search'] ?? null;

        if (! is_array($search)) {
            return [];
        }

        $map = [];

        foreach ($search as $key => $value) {
            if (is_string($key)) {
                $map[$key] = $value;
            }
        }

        return $map;
    }

    /** `$this->raw[$a][$b]`, without the isset dance at every call site. */
    private function path(string $section, string $key): mixed
    {
        $value = $this->raw[$section] ?? null;

        if (! is_array($value)) {
            return null;
        }

        return $value[$key] ?? null;
    }

    /** @return list<string> */
    private function stringList(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $item) {
            if (is_string($item)) {
                $strings[] = $item;
            }
        }

        return $strings;
    }
}
