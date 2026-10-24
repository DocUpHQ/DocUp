<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Toolchain;

use App\Config\ConfigRefused;
use App\Config\ConfigRejection;
use Symfony\Component\Yaml\Yaml;

/**
 * The shipped presets, loaded from `resources/toolchains/`.
 *
 * 🛑 **One directory, fixed at the source root, and no second loader.** This
 * is the whole of the trust boundary around §11.4's seam: a preset is DocUp
 * data, and a repository selects one by name from the published schema's
 * closed enum. `ArchitectureTest` asserts that nothing else reads that
 * directory and that no caller passes a path into {@see load()} — a loader
 * taking a path is one `$config['preset_file']` away from arbitrary command
 * execution with the operator's intent nowhere in the picture.
 *
 * 🛑 **A malformed preset throws at load, not at run.** These files ship with
 * the application, so a missing `image` key is a packaging defect, and the
 * place to find out is the test suite rather than a tenant's build log.
 */
final class ToolchainPresets
{
    /** @var array<string, ToolchainPreset>|null */
    private static ?array $presets = null;

    /**
     * Every preset, keyed by name.
     *
     * @return array<string, ToolchainPreset>
     */
    public static function all(): array
    {
        if (self::$presets !== null) {
            return self::$presets;
        }

        $presets = [];

        foreach (self::files() as $path) {
            $preset = self::load($path);
            $presets[$preset->key] = $preset;
        }

        ksort($presets);

        return self::$presets = $presets;
    }

    /** @return list<string> */
    public static function names(): array
    {
        return array_keys(self::all());
    }

    /**
     * @throws ConfigRefused when the name is not one this installation ships
     */
    public static function get(string $key): ToolchainPreset
    {
        $preset = self::all()[$key] ?? null;

        if (! $preset instanceof ToolchainPreset) {
            throw ConfigRefused::of(
                ConfigRejection::UnknownToolchain,
                $key.'; this installation ships '.implode(', ', self::names()),
            );
        }

        return $preset;
    }

    public static function has(string $key): bool
    {
        return isset(self::all()[$key]);
    }

    /**
     * The presets whose marker files are in the checkout.
     *
     * Used only to make `config.no_toolchain` actionable — see
     * {@see ToolchainPreset::looksLike()} for why nothing selects on this.
     *
     * @param  list<string>  $presentFiles
     * @return list<string>
     */
    public static function suggestionsFor(array $presentFiles): array
    {
        $names = [];

        foreach (self::all() as $preset) {
            if ($preset->looksLike($presentFiles)) {
                $names[] = $preset->key;
            }
        }

        return $names;
    }

    /** The shipped directory. @return list<string> */
    public static function directory(): string
    {
        return dirname(__DIR__, 3).'/resources/toolchains';
    }

    /** @return list<string> */
    private static function files(): array
    {
        $found = glob(self::directory().'/*.yaml');

        if ($found === false || $found === []) {
            throw new \RuntimeException('no toolchain presets found in '.self::directory());
        }

        sort($found);

        return $found;
    }

    private static function load(string $path): ToolchainPreset
    {
        $parsed = Yaml::parseFile($path, Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);

        if (! is_array($parsed)) {
            throw new \RuntimeException('toolchain preset is not a mapping: '.$path);
        }

        $key = self::requiredString($parsed, 'key', $path);

        if ($key !== basename($path, '.yaml')) {
            // The filename is what `glob` orders and what a reviewer greps
            // for; a preset whose key disagreed with its filename would be
            // findable under one name and selectable under another.
            throw new \RuntimeException('toolchain preset key must match its filename: '.$path);
        }

        $configuration = self::section($parsed, 'configuration');

        return new ToolchainPreset(
            key: $key,
            name: self::requiredString($parsed, 'name', $path),
            image: self::requiredString($parsed, 'image', $path),
            detect: self::stringList($parsed['detect'] ?? null),
            environment: self::stringMap($parsed['environment'] ?? null),
            steps: self::commandMap(self::section($parsed, 'steps'), $path),
            formats: self::commandMap(self::section($parsed, 'formats'), $path),
            configurationKey: self::optionalString($configuration, 'key') ?? $key,
            configurationCandidates: self::stringList($configuration['candidates'] ?? null),
            configurationRequired: ($configuration['required'] ?? false) === true,
            strictFlag: self::optionalString($parsed, 'strict_flag') ?? '',
            determinism: self::optionalString($parsed, 'determinism') ?? '',
        );
    }

    /**
     * @param  array<array-key, mixed>  $parsed
     * @return array<array-key, mixed>
     */
    private static function section(array $parsed, string $key): array
    {
        $value = $parsed[$key] ?? null;

        return is_array($value) ? $value : [];
    }

    /** @param array<array-key, mixed> $parsed */
    private static function requiredString(array $parsed, string $key, string $path): string
    {
        $value = $parsed[$key] ?? null;

        if (! is_string($value) || $value === '') {
            throw new \RuntimeException("toolchain preset is missing \"{$key}\": {$path}");
        }

        return $value;
    }

    /** @param array<array-key, mixed> $parsed */
    private static function optionalString(array $parsed, string $key): ?string
    {
        $value = $parsed[$key] ?? null;

        return is_string($value) ? $value : null;
    }

    /**
     * @param  array<array-key, mixed>  $section
     * @return array<string, list<string>>
     */
    private static function commandMap(array $section, string $path): array
    {
        $map = [];

        foreach ($section as $name => $commands) {
            if (! is_string($name)) {
                throw new \RuntimeException('toolchain preset has a non-string step name: '.$path);
            }

            $map[$name] = self::stringList($commands);
        }

        return $map;
    }

    /** @return list<string> */
    private static function stringList(mixed $value): array
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

    /** @return array<string, string> */
    private static function stringMap(mixed $value): array
    {
        if (! is_array($value)) {
            return [];
        }

        $map = [];

        foreach ($value as $name => $item) {
            if (is_string($name) && is_string($item)) {
                $map[$name] = $item;
            }
        }

        return $map;
    }

    /** Test seam: reload after a preset file has been changed on disk. */
    public static function forget(): void
    {
        self::$presets = null;
    }
}
