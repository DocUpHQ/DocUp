<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * §8.4.3's hooks, and the three-way semantics that make them useful.
 *
 * > "`build.jobs` MUST accept the Read the Docs hook names unchanged:
 * > `post_checkout`, `pre_system_dependencies`, `post_system_dependencies`,
 * > `pre_create_environment`, `create_environment`, `post_create_environment`,
 * > `pre_install`, `install`, `post_install`, `pre_build` (with per-format
 * > `html`/`pdf`/`epub`/`htmlzip`), `post_build`. 🛑 `pre_`/`post_` append; a
 * > bare name replaces."
 *
 * Append-or-replace is the whole value of the feature. A repository that
 * needs one extra command before `install` writes three lines; a repository
 * whose dependency manager is not pip replaces `install` outright and keeps
 * everything else. Collapsing the two into "run these as well" would make the
 * second case impossible, and collapsing them the other way would make the
 * first case destroy the preset.
 *
 * 🛑 **Every one of these runs in the build sandbox, `post_checkout`
 * included.** §8.5.7 is categorical about it: "All user-defined hooks
 * **including `post_checkout`** MUST run in the build sandbox, never the
 * fetcher. Read the Docs runs `post_checkout` in the credentialed context;
 * doing so voids the entire credential separation." {@see HOOKS} is ordered
 * so that a caller walking it in order cannot accidentally emit
 * `post_checkout` into the fetch stage — there is nowhere in the fetch stage
 * that reads this class.
 */
final readonly class BuildJobs
{
    /**
     * The predefined steps a hook can wrap, in pipeline order.
     *
     * `checkout` has no `pre_` and no bare form, because by the time any
     * hook can run the checkout has already happened in a different
     * container (§8.5.7). Read the Docs has the same asymmetry.
     *
     * @var list<string>
     */
    public const STEPS = ['checkout', 'system_dependencies', 'create_environment', 'install', 'build'];

    /**
     * The steps a bare hook name may **replace**.
     *
     * 🛑 `checkout` and `system_dependencies` are absent, and §8.4.3's list
     * is where that comes from — it names `post_checkout` and
     * `pre_`/`post_system_dependencies` but no bare form of either. The
     * reason is the same in both cases: neither step runs in a place the
     * author's commands could stand in for. The checkout happens in the
     * credential-free fetcher (§8.5.7) and the system packages are installed
     * by the platform from §8.4.2's `apt_packages`, under §8.5.14's pre-baked
     * image rules.
     *
     * @var list<string>
     */
    public const REPLACEABLE = ['create_environment', 'install', 'build'];

    /** The steps a `pre_` hook may precede. */
    public const WRAPPABLE = ['system_dependencies', 'create_environment', 'install', 'build'];

    /** §8.4.5's four output formats, which `build` is keyed by. */
    public const FORMATS = ['html', 'pdf', 'epub', 'htmlzip'];

    /**
     * @param  array<string, list<string>>  $hooks  flat hooks, by name
     * @param  array<string, list<string>>  $buildByFormat  `build.jobs.build.*`
     */
    private function __construct(
        private array $hooks,
        private array $buildByFormat,
    ) {}

    /**
     * @param  array<array-key, mixed>  $jobs  the schema-validated `build.jobs`
     */
    public static function fromConfig(array $jobs): self
    {
        $hooks = [];
        $buildByFormat = [];

        foreach ($jobs as $name => $commands) {
            if (! is_string($name)) {
                continue;
            }

            if ($name === 'build' && is_array($commands)) {
                foreach ($commands as $format => $formatCommands) {
                    if (is_string($format) && in_array($format, self::FORMATS, true)) {
                        $buildByFormat[$format] = self::strings($formatCommands);
                    }
                }

                continue;
            }

            $hooks[$name] = self::strings($commands);
        }

        return new self($hooks, $buildByFormat);
    }

    public static function none(): self
    {
        return new self([], []);
    }

    /**
     * The commands for one predefined step, with the author's hooks applied.
     *
     * 🛑 The replacement is checked **before** the `pre_`/`post_` wrap, not
     * instead of it. An author who both replaces `install` and adds a
     * `post_install` means both: run my installer, then my follow-up. Dropping
     * the hooks when a replacement exists would silently discard a line
     * somebody wrote.
     *
     * @param  list<string>  $predefined  the preset's own commands for this step
     * @return list<string>
     */
    public function stepsFor(string $step, array $predefined): array
    {
        return array_merge(
            $this->hooks['pre_'.$step] ?? [],
            $this->hooks[$step] ?? $predefined,
            $this->hooks['post_'.$step] ?? [],
        );
    }

    /**
     * The `build` step, which is per format rather than one list.
     *
     * @param  list<string>  $predefined
     * @return list<string>
     */
    public function buildStepFor(string $format, array $predefined): array
    {
        $replacement = $this->buildByFormat[$format] ?? null;

        /*
         * `pre_build` and `post_build` wrap the whole build step rather than
         * each format, because that is what Read the Docs does and because
         * running a `pre_build` four times for a repository emitting four
         * formats would surprise everybody exactly once.
         */
        return $replacement ?? $predefined;
    }

    /** Did the author replace this step rather than wrap it? */
    public function replaces(string $step): bool
    {
        return isset($this->hooks[$step]);
    }

    /** @return list<string> */
    public function hook(string $name): array
    {
        return $this->hooks[$name] ?? [];
    }

    public function isEmpty(): bool
    {
        return $this->hooks === [] && $this->buildByFormat === [];
    }

    /**
     * Every hook name the schema accepts, derived rather than restated.
     *
     * `ConfigContractTest` compares this against the schema's own property
     * list, so a hook added to one and not the other fails the suite instead
     * of being accepted by the schema and ignored by the pipeline — which is
     * the failure mode that leaves an author's commands silently unrun.
     *
     * @return list<string>
     */
    public static function hookNames(): array
    {
        $names = [];

        foreach (self::STEPS as $step) {
            if (in_array($step, self::WRAPPABLE, true)) {
                $names[] = 'pre_'.$step;
            }

            if (in_array($step, self::REPLACEABLE, true)) {
                $names[] = $step;
            }

            $names[] = 'post_'.$step;
        }

        sort($names);

        return $names;
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
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
