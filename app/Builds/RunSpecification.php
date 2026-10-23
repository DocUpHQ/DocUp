<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * The typed run specification of §8.5.13.
 *
 * > "No request-handling or queue-worker process MUST hold a container-runtime
 * > socket. The runner is the sole holder, and it MUST accept only a typed run
 * > specification rendered through a fixed argv template. 🛑 There MUST be no
 * > code path from a webhook, a YAML value or an HTTP request to an arbitrary
 * > runtime call."
 *
 * 🛑 **This class is that sentence's enforcement point, and the work is in the
 * constructor.** Every field is validated against a shape narrow enough that
 * no value can become a flag: the image is a **key into an allowlist** rather
 * than a reference, the stage is an enum, limits are integers, and the command
 * is a list of arguments that are passed as a list — never joined, never
 * shell-interpreted.
 *
 * The attack this prevents is not exotic. A `build.os` value of
 * `ubuntu --privileged -v /:/host` in somebody's `.docup.yaml` becomes two
 * extra flags the moment any part of the path joins arguments into a string.
 * Keeping the image as an allowlist key means the YAML value never reaches
 * argv at all; it reaches an `array_key_exists`.
 *
 * Serialisable to JSON because that is how it crosses to the runner (§8.5.13's
 * "accept only a typed run specification"): the runner re-validates on the way
 * in, so a spool file an attacker managed to write is refused by the same
 * constructor that built it.
 */
final readonly class RunSpecification
{
    /** Phase 06 runs these three stages in containers; the rest are PHP in the worker. */
    private const CONTAINER_STAGES = [Stage::Fetch, Stage::Environment, Stage::Build];

    /**
     * @param  string  $buildId  32 lowercase hex characters
     * @param  string  $imageKey  a key of `config('builds.images')`, never a reference
     * @param  list<string>  $command  argv for the container; each element is passed
     *                                 as one argument and is never interpreted
     * @param  array<string, string>  $environment  §8.4.6-classified; never a secret
     * @param  bool  $acceptsStdin  §8.5.7: the fetch stage reads its credential
     *                              from stdin, which is the only channel that is
     *                              neither argv, nor the environment, nor the URL
     */
    public function __construct(
        public string $buildId,
        public Stage $stage,
        public string $imageKey,
        public array $command,
        public array $environment,
        public string $volume,
        public string $workdir,
        public int $timeoutSeconds,
        public bool $networkEnabled,
        public bool $readOnlyRoot = true,
        public bool $acceptsStdin = false,

        /**
         * A container path to export as a tar into the spool when the stage
         * succeeds.
         *
         * 🛑 This is the §8.21.6 hand-off: the runner produces an archive and
         * the worker publishes it through the **direct upload path**, which is
         * what makes "the built-in runner MUST be implemented as the first
         * consumer of this path, not a privileged special case" literally
         * true rather than aspirational.
         */
        public ?string $exportPath = null,

        /** Destroy the per-build workspace afterwards, whatever the outcome. */
        public bool $releaseWorkspace = false,
    ) {
        $this->assertValid();
    }

    /**
     * @throws \InvalidArgumentException when any field could reach argv as a flag
     */
    private function assertValid(): void
    {
        if (preg_match('/^[0-9a-f]{32}$/', $this->buildId) !== 1) {
            throw new \InvalidArgumentException('buildId must be 32 lowercase hex characters');
        }

        if (! in_array($this->stage, self::CONTAINER_STAGES, true)) {
            throw new \InvalidArgumentException(
                $this->stage->value.' does not run in a container; the worker runs it (§8.5.6)',
            );
        }

        /*
         * 🛑 A key, checked against the allowlist, not a reference. This is
         * the line §8.5.14 turns on: "User-supplied Dockerfiles and arbitrary
         * images MUST NOT be supported."
         */
        if (! array_key_exists($this->imageKey, (array) config('builds.images'))) {
            throw new \InvalidArgumentException("unknown build image: {$this->imageKey}");
        }

        foreach ($this->command as $argument) {
            if ($argument === '') {
                throw new \InvalidArgumentException('every command argument must be a non-empty string');
            }

            /*
             * A NUL byte truncates the argument at the execve boundary, so
             * everything after it would be invisible to any check performed
             * here while still reaching the kernel. A newline is how a value
             * becomes two lines in anything that logs argv.
             */
            if (preg_match('/[\x00\n\r]/', $argument) === 1) {
                throw new \InvalidArgumentException('a command argument contains a control character');
            }
        }

        foreach ($this->environment as $name => $value) {
            if (preg_match('/^[A-Z][A-Z0-9_]{0,63}$/', (string) $name) !== 1) {
                throw new \InvalidArgumentException("not a usable environment variable name: {$name}");
            }

            if (preg_match('/[\x00\n\r]/', $value) === 1) {
                throw new \InvalidArgumentException("environment value for {$name} contains a control character");
            }
        }

        if (preg_match('/^[a-z0-9][a-z0-9_.-]{0,62}$/', $this->volume) !== 1) {
            throw new \InvalidArgumentException('volume names are restricted to the docker-safe set');
        }

        // Absolute, no traversal, no spaces. The workdir is ours and never
        // comes from a repository, but it is checked because the day it does
        // come from one is the day nobody remembers it was not checked.
        if (preg_match('#^/[A-Za-z0-9/_.-]*$#', $this->workdir) !== 1 || str_contains($this->workdir, '..')) {
            throw new \InvalidArgumentException('workdir must be an absolute path with no traversal');
        }

        if ($this->timeoutSeconds < 1 || $this->timeoutSeconds > 7200) {
            throw new \InvalidArgumentException('timeout must be between 1 second and 2 hours');
        }

        /*
         * 🛑 §8.5.7, as an invariant rather than a convention: only `fetch`
         * may be handed a credential, and stdin is the only channel it may
         * arrive through. A spec that opened stdin for the build stage would
         * be the credential separation quietly undone.
         */
        if ($this->acceptsStdin && $this->stage !== Stage::Fetch) {
            throw new \InvalidArgumentException('only the fetch stage may read a credential from stdin (§8.5.7)');
        }

        if ($this->exportPath !== null
            && (preg_match('#^/[A-Za-z0-9/_.-]*$#', $this->exportPath) !== 1 || str_contains($this->exportPath, '..'))) {
            throw new \InvalidArgumentException('exportPath must be an absolute path with no traversal');
        }
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'build_id' => $this->buildId,
            'stage' => $this->stage->value,
            'image_key' => $this->imageKey,
            'command' => $this->command,
            'environment' => $this->environment,
            'volume' => $this->volume,
            'workdir' => $this->workdir,
            'timeout_seconds' => $this->timeoutSeconds,
            'network_enabled' => $this->networkEnabled,
            'read_only_root' => $this->readOnlyRoot,
            'accepts_stdin' => $this->acceptsStdin,
            'export_path' => $this->exportPath,
            'release_workspace' => $this->releaseWorkspace,
        ];
    }

    /**
     * Rebuild from the spool, re-validating.
     *
     * 🛑 The same constructor runs. A spool file is a file on a shared volume,
     * and the whole point of the typed specification is that the runner trusts
     * the *shape* rather than the writer.
     *
     * @param  array<array-key, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $command = [];

        foreach (is_array($data['command'] ?? null) ? $data['command'] : [] as $argument) {
            if (is_string($argument)) {
                $command[] = $argument;
            }
        }

        return new self(
            buildId: self::text($data, 'build_id'),
            stage: Stage::from(self::text($data, 'stage')),
            imageKey: self::text($data, 'image_key'),
            command: $command,
            environment: self::stringMap($data['environment'] ?? []),
            volume: self::text($data, 'volume'),
            workdir: self::text($data, 'workdir'),
            timeoutSeconds: is_int($data['timeout_seconds'] ?? null) ? $data['timeout_seconds'] : 0,
            networkEnabled: ($data['network_enabled'] ?? false) === true,
            readOnlyRoot: ($data['read_only_root'] ?? true) !== false,
            acceptsStdin: ($data['accepts_stdin'] ?? false) === true,
            exportPath: is_string($data['export_path'] ?? null) ? $data['export_path'] : null,
            releaseWorkspace: ($data['release_workspace'] ?? false) === true,
        );
    }

    /**
     * A string field, or the empty string.
     *
     * 🛑 Checked rather than cast. The constructor refuses an empty build
     * id, an unknown image key and a malformed workdir — so a field that
     * arrived as an array or a number becomes a refusal rather than the
     * string `Array`.
     *
     * @param  array<array-key, mixed>  $data
     */
    private static function text(array $data, string $key): string
    {
        $value = $data[$key] ?? null;

        return is_string($value) ? $value : '';
    }

    /** @return array<string, string> */
    private static function stringMap(mixed $value): array
    {
        $map = [];

        foreach (is_array($value) ? $value : [] as $name => $item) {
            if (is_string($name) && (is_string($item) || is_int($item))) {
                $map[$name] = (string) $item;
            }
        }

        return $map;
    }
}
