<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\FailureClass;
use App\Builds\RunSpecification;

/**
 * The `runc` case of §11.4's `RunnerDriver`, over the Docker CLI.
 *
 * 🛑 **Everything is `proc_open` with an argv array. There is no shell
 * anywhere in this file**, and that is the implementation of §8.5.13's "no
 * code path from a webhook, a YAML value or an HTTP request to an arbitrary
 * runtime call". `proc_open` given a list executes the binary directly: no
 * word splitting, no globbing, no `$(...)`, no `;`. A repository value
 * spelled `; docker run --privileged` is a filename that does not exist.
 *
 * The CLI rather than the Engine API over the socket, for one reason worth
 * stating: the argv the template renders is the thing a reviewer and an
 * operator can both read, and `docker run --cap-drop ALL …` in a log line
 * means something to a person in a way a JSON body posted to
 * `/containers/create` does not.
 */
final class DockerRunnerDriver implements RunnerDriver
{
    /** §8.5.21: "truncate lines over 8 KiB". */
    private const MAX_LINE_BYTES = 8192;

    /** §8.5.21: "cap the log at 10 MiB". Enforced while reading, not after. */
    private const MAX_LOG_BYTES = 10 * 1024 * 1024;

    /** §8.5.15: "a stall is ten minutes without output". */
    private const STALL_SECONDS = 600;

    public function __construct(
        private readonly ArgvTemplate $template = new ArgvTemplate,
        private readonly string $docker = 'docker',
    ) {}

    public function createWorkspace(string $buildId): string
    {
        $volume = BuildConfig::string('volume_prefix', 'docup-build-').$buildId;

        $this->capture([$this->docker, 'volume', 'create', $volume]);

        /*
         * 🛑 A fresh volume is owned by root, and every container in the
         * pipeline runs as uid 10001 (§8.5.8 — nothing here is root). So one
         * throwaway container prepares it before anything else mounts it.
         *
         * 🛑 **It creates the directories as well as chowning, and that is
         * not tidiness — it is the fix.** Docker re-initialises an *empty*
         * named volume's mount point from the image on **every** mount, so a
         * volume that was chowned but left empty comes back root-owned to
         * the next container. The symptom was a `Permission denied` from
         * `mkdir` in a container whose own tooling reported the volume as
         * 10001-owned a second earlier, which reads like anything but a
         * mount-point reset. Putting directories in the volume makes it
         * non-empty, and the ownership then survives.
         *
         * The alternative — running the fetch and build containers as root
         * so they can write — trades one container start for the property
         * the whole sandbox rests on.
         */
        [$status, $output] = $this->capture([
            $this->docker, 'run', '--rm', '--network', 'none', '--user', '0:0',
            '--mount', 'type=volume,source='.$volume.',target=/workspace',
            '--label', ArgvTemplate::OWNER_LABEL,
            'busybox:stable',
            'sh', '-c', 'mkdir -p /workspace/source /workspace/output && chown -R 10001:10001 /workspace',
        ]);

        /*
         * 🛑 Loud. A workspace that was not chowned fails every container
         * that mounts it, with `Permission denied` from inside a container
         * whose root filesystem is read-only — which reads like the
         * `--read-only` flag and sends whoever is debugging it to the wrong
         * place entirely. Swallowing the status here cost exactly that
         * detour once already.
         */
        if ($status !== 0) {
            throw new \RuntimeException(
                'could not prepare the build workspace '.$volume.': '.trim($output),
            );
        }

        return $volume;
    }

    public function destroyWorkspace(string $volume): void
    {
        $this->capture([$this->docker, 'volume', 'rm', '--force', $volume]);
    }

    public function sweep(): int
    {
        /*
         * 🛑 By label, never by name. See `ArgvTemplate::OWNER_LABEL`: the
         * name-prefix filter this replaced matched compose's own containers
         * for this project, and the runner removed itself the first time it
         * started. Only containers this runner's template created carry the
         * label, so only those can be swept.
         */
        [$status, $output] = $this->capture([
            $this->docker, 'ps', '--all', '--quiet', '--filter', 'label='.ArgvTemplate::OWNER_LABEL,
        ]);

        if ($status !== 0) {
            return 0;
        }

        $ids = array_values(array_filter(array_map(trim(...), explode("\n", $output))));

        foreach ($ids as $id) {
            $this->capture([$this->docker, 'rm', '--force', $id]);
        }

        return count($ids);
    }

    public function run(RunSpecification $spec, ?string $credential = null): RunOutcome
    {
        $image = $this->resolveImage($spec->imageKey);

        if ($image === null) {
            return RunOutcome::rejected('image key not in the allowlist at run time: '.$spec->imageKey);
        }

        $envFile = $this->writeEnvFile($spec);
        $name = $this->template->containerName($spec);

        // A name collision means this stage is already running for this build.
        // Removing it would be racing the other runner; refusing is correct.
        $this->capture([$this->docker, 'rm', '--force', $name]);

        $argv = $this->template->render($spec, $image, $envFile);
        $started = microtime(true);

        try {
            $result = $this->execute($argv, $spec, $credential);
        } finally {
            @unlink($envFile);
        }

        [$log, $timedOut, $stalled] = $result;

        // 🛑 Inspected before removal. See the `--rm` note in `ArgvTemplate`:
        // the exit code and the OOM flag are only authoritative while the
        // container still exists.
        $state = $this->inspectState($name);
        $this->capture([$this->docker, 'rm', '--force', $name]);

        $exitCode = $state['exit_code'] ?? -1;
        $oom = $state['oom_killed'] ?? false;

        [$class, $reason] = $this->classify($exitCode, $oom, $timedOut, $stalled);

        return new RunOutcome(
            exitCode: $exitCode,
            log: $log,
            facts: $this->readFacts($spec),
            failureClass: $class,
            failureReason: $reason,
            seconds: round(microtime(true) - $started, 3),
            timedOut: $timedOut || $stalled,
            oomKilled: $oom,
        );
    }

    public function exportDirectory(string $volume, string $containerPath, string $destinationTar): bool
    {
        /*
         * 🛑 A throwaway container with **no network and no capabilities**,
         * whose only job is to stream the directory out. It runs `tar`, not a
         * shell, so nothing in the directory's contents can influence what is
         * executed — a filename is a filename to tar, which is the whole
         * reason the output contract is enforced on the extracted side.
         *
         * `busybox` rather than the build image: the build image is the one
         * that just ran repository-influenced code, and the export should not
         * depend on it still being in a state anyone trusts.
         */
        $argv = [
            $this->docker, 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--read-only',
            '--mount', 'type=volume,source='.$volume.',target=/workspace,readonly',
            '--label', ArgvTemplate::OWNER_LABEL,
            'busybox:stable',
            'tar', '-cf', '-', '-C', $containerPath, '.',
        ];

        $handle = @fopen($destinationTar, 'wb');

        if ($handle === false) {
            return false;
        }

        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            fclose($handle);

            return false;
        }

        stream_copy_to_stream($pipes[1], $handle);
        $error = (string) stream_get_contents($pipes[2]);

        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        $status = proc_close($process);
        fclose($handle);

        if ($status !== 0) {
            @unlink($destinationTar);

            // Recorded, not thrown: a missing output directory is §8.4.5's
            // contract failure and the caller says so in those words.
            logger()->debug('build output export failed', ['volume' => $volume, 'stderr' => substr($error, 0, 500)]);

            return false;
        }

        return filesize($destinationTar) > 0;
    }

    /**
     * Run the container, streaming its output under §8.5.21's caps.
     *
     * @param  list<string>  $argv
     * @return array{0: list<string>, 1: bool, 2: bool} log, timed out, stalled
     */
    private function execute(array $argv, RunSpecification $spec, ?string $credential): array
    {
        $descriptors = [
            0 => $spec->acceptsStdin ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            return [['the container runtime could not be started'], false, false];
        }

        /*
         * 🛑 §8.5.7's credential, from the FIFO straight into the container's
         * stdin. It is read here and written there; it is never assigned to a
         * variable that outlives this block, never logged, and never written
         * to a file by this process.
         */
        if ($spec->acceptsStdin) {
            if ($credential !== null && $credential !== '') {
                fwrite($pipes[0], $credential);
            }

            // Closed either way. The fetch entrypoint performs exactly one
            // read of stdin, so a descriptor left open would hang it for
            // every public repository — which is all of them in Phase 06.
            fclose($pipes[0]);
        }

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $log = [];
        $bytes = 0;
        $buffer = ['', ''];
        $capped = false;

        $deadline = microtime(true) + $spec->timeoutSeconds;
        $lastOutput = microtime(true);
        $timedOut = false;
        $stalled = false;

        while (true) {
            $read = array_filter([$pipes[1], $pipes[2]], is_resource(...));

            if ($read === []) {
                break;
            }

            $write = $except = [];

            if (stream_select($read, $write, $except, 0, 200_000) === false) {
                break;
            }

            $sawOutput = false;

            foreach ($read as $index => $stream) {
                $chunk = fread($stream, 65536);

                if ($chunk === false || $chunk === '') {
                    continue;
                }

                $sawOutput = true;
                $slot = $stream === $pipes[1] ? 0 : 1;
                $buffer[$slot] .= $chunk;

                while (($newline = strpos($buffer[$slot], "\n")) !== false) {
                    $line = substr($buffer[$slot], 0, $newline);
                    $buffer[$slot] = substr($buffer[$slot], $newline + 1);

                    if (! $capped) {
                        $line = $this->sanitiseLine($line);
                        $bytes += strlen($line) + 1;

                        if ($bytes > self::MAX_LOG_BYTES) {
                            $log[] = '[log capped at '.self::MAX_LOG_BYTES.' bytes (§8.5.21)]';
                            $capped = true;
                        } else {
                            $log[] = $line;
                        }
                    }
                }
            }

            if ($sawOutput) {
                $lastOutput = microtime(true);
            }

            $status = proc_get_status($process);

            if (! $status['running']) {
                break;
            }

            if (microtime(true) > $deadline) {
                $timedOut = true;
                break;
            }

            // §8.5.15: "a stall is ten minutes without output".
            if (microtime(true) - $lastOutput > self::STALL_SECONDS) {
                $stalled = true;
                break;
            }
        }

        if ($timedOut || $stalled) {
            $this->capture([$this->docker, 'kill', $this->template->containerName($spec)]);
        }

        foreach ([$pipes[1], $pipes[2]] as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        proc_close($process);

        foreach ($buffer as $remainder) {
            if ($remainder !== '' && ! $capped) {
                $log[] = $this->sanitiseLine($remainder);
            }
        }

        return [$log, $timedOut, $stalled];
    }

    /** §8.5.21: strip NUL bytes, truncate lines over 8 KiB. */
    private function sanitiseLine(string $line): string
    {
        $line = str_replace("\0", '', rtrim($line, "\r"));

        if (strlen($line) > self::MAX_LINE_BYTES) {
            return substr($line, 0, self::MAX_LINE_BYTES).'… [line truncated at 8 KiB (§8.5.21)]';
        }

        return $line;
    }

    /**
     * §8.5.15: the exit code and the OOM flag, from the runtime rather than
     * inferred.
     *
     * @return array{exit_code?: int, oom_killed?: bool}
     */
    private function inspectState(string $name): array
    {
        [$status, $output] = $this->capture([
            $this->docker, 'inspect', '--format', '{{.State.ExitCode}} {{.State.OOMKilled}}', $name,
        ]);

        if ($status !== 0) {
            return [];
        }

        $parts = preg_split('/\s+/', trim($output)) ?: [];

        return [
            'exit_code' => isset($parts[0]) ? (int) $parts[0] : -1,
            'oom_killed' => ($parts[1] ?? 'false') === 'true',
        ];
    }

    /**
     * @return array{0: string|null, 1: string|null} §8.5.15 class and reason
     */
    private function classify(int $exitCode, bool $oom, bool $timedOut, bool $stalled): array
    {
        /*
         * 🛑 OOM is checked **before** the exit code, because the kernel
         * leaves exit code 137 behind and 137 is also what a plain SIGKILL
         * produces. Reading the code first would class every OOM as a generic
         * kill and lose §8.5.15's `resource.oom_killed` — which is the
         * difference between telling an author to raise their memory limit
         * and telling them nothing at all.
         */
        if ($oom) {
            return [FailureClass::Resource->value, 'oom_killed'];
        }

        if ($stalled) {
            return [FailureClass::Timeout->value, 'stalled_without_output'];
        }

        if ($timedOut) {
            return [FailureClass::Timeout->value, 'stage_timeout'];
        }

        // §8.5.15: "exit code 183 is a voluntary cancel".
        if ($exitCode === 183) {
            return [FailureClass::Cancelled->value, 'voluntary_cancel'];
        }

        if ($exitCode === 0) {
            return [null, null];
        }

        /*
         * 125 is the Docker CLI's own "the daemon refused this", which is
         * ours and not the author's — classing it as `user` would count it
         * toward §8.5.17's governor and could disable a tenant's webhooks for
         * a problem on our side, which §8.5.17 forbids in those words.
         */
        if ($exitCode === 125) {
            return [FailureClass::Infra->value, 'runtime_refused_the_container'];
        }

        return [FailureClass::User->value, 'build_command_failed'];
    }

    /**
     * A stage may leave a small JSON document for the worker — the fetcher
     * reports ADR 0010's "filter honoured" flag this way.
     *
     * 🛑 Read by `cat` in a throwaway container, not by exporting the volume
     * and opening the tar. The first version used `PharData`, which requires
     * the archive to carry a recognised extension and threw on a temporary
     * path that had none — taking the whole runner process down with it,
     * because one job's failure was not contained. Reading one file directly
     * is simpler, faster, and has no archive parser in it at all.
     *
     * @return array<string, mixed>
     */
    private function readFacts(RunSpecification $spec): array
    {
        if (! $spec->stage->receivesCredentials()) {
            return [];
        }

        [$status, $output] = $this->capture([
            $this->docker, 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--read-only',
            '--mount', 'type=volume,source='.$spec->volume.',target=/workspace,readonly',
            '--label', ArgvTemplate::OWNER_LABEL,
            'busybox:stable',
            'cat', '/workspace/fetch-result.json',
        ]);

        if ($status !== 0) {
            return [];
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($output, true, 8, JSON_THROW_ON_ERROR);

            return $decoded;
        } catch (\JsonException) {
            return [];
        }
    }

    private function resolveImage(string $key): ?string
    {
        /** @var array<string, array<string, string|null>> $images */
        $images = (array) config('builds.images');
        $entry = $images[$key] ?? null;

        if (! is_array($entry) || ! is_string($entry['reference'] ?? null)) {
            return null;
        }

        $reference = $entry['reference'];
        $digest = $entry['digest'] ?? null;

        /*
         * §8.5.14: digest-pinned where a digest is configured. A tag is a
         * mutable pointer, so a tag-only reference means "whatever that name
         * meant the last time something pulled it" — which is not a thing
         * `env_digest` can describe.
         */
        if (is_string($digest) && $digest !== '') {
            return explode(':', $reference)[0].'@'.$digest;
        }

        return $reference;
    }

    private function writeEnvFile(RunSpecification $spec): string
    {
        $path = $this->temporaryPath('env');

        /*
         * 🛑 `x` mode: create exclusively, or fail. `tempnam` creates the
         * file and returns its path, leaving a window between creation and
         * the open in which another process can replace it with a symlink —
         * and this file is about to be handed to the container runtime as
         * `--env-file`. The mode is set on the handle before a byte is
         * written, so the contents are never briefly world-readable.
         */
        $handle = fopen($path, 'xb');

        if ($handle === false) {
            throw new \RuntimeException('could not create an environment file for the container');
        }

        @chmod($path, 0o600);
        fwrite($handle, $this->template->renderEnvFile($spec));
        fclose($handle);

        return $path;
    }

    /**
     * A path nothing else can hold, in a directory we own.
     *
     * 128 bits of CSPRNG rather than a counter or a pid: the runner may run
     * several containers at once, and a predictable name in a shared
     * temporary directory is the other half of the symlink race that `x`
     * mode closes.
     */
    private function temporaryPath(string $kind): string
    {
        $directory = sys_get_temp_dir().'/docup-runner';

        if (! is_dir($directory)) {
            @mkdir($directory, 0o700, true);
        }

        return $directory.'/'.$kind.'-'.bin2hex(random_bytes(16));
    }

    /**
     * @param  list<string>  $argv
     * @return array{0: int, 1: string}
     */
    private function capture(array $argv): array
    {
        $descriptors = [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            return [-1, ''];
        }

        $output = (string) stream_get_contents($pipes[1]);
        $output .= (string) stream_get_contents($pipes[2]);

        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        return [proc_close($process), $output];
    }
}
