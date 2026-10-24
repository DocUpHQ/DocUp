<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\FailureClass;
use App\Builds\RunSpecification;
use App\Builds\Sandbox\EgressMode;
use App\Builds\Sandbox\SandboxPolicy;

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
        private readonly Docker $cli = new Docker,
        private readonly Warden $warden = new Warden,

        /*
         * 🛑 Phase 08: the driver writes a stage's output into the spool
         * as it reads it, and reads the cancel marker from there. Both are
         * the runner's side of a channel the worker owns the other end of,
         * so the path has to come from the same place the job did.
         */
        private readonly Spool $spool = new Spool(''),
    ) {}

    /**
     * The spool, resolved from configuration when none was injected.
     *
     * Not a constructor default, because `Spool::fromConfig()` reads
     * `config()` and a default parameter is evaluated at class-load time —
     * before the application has booted, in a worker that loads this file
     * from the autoloader.
     */
    private function spool(): Spool
    {
        return $this->spool->root() === '' ? Spool::fromConfig() : $this->spool;
    }

    public function createWorkspace(string $buildId): string
    {
        $volume = BuildConfig::string('volume_prefix', 'docup-build-').$buildId;
        $path = Workspace::pathFor($volume);

        /*
         * 🛑 A directory on a bind-mounted root rather than a named volume,
         * and the change is §8.5.18's. The runner must be able to MEASURE a
         * build's disk use while the build runs — §8.5.18 rules out "Read
         * the Docs' unenforced soft limits" — and the two portable ways to
         * put a hard cap on a container's writes both failed when measured
         * in Phase 07:
         *
         *  - `--storage-opt size=` is refused by the daemon on anything but
         *    overlay-on-xfs with pquota;
         *  - a `local` volume with `type=tmpfs` does carry a kernel-enforced
         *    size, and is REMOUNTED EMPTY for every container — so the fetch
         *    stage's checkout vanishes before the build stage starts. That
         *    one cost a full end-to-end run to find, because every stage
         *    succeeded and the generator simply had nothing to build.
         *
         * A bind mount at the same path inside the runner and on the host
         * gives the runner a directory it can `stat` in microseconds, which
         * is what makes `enforceDiskLimit()` continuous rather than a check
         * after the fact.
         */
        foreach ([$path, $path.'/source', $path.'/output'] as $directory) {
            if (! is_dir($directory) && ! @mkdir($directory, 0o750, true) && ! is_dir($directory)) {
                throw new \RuntimeException('could not create the build workspace at '.$directory);
            }
        }

        /*
         * 🛑 Owned by the container's user, because every container in the
         * pipeline runs as uid 10001 (§8.5.8 — nothing here is root) and a
         * root-owned workspace fails every one of them with `Permission
         * denied` from inside a container whose root filesystem is also
         * read-only. That error reads like the `--read-only` flag and sends
         * whoever is debugging it to the wrong place; Phase 06 lost an
         * afternoon to the named-volume version of it.
         *
         * Done in-process. The runner is root in its own container, so this
         * replaces the throwaway `busybox chown` container Phase 06 needed
         * — one less container start on the critical path of every build.
         */
        foreach ([$path, $path.'/source', $path.'/output'] as $directory) {
            @chown($directory, 10001);
            @chgrp($directory, 10001);
        }

        return $volume;
    }

    public function destroyWorkspace(string $volume): void
    {
        Workspace::remove(Workspace::pathFor($volume));
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
        [$status, $output] = $this->cli->capture([
            'ps', '--all', '--quiet', '--filter', 'label='.ArgvTemplate::OWNER_LABEL,
        ]);

        if ($status !== 0) {
            return 0;
        }

        $ids = array_values(array_filter(array_map(trim(...), explode("\n", $output))));

        foreach ($ids as $id) {
            $this->cli->capture(['rm', '--force', $id]);
        }

        return count($ids);
    }

    public function run(RunSpecification $spec, ?string $credential = null): RunOutcome
    {
        $image = $this->resolveImage($spec->imageKey);

        if ($image === null) {
            return RunOutcome::rejected('image key not in the allowlist at run time: '.$spec->imageKey);
        }

        $policy = SandboxPolicy::fromConfig();
        $name = $this->template->containerName($spec);
        $wardenName = null;
        $proxyAddress = null;
        $started = microtime(true);

        /*
         * 🛑 §8.5.9's namespace is built BEFORE the container that lives in
         * it, and a failure here is a refusal rather than a fallback. The
         * alternative — "the warden would not start, so run on the bridge"
         * — is the failure-open shape the whole arrangement exists to
         * prevent, and it would be invisible in a green build.
         */
        try {
            if ($spec->egress === EgressMode::Allowlist) {
                $proxyAddress = $this->warden->proxyAddress();
                $wardenName = $this->warden->start($spec->buildId, $spec->stage, $proxyAddress);
                $placement = SandboxPlacement::inWarden($wardenName, $policy->runtime);
            } elseif ($spec->egress === EgressMode::Open) {
                $placement = SandboxPlacement::unrestricted($policy->runtime);
            } else {
                $placement = SandboxPlacement::isolated($policy->runtime);
            }
        } catch (\RuntimeException $refused) {
            return RunOutcome::rejected('the build sandbox could not be prepared: '.$refused->getMessage());
        }

        $envFile = $this->writeEnvFile($spec, $this->proxyEnvironment($spec, $proxyAddress));

        // A name collision means this stage is already running for this build.
        // Removing it would be racing the other runner; refusing is correct.
        $this->cli->capture(['rm', '--force', $name]);

        $argv = $this->template->render($spec, $image, $envFile, $placement);

        try {
            $result = $this->execute($argv, $spec, $credential, $name);
        } finally {
            @unlink($envFile);
        }

        [$log, $timedOut, $stalled, $sample, $cancelled] = $result;

        // 🛑 Inspected before removal. See the `--rm` note in `ArgvTemplate`:
        // the exit code and the OOM flag are only authoritative while the
        // container still exists.
        $state = $this->inspectState($name);

        /*
         * The three forensic reads, and they are gated on the stage having
         * gone wrong. Each costs a container start or a `docker exec`, and
         * a successful build has nothing to explain - adding a second of
         * post-mortem to every green stage would be paying for an answer
         * nobody asked for.
         */
        $wentWrong = ($state['exit_code'] ?? -1) !== 0 || ! $sample->isClean() || $timedOut || $stalled;
        $diskExhausted = $wentWrong && $this->workspaceIsOverQuota($spec);
        $denial = $wentWrong ? $this->proxyDenial($wardenName, $started) : null;
        $blocked = $wentWrong && $wardenName !== null ? $this->warden->blockedPackets($wardenName) : 0;

        $this->cli->capture(['rm', '--force', $name]);

        if ($wardenName !== null) {
            $this->warden->stop($wardenName);
        }

        $exitCode = $state['exit_code'] ?? -1;
        $oom = ($state['oom_killed'] ?? false) || $sample->oomKills > 0;

        [$class, $reason] = $this->classify(
            $exitCode, $sample, $oom, $timedOut, $stalled, $diskExhausted, $denial, $blocked, $cancelled, $spec,
        );

        return new RunOutcome(
            exitCode: $exitCode,
            log: $log,
            facts: [...$this->readFacts($spec), 'resources' => $sample->toArray()]
                + ($denial === null ? [] : ['egress_denied_host' => $denial]),
            failureClass: $class,
            failureReason: $reason,
            seconds: round(microtime(true) - $started, 3),
            timedOut: $timedOut || $stalled,
            oomKilled: $oom,
        );
    }

    /**
     * §8.5.9's proxy address, as the variables every package manager reads.
     *
     * 🛑 `no_proxy` carries the loopback forms and nothing else. A
     * `no_proxy` listing a hostname would be an allowlist bypass written by
     * us: anything matching it is contacted directly, and the nftables
     * backstop would then drop it — so the build's error would be a
     * connection timeout rather than the proxy's refusal, and the author
     * would be told nothing useful.
     *
     * @return array<string, string>
     */
    private function proxyEnvironment(RunSpecification $spec, ?string $proxyAddress): array
    {
        if ($spec->egress !== EgressMode::Allowlist || $proxyAddress === null) {
            return [];
        }

        $url = 'http://'.$proxyAddress.':'.BuildConfig::positiveInt('sandbox.proxy_port', 3128);

        // Both cases: curl and git read the lowercase names, Python and most
        // JVM tooling read the uppercase ones, and a build that picked the
        // wrong one would be refused at layer 3 with no explanation.
        return [
            'http_proxy' => $url,
            'https_proxy' => $url,
            'HTTP_PROXY' => $url,
            'HTTPS_PROXY' => $url,
            'no_proxy' => 'localhost,127.0.0.1,::1',
            'NO_PROXY' => 'localhost,127.0.0.1,::1',
        ];
    }

    /**
     * The host the §8.5.9 proxy refused for this build, if it refused one.
     *
     * 🛑 Attributed by the **warden's** address, which is the client address
     * the proxy sees: the build container has no address of its own, it is
     * inside the warden's namespace. That is what makes this attribution
     * exact rather than a guess from a time window — two builds running at
     * once have two wardens.
     */
    private function proxyDenial(?string $wardenName, float $since): ?string
    {
        if ($wardenName === null) {
            return null;
        }

        [$status, $address] = $this->cli->capture([
            'inspect', '--format',
            '{{ with (index .NetworkSettings.Networks "'.BuildConfig::string('sandbox.network', 'docup_sandboxes').'") }}{{ .IPAddress }}{{ end }}',
            $wardenName,
        ]);

        $address = trim($address);

        if ($status !== 0 || $address === '') {
            return null;
        }

        [$status, $label] = $this->cli->capture([
            'ps', '--quiet', '--filter', 'label='.BuildConfig::string('sandbox.proxy_label', 'docup.role=egress-proxy'),
        ]);

        $proxyId = trim(explode("\n", trim($label))[0]);

        if ($status !== 0 || $proxyId === '') {
            return null;
        }

        [, $logs] = $this->cli->capture([
            'logs', '--since', (string) (int) ($since - 1), $proxyId,
        ]);

        $denied = null;

        foreach (explode("\n", $logs) as $line) {
            if (! str_contains($line, ' '.$address.' ') || ! str_contains($line, 'TCP_DENIED')) {
                continue;
            }

            /*
             * `<ts> <client> TCP_DENIED/403 CONNECT host:443` for a tunnel,
             * and `… GET http://host/path` for a plain request. Normalised
             * to a bare host here so the classifier can compare one thing:
             * the metadata endpoint arrives in both shapes depending on
             * whether the build used https, and a classifier matching the
             * raw field would catch one and miss the other.
             */
            $fields = preg_split('/\s+/', trim($line)) ?: [];
            $target = $fields[4] ?? '';

            if ($target === '') {
                continue;
            }

            $target = preg_replace('#^[a-z]+://#i', '', $target) ?? $target;
            // `strtok` returns false only when there is nothing to tokenise,
            // which the empty-target check above has already excluded.
            $host = strtok($target, '/:');

            if (is_string($host)) {
                $denied = $host;
            }
        }

        return $denied;
    }

    /**
     * Whether the workspace is over §8.5.18's disk limit.
     *
     * 🛑 Measured from the runner's own process, not sniffed from the
     * build's output. A generator that runs out of space reports something
     * else entirely — "cannot write file", "unexpected EOF", a tracebacked
     * `IOError` — so a classifier that searched the log for "No space left
     * on device" would miss every tool that phrases it differently, and
     * would also catch builds that printed the phrase for another reason.
     */
    private function workspaceIsOverQuota(RunSpecification $spec): bool
    {
        $ceiling = BuildConfig::positiveInt('limits.disk_mb', 2048) * 1024 * 1024;

        return Workspace::bytesUsed(Workspace::pathFor($spec->volume), $ceiling) > $ceiling;
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
            $this->cli->binary(), 'run', '--rm', '--network', 'none', '--cap-drop', 'ALL',

            /*
             * 🛑 As the workspace's own user, not as root.
             *
             * `--cap-drop ALL` removes CAP_DAC_OVERRIDE, so a root process
             * in this container is subject to ordinary permission checks
             * like anybody else — and the workspace is mode 0750 owned by
             * uid 10001. The first version ran as root and failed with
             * `tar: can't change directory to '/workspace/output':
             * Permission denied`, which reads like a mount problem and is
             * in fact root being correctly told no. Matching the owner is
             * the right fix; widening the directory to 0755 would have been
             * the easy one.
             */
            '--user', '10001:10001',
            '--security-opt', 'no-new-privileges', '--read-only',
            '--mount', 'type=bind,source='.Workspace::pathFor($volume).',target=/workspace,readonly',
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
     * @param  string  $containerName  so the cgroup sampler can find the
     *                                 container WHILE it runs, which is the
     *                                 only time its counters exist
     * @return array{0: list<string>, 1: bool, 2: bool, 3: CgroupSample, 4: bool}
     */
    private function execute(array $argv, RunSpecification $spec, ?string $credential, string $containerName): array
    {
        $descriptors = [
            0 => $spec->acceptsStdin ? ['pipe', 'r'] : ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($argv, $descriptors, $pipes);

        if (! is_resource($process)) {
            return [['the container runtime could not be started'], false, false, new CgroupSample, false];
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
        $sampler = null;
        $sample = new CgroupSample;
        $overQuota = false;
        $cancelled = false;
        $lastDiskCheck = microtime(true);
        $lastCancelCheck = microtime(true);

        /*
         * 🛑 §8.5.21's "stream build logs line by line", as a file the
         * worker can tail. Until Phase 08 a stage's output crossed in the
         * result document, so a nine-minute build produced nothing to read
         * for nine minutes — which makes §8.5.22's offset contract and
         * §8.5.23's queue position decorations rather than features.
         *
         * Opened lazily: a stage that prints nothing leaves no file, and
         * the worker treats an absent file as an empty one.
         */
        $spool = $this->spool();
        $live = new LiveLogWriter($spool->liveLog($spool->jobId($spec)), $credential);

        $deadline = microtime(true) + $spec->timeoutSeconds;
        $lastOutput = microtime(true);
        $timedOut = false;
        $stalled = false;
        $exited = false;

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
                        $live->write($line, $slot === 0 ? 'out' : 'err');
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

            /*
             * 🛑 §8.5.15's authoritative reading, taken HERE because the
             * cgroup is deleted the moment the container exits (measured in
             * Phase 07; see `CgroupSampler`). Sampling in this loop costs one
             * `file_get_contents` per 200 ms select timeout and is the only
             * point at which `oom_kill` and `pids.events:max` are readable
             * at all.
             */
            $sampler ??= $this->resolveSampler($containerName);
            $sample = $sampler === null ? $sample : $sample->merge($sampler->sample());

            /*
             * 🛑 §8.5.18's disk limit, ENFORCED rather than noticed. Two
             * seconds is the cadence: the measurement stops as soon as the
             * ceiling is passed (see {@see Workspace::bytesUsed()}), so the
             * case this is protecting against — a build writing as fast as
             * the disk allows — is also the cheapest case to detect. The
             * overshoot is bounded by what one tick can write, which is the
             * honest cost of having no filesystem quota to hand the kernel.
             */
            /*
             * 🛑 §8.5.23: "support cancelling a running build with effect
             * within 5 seconds". Checked every half second against a file
             * the worker writes, so the bound is this interval plus the
             * time `docker kill` takes — not a queue's visibility timeout
             * and not a poll somebody tuned for a different purpose.
             */
            if (microtime(true) - $lastCancelCheck > 0.5) {
                $lastCancelCheck = microtime(true);

                if ($spool->cancelRequested($spool->jobId($spec))) {
                    $cancelled = true;

                    break;
                }
            }

            if (microtime(true) - $lastDiskCheck > 2.0) {
                $lastDiskCheck = microtime(true);

                if ($this->workspaceIsOverQuota($spec)) {
                    $overQuota = true;

                    break;
                }
            }

            /*
             * 🛑 **Exiting is not the same as finished, and conflating the
             * two silently truncates the log.**
             *
             * This used to `break` the moment `proc_get_status` reported
             * the process gone — which discards whatever the kernel still
             * holds in the pipes. A container that writes 64 KiB and exits
             * immediately loses everything after the first chunk: the
             * symptom found here was a 64 KiB line arriving as exactly
             * 8192 bytes with no truncation marker and the next line
             * missing entirely, which looks like a bug in §8.5.21's
             * truncation rather than lost output.
             *
             * So the exit is recorded and the loop keeps draining until
             * both pipes report EOF. The streams are non-blocking, so a
             * read at EOF returns '' and sets `feof` — this adds one more
             * pass, not a wait.
             */
            if (! $exited) {
                $status = proc_get_status($process);
                $exited = ! $status['running'];
            }

            if ($exited && feof($pipes[1]) && feof($pipes[2])) {
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

        if ($timedOut || $stalled || $overQuota || $cancelled) {
            $this->cli->capture(['kill', $this->template->containerName($spec)]);
        }

        foreach ([$pipes[1], $pipes[2]] as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        proc_close($process);

        foreach ($buffer as $slot => $remainder) {
            if ($remainder !== '' && ! $capped) {
                $sanitised = $this->sanitiseLine($remainder);
                $live->write($sanitised, $slot === 0 ? 'out' : 'err');
                $log[] = $sanitised;
            }
        }

        $live->close();

        /*
         * One last reading before the corpse is cold. A container that ran
         * for less than the first select timeout would otherwise never have
         * been sampled at all.
         */
        $sampler ??= $this->resolveSampler($containerName);
        $sample = $sampler === null ? $sample : $sample->merge($sampler->sample());

        return [$log, $timedOut, $stalled, $sample, $cancelled];
    }

    /**
     * The sampler for a running container, resolved once.
     *
     * Looked up by the container's full id rather than its name, because
     * that is what the cgroup directory is named after.
     */
    private function resolveSampler(string $containerName): ?CgroupSampler
    {
        [$status, $id] = $this->cli->capture(['inspect', '--format', '{{.Id}}', $containerName]);

        return $status === 0 ? CgroupSampler::forContainer(trim($id)) : null;
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
        [$status, $output] = $this->cli->capture([
            'inspect', '--format', '{{.State.ExitCode}} {{.State.OOMKilled}}', $name,
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
     * §8.5.15's class and identifier, most specific signal first.
     *
     * 🛑 **A kernel resource event always fails the stage, even on exit 0.**
     * That is a decision rather than an obvious reading, so here is the
     * reason: a generator whose subprocess was OOM-killed, or whose forks
     * were refused at the PID ceiling, can still exit 0 having written a
     * partially generated site — and §8.4.5's output contract checks that a
     * site exists, not that it is complete. Publishing that silently is
     * worse than a failure an author can act on. The counters only rise when
     * the kernel really did kill or refuse something, so there is no benign
     * reading to mistake for one.
     *
     * @return array{0: string|null, 1: string|null}
     */
    private function classify(
        int $exitCode,
        CgroupSample $sample,
        bool $oom,
        bool $timedOut,
        bool $stalled,
        bool $diskExhausted,
        ?string $deniedHost,
        int $blockedPackets,
        bool $cancelled,
        RunSpecification $spec,
    ): array {
        /*
         * 🛑 §8.5.23's cancellation, checked FIRST and before every
         * resource signal. A container killed on request exits 137 and
         * may well have been near its memory ceiling when it died —
         * reading the OOM flag first would tell an author their build ran
         * out of memory when in fact somebody pressed cancel, which is
         * both wrong and the kind of wrong that sends them optimising
         * something that was never the problem.
         */
        if ($cancelled) {
            return [FailureClass::Cancelled->value, 'cancelled_by_request'];
        }

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

        /*
         * `pids.events:max` has no equivalent anywhere in `docker inspect`,
         * which is why a fork bomb was indistinguishable from a successful
         * build before Phase 07: the container exits 0 and the kernel's
         * refusals leave no other trace.
         */
        if ($sample->pidLimitHits > 0) {
            return [FailureClass::Resource->value, 'pid_limit_exceeded'];
        }

        if ($diskExhausted) {
            return [FailureClass::Resource->value, 'disk_quota_exceeded'];
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
         * 🛑 §8.5.9's refusals, and they are **three** identifiers rather
         * than one. Phase 07's exit criteria require a non-allowlisted
         * package host, an outbound request to a blocked host and the cloud
         * metadata endpoint to reach *distinct* terminal states — and they
         * deserve to, because the three need different sentences in front of
         * an author. A dependency that cannot be installed is a packaging
         * problem; a build reaching 169.254.169.254 is a security incident.
         *
         * The host comes from the proxy's own access log, attributed by the
         * warden's address, so the message can name it.
         */
        if ($deniedHost !== null) {
            if ($deniedHost === '169.254.169.254') {
                return [FailureClass::User->value, 'egress_metadata_endpoint_denied'];
            }

            if ($spec->stage->value === 'environment') {
                return [FailureClass::User->value, 'package_host_not_allowlisted'];
            }

            return [FailureClass::User->value, 'egress_host_not_allowlisted'];
        }

        /*
         * 🛑 Nothing in the proxy's log, but the nftables ruleset dropped
         * packets: a build that opened a socket itself and went round the
         * proxy entirely. Distinguishable from a proxy refusal precisely
         * because the proxy never saw it, which is the whole point of the
         * second layer.
         *
         * Read from a **named nft counter**, not inferred from the build's
         * own words. "Connection timed out", "Network is unreachable" and a
         * tracebacked `OSError` are the same event phrased three ways, and a
         * classifier that sniffed for them would also catch every build
         * whose dependency server was simply down.
         */
        if ($blockedPackets > 0) {
            return [FailureClass::User->value, 'egress_blocked_at_layer3'];
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
     * 🛑 Read straight off the workspace, which the runner can now see
     * (Phase 07's bind mount). Phase 06 read it with `cat` in a throwaway
     * container because the workspace was a named volume and there was no
     * other way in; before that it used `PharData`, which threw on a
     * temporary path with no recognised extension and took the whole runner
     * process down with it. Three versions, each simpler than the last.
     *
     * The file is written by the fetch image, which runs repository-free
     * code (§8.5.7) — but the decode is still bounded in depth and the
     * result is still only used for facts nothing is authorised by.
     *
     * @return array<string, mixed>
     */
    private function readFacts(RunSpecification $spec): array
    {
        if (! $spec->stage->receivesCredentials()) {
            return [];
        }

        $path = Workspace::pathFor($spec->volume).'/fetch-result.json';

        if (! is_file($path) || filesize($path) > 65536) {
            return [];
        }

        $body = @file_get_contents($path);

        if ($body === false) {
            return [];
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($body, true, 8, JSON_THROW_ON_ERROR);

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

    /** @param array<string, string> $extra */
    private function writeEnvFile(RunSpecification $spec, array $extra = []): string
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
        fwrite($handle, $this->template->renderEnvFile($spec, $extra));
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
}
