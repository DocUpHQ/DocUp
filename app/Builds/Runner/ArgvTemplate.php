<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\RunSpecification;

/**
 * The fixed argv template of §8.5.13.
 *
 * 🛑 In `App\Builds\Runner` rather than `App\Builds`, because this is the
 * one class outside the driver that names a container runtime — and
 * `ArchitectureTest::test_only_the_runner_namespace_names_a_container_runtime`
 * allows exactly one namespace to. An exemption for this file would have
 * been an allowlist with one entry, which is how allowlists start.
 *
 * > "it MUST accept only a typed run specification rendered through a **fixed
 * > argv template**. 🛑 There MUST be no code path from a webhook, a YAML
 * > value or an HTTP request to an arbitrary runtime call."
 *
 * 🛑 **"Fixed" means the flags are literals in this file and nothing else
 * ever becomes one.** Every element this method emits is either a constant
 * written here or a value from {@see RunSpecification}, which validated it.
 * There is no concatenation, no `implode`, no shell. A value containing
 * `--privileged` arrives at the daemon as the literal string `--privileged`
 * in a value position, where it is a volume name that does not exist rather
 * than a flag that grants the container the host.
 *
 * 🛑 **The environment is written to a file, not passed as `-e`.** Two
 * reasons, and the second is the one that matters: argv is readable by any
 * process on the host through `/proc/<pid>/cmdline`, and `docker inspect`
 * returns `Config.Env` to anyone who can reach the socket. §8.5.25 requires
 * component secrets to be "never present during `fetch`" and redacted
 * everywhere; keeping them out of argv and out of the container config is how
 * that survives contact with an operator running `docker inspect` to debug
 * something unrelated.
 *
 * The §8.5.8 hardening flags are set here even though sandbox hardening is
 * Phase 07's deliverable. They are one literal each and omitting them would
 * mean shipping a phase whose containers run with the host's default
 * capabilities — Phase 07 adds the network namespace, the nftables backstop,
 * the egress proxy and the boot self-test, which is where the real work is.
 */
final readonly class ArgvTemplate
{
    /**
     * The label every container this template renders carries, and the only
     * thing the sweep will remove.
     */
    public const OWNER_LABEL = 'docup.owner=build-runner';

    /**
     * @param  string  $imageReference  resolved from the allowlist by the caller,
     *                                  never taken from the specification
     * @param  string  $envFilePath  a file the runner wrote, mode 0600
     * @param  SandboxPlacement  $placement  the network namespace and runtime the
     *                                       runner resolved; never repository input
     * @return list<string>
     */
    public function render(
        RunSpecification $spec,
        string $imageReference,
        string $envFilePath,
        SandboxPlacement $placement,
    ): array {

        $argv = [
            'docker', 'run',

            /*
             * 🛑 **No `--rm`, deliberately.** §8.5.15 requires OOM to be read
             * "authoritatively from cgroup `memory.events:oom_kill`" rather
             * than guessed from an exit code — and a container removed the
             * instant it exits takes its cgroup, its `State.OOMKilled` and
             * its real exit status with it. The driver inspects the corpse
             * and then removes it, so the distinction between "the generator
             * exited 137" and "the kernel killed it for memory" survives long
             * enough to be recorded. Those two need different words in front
             * of an author, and `resource.oom_killed` is one of §8.5.15's own
             * worked examples.
             *
             * The cost is that a runner killed between `run` and `rm` leaves
             * a container behind, which `DockerRunnerDriver::sweep()` removes
             * at start-up by name prefix.
             */

            // Named so a stuck container is identifiable without correlating
            // ids, and so a second run for the same build+stage collides
            // instead of silently running twice.
            '--name', $this->containerName($spec),

            /*
             * 🛑 **The sweep's only safe filter.** A runner that dies leaves
             * containers behind, and the runner removes them at start-up —
             * but it must remove only its own. The first version filtered on
             * the name prefix `docup-`, which also matches every container
             * compose creates for this project: `docup-app-1`, `docup-db-1`,
             * `docup-runner-1`. It removed itself on its first start, and had
             * `docker ps` returned its siblings first it would have removed
             * the database.
             *
             * A label this template is the only writer of cannot collide with
             * a naming convention somebody else chose. Found by running it.
             */
            '--label', self::OWNER_LABEL,
            '--label', 'docup.build='.$spec->buildId,
            '--label', 'docup.stage='.$spec->stage->value,

            // ---------------------------------------------- §8.5.8 hardening
            '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--pids-limit', (string) BuildConfig::positiveInt('limits.pids', 512),
            '--memory', BuildConfig::positiveInt('limits.memory_mb', 4096).'m',

            /*
             * 🛑 "swap disabled" (§8.5.8). `--memory-swap` equal to `--memory`
             * is how Docker expresses that; omitting it gives the container
             * twice its memory limit in swap, which turns an OOM kill the
             * runner can classify into a machine that thrashes for half an
             * hour and reports a timeout.
             */
            '--memory-swap', BuildConfig::positiveInt('limits.memory_mb', 4096).'m',
            '--cpus', BuildConfig::cpus(),
        ];

        if ($spec->readOnlyRoot) {
            $argv[] = '--read-only';
        }

        /*
         * The only writable path outside the build volume. `noexec` matters:
         * a generator that downloads a binary into /tmp and runs it is the
         * ordinary shape of a supply-chain compromise, and this makes it fail
         * at the exec rather than succeed quietly.
         */
        /*
         * 🛑 `mode=1777` is not decoration. Docker gives a `--tmpfs` with
         * explicit options a default mode of 0755 owned by root, and every
         * container here runs as uid 10001 — so without it the generator
         * cannot write to /tmp at all. Found by running the containers by
         * hand; the symptom was a permission error from inside a container
         * whose whole root filesystem is read-only, which reads like the
         * `--read-only` flag being at fault rather than the tmpfs mode.
         */
        $argv[] = '--tmpfs';
        $argv[] = '/tmp:rw,noexec,nosuid,nodev,mode=1777,size='.BuildConfig::positiveInt('limits.tmpfs_mb', 512).'m';

        if ($spec->stage->receivesCredentials()) {
            /*
             * §8.5.7's credential lands here, written by the fetch image's
             * entrypoint from stdin. Its own tmpfs so it is never on a disk,
             * never in the volume the build stage later mounts, and gone when
             * the container exits.
             */
            /*
             * Owned by the container's own user and mode 0700, not 1777: this
             * tmpfs holds §8.5.7's credential for the length of one clone,
             * and a world-writable directory for a credential would be a
             * worse answer than the permission error that revealed the
             * default.
             */
            $argv[] = '--tmpfs';
            $argv[] = '/run:rw,noexec,nosuid,nodev,uid=10001,gid=10001,mode=0700,size=1m';
        }

        /*
         * §8.5.9, as one flag. Phase 06 could only choose between `none` and
         * `bridge` because there was no proxy to point at; Phase 07's three
         * modes are rendered by {@see SandboxPlacement}, and the one that
         * matters - `container:<warden>` - puts this container inside a
         * network namespace whose nftables ruleset was installed before it
         * started and which it has no capability to change (ADR 0011).
         */
        $argv[] = '--network';
        $argv[] = $placement->network;

        /*
         * 🛑 §8.5.11's isolation declaration, reaching the runtime. Absent
         * when the operator declared nothing, which only production boot
         * refuses - a development machine with no gVisor installed is a
         * supported configuration and must not be given a `--runtime` flag
         * naming a binary that is not there.
         *
         * The value is a lookup in the §8.5.11 allowlist, never the
         * operator's string: `--runtime` names an executable the daemon
         * runs, and an unvalidated value here would be the one place in the
         * pipeline where configuration becomes code.
         */
        if ($placement->runtime !== null) {
            $argv[] = '--runtime';
            $argv[] = $placement->runtime;
        }

        /*
         * One workspace per build (§8.5.20's reasoning, applied to working
         * trees rather than caches): never shared, created and removed by
         * the runner.
         *
         * 🛑 A bind rather than a named volume, since Phase 07. The runner
         * has to be able to measure this tree while the build runs to
         * enforce §8.5.18's disk limit, and it can only do that for a path
         * it can see — see {@see Workspace}, which records the two
         * kernel-enforced alternatives that were measured and refused.
         */
        $argv[] = '--mount';
        $argv[] = 'type=bind,source='.Workspace::pathFor($spec->volume).',target=/workspace';

        $argv[] = '--workdir';
        $argv[] = $spec->workdir;

        // See the class docblock: a file, never `-e`.
        $argv[] = '--env-file';
        $argv[] = $envFilePath;

        if ($spec->acceptsStdin) {
            $argv[] = '--interactive';
        }

        $argv[] = $imageReference;

        /*
         * 🛑 The image is the last flag-position element. Everything after it
         * is the container's own argv, which Docker does not interpret — so
         * a hostile value in `command` cannot become a `docker run` flag even
         * if it is spelled like one. The validation in `RunSpecification`
         * stops it being a hostile *argument*; this ordering stops it being a
         * flag at all.
         *
         * 🛑 A stage carrying a §8.4.10 script takes neither path: its argv
         * is two fixed elements, both chosen here, with nothing of the
         * repository's in it. The commands are in a file the runner wrote
         * (`DockerRunnerDriver::writeScript()`), which is the narrowest
         * reading of §8.5.13's "fixed argv template" that still lets an
         * author run their own build.
         */
        if ($spec->script !== null) {
            $argv[] = $spec->shell;
            $argv[] = RunSpecification::SCRIPT_PATH;

            return $argv;
        }

        foreach ($spec->command as $argument) {
            $argv[] = $argument;
        }

        return $argv;
    }

    /** `docup-<build>-<stage>`: identifiable, and collides with a duplicate run. */
    public function containerName(RunSpecification $spec): string
    {
        return 'docup-'.$spec->buildId.'-'.$spec->stage->value;
    }

    /**
     * The `--env-file` body.
     *
     * Docker's env-file parser takes `NAME=value` to the end of the line with
     * no quoting and no escapes, so a value containing a newline would inject
     * a second variable. {@see RunSpecification} already refuses those; this
     * asserts it again rather than trusting a caller to have used the right
     * constructor, because the cost is one comparison and the failure is a
     * variable nobody declared.
     *
     * @param  array<string, string>  $extra  the runner's own variables — the
     *                                        §8.5.9 proxy address and nothing
     *                                        else today — appended last
     */
    public function renderEnvFile(RunSpecification $spec, array $extra = []): string
    {
        $lines = [];

        foreach ($spec->environment as $name => $value) {
            if (str_contains($value, "\n") || str_contains($value, "\r")) {
                throw new \InvalidArgumentException("environment value for {$name} spans lines");
            }

            $lines[] = $name.'='.$value;
        }

        /*
         * 🛑 The runner's own variables are appended LAST, and the order is
         * the control: Docker's env-file parser lets a later line replace an
         * earlier one, so appending is what stops anything that crossed the
         * spool from redirecting `https_proxy` at an address of its own
         * choosing. §8.4.6's three scopes govern what a *build* may be told;
         * the proxy address is none of them — it is resolved per run by the
         * process holding the socket, and the specification never knew it.
         */
        foreach ($extra as $name => $value) {
            if (preg_match('/^[A-Za-z][A-Za-z0-9_]{0,63}$/', $name) !== 1
                || preg_match('/[\x00\n\r]/', $value) === 1) {
                throw new \InvalidArgumentException('unusable runner environment variable: '.$name);
            }

            $lines[] = $name.'='.$value;
        }

        return implode("\n", $lines)."\n";
    }
}
