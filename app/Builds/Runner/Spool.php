<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\RunSpecification;

/**
 * The directory the worker and the runner exchange work through.
 *
 * 🛑 **Why a directory and not a queue or a socket.** §8.5.13 makes the runner
 * the sole holder of the container-runtime socket, and Phase 06's exit
 * criteria require its environment to contain "no database credentials and no
 * `APP_KEY`". A Laravel queue would hand it the database. An HTTP endpoint
 * would give a listening port to the one host that runs other tenants' code
 * moments later. A directory gives it neither, and the whole exchange can be
 * audited by listing it.
 *
 * 🛑 **Claiming is a `rename`, which is atomic.** Two runners racing for the
 * same job both call `rename(inbox/j, claimed/j)`; exactly one succeeds. That
 * is the entire mutual exclusion, it needs no lock file, and it cannot leave
 * a job claimed by a process that has died — the reaper looks at
 * `claimed/` by age. A lock file would need a liveness protocol of its own,
 * which is the heartbeat lease, and the lease belongs on the step row where
 * an operator can see it.
 *
 * 🛑 **The credential channel, and the compromise in it, stated plainly.**
 *
 * §8.5.7 governs how a credential reaches *git*: "only through a git
 * credential helper reading a file descriptor — never argv, never the remote
 * URL, never the environment". That is satisfied in full — the runner pipes
 * the bytes into the fetch container's **stdin**, and the container's
 * entrypoint puts them on a tmpfs the helper reads.
 *
 * What §8.5.7 does not govern is the hop from the worker to the runner, and
 * here the implementation is weaker than it should be: a mode-0600 file in
 * the spool, written just before the job is visible and unlinked by the
 * runner the instant it has been read. §11.2 permits it — the runner zone's
 * declared contents are "runtime socket, **git credentials**" — but it is a
 * secret briefly at rest on a shared volume, which is the thing §9.1.7
 * spends an envelope avoiding everywhere else.
 *
 * A FIFO would carry it in kernel buffers with nothing at rest, and was
 * tried first. It does not work from PHP without a non-blocking `open`:
 * `fopen($fifo, 'w')` blocks until a reader arrives, `fopen($fifo, 'r+')`
 * returns immediately but discards the buffer when the last descriptor
 * closes, and there is no mode that gives both. Either shape deadlocks the
 * worker against a runner that has not claimed the job yet.
 *
 * Recorded as owed rather than papered over: the fix is a non-blocking open
 * through `ext-posix`, or an `SO_PASSCRED` unix socket, and it belongs with
 * Phase 07's trust-zone work where the runner's boundary is being built
 * anyway. The exposure today is bounded by a 0600 mode on a volume only the
 * worker and the runner mount, by a window of milliseconds, and by the fact
 * that a public repository — which is all Phase 06 can reach — sends nothing
 * at all.
 */
final readonly class Spool
{
    public function __construct(private string $root) {}

    public static function fromConfig(): self
    {
        return new self(BuildConfig::string('spool', '/var/lib/docup/spool'));
    }

    public function root(): string
    {
        return $this->root;
    }

    /** Create the four directories, idempotently. */
    public function ensure(): void
    {
        foreach (['tmp', 'inbox', 'claimed', 'outbox', 'cred'] as $directory) {
            $path = $this->root.'/'.$directory;

            if (! is_dir($path)) {
                @mkdir($path, $directory === 'cred' ? 0o700 : 0o750, true);
            }
        }
    }

    /** `<build>-<stage>`: one job per stage of a build, and collisions are a bug. */
    public function jobId(RunSpecification $spec): string
    {
        return $spec->buildId.'-'.$spec->stage->value;
    }

    public function inbox(string $jobId): string
    {
        return $this->root.'/inbox/'.$jobId.'.json';
    }

    public function claimed(string $jobId): string
    {
        return $this->root.'/claimed/'.$jobId.'.json';
    }

    public function result(string $jobId): string
    {
        return $this->root.'/outbox/'.$jobId.'.json';
    }

    /** Where the build stage's output tar lands, for the worker to publish. */
    public function output(string $jobId): string
    {
        return $this->root.'/outbox/'.$jobId.'.tar';
    }

    public function credentialPath(string $jobId): string
    {
        return $this->root.'/cred/'.$jobId;
    }

    /**
     * Leave a credential for the runner.
     *
     * 🛑 Written to `tmp/` with mode 0600 **before** it is renamed into
     * `cred/`, so the file is never visible at its final path while it is
     * still being written and never visible at all with a permissive mode.
     * `chmod` after `file_put_contents` would leave a window in which the
     * file exists world-readable.
     */
    public function writeCredential(string $jobId, string $credential): void
    {
        $this->ensure();

        $temporary = $this->root.'/tmp/'.$jobId.'.cred';

        $handle = fopen($temporary, 'wb');

        if ($handle === false) {
            throw new \RuntimeException('could not stage a credential for the runner');
        }

        @chmod($temporary, 0o600);
        fwrite($handle, $credential);
        fclose($handle);

        rename($temporary, $this->credentialPath($jobId));
    }

    /**
     * Take the credential, removing it.
     *
     * Read-and-unlink in one call so there is no path on which a caller gets
     * the bytes and forgets to remove the file. Returns null when there is
     * none, which is the ordinary case: a public repository needs no
     * credential and none is written.
     */
    public function takeCredential(string $jobId): ?string
    {
        $path = $this->credentialPath($jobId);

        if (! is_file($path)) {
            return null;
        }

        $credential = file_get_contents($path);
        @unlink($path);

        return $credential === false ? null : $credential;
    }

    /**
     * Publish a job.
     *
     * 🛑 Written to `tmp/` and **renamed** into `inbox/`. A runner polling
     * `inbox/` must never see a half-written document, and `rename` within one
     * filesystem is the only way to promise that without a lock. Writing in
     * place and hoping the poll interval is longer than the write is how a
     * runner ends up parsing half a JSON object at the worst moment.
     */
    public function submit(RunSpecification $spec): string
    {
        $this->ensure();

        $jobId = $this->jobId($spec);
        $temporary = $this->root.'/tmp/'.$jobId.'.json';

        file_put_contents($temporary, json_encode($spec->toArray(), JSON_THROW_ON_ERROR));
        @chmod($temporary, 0o640);

        if (! rename($temporary, $this->inbox($jobId))) {
            @unlink($temporary);

            throw new \RuntimeException("could not submit job {$jobId} to the runner spool");
        }

        return $jobId;
    }

    /**
     * Claim the next job, or null.
     *
     * @return array{0: string, 1: RunSpecification}|null
     */
    public function claimNext(): ?array
    {
        $this->ensure();

        $candidates = glob($this->root.'/inbox/*.json') ?: [];
        sort($candidates, SORT_STRING);   // oldest job id first; ids are time-ordered UUIDv7 prefixes

        foreach ($candidates as $candidate) {
            $jobId = basename($candidate, '.json');

            // The claim. Exactly one caller's rename succeeds.
            if (! @rename($candidate, $this->claimed($jobId))) {
                continue;
            }

            $body = @file_get_contents($this->claimed($jobId));

            if ($body === false) {
                continue;
            }

            try {
                /** @var array<array-key, mixed> $decoded */
                $decoded = json_decode($body, true, 16, JSON_THROW_ON_ERROR);

                // 🛑 Re-validated by the same constructor the worker used. A
                // spool file is a file; the typed specification is trusted for
                // its shape, never for its author.
                return [$jobId, RunSpecification::fromArray($decoded)];
            } catch (\JsonException|\InvalidArgumentException $refused) {
                $this->writeResult($jobId, RunOutcome::rejected($refused->getMessage())->toArray());

                continue;
            }
        }

        return null;
    }

    /** @param  array<string, mixed>  $result */
    public function writeResult(string $jobId, array $result): void
    {
        $this->ensure();

        $temporary = $this->root.'/tmp/'.$jobId.'.result.json';
        file_put_contents($temporary, json_encode($result, JSON_THROW_ON_ERROR));
        rename($temporary, $this->result($jobId));

        @unlink($this->claimed($jobId));
    }

    /** The result, once the runner has written it. Null while it has not. */
    public function readResult(string $jobId): ?RunOutcome
    {
        $path = $this->result($jobId);

        if (! is_file($path)) {
            return null;
        }

        $body = file_get_contents($path);

        if ($body === false) {
            return null;
        }

        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($body, true, 16, JSON_THROW_ON_ERROR);

        return RunOutcome::fromArray($decoded);
    }

    /** Remove everything belonging to a finished job. */
    public function discard(string $jobId): void
    {
        foreach ([
            $this->inbox($jobId),
            $this->claimed($jobId),
            $this->result($jobId),
            $this->output($jobId),
            $this->credentialPath($jobId),
        ] as $path) {
            @unlink($path);
        }
    }
}
