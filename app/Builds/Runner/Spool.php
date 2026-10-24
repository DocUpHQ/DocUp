<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\BuildConfig;
use App\Builds\Exceptions\RunSpecificationRefused;
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
 * 🛑 **The credential never crosses this directory.** Phase 06 passed it as
 * a mode-0600 file here and recorded the compromise as owed: a secret
 * briefly at rest on a shared volume, which is what §9.1.7 spends an
 * envelope avoiding everywhere else. Phase 07 pays it off —
 * {@see CredentialChannel} is an `AF_UNIX` socket, and the only thing in
 * this directory is the rendezvous node. §8.5.7's own requirement, that the
 * credential reach *git* through a file descriptor and never argv, the URL
 * or the environment, was satisfied from Phase 06 and is unchanged.
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
        foreach (['tmp', 'inbox', 'claimed', 'outbox', 'cred', 'live', 'cancel'] as $directory) {
            $path = $this->root.'/'.$directory;

            if (! is_dir($path)) {
                @mkdir($path, $directory === 'cred' ? 0o700 : 0o750, true);
            }
        }
    }

    /** `<build>-<stage>`: one job per stage of a build, and collisions are a bug. */
    public function jobId(RunSpecification $spec): string
    {
        return $spec->buildId.'-'.$spec->stage->value.($spec->pass === '' ? '' : '-'.$spec->pass);
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

    /**
     * Where the runner streams a stage's output WHILE it runs (§8.5.21).
     *
     * 🛑 The whole point of Phase 08. Until now a stage's log crossed in
     * the result document, which meant a nine-minute build produced
     * nothing to read for nine minutes and then produced all of it — and
     * §8.5.23's queue position and §8.5.22's offset contract both exist to
     * be watched, not to be delivered at the end.
     *
     * The runner writes here; the worker tails it, redacts and persists.
     * The file holds whatever the container printed, so it is the one
     * place in the pipeline where an unredacted secret could appear — the
     * runner scrubs the single credential it holds before writing, and the
     * directory is inside the spool, which only the worker and the runner
     * mount.
     */
    public function liveLog(string $jobId): string
    {
        return $this->root.'/live/'.$jobId.'.ndjson';
    }

    /**
     * §8.5.23's cancellation, as a file the runner can see.
     *
     * 🛑 A file rather than a signal or a queue message, for the reason the
     * whole spool exists: the runner has no database and no listening
     * port. The worker writes this when a cancel is requested and the
     * runner's output loop checks for it on every pass, so "within 5
     * seconds" is bounded by the loop's 200 ms tick rather than by a poll
     * interval somebody tuned.
     */
    public function cancelMarker(string $jobId): string
    {
        return $this->root.'/cancel/'.$jobId;
    }

    public function requestCancel(string $jobId): void
    {
        $this->ensure();

        @touch($this->cancelMarker($jobId));
    }

    public function cancelRequested(string $jobId): bool
    {
        return is_file($this->cancelMarker($jobId));
    }

    /** The rendezvous node for {@see CredentialChannel}; never a file of bytes. */
    public function credentialPath(string $jobId): string
    {
        return $this->root.'/cred/'.$jobId.'.sock';
    }

    /**
     * Open the credential channel for a job.
     *
     * 🛑 Opened **before** the job is submitted. A runner that claimed the
     * job first would find no socket and fetch without a credential, which
     * for a private repository is an authentication failure reported as a
     * missing ref — the most misleading answer available.
     */
    public function openCredentialChannel(string $jobId, string $credential): CredentialChannel
    {
        $this->ensure();

        return CredentialChannel::open($this->credentialPath($jobId), $credential);
    }

    /**
     * The runner's side: take the credential off the channel.
     *
     * Null when there is none, which is the ordinary case — a public
     * repository needs no credential and the worker opens no channel.
     */
    public function takeCredential(string $jobId): ?string
    {
        return CredentialChannel::receive($this->credentialPath($jobId));
    }

    /**
     * §8.5.12's verdict, for the processes that cannot run it themselves.
     *
     * 🛑 The runner holds the socket and no database; the worker and the
     * dashboard hold the database and no socket. So the self-test's result
     * crosses the one channel the trust zones share, in the one direction
     * that leaks nothing: a boolean and a sentence, written by the side
     * that has no credentials to disclose.
     */
    public function writeSelfTest(bool $passed, string $summary): void
    {
        $this->ensure();

        $temporary = $this->root.'/tmp/self-test.json';
        $document = ['passed' => $passed, 'summary' => $summary, 'at' => time()];

        file_put_contents($temporary, json_encode($document, JSON_THROW_ON_ERROR));
        @rename($temporary, $this->root.'/self-test.json');
    }

    /** @return array{passed: bool, summary: string, at: int}|null */
    public function readSelfTest(): ?array
    {
        $body = @file_get_contents($this->root.'/self-test.json');

        if ($body === false) {
            return null;
        }

        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return [
            'passed' => ($decoded['passed'] ?? false) === true,
            'summary' => is_string($decoded['summary'] ?? null) ? $decoded['summary'] : '',
            'at' => is_int($decoded['at'] ?? null) ? $decoded['at'] : 0,
        ];
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
                /*
                 * 🛑 The refusal keeps its own identifier. A spool document
                 * asking for a mount, a capability or the runtime socket is
                 * `rejected.runtime_socket_requested`; a malformed one is
                 * `rejected.run_specification_refused`. They are the same
                 * code path and very different events.
                 */
                $code = $refused instanceof RunSpecificationRefused
                    ? $refused->reason
                    : 'run_specification_refused';

                $this->writeResult($jobId, RunOutcome::rejected($refused->getMessage(), $code)->toArray());

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
            $this->liveLog($jobId),
            $this->cancelMarker($jobId),
        ] as $path) {
            @unlink($path);
        }
    }
}
