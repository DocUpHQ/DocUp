<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

/**
 * The worker → runner credential hop, with nothing at rest.
 *
 * 🛑 **This replaces the mode-0600 file Phase 06 shipped**, which that
 * phase's build log recorded as owed: "a secret briefly at rest on a shared
 * volume, which is the thing §9.1.7 spends an envelope avoiding everywhere
 * else."
 *
 * A FIFO was tried first and cannot work from PHP: `fopen($f, 'w')` blocks
 * until a reader arrives and `fopen($f, 'r+')` discards the buffer when the
 * last descriptor closes, so either shape deadlocks the worker against a
 * runner that has not claimed the job yet. Phase 06 concluded the fix
 * needed `ext-posix` or an `SO_PASSCRED` socket.
 *
 * 🛑 **It needed neither.** An `AF_UNIX` *stream* socket has the property
 * the FIFO lacks: `stream_socket_server()` returns immediately with nobody
 * connected, and `stream_socket_accept($server, 0)` polls without blocking.
 * So the worker can open the channel, publish the job, and then offer the
 * credential from inside the loop it was already using to wait for the
 * result — no extra thread, no extra process, no deadlock. Measured across
 * two containers over a shared named volume before this was written.
 *
 * What the credential never touches, as a result: the filesystem, argv, the
 * environment, the database, and any log. It exists in the worker's memory,
 * in a kernel socket buffer, and in the runner's memory for the length of
 * one `fwrite` into a container's stdin.
 *
 * The socket file itself is mode 0600 and is unlinked in `close()`. A
 * filesystem node with no bytes behind it is not a secret at rest; it is a
 * rendezvous point, and the permission is there so that nothing else on the
 * volume can be the one to arrive.
 */
final class CredentialChannel
{
    /** @var resource|null */
    private $server;

    private bool $delivered = false;

    /** @param  resource  $server */
    private function __construct(
        $server,
        private readonly string $path,
        private string $credential,
    ) {
        $this->server = $server;
    }

    /**
     * Open a channel for one job.
     *
     * @throws \RuntimeException when the socket cannot be created, which is
     *                           a refusal rather than a fallback to a file:
     *                           the file is the thing this exists to remove
     */
    public static function open(string $path, string $credential): self
    {
        @unlink($path);

        $server = @stream_socket_server('unix://'.$path, $errno, $error);

        if ($server === false) {
            throw new \RuntimeException(
                'could not open the credential channel at '.$path.': '.$error.' ('.$errno.')',
            );
        }

        @chmod($path, 0o600);

        return new self($server, $path, $credential);
    }

    /**
     * Hand the credential over if the runner is asking for it right now.
     *
     * 🛑 Returns immediately either way. Called from the worker's existing
     * result-polling loop, which must not stall: a blocking accept here
     * would hang the worker for the whole stage timeout whenever a job was
     * claimed by a runner that then died.
     */
    public function serveOnce(): bool
    {
        if ($this->server === null || $this->delivered) {
            return $this->delivered;
        }

        $client = @stream_socket_accept($this->server, 0);

        if ($client === false) {
            return false;
        }

        fwrite($client, $this->credential);
        fclose($client);

        $this->delivered = true;

        /*
         * Overwritten and dropped the moment it has been handed over, so a
         * worker that goes on to run eleven more stages is not holding a
         * repository credential in memory throughout.
         */
        $this->credential = '';
        $this->closeServer();

        return true;
    }

    public function delivered(): bool
    {
        return $this->delivered;
    }

    public function close(): void
    {
        $this->credential = '';
        $this->closeServer();
        @unlink($this->path);
    }

    private function closeServer(): void
    {
        if (is_resource($this->server)) {
            fclose($this->server);
        }

        $this->server = null;
    }

    /**
     * The runner's side: connect, read the credential, and that is all.
     *
     * Null when there is no channel, which is the ordinary case — a public
     * repository needs no credential and the worker opens none.
     *
     * The read timeout matters: the worker only accepts on its polling
     * tick, so the connection succeeds instantly (the kernel backlog takes
     * it) and the bytes arrive a fraction of a second later. A runner with
     * no timeout would wait for ever for a worker that had died between
     * publishing the job and serving it.
     */
    public static function receive(string $path, float $timeoutSeconds = 15.0): ?string
    {
        if (! file_exists($path)) {
            return null;
        }

        $client = @stream_socket_client('unix://'.$path, $errno, $error, $timeoutSeconds);

        if ($client === false) {
            return null;
        }

        stream_set_timeout($client, (int) $timeoutSeconds);
        $credential = stream_get_contents($client);
        fclose($client);

        return is_string($credential) && $credential !== '' ? $credential : null;
    }
}
