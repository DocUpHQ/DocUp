<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

/**
 * A real HTTP origin on loopback, for the controls that cannot be proven
 * against their own configuration.
 *
 * 🛑 Phase 04 recorded this lesson at a cost of a day (§18.18): "a config
 * asserted only against a constant is a config nobody has run". Two of
 * §8.3.9's clauses are exactly that shape. `CURLOPT_FOLLOWLOCATION => false`
 * in a test that asserts the options array proves the array; it does not
 * prove that a 302 is not followed, which is a claim about libcurl. And a
 * byte cap asserted against `strlen($body)` proves nothing about whether the
 * transfer was aborted mid-flight or buffered whole and then measured.
 *
 * So this serves real bytes over a real socket. It is PHP's built-in server
 * with a router script, started as a child process and reaped in `stop()`.
 *
 * The egress client's **address policy correctly refuses loopback**, which is
 * why a test using this server constructs its client with
 * `enforceAddressPolicy: false`. That is standing one control down to exercise
 * another, in a test, with the production wiring asserted separately by
 * `EgressConfigurationTest` and `ArchitectureTest` — not the same thing as
 * shipping it off.
 */
final class LoopbackHttpServer
{
    /** @var resource|null */
    private $process = null;

    /** @var array<int, resource> */
    private array $pipes = [];

    private int $port;

    private string $routerPath;

    public function __construct(private string $router)
    {
        $this->port = random_int(20000, 45000);
        $this->routerPath = tempnam(sys_get_temp_dir(), 'docup-router').'.php';
    }

    /** `http://host:port`, where `host` is the name the caller will pin. */
    public function origin(string $host = '127.0.0.1'): string
    {
        return 'http://'.$host.':'.$this->port;
    }

    public function port(): int
    {
        return $this->port;
    }

    public function start(): self
    {
        file_put_contents($this->routerPath, $this->router);

        $descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];

        $process = proc_open(
            ['php', '-S', '127.0.0.1:'.$this->port, '-t', dirname($this->routerPath), $this->routerPath],
            $descriptors,
            $this->pipes,
        );

        if (! is_resource($process)) {
            throw new \RuntimeException('could not start the loopback HTTP server');
        }

        $this->process = $process;
        $this->waitUntilListening();

        return $this;
    }

    public function stop(): void
    {
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        $this->pipes = [];

        if (is_resource($this->process)) {
            proc_terminate($this->process);
            proc_close($this->process);
            $this->process = null;
        }

        @unlink($this->routerPath);
    }

    /**
     * Poll the socket rather than sleeping a fixed interval.
     *
     * A fixed sleep is either too short on a loaded CI runner — where it
     * produces a flake that reads as a transport bug — or too long everywhere
     * else.
     */
    private function waitUntilListening(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $socket = @fsockopen('127.0.0.1', $this->port, $errno, $error, 0.2);

            if (is_resource($socket)) {
                fclose($socket);

                return;
            }

            usleep(50_000);
        }

        throw new \RuntimeException('the loopback HTTP server did not start listening on port '.$this->port);
    }
}
