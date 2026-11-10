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

    /**
     * Everything the server has written, accumulated.
     *
     * A field rather than a read on demand, because `stream_get_contents`
     * **drains** a pipe: reading it twice loses what the first read took, and
     * the readiness check reads it every 50 ms.
     */
    private string $said = '';

    /**
     * 🛑 How many ports to try before giving up.
     *
     * The first version took `random_int(20000, 45000)` and used it without
     * asking whether anything was already there. On a CI runner something
     * often is, and the two outcomes were both bad: `php -S` failed to bind
     * and the readiness probe then **connected to the other process**, which
     * is a false green; or nothing was listening and the probe waited ten
     * seconds to report "did not start listening", which named the symptom and
     * not the cause.
     */
    private const int PORT_ATTEMPTS = 20;

    /**
     * @param  int|null  $port  a port to use instead of a found one.
     *                          🛑 For the fixture's own test only, which has
     *                          to hold a port itself to prove that a server
     *                          that cannot bind is reported as having
     *                          **exited** rather than as having been slow.
     *                          Every real caller omits it and gets a port
     *                          nothing was listening on.
     */
    public function __construct(private string $router, ?int $port = null)
    {
        $this->port = $port ?? self::freePort();
        $this->routerPath = tempnam(sys_get_temp_dir(), 'docup-router').'.php';
    }

    /**
     * A port nothing is listening on, found by **binding** it.
     *
     * 🛑 Binding is the only way to know. `fsockopen` failing says nothing was
     * listening a moment ago on the address it tried; binding says this
     * process could have the port, which is the question `php -S` is about to
     * ask.
     *
     * 🛑 And not `tcp://127.0.0.1:0` to let the OS choose, which is the
     * shorter version of this method: the OS allocates from the **ephemeral**
     * range, which is where every outbound connection on the machine also
     * comes from — so an allocated-then-released port is likelier to be taken
     * back between here and `php -S` than a random high one is to be busy in
     * the first place. A bounded search over a fixed range is the safer trade.
     */
    private static function freePort(): int
    {
        for ($attempt = 0; $attempt < self::PORT_ATTEMPTS; $attempt++) {
            $port = random_int(20000, 45000);

            $probe = @stream_socket_server(
                'tcp://127.0.0.1:'.$port,
                $errno,
                $error,
                STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
            );

            if (is_resource($probe)) {
                fclose($probe);

                return $port;
            }
        }

        throw new \RuntimeException(
            'could not find a free loopback port in '.self::PORT_ATTEMPTS.' attempts',
        );
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

        /*
         * Non-blocking, so {@see self::waitUntilListening()} can read what the
         * server said on the way out without hanging on a process that is
         * still running.
         */
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                stream_set_blocking($pipe, false);
            }
        }

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
     * Poll until the server **says it has started**, or until it is known to
     * be dead.
     *
     * A fixed sleep is either too short on a loaded CI runner — where it
     * produces a flake that reads as a transport bug — or too long everywhere
     * else. So this polls; what was wrong was never the polling but what it
     * polled for.
     *
     * ## 🛑 An open socket is not a running server
     *
     * The first version accepted any `fsockopen`, which cannot tell "the
     * development server is up" from "something else holds this port". That is
     * the mistake `compose.ldap.yaml` records about slapd and
     * `compose.meilisearch.yaml` about Meilisearch — a port probe goes green
     * while the service behind it is absent — and here it is worse, because the
     * other process then answers the test's requests and the failure reads as a
     * transport bug. It is also **reproducible**:
     * `tests/Unit/Support/LoopbackHttpServerTest` holds a port and watches
     * `php -S` die on it, and the old probe connected to the test's own socket
     * and reported success.
     *
     * ## 🛑 So readiness is the server's own announcement
     *
     * `php -S` writes `PHP x.y.z Development Server (http://127.0.0.1:PORT)
     * started` once it has bound, and `Failed to listen on …` when it cannot.
     * Waiting for the first, **with this port in it**, is a signal only this
     * server can produce: a squatter cannot forge it, and unlike an HTTP
     * request it triggers nothing.
     *
     * 🛑 An HTTP request was the obvious alternative and is wrong **here**: the
     * caller supplies the router, and the routers have side effects the tests
     * assert on. One streams a megabyte and writes a marker file only after it
     * finishes, which is the whole premise of §8.3.9's byte-cap test — a
     * readiness request would run it, write the marker and make the assertion
     * meaningless. It hung the suite when tried.
     *
     * ## 🛑 And a dead server is reported as dead, immediately
     *
     * The first version did not look at the child at all, so it waited the
     * full ten seconds for a process that had been dead since the first
     * millisecond, then reported it as slow. Measured: `php -S` on a taken port
     * exits with code 1 within 100 ms. This checks `proc_get_status()` each
     * pass and fails at once with the exit code and the server's own words.
     *
     * That mystery cost PR #27 a CI cycle and PR #29 another, which is why a
     * Phase 29 branch is touching a Phase 05 fixture at all.
     */
    private function waitUntilListening(): void
    {
        $deadline = microtime(true) + 10.0;

        while (microtime(true) < $deadline) {
            $this->drain();

            if ($this->announcedItself()) {
                return;
            }

            $died = $this->exitedWith();

            if ($died !== null) {
                /*
                 * 🛑 The announcement is checked BEFORE this, because a server
                 * that started and then exited for its own reasons — a router
                 * calling `die()`, which §8.3.9's byte-cap test relies on — has
                 * still started. Checking death first would turn that test's
                 * own mechanism into a fixture failure.
                 */
                throw new \RuntimeException(
                    'the loopback HTTP server exited with code '.$died.' before listening on port '
                    .$this->port.': '.($this->said ?: '(it said nothing)'),
                );
            }

            usleep(50_000);
        }

        $this->drain();

        throw new \RuntimeException(
            'the loopback HTTP server did not announce itself on port '.$this->port.' within 10s: '
            .($this->said ?: '(it said nothing)'),
        );
    }

    /**
     * Whether the server has announced **this** port.
     *
     * The port is matched as well as the phrase, so the announcement cannot be
     * another server's — which is the whole reason this is the readiness signal
     * rather than a socket connect.
     */
    private function announcedItself(): bool
    {
        return str_contains($this->said, 'Development Server')
            && str_contains($this->said, (string) $this->port);
    }

    /** The child's exit code if it has already exited, else null. */
    private function exitedWith(): ?int
    {
        if (! is_resource($this->process)) {
            return null;
        }

        $status = proc_get_status($this->process);

        if ($status['running'] === true) {
            return null;
        }

        /*
         * `exitcode` is -1 once the status has already been reaped, which is
         * why it is reported as-is rather than tidied: a -1 here says "it is
         * gone and PHP no longer knows why", and inventing a 0 would turn that
         * into "it succeeded".
         */
        return (int) $status['exitcode'];
    }

    /** Move whatever the server has written into {@see self::$said}. */
    private function drain(): void
    {
        foreach ($this->pipes as $pipe) {
            if (is_resource($pipe)) {
                $this->said .= (string) stream_get_contents($pipe);
            }
        }

        $this->said = trim((string) preg_replace('/\s+/', ' ', $this->said));
    }
}
