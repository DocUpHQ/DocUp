<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use Tests\Support\LoopbackHttpServer;

/**
 * 🛑 A test for a test fixture, because this one failed CI twice and lied
 * about why.
 *
 * `tests/Feature/Egress/HardenedEgressClientTest` drives §8.3.9's hardened
 * client against a real loopback origin, and {@see LoopbackHttpServer} starts
 * that origin. Twice now — PR #27 and PR #29 — it has failed the baseline gate
 * with **"the loopback HTTP server did not start listening on port NNNNN"**,
 * which named the symptom and not the cause, and both times the response was
 * to re-run the job.
 *
 * Two defects, and neither was the transport the message pointed at:
 *
 * 1. The port came from `random_int(20000, 45000)` and was used **without
 *    asking whether anything was already there**. On a loaded runner something
 *    often is, and both outcomes were bad: `php -S` failed to bind and the
 *    readiness probe then connected to the *other* process, which is a false
 *    green; or nothing was listening and the probe waited the full ten seconds.
 * 2. Nothing looked at the child process. `php -S` that cannot bind prints
 *    `Failed to listen on …` and **exits** — so the fixture waited ten seconds
 *    for a process that had been dead since the first millisecond, and then
 *    reported it as slow.
 *
 * This file is the standing answer to "why can it not recur". The second
 * defect is the one this test can prove directly, by holding the port itself.
 */
final class LoopbackHttpServerTest extends TestCase
{
    /**
     * 🛑 A server that cannot bind is reported as having **exited**, with its
     * own words, and not after a ten-second wait.
     *
     * The port is held by this test for the duration, so `php -S` cannot have
     * it. Before the fix this produced "did not start listening" ten seconds
     * later; now it produces the exit code and whatever the server said, at
     * once.
     */
    public function test_a_server_that_cannot_bind_reports_its_own_failure(): void
    {
        $taken = @stream_socket_server(
            'tcp://127.0.0.1:0',
            $errno,
            $error,
            STREAM_SERVER_BIND | STREAM_SERVER_LISTEN,
        );

        $this->assertIsResource($taken, 'this test needs a port of its own to hold');

        $name = (string) stream_socket_get_name($taken, false);
        $port = (int) substr($name, strrpos($name, ':') + 1);

        $server = new LoopbackHttpServer('<?php echo "never reached";', $port);

        $started = microtime(true);
        $refused = null;

        /*
         * 🛑 The failure is captured rather than asserted inside the `catch`.
         * PHPUnit's own `fail()` throws `AssertionFailedError`, which extends
         * `RuntimeException` — so a `catch (\RuntimeException)` around a
         * `$this->fail()` swallows the assertion and the test reports the wrong
         * thing. Found by writing it the obvious way first.
         */
        try {
            $server->start();
        } catch (\RuntimeException $thrown) {
            $refused = $thrown;
        } finally {
            $elapsed = microtime(true) - $started;
        }

        try {
            $this->assertInstanceOf(
                \RuntimeException::class,
                $refused,
                'starting a server on a port this test holds must not succeed',
            );

            $this->assertStringContainsString(
                'exited with code',
                $refused->getMessage(),
                '🛑 the message must name the exit, not describe the wait — that is the whole fix',
            );

            $this->assertStringContainsString(
                'Address already in use',
                $refused->getMessage(),
                "and it must carry the server's own words, which are the actual cause",
            );

            $this->assertStringContainsString(
                (string) $port,
                $refused->getMessage(),
                'and it must name the port, so the cause is checkable',
            );

            /*
             * 🛑 The timing is the assertion, not a performance note. The old
             * fixture reported this case after its full ten-second deadline;
             * failing fast is what turns it from "CI was slow" into "the port
             * was taken". Five seconds is a generous ceiling for a process
             * that exits immediately — the point is that it is nowhere near
             * the deadline.
             */
            $this->assertLessThan(
                5.0,
                $elapsed,
                'a dead child must be noticed at once, not waited out',
            );
        } finally {
            $server->stop();
            fclose($taken);
        }
    }

    /**
     * 🛑 The port is one nothing was listening on, which is how the false
     * green is closed.
     *
     * Readiness is still a socket connect — the fixture's own note says why an
     * HTTP probe is wrong here, since the caller supplies the router and the
     * routers have side effects the tests assert on. So the guarantee has to
     * come from selection: a port this fixture could bind is a port nothing
     * else held.
     *
     * Asserted by starting two servers at once. Before the fix they drew
     * independently from a 25,000-port range and could collide; now each binds
     * its own first.
     */
    public function test_two_servers_at_once_get_different_ports_and_both_answer(): void
    {
        $first = (new LoopbackHttpServer('<?php echo "first";'))->start();
        $second = (new LoopbackHttpServer('<?php echo "second";'))->start();

        try {
            $this->assertNotSame($first->port(), $second->port());

            $this->assertSame('first', $this->fetch($first->origin()));
            $this->assertSame('second', $this->fetch($second->origin()));
        } finally {
            $first->stop();
            $second->stop();
        }
    }

    /**
     * The origin is addressable by a name the caller pins, which is what
     * §8.3.9's tests use it for.
     */
    public function test_the_origin_carries_the_host_the_caller_names(): void
    {
        $server = new LoopbackHttpServer('<?php echo "x";');

        $this->assertSame('http://pinned.test:'.$server->port(), $server->origin('pinned.test'));
        $this->assertSame('http://127.0.0.1:'.$server->port(), $server->origin());
    }

    /**
     * A plain GET, with no egress client involved.
     *
     * 🛑 `file_get_contents` rather than `HardenedEgressClient`: this file
     * tests the fixture, and reaching for the class the fixture exists to test
     * would make a fixture failure look like a transport failure, which is the
     * confusion the whole file is about. §8.3.9's architecture test permits a
     * URL through a stream function only outside `app/`, which this is.
     */
    private function fetch(string $origin): string
    {
        $context = stream_context_create(['http' => ['timeout' => 5]]);

        return (string) @file_get_contents($origin.'/probe', false, $context);
    }
}
