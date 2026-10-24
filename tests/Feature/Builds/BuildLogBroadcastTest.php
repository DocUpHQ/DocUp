<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\Log\BuildLogAppended;
use Illuminate\Broadcasting\PrivateChannel;
use Symfony\Component\Yaml\Yaml;
use Tests\TestCase;

/**
 * §8.5.22's WebSocket profile: optional, and a second transport rather
 * than a second contract.
 *
 * > "Polling MUST be the default and the only thing in the core compose
 * > file; WebSocket streaming MUST be an optional profile."
 *
 * 🛑 **What is asserted here is the SHAPE, not a running server.** The
 * core profile ships no WebSocket server and this suite does not stand
 * one up — doing so would make every test depend on the thing §19/22
 * specifically keeps out of the core. What can be checked, and what
 * actually goes wrong, is whether the profile has leaked into the core
 * file and whether the socket could ever carry more than the poll does.
 */
final class BuildLogBroadcastTest extends TestCase
{
    /** 🛑 "...the only thing in the core compose file." */
    public function test_the_core_compose_file_contains_no_websocket_service(): void
    {
        /** @var array<string, mixed> $core */
        $core = Yaml::parseFile(base_path('compose.yaml'));

        /** @var array<string, mixed> $services */
        $services = is_array($core['services'] ?? null) ? $core['services'] : [];

        $this->assertArrayNotHasKey('websocket', $services);

        $raw = (string) file_get_contents(base_path('compose.yaml'));

        foreach (['reverb', 'REVERB', 'BROADCAST_CONNECTION', 'websocket'] as $needle) {
            $this->assertStringNotContainsString(
                $needle,
                $raw,
                'the optional WebSocket profile has leaked into the core compose file (§8.5.22)',
            );
        }
    }

    /** ...and the overlay that is the whole of the profile does exist. */
    public function test_the_optional_overlay_exists_and_declares_the_service(): void
    {
        $this->assertFileExists(base_path('compose.websocket.yaml'));

        /** @var array<string, mixed> $overlay */
        $overlay = Yaml::parseFile(base_path('compose.websocket.yaml'));

        /** @var array<string, mixed> $services */
        $services = is_array($overlay['services'] ?? null) ? $overlay['services'] : [];

        $this->assertArrayHasKey('websocket', $services);

        /*
         * 🛑 Loopback only. A WebSocket carrying build logs carries paths,
         * dependency versions and sometimes content — §8.5.22's own
         * reasoning for the per-project anonymous setting applies with
         * more force to a port.
         */
        $raw = (string) file_get_contents(base_path('compose.websocket.yaml'));
        $this->assertStringContainsString('127.0.0.1:', $raw);
    }

    /** 🛑 Broadcasting is off unless an operator turns it on. */
    public function test_broadcasting_defaults_to_null(): void
    {
        $this->assertSame('null', (string) config('broadcasting.connections.null.driver'));

        $fresh = require base_path('config/broadcasting.php');

        $this->assertSame('null', $fresh['default'], 'the shipped default must broadcast nothing');

        /*
         * 🛑 And it survives the trap: `BROADCAST_CONNECTION=null` in an
         * environment file is parsed as PHP null, so a plain default
         * argument would be skipped and Laravel would fail to resolve any
         * connection at all.
         */
        $this->assertSame('null', (string) config('broadcasting.default'));
    }

    /**
     * 🛑 The event carries a CURSOR, never a line.
     *
     * This is what makes "one contract, both transports" true. A payload
     * containing the log text would be a second serialisation that could
     * disagree with the endpoint's — and the one that disagreed would be
     * the untested one, because polling is what the suite exercises.
     */
    public function test_the_broadcast_payload_is_a_cursor_and_nothing_else(): void
    {
        $event = new BuildLogAppended(str_repeat('a', 32), 42, false);

        $this->assertSame(['next' => 42, 'complete' => false], $event->broadcastWith());
        $this->assertSame('log.appended', $event->broadcastAs());
    }

    /** 🛑 And a private channel, so the socket is an authorisation boundary. */
    public function test_the_channel_is_private_and_named_for_the_build(): void
    {
        $build = str_repeat('b', 32);
        $channel = (new BuildLogAppended($build, 1, true))->broadcastOn();

        $this->assertInstanceOf(PrivateChannel::class, $channel);
        $this->assertSame('private-builds.'.$build, $channel->name);
    }

    /**
     * 🛑 The channel authorisation exists at all.
     *
     * A private channel with no registered callback is one Laravel
     * refuses — which looks identical to a channel nobody secured, right
     * up until an operator enables the profile and it does not work. The
     * callback is registered from `bootstrap/app.php` whether or not a
     * broadcaster is configured, for exactly that reason.
     */
    public function test_the_channel_authorisation_is_registered(): void
    {
        $channels = (string) file_get_contents(base_path('routes/channels.php'));

        $this->assertStringContainsString("Broadcast::channel('builds.{buildHex}'", $channels);
        $this->assertStringContainsString('Capability::ProjectView', $channels);
        $this->assertStringContainsString(
            'channels:',
            (string) file_get_contents(base_path('bootstrap/app.php')),
            'the channel file is not registered, so every private channel is refused',
        );
    }
}
