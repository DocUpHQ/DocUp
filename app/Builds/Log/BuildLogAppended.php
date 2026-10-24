<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Log;

use Illuminate\Broadcasting\Channel;
use Illuminate\Broadcasting\PrivateChannel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcast;
use Illuminate\Foundation\Events\Dispatchable;
use Illuminate\Queue\SerializesModels;

/**
 * §8.5.22's optional WebSocket profile, as the one thing it pushes.
 *
 * > "Build logs MUST be exposed through one offset-addressed contract
 * > … consumable by both transports. Polling MUST be the default and the
 * > only thing in the core compose file; WebSocket streaming MUST be an
 * > optional profile."
 *
 * 🛑 **This event carries a cursor, not a log line, and that is the whole
 * design.** "One contract, both transports" is only true if the WebSocket
 * says *where to read from* rather than *what was written*: a client that
 * receives this fetches the page it was already entitled to, through the
 * same endpoint, under the same authorisation, with the same gap
 * reporting. Pushing the lines themselves would be a second serialisation
 * of one log — and the two would disagree eventually, with the untested
 * one being whichever the suite does not poll.
 *
 * 🛑 It also means the WebSocket grants nothing. A listener still has to
 * be allowed to read the log by `BuildAccess`; the socket only saves it
 * from asking every second.
 *
 * Broadcast on a **private** channel, authorised in `routes/channels.php`
 * by the same policy as the endpoint. Nothing is sent at all under the
 * default `null` connection, which is what keeps the profile optional.
 */
final class BuildLogAppended implements ShouldBroadcast
{
    use Dispatchable;
    use SerializesModels;

    public function __construct(
        /** The build, as 32 hex characters. */
        public readonly string $buildHex,

        /** The `from` a listener should ask the log endpoint for. */
        public readonly int $next,

        /** Whether the build has reached a terminal state. */
        public readonly bool $complete,
    ) {}

    public function broadcastOn(): Channel
    {
        return new PrivateChannel('builds.'.$this->buildHex);
    }

    public function broadcastAs(): string
    {
        return 'log.appended';
    }

    /**
     * @return array<string, mixed>
     */
    public function broadcastWith(): array
    {
        return ['next' => $this->next, 'complete' => $this->complete];
    }
}
