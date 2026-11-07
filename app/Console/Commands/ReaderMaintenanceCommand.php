<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Readers\Grants\GrantKeys;
use App\Readers\ReaderHandoff;
use App\Readers\ReaderSessions;
use Illuminate\Console\Command;

/**
 * `docup:readers:maintain` — the three housekeeping jobs §12.4 and §8.12.11
 * imply but no request can do.
 *
 * 🛑 One command rather than three, because they are one operational fact:
 * nothing about the reader session machinery stays correct without something
 * running on a clock, and three schedule entries are three things to forget to
 * configure. The §8.5.3 scheduler already runs, so this costs one line in
 * `routes/console.php`.
 *
 * What it does and why each one has to be scheduled:
 *
 * - **Expired sessions**, deleted. §12.4's absolute ceiling is enforced on
 *   every use, so an expired row authorises nothing — but `docs_sessions` holds
 *   one row per reader per project per domain, and §8.12.15's session inventory
 *   is a security surface an operator has to be able to read.
 * - **Spent handoff codes**, deleted. One row per sign-in, dead after thirty
 *   seconds, and no fact §8.22's chain does not already hold.
 * - 🛑 **The key rotation advanced.** This is the one that matters: {@see KeyState}
 *   has four states and three of the transitions are time-based, so a key sits
 *   in `retiring` forever on an installation where nobody runs a command. The
 *   state machine's final state is only reachable from a clock.
 */
final class ReaderMaintenanceCommand extends Command
{
    protected $signature = 'docup:readers:maintain
        {--no-rotate : Sweep expired rows but leave the signing keys alone}';

    protected $description = 'Sweep expired reader sessions and handoff codes, and advance the grant key rotation';

    public function handle(
        ReaderSessions $sessions,
        ReaderHandoff $handoff,
        GrantKeys $keys,
    ): int {
        $this->line('sessions_swept='.$sessions->sweep());
        $this->line('handoff_codes_swept='.$handoff->sweep());

        if ($this->option('no-rotate')) {
            return self::SUCCESS;
        }

        /*
         * 🛑 **Retirement only, not promotion.** `rotate()` advances the state
         * machine by one step, and a scheduled call would therefore promote a
         * pending key — turning key rotation into something that happens on its
         * own, nightly, whether or not an operator meant it.
         *
         * That is the wrong default for the installation's most important
         * keypair: §8.12.11's grant mints read access to every private project,
         * and a rotation is a moment when a stale JWKS cache at the edge
         * becomes an outage. So the schedule retires what has served its window
         * — the half that is pure housekeeping and that nothing else can do —
         * and promotion stays an operator's `docup:readers:rotate`.
         */
        $retired = $keys->retireExpired();

        $this->line('keys_retired='.$retired);

        return self::SUCCESS;
    }
}
