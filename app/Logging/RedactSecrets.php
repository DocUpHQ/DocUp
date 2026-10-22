<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Logging;

use App\Credentials\SecretRedactor;
use Illuminate\Log\Logger;
use Monolog\Logger as MonologLogger;

/**
 * The log tap that puts {@see SecretRedactor} on a channel.
 *
 * 🛑 Declared on **every** channel in `config/logging.php`, and
 * `ArchitectureTest::test_every_log_channel_redacts_secrets` fails CI when a
 * channel is added without it. Phase 05's exit criterion is "no token appears
 * in any log, **at any log level**", and the way that criterion is lost is not
 * a level being forgotten — it is a channel being added for a new deployment
 * profile six phases from now by somebody who has never read this file.
 */
final class RedactSecrets
{
    public function __invoke(Logger $logger): void
    {
        $monolog = $logger->getLogger();

        /*
         * Laravel types this as a PSR `LoggerInterface`, and a channel built
         * from a custom driver may genuinely return something that is not
         * Monolog. Skipping quietly would be the wrong answer — a channel that
         * silently refuses the redactor is exactly the hole the architecture
         * test exists to close — so an unexpected logger is a loud failure at
         * boot rather than an unredacted log at 3am.
         */
        if (! $monolog instanceof MonologLogger) {
            throw new \LogicException(
                'the SPEC 8.5.21 redaction tap needs a Monolog channel; '.$monolog::class.' cannot carry a processor',
            );
        }

        $monolog->pushProcessor(new SecretRedactor);
    }
}
