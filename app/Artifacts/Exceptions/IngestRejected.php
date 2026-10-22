<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts\Exceptions;

use App\Artifacts\RejectionCode;

/**
 * An artifact tree was refused by the §8.8.2 ingestor.
 *
 * 🛑 Named `$rejection`, not `$code`: `Exception::$code` already exists, is an
 * `int`, and is readwrite, so declaring a typed readonly `$code` here shadows
 * it. PHP permits it and Larastan does not, correctly — anything catching this
 * as a plain `Throwable` and reading `getCode()` would get a type it cannot
 * use.
 *
 * 🛑 Carries the {@see RejectionCode} rather than only a message, because
 * §8.19.15 requires a **stable identifier** that reaches `builds.failure_identifier`,
 * the API response and the build log. A message is for a human; the code is what
 * an operator's alert matches on and what a CI script branches on.
 *
 * The offending entry name is carried separately and deliberately NOT
 * interpolated into the code: the code must stay a fixed string, or every
 * rejection becomes its own identifier and nothing can be aggregated.
 */
final class IngestRejected extends \RuntimeException
{
    /**
     * Named constructor, used in preference to `new` at every call site.
     *
     * `IngestRejected::because(RejectionCode::SymlinkRejected, $name)` reads as the
     * sentence it is; `new IngestRejected(...)` reads as plumbing. With a
     * hundred-odd throw sites in one ingest path, that difference is what keeps
     * the validator legible as a list of rules.
     */
    public static function because(RejectionCode $code, ?string $entry = null, ?string $detail = null): self
    {
        return new self($code, $entry, $detail);
    }

    public function __construct(
        public readonly RejectionCode $rejection,
        public readonly ?string $entry = null,
        public readonly ?string $detail = null,
    ) {
        $message = $rejection->value.': '.$rejection->describe();

        if ($entry !== null) {
            // The entry name is attacker-supplied, so it is escaped before it
            // reaches a log line or an API response. An entry called
            // "x\n2026-01-01 INFO all fine" must not be able to forge a log
            // record, and one containing control characters must not corrupt a
            // terminal reading the output.
            $message .= ' Entry: '.addcslashes($entry, "\0..\37\177..\377\\");
        }

        if ($detail !== null) {
            $message .= ' ('.$detail.')';
        }

        parent::__construct($message);
    }
}
