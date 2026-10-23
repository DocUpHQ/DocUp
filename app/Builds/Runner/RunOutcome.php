<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\FailureClass;

/**
 * What the runner has to say about one container.
 *
 * 🛑 The log is carried as **lines already truncated and capped**, per
 * §8.5.21 — "strip NUL bytes, truncate lines over 8 KiB, cap the log at
 * 10 MiB". Truncating in the runner rather than in the worker matters: the
 * runner is the process reading an unbounded stream from a container that may
 * be trying to exhaust it, and a cap applied after the bytes have crossed the
 * spool is a cap on where they are stored, not on what they cost.
 *
 * 🛑 Redaction is the **worker's** job and not the runner's, and this is the
 * one place where that split is worth stating: §8.5.21 requires redaction "by
 * literal, base64 and URL-encoded match", which needs to know the secret
 * values — and the runner deliberately holds no `APP_KEY` and cannot open the
 * vault. So the runner never writes a credential into the log it returns (it
 * never has one except on the FIFO), and the worker runs the §8.5.21 scrubber
 * over everything before persistence.
 */
final readonly class RunOutcome
{
    /**
     * @param  list<string>  $log
     * @param  array<string, mixed>  $facts  whatever the stage reported about itself
     */
    public function __construct(
        public int $exitCode,
        public array $log,
        public array $facts = [],
        public ?string $failureClass = null,
        public ?string $failureReason = null,
        public float $seconds = 0.0,
        public bool $timedOut = false,
        public bool $oomKilled = false,
    ) {}

    public function succeeded(): bool
    {
        return $this->exitCode === 0 && $this->failureClass === null;
    }

    /** A spec the runner refused to run at all — it never reached a container. */
    public static function rejected(string $reason): self
    {
        return new self(
            exitCode: -1,
            log: [],
            failureClass: FailureClass::Rejected->value,
            // Shape-checked by `BuildFailure`, so it is lower_snake here too.
            failureReason: 'run_specification_refused',
            facts: ['detail' => $reason],
        );
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'exit_code' => $this->exitCode,
            'log' => $this->log,
            'facts' => $this->facts,
            'failure_class' => $this->failureClass,
            'failure_reason' => $this->failureReason,
            'seconds' => $this->seconds,
            'timed_out' => $this->timedOut,
            'oom_killed' => $this->oomKilled,
        ];
    }

    /**
     * Rebuild from the spool.
     *
     * 🛑 Every field is checked rather than cast. The document comes off a
     * shared volume, and `(int) $data['exit_code']` on an array yields 1 —
     * a build that failed would be read as one that succeeded.
     *
     * @param  array<array-key, mixed>  $data
     */
    public static function fromArray(array $data): self
    {
        $log = [];

        foreach (is_array($data['log'] ?? null) ? $data['log'] : [] as $line) {
            if (is_string($line)) {
                $log[] = $line;
            }
        }

        $facts = [];

        foreach (is_array($data['facts'] ?? null) ? $data['facts'] : [] as $name => $value) {
            if (is_string($name)) {
                $facts[$name] = $value;
            }
        }

        return new self(
            exitCode: is_int($data['exit_code'] ?? null) ? $data['exit_code'] : -1,
            log: $log,
            facts: $facts,
            failureClass: is_string($data['failure_class'] ?? null) ? $data['failure_class'] : null,
            failureReason: is_string($data['failure_reason'] ?? null) ? $data['failure_reason'] : null,
            seconds: is_float($data['seconds'] ?? null) || is_int($data['seconds'] ?? null)
                ? (float) $data['seconds']
                : 0.0,
            timedOut: ($data['timed_out'] ?? false) === true,
            oomKilled: ($data['oom_killed'] ?? false) === true,
        );
    }
}
