<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * A typed failure: a §8.5.15 class, a stable identifier, and the stage.
 *
 * 🛑 The identifier is `<class>.<reason>`, as §8.5.15's own examples are —
 * `contract.multiple_pdf_files`, `resource.oom_killed`. Deriving it from the
 * class rather than accepting a free string is what keeps the two from
 * drifting: an identifier of `infra.oom_killed` on a `resource` failure would
 * retry something §8.5.16 says must not retry, and nothing would catch it.
 *
 * Thrown rather than returned, for the reason `EgressRefused` is: a result
 * object that must be inspected is one somebody does not inspect, and what
 * goes uninspected here is whether a build failed.
 */
final class BuildFailure extends \RuntimeException
{
    private function __construct(
        public readonly FailureClass $class,
        public readonly string $reason,
        public readonly ?Stage $stage = null,
        public readonly ?int $exitCode = null,
    ) {
        parent::__construct($this->identifier());
    }

    /**
     * @param  string  $reason  the second half of the identifier: lower_snake,
     *                          stable, and part of the §8.1.11 public contract
     *                          once it has shipped
     */
    public static function of(
        FailureClass $class,
        string $reason,
        ?Stage $stage = null,
        ?int $exitCode = null,
    ): self {
        if (preg_match('/^[a-z][a-z0-9_]{2,63}$/', $reason) !== 1) {
            /*
             * Refused rather than sanitised. A reason that does not fit the
             * shape is one somebody wrote as prose, and prose in this field
             * reaches an operator's alert rule as a string that changes every
             * time the message is reworded.
             */
            throw new \InvalidArgumentException("a failure reason must be lower_snake_case: {$reason}");
        }

        return new self($class, $reason, $stage, $exitCode);
    }

    /** `resource.oom_killed`. The string that reaches alerts and runbooks. */
    public function identifier(): string
    {
        return $this->class->value.'.'.$this->reason;
    }

    /**
     * The sentence an author reads, from {@see FailureCatalogue}.
     *
     * Separate from {@see identifier()} because the two have opposite
     * obligations: the identifier never changes and the message is reworded
     * whenever a clearer wording is found.
     */
    public function userMessage(): string
    {
        return FailureCatalogue::message($this->identifier());
    }

    public function isRetryable(): bool
    {
        return $this->class->isRetryable() && ($this->stage?->mayRetry() ?? false);
    }

    /**
     * @return array<string, mixed> for the build and step rows
     */
    public function columns(): array
    {
        return [
            'failure_class' => $this->class->value,
            'failure_identifier' => $this->identifier(),
            'exit_code' => $this->exitCode,
        ];
    }
}
