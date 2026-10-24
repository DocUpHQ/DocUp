<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

use App\Builds\FailureCatalogue;

/**
 * A version operation that will not be performed.
 *
 * Thrown rather than returned, for the reason `ConfigRefused` and
 * `EgressRefused` are: a result object that must be inspected is one
 * somebody eventually does not inspect, and what goes uninspected here is
 * whether a URL readers depend on just changed.
 */
final class VersionRefused extends \RuntimeException
{
    private function __construct(
        public readonly VersionRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(VersionRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }

    /** The sentence an operator reads, from the one catalogue that owns prose. */
    public function userMessage(): string
    {
        $message = FailureCatalogue::message($this->identifier());

        return $this->detail === '' ? $message : $message.' '.$this->detail;
    }
}
