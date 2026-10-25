<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * A composition write that will not be performed.
 *
 * Thrown rather than returned, for the reason `VersionRefused`,
 * `ConfigRefused` and `EgressRefused` are: a result object that must be
 * inspected is one somebody eventually does not inspect.
 *
 * 🛑 That argument is at its strongest here. What goes uninspected if a
 * caller ignores a returned value is §8.7.7's ceiling — "a declassification
 * primitive in a product whose headline feature is per-project
 * authentication". A thrown refusal cannot be ignored by omission.
 */
final class CompositionRefused extends \RuntimeException
{
    private function __construct(
        public readonly CompositionRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(CompositionRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }
}
