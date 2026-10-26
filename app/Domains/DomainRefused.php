<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

/**
 * A domain write that will not be performed.
 *
 * Thrown rather than returned, for the reason `CompositionRefused`,
 * `CollectionRefused` and `EgressRefused` are: a result object that must be
 * inspected is one somebody eventually does not inspect — and what goes
 * unchecked here is §8.10.4's "proof of domain control MUST precede … any
 * byte served for a custom hostname".
 */
final class DomainRefused extends \RuntimeException
{
    private function __construct(
        public readonly DomainRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(DomainRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }
}
