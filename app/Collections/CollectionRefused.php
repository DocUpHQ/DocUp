<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Collections;

/**
 * A collection write that will not be performed.
 *
 * Thrown rather than returned, for the reason `CompositionRefused`,
 * `VersionRefused` and `ConfigRefused` are: a result object that must be
 * inspected is one somebody eventually does not inspect — and one of the
 * refusals here is §8.12.8's, which may never be skipped by omission.
 */
final class CollectionRefused extends \RuntimeException
{
    private function __construct(
        public readonly CollectionRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(CollectionRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }
}
