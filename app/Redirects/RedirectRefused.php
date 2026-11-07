<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * A redirect rule that will not be saved.
 *
 * Thrown rather than returned, for the reason `DomainRefused`,
 * `CertificateRefused` and `EgressRefused` are: a result object that must be
 * inspected is one somebody eventually does not inspect — and what goes
 * unchecked here is §8.11.2's open redirect.
 */
final class RedirectRefused extends \RuntimeException
{
    public function __construct(
        public readonly RedirectRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(RedirectRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }
}
