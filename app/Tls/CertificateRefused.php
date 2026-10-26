<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

/**
 * A certificate operation that will not be performed.
 *
 * Thrown rather than returned, for the reason `DomainRefused` and
 * `EgressRefused` are: a result object that must be inspected is one somebody
 * eventually does not inspect — and what goes unchecked here is a hostname
 * serving a certificate that is not its own.
 */
final class CertificateRefused extends \RuntimeException
{
    public function __construct(
        public readonly CertificateRejection $rejection,
        public readonly string $detail = '',
    ) {
        parent::__construct($rejection->identifier().($detail === '' ? '' : ': '.$detail));
    }

    public static function of(CertificateRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }

    public function identifier(): string
    {
        return $this->rejection->identifier();
    }
}
