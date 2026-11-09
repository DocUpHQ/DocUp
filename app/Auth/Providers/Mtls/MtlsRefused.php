<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Mtls;

/**
 * A forwarded client certificate refused, carrying its reason as a
 * {@see MtlsRejection}.
 *
 * 🛑 The `detail` is for an **operator** only. It may hold a distinguished
 * name, an OpenSSL error string or a fragment of the header's value, and
 * §8.12.23 gives a refused reader the project's `deny_status` and an empty
 * body. {@see MtlsRejection::explain()} is what an operator sees and it
 * repeats nothing from the certificate.
 */
final class MtlsRefused extends \RuntimeException
{
    private function __construct(
        public readonly MtlsRejection $rejection,
        public readonly string $detail,
    ) {
        parent::__construct($rejection->value.($detail === '' ? '' : ': '.$detail));
    }

    public static function of(MtlsRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail);
    }
}
