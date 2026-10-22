<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * A repository URL refused by §8.3.4.
 *
 * 🛑 The message never contains the URL. The field this exception guards is
 * the one operators paste tokens into by mistake, and an exception message
 * reaches the log, the error tracker and whatever renders the trace. The
 * rejection identifier and the host are enough to act on, and the host is
 * omitted too when the refusal happened before a host was parsed.
 */
final class SourceRefused extends \RuntimeException
{
    /** @param  array<string, mixed>  $context  addresses and classes only; never a URL or a credential */
    public function __construct(
        public readonly SourceRejection $rejection,
        public readonly ?string $host = null,
        public readonly array $context = [],
    ) {
        parent::__construct($host === null ? $rejection->value : $rejection->value.' ('.$host.')');
    }

    public function identifier(): string
    {
        return $this->rejection->value;
    }
}
