<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * A refusal by the §8.3.9 egress client.
 *
 * Thrown rather than returned. A result object that must be inspected is a
 * result object somebody does not inspect, and the thing not inspected here is
 * whether we just made a request into the private network. An exception is the
 * control-flow construct that cannot be ignored by omission.
 *
 * 🛑 The message carries the rejection identifier and the **host**, never the
 * full URL. A URL reaching an exception message reaches the log, the error
 * tracker and whatever renders the stack trace, and a URL is the most common
 * place a credential turns up by accident (§8.3.3, and
 * {@see EgressRejection::CredentialsInUrl}).
 */
final class EgressRefused extends \RuntimeException
{
    /** @param  array<string, mixed>  $context  addresses and classes only; never a URL or a header */
    public function __construct(
        public readonly EgressRejection $rejection,
        public readonly ?string $host = null,
        public readonly array $context = [],
    ) {
        parent::__construct(
            $host === null
                ? $rejection->value.': '.$rejection->reason()
                : $rejection->value.': '.$rejection->reason().' ('.$host.')',
        );
    }

    /** The stable identifier, for an API response or an audit record. */
    public function identifier(): string
    {
        return $this->rejection->value;
    }
}
