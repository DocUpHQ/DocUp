<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

/**
 * An OIDC exchange refused, carrying the reason as a stable identifier.
 *
 * 🛑 **The `detail` is for the audit chain and the operator, never for the
 * reader.** §8.12.23 makes a failed login the project's `deny_status` with no
 * body, so nothing here reaches a browser — which is what lets the detail be
 * specific enough to be useful. A message that had to be safe to show a
 * stranger would have to say nothing.
 *
 * 🛑 `detail` is also **not** where provider-supplied text goes. §8.22.5 keeps
 * free text out of the audit chain, and an IdP's `error_description` is free
 * text somebody else wrote. Describe what DocUp concluded, not what the
 * provider said.
 */
final class OidcRefused extends \RuntimeException
{
    private function __construct(
        public readonly OidcRejection $rejection,
        string $detail,
    ) {
        parent::__construct($detail);
    }

    public static function of(OidcRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail === '' ? $rejection->value : $detail);
    }
}
