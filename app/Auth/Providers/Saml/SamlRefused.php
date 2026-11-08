<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

/**
 * A SAML response refused, carrying the reason as a stable identifier.
 *
 * 🛑 **The `detail` is for the audit chain and the operator, never for the
 * reader** — the same split `App\Auth\Providers\Oidc\OidcRefused` describes. §8.12.23 makes a failed login the project's `deny_status` with no
 * body, so nothing here reaches a browser, which is what lets the detail be
 * specific enough to act on.
 *
 * 🛑 And **nothing from the assertion** goes in it. §8.22.5 keeps free text out
 * of the audit chain, and a SAML response is a document somebody else wrote:
 * its `StatusMessage`, its attribute values and its `NameID` are all free text.
 * Describe what DocUp concluded, never what the identity provider said.
 */
final class SamlRefused extends \RuntimeException
{
    private function __construct(
        public readonly SamlRejection $rejection,
        string $detail,
    ) {
        parent::__construct($detail);
    }

    public static function of(SamlRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail === '' ? $rejection->value : $detail);
    }
}
