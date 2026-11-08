<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

/**
 * §8.13.7's provisioning refused, in protocol-free terms.
 *
 * 🛑 **Caught and translated, never allowed to escape to a reader.** Each
 * protocol's callback maps the rejection onto its own vocabulary — so an OIDC
 * login still audits `oidc.provisioning_disabled.refused` exactly as Phase 24
 * shipped it, and a SAML login audits `saml.provisioning_disabled.refused`.
 * A `ProvisioningRefused` reaching a response would mean a protocol gained a
 * caller and forgot its translation, which is the shape the architecture test
 * looks for.
 *
 * 🛑 And **nothing from the identity provider** goes in the detail. §8.22.5
 * keeps free text out of the chain, and a subject, a display name and an
 * attribute value are all free text somebody else wrote.
 */
final class ProvisioningRefused extends \RuntimeException
{
    private function __construct(
        public readonly ProvisioningRejection $rejection,
        string $detail,
    ) {
        parent::__construct($detail);
    }

    public static function of(ProvisioningRejection $rejection, string $detail = ''): self
    {
        return new self($rejection, $detail === '' ? $rejection->value : $detail);
    }
}
