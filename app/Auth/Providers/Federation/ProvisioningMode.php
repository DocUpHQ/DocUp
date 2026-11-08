<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

/**
 * §8.13.7's three JIT provisioning modes, per binding.
 *
 * > "JIT provisioning MUST be per binding (`disabled`, `create_reader`,
 * > `create_reader_and_map_groups`). IdP-sourced role assignments MUST be
 * > **reconciled — added *and* removed** — on every login."
 *
 * 🛑 **`disabled` is the default**, and that is a decision worth stating. A
 * binding whose mode nobody set admits only readers an operator created by
 * hand — which is the behaviour an operator who has not thought about
 * provisioning would want, and the opposite of what a convenient default would
 * give them. §8.12.19's whole lifecycle exists because authentication
 * configuration that half-works is worse than configuration that refuses.
 *
 * 🛑 The modes are deliberately **not** a boolean pair. "Create readers" and
 * "map their groups" are separable because mapping groups means writing rows
 * that grant access, and an operator may reasonably want the first without the
 * second while they work out what their directory's groups mean.
 */
enum ProvisioningMode: string
{
    /**
     * No reader identity is created. A subject with no existing identity is
     * refused — see `ProvisioningRejection::ProvisioningDisabled`, which is
     * audited rather than silent, because "somebody who should have access
     * does not" is a thing the operator needs to find out.
     */
    case Disabled = 'disabled';

    /**
     * A reader identity is created on first login, and the token's groups are
     * ignored. The reader is `authenticated` (§12.3) and satisfies the
     * binding's own leaf; nothing else.
     */
    case CreateReader = 'create_reader';

    /**
     * 🛑 And the binding's group mappings are applied, **reconciled** against
     * what the token asserts: a group removed at the identity provider is
     * removed here, not merely not added.
     *
     * §8.13.7 says "added *and* removed", with the emphasis in the
     * specification. The asymmetric implementation — add what is asserted,
     * leave the rest — is the one somebody writes by accident, and its failure
     * mode is a reader who was removed from a group at the IdP keeping the
     * access that group gave them for ever. §17 makes it an exit criterion for
     * exactly that reason.
     */
    case CreateReaderAndMapGroups = 'create_reader_and_map_groups';

    /** Whether this mode may create a reader identity that does not exist. */
    public function mayCreate(): bool
    {
        return $this !== self::Disabled;
    }

    /** Whether this mode applies the binding's group mappings. */
    public function mapsGroups(): bool
    {
        return $this === self::CreateReaderAndMapGroups;
    }

    /**
     * 🛑 Parse a configured value, failing to `disabled`.
     *
     * An unreadable mode is the safest one, and this is the direction that
     * needs stating: a typo in a configuration JSON becomes "admit nobody new"
     * rather than "admit everybody and map their groups".
     */
    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? (self::tryFrom($value) ?? self::Disabled) : self::Disabled;
    }
}
