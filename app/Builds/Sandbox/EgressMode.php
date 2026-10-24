<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Sandbox;

/**
 * What a build container may reach, as one value (§8.5.9).
 *
 * 🛑 Three states rather than a boolean, because `none` and `open` are not
 * two ends of one axis: `none` is **stricter** than the default and `open`
 * is weaker than it. A boolean called `egress_enabled` would have put the
 * strictest and the most dangerous configuration on the same side of the
 * question, which is how a hardening flag comes to be flipped by somebody
 * who read it as "turn the network on".
 */
enum EgressMode: string
{
    /**
     * §8.5.9's default. The sandboxes network, the warden's nftables
     * backstop, and the single allowlisted CONNECT proxy.
     */
    case Allowlist = 'allowlist';

    /**
     * No network namespace at all. Phase 06's position, kept because it is
     * the right one for a stage that genuinely needs nothing — §8.5.6's
     * `build` stage with a pre-baked toolchain reaches no index.
     */
    case None = 'none';

    /**
     * 🛑 A routed network with no proxy and no backstop. The only mode that
     * §8.5.11's `DOCUP_ACKNOWLEDGE_UNSANDBOXED` exists for, and the only one
     * where a build can speak to anything it can resolve.
     */
    case Open = 'open';

    /** Unknown values become the safest mode, never the most convenient one. */
    public static function fromConfig(mixed $value): self
    {
        return is_string($value) ? (self::tryFrom($value) ?? self::None) : self::None;
    }

    /** True when §8.5.11 requires an explicit acknowledgement alongside `runc`. */
    public function isUnrestricted(): bool
    {
        return $this === self::Open;
    }
}
