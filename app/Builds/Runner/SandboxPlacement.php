<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

/**
 * Where one container is placed: its network namespace and its runtime.
 *
 * 🛑 A value object rather than two more parameters on
 * {@see ArgvTemplate::render()}, because both fields reach `docker run` as
 * flags and both are resolved by the runner rather than supplied by the
 * caller. Keeping them together is what makes it obvious at the call site
 * that a container cannot be given a runtime without also being given a
 * network — the combination §8.5.9 and §8.5.11 each constrain half of.
 *
 * Neither field is ever repository input. `network` is a literal, or the
 * name of a warden this runner started; `runtime` is a value from the
 * §8.5.11 allowlist, resolved from the operator's declaration.
 */
final readonly class SandboxPlacement
{
    private function __construct(
        /** `none`, `bridge`, or `container:<warden>`. */
        public string $network,

        /** `docker run --runtime`, or null for the daemon's own default. */
        public ?string $runtime,
    ) {}

    /** §8.5.9's strictest placement: no network namespace of any kind. */
    public static function isolated(?string $runtime = null): self
    {
        return new self('none', $runtime);
    }

    /** Inside a warden's already-locked namespace (ADR 0011). */
    public static function inWarden(string $wardenContainer, ?string $runtime = null): self
    {
        if (preg_match('/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$/', $wardenContainer) !== 1) {
            throw new \InvalidArgumentException('not a container name: '.$wardenContainer);
        }

        return new self('container:'.$wardenContainer, $runtime);
    }

    /**
     * 🛑 §8.5.11's `open` egress: a routed network with no proxy and no
     * backstop. Reachable only through an explicit configuration the boot
     * assertion refuses in production without
     * `DOCUP_ACKNOWLEDGE_UNSANDBOXED`.
     */
    public static function unrestricted(?string $runtime = null): self
    {
        return new self('bridge', $runtime);
    }
}
