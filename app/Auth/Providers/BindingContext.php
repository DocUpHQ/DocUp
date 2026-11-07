<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Credentials\SecretString;

/**
 * One resolved binding, as a driver sees it.
 *
 * 🛑 **The secrets are opened once, here, and only when the binding's own
 * driver asks for them.** §8.12.2: "envelope-encrypted secrets no API or UI
 * ever returns" — so the sealed material never reaches this object, and the
 * opened material arrives as {@see SecretString}, whose plaintext is reachable
 * only through `reveal()` and is therefore greppable.
 *
 * 🛑 **A driver cannot see another binding.** This carries one binding's own
 * state, so a driver cannot enumerate the installation's providers, read a
 * sibling's secret, or fall back to another one — which §8.12.19 forbids in as
 * many words: "never fall back to another provider, never to public".
 */
final readonly class BindingContext
{
    /**
     * @param  string  $id  raw 16 bytes
     * @param  string  $type  §8.12.2's driver type string
     * @param  string  $name  the operator's own name; §8.12.19's 503 names it
     * @param  array<string, mixed>  $config  non-secret configuration
     * @param  array<string, SecretString>  $secrets  🛑 opened lazily by the
     *                                                resolver and never
     *                                                serialised; empty for a
     *                                                driver that holds none
     * @param  BindingState  $state  §8.12.19's five states
     * @param  bool  $shareable  whether a share link may be minted against it
     * @param  string|null  $projectId  raw 16 bytes, when the binding is
     *                                  project-scoped
     * @param  string|null  $organisationId  raw 16 bytes, or null at
     *                                       installation scope
     * @param  int  $epoch  §10.6; invalidates a cached driver instance
     */
    public function __construct(
        public string $id,
        public string $type,
        public string $name,
        public array $config = [],
        public array $secrets = [],
        public BindingState $state = BindingState::Draft,
        public bool $shareable = false,
        public ?string $projectId = null,
        public ?string $organisationId = null,
        public int $epoch = 0,
    ) {}

    /**
     * One config value, narrowed to a string.
     *
     * 🛑 Returns null rather than casting, because a driver that received
     * `"Array"` from a misconfigured JSON object would then compare it against
     * something and silently not match. §9.4's level 9 covers this namespace
     * precisely because a type error here is an authorisation bug.
     */
    public function string(string $key): ?string
    {
        $value = $this->config[$key] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * One config value, narrowed to a list of strings.
     *
     * 🛑 An entry that is not a string drops the **whole** list rather than
     * part of it. A partially-read `ip_allowlist` is a gate that admits a
     * narrower set than the operator configured — which fails closed, so it is
     * not a hole, but it is a gate that silently stopped doing what its own row
     * says. Refusing the lot makes the probe fail instead.
     *
     * @return list<string>|null
     */
    public function strings(string $key): ?array
    {
        $value = $this->config[$key] ?? null;

        if (! is_array($value)) {
            return null;
        }

        $out = [];

        foreach ($value as $entry) {
            if (! is_string($entry)) {
                return null;
            }

            $out[] = $entry;
        }

        return $out;
    }

    /** One opened secret's plaintext, or null when the binding holds none. */
    public function secret(string $key): ?string
    {
        $secret = $this->secrets[$key] ?? null;

        return $secret instanceof SecretString ? $secret->reveal() : null;
    }

    /**
     * 🛑 §8.12.19: a binding authenticates nobody unless it is `active`.
     *
     * `draft` and `verifying` have not been proven; `disabled` was turned off;
     * `degraded` is the one that must produce a 503 rather than a refusal, and
     * {@see BindingState::deniesWithServiceUnavailable()} separates it.
     */
    public function isUsable(): bool
    {
        return $this->state === BindingState::Active;
    }
}
