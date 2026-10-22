<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * The §8.3.9 budget, as one value object.
 *
 * The defaults here are the specification's numbers, not a suggestion:
 * "a scheme allowlist, resolve-then-pin connection, disabled redirects, denial
 * of private/loopback/link-local/metadata addresses, a 5-second timeout and a
 * 256 KiB response cap".
 *
 * 🛑 `enforceAddressPolicy` is the one field that can weaken the client, and it
 * exists for exactly one reason: the redirect and byte-cap controls have to be
 * proven against a **running** HTTP server, and the only server a test suite
 * can stand up is on loopback — which the address policy correctly refuses.
 * Phase 04 was taught this the hard way (§18.18): a control asserted only
 * against its own configuration is a control nobody has run. Standing one
 * control down to exercise another, in a test, with the production wiring
 * asserted separately, is not the same thing as shipping it off.
 *
 * Two gates keep it honest, and both must stay:
 *  - `ArchitectureTest::test_nothing_in_the_application_disables_the_egress_address_policy`
 *    fails if anything under `app/` passes false.
 *  - `EgressConfigurationTest` asserts the committed `config/egress.php`
 *    enforces it, allows only `https`, and reads none of these values from the
 *    environment — §20.4's invariant is that no security control sits behind a
 *    flag that defaults open, and the cheapest way to honour it is to have no
 *    flag at all.
 */
final readonly class EgressOptions
{
    /**
     * @param  list<string>  $allowedSchemes
     * @param  list<int>  $allowedPorts
     */
    public function __construct(
        public array $allowedSchemes = ['https'],
        public array $allowedPorts = [443],
        public int $timeoutSeconds = 5,
        public int $maxResponseBytes = 262144,
        public bool $enforceAddressPolicy = true,
    ) {}

    /**
     * The options as `config/egress.php` states them.
     *
     * 🛑 Every fallback below is the **safe** value, not a neutral one. A
     * configuration file that is missing, truncated or mistyped must produce
     * the specification's policy rather than an open one, because a failure
     * that opens egress is invisible until it is exploited.
     */
    public static function fromConfig(): self
    {
        $config = config('egress');
        $config = is_array($config) ? $config : [];

        $schemes = [];

        foreach (is_array($config['allowed_schemes'] ?? null) ? $config['allowed_schemes'] : ['https'] as $scheme) {
            if (is_string($scheme) && $scheme !== '') {
                $schemes[] = strtolower($scheme);
            }
        }

        $ports = [];

        foreach (is_array($config['allowed_ports'] ?? null) ? $config['allowed_ports'] : [] as $port) {
            if (is_int($port) || (is_string($port) && ctype_digit($port))) {
                $ports[] = (int) $port;
            }
        }

        return new self(
            allowedSchemes: $schemes === [] ? ['https'] : $schemes,
            allowedPorts: $ports,
            timeoutSeconds: is_int($config['timeout_seconds'] ?? null) ? $config['timeout_seconds'] : 5,
            maxResponseBytes: is_int($config['max_response_bytes'] ?? null) ? $config['max_response_bytes'] : 262144,
            enforceAddressPolicy: ($config['enforce_address_policy'] ?? true) !== false,
        );
    }

    public function permitsScheme(string $scheme): bool
    {
        return in_array(strtolower($scheme), $this->allowedSchemes, true);
    }

    public function permitsPort(int $port): bool
    {
        return in_array($port, $this->allowedPorts, true);
    }
}
