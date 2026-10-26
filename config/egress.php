<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| The §8.3.9 egress budget
|------------------------------------------------------------------------------
| 🛑 Every value here is the specification's, and **none of them reads from
| `env()`**. That is deliberate and it is §20.4's invariant: "no security
| control sits behind a flag that defaults open". A control an operator can
| widen from a `.env` file is a control that gets widened at 2am by somebody
| debugging a webhook, and never narrowed again. An operator who genuinely
| needs a wider policy edits a file that is in their configuration management
| and shows up in a diff.
|
| `EgressConfigurationTest` asserts all of this, including the absence of
| `env()`, so a later edit that adds one fails CI.
*/

return [

    /*
     * §8.3.9's scheme allowlist. HTTPS only.
     *
     * Plain HTTP is absent rather than discouraged: every provider in §8.3.1
     * serves HTTPS, and an outbound request whose content is attacker-visible
     * and attacker-modifiable is not a request worth making from a credentialed
     * process.
     */
    'allowed_schemes' => ['https'],

    /*
     * Ports. **Empty means unrestricted**, and that is the shipped default.
     *
     * 🛑 §8.3.9 specifies a *scheme* allowlist and not a port allowlist, and
     * the omission is correct: self-hosted Gitea, Forgejo and GitLab on
     * `:3000`, `:8443` or `:9443` are the normal case, not an exception, so a
     * list would be wrong for most installations and would be widened
     * carelessly by the rest. The attack a port list would close — reaching a
     * non-HTTP service such as Redis by smuggling — is already closed by
     * `allowed_schemes` being HTTPS-only with certificate verification on:
     * nothing that is not a TLS server with a valid certificate for the name
     * can be spoken to at all.
     *
     * The control exists for operators who want it; it simply does not default
     * to a list that would break them.
     */
    'allowed_ports' => [],

    /* §8.3.9: a 5-second timeout, as a ceiling on the whole transfer. */
    'timeout_seconds' => 5,

    /* §8.3.9: a 256 KiB response cap, enforced mid-transfer. */
    'max_response_bytes' => 262144,

    /*
     * 🛑 The address policy. True, always, in every environment.
     *
     * The only thing that sets this false is an integration test that needs a
     * loopback HTTP server to prove the redirect and byte-cap controls against
     * a running origin rather than against their own configuration — the
     * §18.18 lesson from Phase 04. It is not reachable from the environment,
     * and `ArchitectureTest` fails if anything under `app/` passes false.
     */
    'enforce_address_policy' => true,

    /*
     *--------------------------------------------------------------------------
     * Operator-declared internal destinations (SPEC 8.10.14; Phase 19)
     *--------------------------------------------------------------------------
     * 🛑 **Empty by default, and this is NOT `enforce_address_policy` under
     * another name.** That flag stands the whole policy down for every host
     * and exists only as a test affordance; this names specific hostnames and
     * waives exactly one address class for them.
     *
     * Why it exists. SPEC 8.10.14 requires support for "an internal ACME
     * directory (step-ca, Vault, ADCS) for air-gapped and corporate-PKI
     * installations", and such a directory is by definition on a private
     * address — which SPEC 8.3.9 refuses, with no exemption. The two
     * requirements cannot both hold as written, so Phase 19 records the
     * conflict as a proposed amendment to SPEC 8.3.9 and resolves it the
     * narrowest way available:
     *
     *   - It is a list of **exact hostnames**, never a CIDR and never a
     *     wildcard, so it cannot be widened by accident.
     *   - It waives **only** the private and unique-local classes. Loopback,
     *     link-local, the cloud metadata address, the unspecified address and
     *     the reserved ranges stay refused for these hosts as for every other
     *     — so an operator who writes `ca.internal` cannot reach
     *     169.254.169.254 by pointing it there.
     *   - It is configuration, not an environment variable that defaults
     *     open, which is SPEC 20.4's invariant.
     *
     * 🛑 **A file, not an environment variable**, and the test directly
     * above this file's own rules says why: "an egress control reachable
     * from .env is a control that gets widened at 2am and never narrowed."
     * `deploy/internal-destinations.conf` ships empty, is read at boot, and
     * is the same operator-managed-file shape as
     * `deploy/egress-allowlist.conf` for the build proxy and
     * `deploy/header-allowlist.conf` for SPEC 8.10.22. Declaring internal
     * infrastructure should take a deliberate edit and a restart.
     *
     * 🛑 SPEC 8.3.9's own wording scopes it to "every outbound request derived
     * from **user-supplied configuration**". An ACME directory an operator put
     * in that file is installation configuration, in the same class as
     * `DB_HOST` — not something a tenant can set. That is the reading this
     * list relies on, and the reason it is a list of hostnames rather than a
     * switch.
     */
    'internal_destinations' => (static function (): array {
        $path = base_path('deploy/internal-destinations.conf');

        if (! is_file($path)) {
            return [];
        }

        $hosts = [];

        foreach (explode("\n", (string) file_get_contents($path)) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            $hosts[] = $line;
        }

        return $hosts;
    })(),

];
