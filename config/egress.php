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

];
