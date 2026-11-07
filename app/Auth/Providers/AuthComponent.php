<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\AccessLeaf;

/**
 * 🛑 §8.12.2's driver contract: one interface, and a third-party driver is a
 * class implementing it plus a registry entry.
 *
 * > "Every authentication and authorisation mechanism MUST be a plugin instance
 * > in **one** `auth_provider_bindings` table with a driver type string,
 * > non-secret JSON config, a `config_version`, and envelope-encrypted secrets
 * > no API or UI ever returns. **Third-party drivers MUST be installable
 * > without migrations.**"
 *
 * That last sentence is what this interface is for. A driver contributes a
 * `type` string, a config schema, a probe and an attempt — and nothing else. It
 * cannot add a column, cannot add a route, and cannot add a leaf kind.
 *
 * ## 🛑 What a driver is NOT allowed to decide
 *
 * Three things, each of which a driver would plausibly want to and each of
 * which is somewhere else on purpose:
 *
 * 1. **Its own leaf kind.** {@see leaf()} returns one, but the value is read
 *    from §8.12.17's table via {@see AccessLeaf::forDriver()} — the driver
 *    reports what it is, and the *classification* lives in one place because
 *    §8.12.7's satisfiability invariant "is defined over that classification".
 *    A driver that could declare itself identity-bearing could make
 *    `ip_allowlist` count as authentication.
 * 2. **Whether a reader is allowed.** A driver returns an {@see AttemptResult},
 *    which is evidence; §12.3's one function decides. §4.3 allows exactly one
 *    decider and an architecture test enforces it.
 * 3. **Protocol validation.** §8.12.18: "Protocol validation MUST be
 *    framework-enforced, not driver-optional." A driver that validated its own
 *    PKCE, nonce or signature would be a driver that could forget to — which is
 *    the failure the requirement names. P24 puts that enforcement in the
 *    framework; the drivers here have no protocol to validate.
 */
interface AuthComponent
{
    /**
     * §8.12.2's driver type string, as stored in `auth_provider_bindings.type`.
     *
     * 🛑 Must match a case in §8.12.17's table, which
     * {@see AccessLeaf::forDriver()} implements — the registry refuses a driver
     * whose type that function does not classify, so an unclassified driver
     * cannot be registered rather than being registered and guessed at.
     */
    public static function type(): string;

    /**
     * 🛑 The leaf kind this driver's satisfaction produces, from §8.12.17.
     *
     * Read from one table rather than declared here. See the class note: a
     * driver that could declare its own kind could make a gate into an
     * identity.
     */
    public static function leaf(): AccessLeaf;

    /**
     * Whether this driver may be configured at project scope.
     *
     * 🛑 §8.12.4: "`ldap`, `mtls` and `header_trust` MUST be **installation-scope
     * only** — they reach into the operator's internal network or depend on
     * facts only the TLS terminator can establish, so project-scope
     * configuration would convert tenant self-service into an SSRF or
     * header-spoofing primitive."
     *
     * A capability on the driver rather than a list in the resolver, because
     * the reason is a property of the driver and belongs beside it.
     */
    public static function allowsProjectScope(): bool;

    /**
     * 🛑 §8.12.5's capability flag: whether this driver may produce a dashboard
     * role.
     *
     * > "Project-scoped bindings MUST NOT produce any dashboard role, enforced
     * > both as a driver capability flag and as a validation invariant on group
     * > mappings."
     *
     * "Both" is the requirement, so this is one of the two. Every v1 driver
     * returns false — group mappings arrive with OIDC in P24 — and it is here
     * from the start so the flag exists before the first driver that wants it.
     */
    public static function mayMapDashboardRoles(): bool;

    /**
     * Validate a binding's non-secret config, refusing rather than correcting.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed> the normalised config to store
     *
     * @throws BindingRefused when the config cannot be stored
     */
    public function validate(array $config): array;

    /**
     * 🛑 §8.12.19's automated half: "MUST NOT leave `verifying` until an
     * automated probe passes **and** a human completes a test login".
     *
     * A probe answers "could this provider work", never "is this reader
     * allowed". For a driver with nothing to reach — `public`, `password`,
     * `ip_allowlist` — it is a configuration check, which is still worth
     * running: a `password` binding with no password sealed is a binding that
     * will deny everybody at the worst possible moment.
     */
    public function probe(BindingContext $binding): ProbeResult;

    /**
     * 🛑 What the reader presented, as **evidence** rather than a verdict.
     *
     * Returns {@see AttemptResult::unsatisfied()} when nothing was presented —
     * which is the ordinary case on a public page and must not be an error.
     * §12.3's one function turns evidence into an outcome.
     */
    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult;
}
