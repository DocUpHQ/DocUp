<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

/**
 * 🛑 §8.12.19's five states, with the reason for each beside it.
 *
 * > "Bindings MUST progress `draft → verifying → active → degraded →
 * > disabled`, and MUST NOT leave `verifying` until an automated probe passes
 * > **and** a human completes a test login. A degraded binding MUST **deny**
 * > with a branded 503 naming the binding and linking to its health page —
 * > never fall back to another provider, never to public, and the UI MUST NOT
 * > offer a 'make public' button there."
 *
 * The arrow in that sentence is a *progression*, not a cycle, and
 * {@see self::mayTransitionTo()} is it. The one transition operators reach for
 * and that is refused is `degraded → active` by hand: a binding that failed its
 * probe five times becomes healthy by **passing a probe**, not by somebody
 * saying it is fine.
 */
enum BindingState: string
{
    /**
     * Configured and authenticating nobody.
     *
     * The default, so a binding half-created in a form cannot admit a reader
     * while the operator is still typing.
     */
    case Draft = 'draft';

    /**
     * 🛑 Awaiting **both** of §8.12.19's conditions: an automated probe and a
     * human test login.
     *
     * Two conditions rather than one because they catch different failures. A
     * probe proves the installation can reach the provider; a test login proves
     * a *person* can get in. An OIDC binding with a valid discovery document
     * and a wrong client secret passes the first and fails the second, and it
     * is the second that an operator would otherwise discover from a reader's
     * support ticket.
     */
    case Verifying = 'verifying';

    /** Proven, and the only state that authenticates anybody. */
    case Active = 'active';

    /**
     * 🛑 Failing, and **denying with a 503** rather than falling back.
     *
     * The requirement is explicit about the thing not to do: "never fall back
     * to another provider, never to public". A documentation site that quietly
     * became public because its IdP was unreachable is the worst outcome
     * available here, and it is the one a naive fallback produces.
     */
    case Degraded = 'degraded';

    /** Turned off deliberately. Authenticates nobody and raises no alert. */
    case Disabled = 'disabled';

    /**
     * 🛑 Whether this state must answer a reader with a branded 503.
     *
     * Only `degraded`. The other four non-active states are refusals of the
     * reader — the binding is not in service and §8.12.23's `deny_status`
     * applies. `degraded` is a refusal of the *installation*: the reader may
     * hold a perfectly good credential and the installation cannot tell, which
     * is what 503 means and what 404 would hide.
     */
    public function deniesWithServiceUnavailable(): bool
    {
        return $this === self::Degraded;
    }

    /**
     * 🛑 §8.12.19's progression, as a function.
     *
     * The refusals are the content:
     *
     * - **`degraded → active` is refused.** A binding becomes healthy by
     *   passing a probe, which clears the failure counter and moves it back
     *   itself; an operator who could set `active` by hand would be overriding
     *   the only evidence there is.
     * - **`draft → active` is refused.** That is §8.12.19's own sentence: a
     *   binding "MUST NOT leave `verifying`" without both conditions, and
     *   skipping `verifying` would skip both.
     * - **`disabled → active` is refused**, for the first reason: a binding
     *   turned off months ago has unproven configuration, so it re-enters at
     *   `verifying`.
     */
    public function mayTransitionTo(self $next): bool
    {
        return match ($this) {
            self::Draft => in_array($next, [self::Verifying, self::Disabled], true),
            self::Verifying => in_array($next, [self::Active, self::Draft, self::Disabled], true),
            self::Active => in_array($next, [self::Degraded, self::Disabled, self::Verifying], true),
            self::Degraded => in_array($next, [self::Verifying, self::Disabled], true),
            self::Disabled => in_array($next, [self::Verifying, self::Draft], true),
        };
    }

    /**
     * How many consecutive probe failures move `active` to `degraded`.
     *
     * 🛑 Five, and the number is an argument rather than a preference: one
     * failed probe is a network and five is a provider. Degrading on the first
     * failure would make every transient DNS blip take a project's
     * documentation offline with a 503, which is the behaviour operators
     * disable the feature to escape.
     */
    public const int DEGRADE_AFTER_FAILURES = 5;
}
