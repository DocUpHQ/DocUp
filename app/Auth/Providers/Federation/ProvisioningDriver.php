<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Federation;

use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;

/**
 * 🛑 §11.4's `ProvisioningDriver` seam: **inbound** identity provisioning,
 * pushed by a directory rather than discovered at login.
 *
 * > "**[P2]** SCIM 2.0 inbound provisioning, at installation and organisation
 * > scope only. The `ProvisioningDriver` seam ships in v1 and the documentation
 * > states the deprovisioning latency honestly."
 *
 * The seam ships now; SCIM 2.0 is P2 and ships later against this interface.
 * That ordering is the requirement's, and it is the right way round: a seam
 * introduced *with* its first implementation is a seam shaped by that
 * implementation, and the next one does not fit.
 *
 * ## 🛑 The distinction from JIT provisioning, which is the whole reason this
 * exists
 *
 * {@see ReaderProvisioning} is **pull**: a reader signs in, the provider's
 * claims arrive with them, and §8.13.7 reconciles what those claims say. It can
 * only ever act on a reader who is present. So it cannot offboard anybody —
 * the one thing an offboarding needs is to act on somebody who is **not**
 * present, and who will never log in again precisely because they have left.
 *
 * This seam is **push**: the directory tells DocUp that somebody has gone, and
 * DocUp acts. Every method below exists because a pull model cannot express it.
 *
 * ## 🛑 Installation and organisation scope only, and it is not configurable
 *
 * §8.12.5: "SCIM endpoints and portal-role group mappings MUST exist at
 * installation and organisation scope only." A project-scoped provisioning
 * endpoint would let a tenant create and delete reader identities in an
 * organisation's table, and map groups that §8.12.5 already forbids them from
 * mapping. {@see self::allowsProjectScope()} is on the interface and returns a
 * constant; an architecture test asserts every registered driver returns false,
 * so a third-party driver cannot answer otherwise and be registered.
 *
 * ## 🛑 What a driver may NOT do
 *
 * The same three things {@see AuthComponent} forbids, plus
 * one of this seam's own:
 *
 * 1. **Decide access.** A provisioning driver changes who exists; §12.3's one
 *    function decides what they may read, and it reads rows rather than drivers.
 * 2. **Write a reader identity itself.** Every method here returns a
 *    *decision about an identity* and {@see ReaderProvisioning} performs it,
 *    because that class is where §8.12.1's `(binding_id, subject_hash)` keying
 *    and §9.1.4's "email MUST NEVER be used for linking or lookup" are
 *    enforced. A driver that inserted its own row would be a second place to
 *    get the keying wrong.
 * 3. **Map a dashboard role at project scope** (§8.12.5), which it cannot
 *    reach because it cannot be project-scoped.
 * 4. 🛑 **Promise a latency.** {@see ProvisioningLatency} computes the bound
 *    from §10.8's registry and the grant TTL. A driver that reported its own
 *    would be restating a number §8.12.15 forbids restating — and it would be
 *    reporting the directory's push interval, which is not the bound at all.
 */
interface ProvisioningDriver
{
    /**
     * The driver type string, as stored on the binding.
     *
     * 🛑 Distinct from {@see AuthComponent::type()}'s
     * namespace, because a provisioning source and an authentication source are
     * different things even when one directory is both: `scim` provisions and
     * `oidc` authenticates, and an installation commonly runs them against the
     * same IdP. Conflating the two strings would make "which binding vouched
     * for this session" and "which binding provisioned this identity" one
     * column with two meanings.
     */
    public static function type(): string;

    /**
     * 🛑 §8.12.5: always false. See the class note.
     *
     * On the interface rather than in a list, for the reason
     * {@see AuthComponent::allowsProjectScope()} gives: the
     * reason is a property of the driver and belongs beside it. Unlike that
     * method, this one has no legitimate `true` — an architecture test asserts
     * so by name, because an interface cannot.
     */
    public static function allowsProjectScope(): bool;

    /**
     * Validate the binding's non-secret configuration, refusing rather than
     * correcting.
     *
     * @param  array<string, mixed>  $config
     * @return array<string, mixed> the normalised config to store
     *
     * @throws BindingRefused
     */
    public function validate(array $config): array;

    /**
     * 🛑 One inbound change, as an **intent** rather than an action.
     *
     * Returns what the directory asked for; {@see ReaderProvisioning} decides
     * whether it is permitted and performs it. Two reasons, and the second is
     * the one that matters:
     *
     * - §8.12.1's keying lives in one place, as the class note says;
     * - a driver that acted could not be **dry-run**, and an operator
     *   connecting a directory to a live installation needs to see what a sync
     *   would do before it does it. SCIM's first run against a real directory
     *   is exactly when a mapping mistake deletes everybody.
     *
     * @param  array<string, mixed>  $payload  the request as the directory sent
     *                                         it, already shape-validated by
     *                                         the transport
     *
     * @throws ProvisioningRefused when the payload cannot be understood at all
     */
    public function interpret(BindingContext $binding, array $payload): ProvisioningIntent;

    /**
     * 🛑 Whether this driver can enumerate the directory, and the honest answer
     * is usually no.
     *
     * SCIM 2.0's `/Users` supports listing, but many IdPs implement it partially
     * or not at all, and an operator who believes DocUp can reconcile the whole
     * directory will expect departures to be noticed without a push. They will
     * not be.
     *
     * So this is a capability rather than an assumption, and
     * {@see ProvisioningLatency} is about the push path because the push path
     * is the one that exists.
     */
    public function supportsEnumeration(): bool;
}
