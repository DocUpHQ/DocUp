<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

/**
 * Why a binding write was refused.
 *
 * 🛑 §8.1.11 public contract: these values reach an operator's form and the
 * API's error bodies, so each is a stable identifier and a rename is a contract
 * change — the same standing §8.12.7's `RequirementRejection` has.
 */
enum BindingRejection: string
{
    /**
     * 🛑 §8.12.2's registry refusing a `type` it does not know.
     *
     * A string column is what makes a third-party driver installable without a
     * migration; the registry is what stops that becoming a column anybody can
     * put anything in.
     */
    case UnknownDriver = 'binding.unknown_driver';

    /**
     * 🛑 §8.12.4: "`ldap`, `mtls` and `header_trust` MUST be
     * **installation-scope only** — they reach into the operator's internal
     * network or depend on facts only the TLS terminator can establish, so
     * project-scope configuration would convert tenant self-service into an
     * SSRF or header-spoofing primitive."
     */
    case ScopeNotPermitted = 'binding.scope_not_permitted';

    /**
     * 🛑 §8.12.4's installation-level restriction: "The installation operator
     * MUST be able to restrict which driver types project administrators may
     * configure, with a logged escape hatch."
     */
    case DriverTypeRestricted = 'binding.driver_type_restricted';

    /** The driver's own config validation refused a value. */
    case ConfigInvalid = 'binding.config_invalid';

    /**
     * 🛑 A secret is required and absent. Its own code because the remedy is
     * different from a bad config value: the operator has to supply something
     * no API will ever show them again.
     */
    case SecretMissing = 'binding.secret_missing';

    /** 🛑 §8.12.19's progression refusing a transition. */
    case TransitionNotPermitted = 'binding.transition_not_permitted';

    /**
     * 🛑 §8.12.19: "A referenced binding MUST NOT be deletable."
     *
     * Enforced by the database as well (`reader_credentials.binding_id` is
     * `RESTRICT`), and reported here so an operator gets a sentence rather than
     * a constraint violation.
     */
    case StillReferenced = 'binding.still_referenced';

    /**
     * 🛑 §8.12.5: "Project-scoped bindings MUST NOT produce any dashboard
     * role, enforced both as a driver capability flag and as a validation
     * invariant on group mappings."
     *
     * This is the validation-invariant half. The flag half is
     * {@see AuthComponent::mayMapDashboardRoles()}.
     */
    case DashboardRoleNotPermitted = 'binding.dashboard_role_not_permitted';

    /**
     * 🛑 A share link with no expiry. §8.12.16 makes expiry **mandatory**, and
     * the database refuses it too — a permanent URL for private content is the
     * failure, and forgetting the expiry is the whole way it happens.
     */
    case ShareLinkNeedsExpiry = 'credential.share_link_needs_expiry';

    /**
     * A share link against a binding whose `shareable` flag is false.
     *
     * 🛑 Default-false on the column, because §8.12.16 gives a share link
     * mandatory expiry and a rate limiter, and a driver nobody has thought
     * about in those terms must not acquire a credential class by default.
     */
    case BindingNotShareable = 'credential.binding_not_shareable';
}
