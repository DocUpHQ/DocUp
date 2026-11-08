<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\AccessLeaf;
use App\Auth\Providers\Drivers\IpAllowlistDriver;
use App\Auth\Providers\Drivers\LdapDriver;
use App\Auth\Providers\Drivers\OidcDriver;
use App\Auth\Providers\Drivers\PasswordDriver;
use App\Auth\Providers\Drivers\PortalSessionDriver;
use App\Auth\Providers\Drivers\PublicDriver;
use App\Auth\Providers\Drivers\ReaderTokenDriver;
use App\Auth\Providers\Drivers\SamlDriver;
use App\Auth\Providers\Drivers\SharedLinkDriver;

/**
 * 🛑 §8.12.2's registry: what makes `auth_provider_bindings.type` a free string
 * safe to store.
 *
 * The column is a string because "Third-party drivers MUST be installable
 * without migrations", and a string column accepts anything. This class is the
 * constraint that an enum would otherwise have been — with the difference that
 * adding a driver is a line here rather than a schema change.
 *
 * ## 🛑 Two invariants, both asserted by a test
 *
 * 1. **Every registered driver's type is classified by §8.12.17.**
 *    {@see AccessLeaf::forDriver()} is that table as a function and returns
 *    null for a type it has not been taught; {@see self::assertRegistrable()}
 *    refuses such a driver. The reason is §8.12.7: the satisfiability invariant
 *    "is defined over that classification", so a driver whose leaf kind nobody
 *    declared would be a driver the invariant cannot reason about — and the
 *    silent default would be `binding`, i.e. an identity nobody granted.
 * 2. **Every driver's declared leaf matches §8.12.17's.** A driver reports its
 *    kind and the table decides it, so the two must agree; a mismatch is a
 *    driver trying to reclassify itself, which is how `ip_allowlist` would
 *    become authentication.
 *
 * ## 🛑 §8.12.4's restriction is applied here and not in the UI
 *
 * > "The installation operator MUST be able to restrict which driver types
 * > project administrators may configure, with a logged escape hatch."
 *
 * A UI-only restriction is one the API does not have. {@see self::permittedAt()}
 * is the one place that answers "may this scope configure this type", so the
 * dashboard and the API ask the same function.
 */
final class DriverRegistry
{
    /**
     * §8.12.17's v1-mandatory set: "the six `any`-scope drivers plus `oidc`".
     *
     * 🛑 `oidc` arrived in **Phase 24**, with §8.12.18's framework-enforced
     * protocol validation rather than before it. Phase 23 left it out on
     * purpose — its scope said "Explicitly not in scope: OIDC, SAML, LDAP" —
     * because a registry entry without that enforcement would be a driver that
     * validates its own protocol, which the requirement forbids by name. The
     * exchange lives in `App\Auth\Providers\Oidc` behind classes with no
     * options, so {@see OidcDriver} conducts no protocol at all.
     *
     * 🛑 `saml` arrived in **Phase 25**, which is the phase §17.3 names for
     * it, and under the same condition `oidc` had to meet: §8.12.18's
     * validation is enforced by the framework and not by the driver. The whole
     * XML boundary — `SafeXml`, `SignatureVerifier`, `ResponseValidator`,
     * `AssertionReplayCache` — is `final` and takes no options, so
     * `SamlDriver` conducts no protocol and cannot weaken any of it.
     *
     * 🛑 `ldap` arrived in **Phase 26b**, which is the phase §17.3 names for
     * it, under the same condition and with one addition: it is
     * **installation-scope only** (§8.12.4), which {@see LdapDriver::allowsProjectScope()}
     * returns false for and {@see self::permittedAt()} enforces. §8.12.18's four
     * LDAP requirements live in `App\Auth\Providers\Ldap` behind `final`
     * classes with no options — so `LdapDriver` conducts no protocol either.
     *
     * `mtls` and `header_trust` are still absent: §8.12.17 puts them after the
     * cut line and §17.3 names the phase that carries each.
     *
     * @var array<string, class-string<AuthComponent>>
     */
    private const array DRIVERS = [
        'public' => PublicDriver::class,
        'portal_session' => PortalSessionDriver::class,
        'password' => PasswordDriver::class,
        'shared_link' => SharedLinkDriver::class,
        'reader_token' => ReaderTokenDriver::class,
        'ip_allowlist' => IpAllowlistDriver::class,
        'oidc' => OidcDriver::class,
        'saml' => SamlDriver::class,
        'ldap' => LdapDriver::class,
    ];

    /**
     * Every registered type.
     *
     * @return list<string>
     */
    public static function types(): array
    {
        return array_keys(self::DRIVERS);
    }

    /**
     * The driver for a type, or null.
     *
     * 🛑 Resolved through the container so a driver may take dependencies —
     * `SharedLinkDriver` needs the credential store and the rate limiter — but
     * **only** from this list. A driver resolved by a type string a request
     * supplied would be arbitrary class instantiation; the list is what makes
     * the string a key rather than a class name.
     */
    public static function for(string $type): ?AuthComponent
    {
        $class = self::DRIVERS[$type] ?? null;

        /*
         * 🛑 No `instanceof AuthComponent` guard, and Larastan is why: the
         * array is typed `class-string<AuthComponent>`, so the check is
         * statically unreachable and level 8 refuses it as always-true. The
         * type is the guard, which is the stronger form — a class that did not
         * implement the interface could not be added to the list at all.
         */
        return $class === null ? null : app($class);
    }

    /**
     * The driver for a type, or refuse.
     *
     * @throws BindingRefused
     */
    public static function require(string $type): AuthComponent
    {
        $driver = self::for($type);

        if ($driver === null) {
            throw BindingRefused::of(BindingRejection::UnknownDriver, $type);
        }

        return $driver;
    }

    /**
     * 🛑 Whether a scope may configure a type (§8.12.4).
     *
     * Two gates, in order, because they fail for different reasons and an
     * operator needs to know which:
     *
     * 1. The **driver's own** capability. `ldap`, `mtls` and `header_trust` are
     *    installation-only because they "reach into the operator's internal
     *    network or depend on facts only the TLS terminator can establish". No
     *    configuration lifts that — it is a property of the driver.
     * 2. The **installation's** restriction, which an operator sets and which
     *    §8.12.4 gives "a logged escape hatch". That is the unsafe flag
     *    `DOCUP_DANGEROUSLY_ALLOW_UNLISTED_AUTH_TYPES`, already in §8.22.11's
     *    registry since Phase 01.
     *
     * @param  'installation'|'organisation'|'project'  $scopeType
     *
     * @throws BindingRefused
     */
    public static function permittedAt(string $type, string $scopeType): AuthComponent
    {
        $driver = self::require($type);

        if ($scopeType === 'project' && ! $driver::allowsProjectScope()) {
            throw BindingRefused::of(
                BindingRejection::ScopeNotPermitted,
                $type.' is installation-scope only (§8.12.4)',
            );
        }

        if (! self::allowedByInstallation($type)) {
            throw BindingRefused::of(
                BindingRejection::DriverTypeRestricted,
                $type.' is not in docup.auth.permitted_types',
            );
        }

        return $driver;
    }

    /**
     * §8.12.4's installation-level restriction.
     *
     * 🛑 An **unset** list means every registered type is permitted, which is
     * the only safe default for an *allowlist of features* rather than of
     * credentials: an empty default would make a fresh installation unable to
     * configure any authentication at all, and the first thing an operator
     * would do is find the flag that disables the check.
     *
     * 🛑 The escape hatch is §8.22.11's existing
     * `DOCUP_DANGEROUSLY_ALLOW_UNLISTED_AUTH_TYPES`, so there is no second
     * unsafe flag — the architecture test asserts every one of them lives in
     * that registry.
     */
    private static function allowedByInstallation(string $type): bool
    {
        if (config('docup.unsafe.allow_unlisted_auth_types') === true) {
            return true;
        }

        $permitted = config('docup.auth.permitted_types');

        if (! is_array($permitted) || $permitted === []) {
            return true;
        }

        return in_array($type, $permitted, true);
    }

    /**
     * 🛑 The two registry invariants, as one assertion the test calls.
     *
     * Not run per request: it is a property of the committed code, so it
     * belongs to the architecture suite rather than to the serving path. Here
     * rather than in the test so that the *rule* lives beside the registry and
     * the test only has to call it.
     *
     * @return list<string> the violations, empty when the registry is sound
     */
    public static function assertRegistrable(): array
    {
        $problems = [];

        foreach (self::DRIVERS as $type => $class) {
            /*
             * The interface is guaranteed by `class-string<AuthComponent>`, so
             * what is left to assert is the two things a type system cannot:
             * that the driver agrees with the key it is registered under, and
             * that §8.12.17 classifies it.
             */
            $driver = app($class);

            if ($driver::type() !== $type) {
                $problems[] = $class.' is registered as "'.$type.'" and reports "'.$driver::type().'"';
            }

            /*
             * 🛑 §8.12.17's table is the authority. A driver whose type that
             * function does not classify cannot be reasoned about by §8.12.7's
             * satisfiability invariant.
             */
            $classified = AccessLeaf::forDriver($type);

            if ($classified === null) {
                $problems[] = $type.' is not classified by §8.12.17 (AccessLeaf::forDriver)';

                continue;
            }

            if ($driver::leaf() !== $classified) {
                $problems[] = $type.' reports leaf "'.$driver::leaf()->value
                    .'" and §8.12.17 says "'.$classified->value.'"';
            }
        }

        return $problems;
    }

    /**
     * 🛑 Guard against a driver resolving to something that is not one.
     *
     * @throws \RuntimeException
     */
    public static function assertSound(): void
    {
        $problems = self::assertRegistrable();

        if ($problems !== []) {
            throw new \RuntimeException('driver registry is unsound: '.implode('; ', $problems));
        }
    }
}
