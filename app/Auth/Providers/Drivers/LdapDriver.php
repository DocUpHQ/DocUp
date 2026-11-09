<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Drivers;

use App\Access\AccessLeaf;
use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\AuthComponent;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\DriverRegistry;
use App\Auth\Providers\Federation\ProvisioningMode;
use App\Auth\Providers\Ldap\LdapConnection;
use App\Auth\Providers\Ldap\LdapFilter;
use App\Auth\Providers\Ldap\LdapRefused;
use App\Auth\Providers\Ldap\LdapRejection;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * §8.12.17's `ldap` driver: ninth registry entry, **installation scope only**.
 *
 * 🛑 This class conducts no protocol, exactly as {@see OidcDriver} and
 * {@see SamlDriver} conduct none. §8.12.18's four LDAP requirements live in
 * `App\Auth\Providers\Ldap` behind `final` classes with no options — DN and
 * filter escaping in {@see LdapFilter}, and bind credentials, LDAPS-or-StartTLS
 * with certificate verification and referral chasing in
 * {@see LdapConnection} — so there is nothing here that could weaken any of
 * them, and an architecture test asserts the namespace offers nothing to opt
 * out of.
 *
 * ## 🛑 Installation scope only, and §8.12.4 says why in its own words
 *
 * > "`ldap`, `mtls` and `header_trust` MUST be **installation-scope only** —
 * > they reach into the operator's internal network or depend on facts only the
 * > TLS terminator can establish, so project-scope configuration would convert
 * > tenant self-service into an SSRF or header-spoofing primitive."
 *
 * A project administrator who could configure this would be a tenant who could
 * point DocUp's server at any host on the operator's network and read the
 * response through the error message. {@see self::allowsProjectScope()} is the
 * whole of the enforcement and {@see DriverRegistry::permittedAt()}
 * is its one call site.
 *
 * ## 🛑 Where the reader's password is checked, and where it is not
 *
 * Not here, and not on the serving path. {@see self::attempt()} is satisfied by
 * a **session** established through this binding, exactly as `oidc` and `saml`
 * are: the directory bind happens once, at a sign-in endpoint, and a session
 * carries it afterwards. The alternative — binding on every reader request —
 * would put the reader's password on every request and a directory round-trip
 * in front of every page, and §8.12.13's whole Tier A design is about one
 * signature verification and zero database round-trips.
 */
final class LdapDriver implements AuthComponent
{
    /**
     * The attribute names a binding may read, and the default.
     *
     * 🛑 An allowlist of **config keys**, not of attributes: an operator names
     * which directory attribute carries the subject and which carries the
     * groups, and those names are theirs. What this bounds is the shape of the
     * configuration, so a typo is a refusal at write time rather than an
     * attribute that silently resolves to nothing.
     */
    private const string ATTRIBUTE_PATTERN = '/^[A-Za-z][A-Za-z0-9-]{0,63}$/';

    public static function type(): string
    {
        return 'ldap';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    public static function allowsProjectScope(): bool
    {
        /*
         * 🛑 False, and §8.12.4 is quoted in the class note because this single
         * `false` is the whole of the enforcement. §19's decision register
         * records it as decision 18: "A project admin configuring them converts
         * tenant self-service into an SSRF or header-spoofing primitive."
         */
        return false;
    }

    public static function mayMapDashboardRoles(): bool
    {
        /*
         * 🛑 True **as a driver capability**, with the same division
         * {@see OidcDriver} states: the flag says this driver *can* map a
         * provider group onto one of §12.1's fixed roles, and the **scope**
         * check says whether a given binding may. §8.12.5 requires both, and
         * they answer different questions.
         *
         * For this driver the scope question has one answer — installation —
         * which is precisely the scope §8.12.5 permits dashboard single sign-on
         * at. So the capability is reachable here in a way it is not for a
         * project-scoped `oidc` binding.
         */
        return true;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array<string, mixed>
     *
     * @throws BindingRefused
     */
    public function validate(array $config): array
    {
        $uri = $this->uri($config);
        $baseDn = $this->required($config, 'base_dn');

        /*
         * 🛑 A base DN is not validated as a DN, and that is deliberate. RFC
         * 4514 permits escaped forms this project has no business re-deriving,
         * and a parser of our own would be a second opinion that refuses a DN
         * the directory accepts. What is checked is that it is not empty and
         * not absurd — the directory is the authority on the rest, and
         * §8.12.19's probe is where it answers.
         */
        if (mb_strlen($baseDn) > 512) {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, '`base_dn` is at most 512 characters');
        }

        $filter = $this->required($config, 'user_filter');

        /* §8.12.18's escaping, asserted usable at write time. */
        LdapFilter::assertUsable($filter);

        $bindDn = $this->required($config, 'bind_dn');

        if (mb_strlen($bindDn) > 512) {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, '`bind_dn` is at most 512 characters');
        }

        $normalised = [
            'uri' => $uri,
            'base_dn' => $baseDn,
            'user_filter' => $filter,
            'bind_dn' => $bindDn,
            'subject_attribute' => $this->attribute($config, 'subject_attribute', 'uid'),
            'groups_attribute' => $this->attribute($config, 'groups_attribute', 'memberOf'),
            'display_attribute' => $this->attribute($config, 'display_attribute', 'cn'),
        ];

        $provisioning = $config['provisioning'] ?? ProvisioningMode::CreateReader->value;

        if (! is_string($provisioning) || ProvisioningMode::tryFrom($provisioning) === null) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`provisioning` is one of: '.implode(', ', array_map(
                    static fn (ProvisioningMode $mode): string => $mode->value,
                    ProvisioningMode::cases(),
                )),
            );
        }

        $normalised['provisioning'] = $provisioning;

        return $normalised;
    }

    /**
     * §8.12.19's automated probe: can DocUp reach this directory and sign in
     * to it?
     *
     * 🛑 It performs a **real bind** with the configured service account,
     * because that is the thing that breaks. A probe that only parsed the URI
     * would pass on a directory that refuses the credentials, and §8.12.19
     * exists to stop a binding reaching `active` in that state — where it
     * denies every reader at the worst possible moment.
     *
     * 🛑 And it reports a missing extension as a failure rather than throwing.
     * §11.2 makes `ext-ldap` a `suggest`, so an installation without it is
     * supported; the operator is owed a sentence naming the extension, which is
     * what {@see LdapRejection::explain()} gives them.
     */
    public function probe(BindingContext $binding): ProbeResult
    {
        if (! LdapConnection::available()) {
            return ProbeResult::fail(LdapRejection::ExtensionMissing->explain());
        }

        $uri = $binding->string('uri');
        $bindDn = $binding->string('bind_dn');
        $password = $binding->secret('bind_password');

        if ($uri === null || $bindDn === null) {
            return ProbeResult::fail('the binding has no `uri` or no `bind_dn`');
        }

        if ($password === null || $password === '') {
            return ProbeResult::fail(LdapRejection::BindCredentialsMissing->explain());
        }

        try {
            $connection = LdapConnection::open($uri, $bindDn, $password);
        } catch (LdapRefused $refused) {
            return ProbeResult::fail($refused->rejection->explain());
        }

        $connection->close();

        /*
         * 🛑 The summary names the TLS posture, because that is the one thing
         * an operator cannot see from the outside and the one §8.12.18 cares
         * most about. `ldaps://` is TLS from the first byte; anything else
         * reached here only by completing StartTLS, since
         * {@see LdapConnection::open()} refuses otherwise.
         */
        return ProbeResult::pass(
            'bound to the directory over '
            .(str_starts_with($uri, 'ldaps://') ? 'LDAPS' : 'StartTLS')
            .' with certificate verification',
        );
    }

    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $subject = $presented->sessionSubject;

        /*
         * 🛑 Satisfied only by a session established through **this** binding —
         * `OidcDriver`'s and `SamlDriver`'s rule, for the same reason. A
         * directory bind is not something to repeat per request: it would put
         * the reader's password on every request and a network round-trip in
         * front of every page, against §8.12.13's "one signature verification,
         * zero database round-trips".
         *
         * `hash_equals` because both sides are raw 16 bytes and the comparison
         * decides access.
         */
        if ($subject === null || $presented->sessionBinding === null) {
            return AttemptResult::unsatisfied();
        }

        if (! hash_equals($binding->id, $presented->sessionBinding)) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 No scope. §12.3's last conjunct narrows for `{share}` and
         * `{bearer}`, which are credentials with a stated reach. A
         * directory-authenticated reader is admitted by whatever the rule says;
         * their groups shape *which* rules match, not how far one reaches.
         */
        return AttemptResult::satisfiedBy(AccessLeaf::Binding, subject: $subject);
    }

    /**
     * 🛑 `ldaps://` or `ldap://` with a host, and nothing else.
     *
     * The scheme is what decides whether {@see LdapConnection::open()} starts
     * TLS or expects it from the first byte, so a missing or unknown scheme
     * cannot be defaulted: defaulting to `ldap://` would make a typo a
     * plaintext bind, and defaulting to `ldaps://` would make it a connection
     * failure an operator reads as a firewall problem.
     *
     * @param  array<string, mixed>  $config
     *
     * @throws BindingRefused
     */
    private function uri(array $config): string
    {
        $uri = $this->required($config, 'uri');
        $parts = parse_url($uri);

        if (! is_array($parts) || ! isset($parts['scheme'], $parts['host'])) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`uri` is `ldaps://host[:port]` or `ldap://host[:port]`',
            );
        }

        if (! in_array($parts['scheme'], ['ldap', 'ldaps'], true)) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`uri` must use the `ldap` or `ldaps` scheme; an `ldap` URI is upgraded with '
                .'StartTLS and refused if it cannot be (§8.12.18)',
            );
        }

        /*
         * 🛑 No path, query or fragment. An LDAP URI can carry a base DN and a
         * filter in its path per RFC 4516, and accepting that would give an
         * operator two places to say the same thing — with the directory
         * honouring one and DocUp's own validation checking the other.
         */
        if (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/') {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`uri` carries no path; the base DN and filter are their own settings',
            );
        }

        if (isset($parts['query']) || isset($parts['fragment'])) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`uri` carries no query or fragment',
            );
        }

        return $uri;
    }

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws BindingRefused
     */
    private function required(array $config, string $key): string
    {
        $value = $config[$key] ?? null;

        if (! is_string($value) || trim($value) === '') {
            throw BindingRefused::of(BindingRejection::ConfigInvalid, 'ldap needs a `'.$key.'`');
        }

        return trim($value);
    }

    /**
     * @param  array<string, mixed>  $config
     *
     * @throws BindingRefused
     */
    private function attribute(array $config, string $key, string $default): string
    {
        $value = $config[$key] ?? $default;

        if (! is_string($value) || preg_match(self::ATTRIBUTE_PATTERN, $value) !== 1) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`'.$key.'` is an LDAP attribute name: a letter followed by letters, digits or hyphens',
            );
        }

        return $value;
    }
}
