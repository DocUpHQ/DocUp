<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Ldap;

use App\Auth\Providers\Drivers\LdapDriver;
use LDAP\Connection;
use LDAP\Result;

/**
 * 🛑 §8.12.18's other three LDAP requirements, as a boundary with **no
 * options**.
 *
 * > "**LDAP:** DN and filter escaping, bind credentials required, LDAPS or
 * > StartTLS with certificate verification, referral chasing off."
 *
 * {@see LdapFilter} is the escaping. This is the rest, and like Phase 25's XML
 * boundary it is written so that the unsafe configuration **cannot be
 * expressed**: there is no `$verifyCertificate`, no `$allowPlaintext`, no
 * `$followReferrals` and no `$insecure` anywhere in the signature. §8.12.18
 * says protocol validation is "framework-enforced, not driver-optional", and an
 * architecture test asserts those names are absent from this namespace —
 * because a behavioural test passes while an unused opt-out sits in a
 * constructor waiting for the first operator with a self-signed certificate
 * and a deadline.
 *
 * ## 🛑 Why `ext-ldap` is checked and not assumed
 *
 * §11.2 makes the extension a composer `suggest` (amended in Phase 26b — the
 * library that would have carried it declares it in its own `require`, so the
 * suggestion was unreachable). An installation can therefore run DocUp without
 * it, and must get a sentence naming the extension rather than
 * `Call to undefined function ldap_connect()` in a stack trace. The shipped
 * images carry it; a bare-metal installation may not.
 *
 * ## 🛑 Why there is no plaintext mode at all
 *
 * The requirement says "LDAPS **or** StartTLS", so port 389 with no TLS is not
 * one of the choices. A bind sends the password in the clear, and the usual
 * argument for allowing it — "it is an internal network" — is the argument
 * §8.12.4 already rejects by making this driver installation-scope only. There
 * is no flag, which means there is nothing to find when somebody searches the
 * configuration for a way to turn it off.
 */
final class LdapConnection
{
    /**
     * Seconds to wait for the directory, in total and on the network leg.
     *
     * 🛑 Short, and short on purpose. This runs while a reader waits for a
     * sign-in form to answer, and §8.12.19's `degraded` state exists precisely
     * so that an unreachable directory becomes a branded 503 naming the binding
     * rather than a request that hangs until the web server gives up.
     */
    public const int TIMEOUT_SECONDS = 5;

    private function __construct(private readonly Connection $handle) {}

    /**
     * Whether this installation can speak LDAP at all.
     *
     * Read by {@see LdapDriver::probe()} so that
     * §8.12.19's probe refuses with a sentence an operator can act on, and by
     * the tests so they skip rather than fail where the extension is absent.
     */
    public static function available(): bool
    {
        return extension_loaded('ldap');
    }

    /**
     * Open a connection, start TLS where the scheme needs it, and bind.
     *
     * 🛑 **Bind credentials are required** — §8.12.18 again — so there is no
     * anonymous path. An anonymous bind succeeds against many directories and
     * returns a search result stripped of the attributes the filter needed,
     * which presents as "the user does not exist" for every user: a total
     * outage that looks like a filter mistake.
     *
     * @param  string  $uri  `ldaps://host:636` or `ldap://host:389`; the second
     *                       is upgraded with StartTLS and refused if it cannot be
     * @param  string  $bindDn  the service account's DN
     * @param  string  $password  the service account's password
     *
     * @throws LdapRefused
     */
    public static function open(string $uri, string $bindDn, string $password): self
    {
        if (! self::available()) {
            throw LdapRefused::of(LdapRejection::ExtensionMissing);
        }

        if ($bindDn === '' || $password === '') {
            throw LdapRefused::of(LdapRejection::BindCredentialsMissing);
        }

        $handle = @ldap_connect($uri);

        if (! $handle instanceof Connection) {
            throw LdapRefused::of(LdapRejection::Unreachable, 'the LDAP URI could not be parsed');
        }

        /*
         * 🛑 Version 3 before anything else. A v2 connection has no StartTLS
         * and no SASL, so leaving the default would make the TLS requirement
         * below silently unsatisfiable on a directory that still answers v2.
         */
        ldap_set_option($handle, LDAP_OPT_PROTOCOL_VERSION, 3);

        /*
         * 🛑 §8.12.18: "referral chasing off". A referral is the directory
         * telling the client to go and ask a different server — which is an
         * SSRF primitive handed over by the thing being authenticated against,
         * and §8.12.4 names exactly that risk as the reason this driver is
         * installation-scope only. Off means the client never follows one.
         */
        ldap_set_option($handle, LDAP_OPT_REFERRALS, 0);

        /*
         * 🛑 §8.12.18: "with certificate verification". `LDAP_OPT_X_TLS_HARD`
         * requires a valid chain **and** a matching name, and it is set on the
         * connection before StartTLS so it governs that negotiation too.
         *
         * Setting it has to come before the handshake: after it, the option is
         * recorded and nothing re-verifies.
         */
        ldap_set_option($handle, LDAP_OPT_X_TLS_REQUIRE_CERT, LDAP_OPT_X_TLS_HARD);

        ldap_set_option($handle, LDAP_OPT_NETWORK_TIMEOUT, self::TIMEOUT_SECONDS);
        ldap_set_option($handle, LDAP_OPT_TIMELIMIT, self::TIMEOUT_SECONDS);

        /*
         * 🛑 StartTLS for an `ldap://` URI, and a **refusal** if it fails
         * rather than a fall-through. The failure mode this closes is the
         * downgrade: a directory that does not offer StartTLS would otherwise
         * leave the connection in the clear and the bind below would still
         * succeed, so the password would cross the network in plaintext and
         * everything would look like it worked.
         */
        if (! str_starts_with($uri, 'ldaps://')) {
            if (@ldap_start_tls($handle) !== true) {
                throw LdapRefused::of(
                    LdapRejection::TlsUnavailable,
                    'StartTLS was refused or the certificate did not verify',
                );
            }
        }

        if (@ldap_bind($handle, $bindDn, $password) !== true) {
            /*
             * 🛑 The service account's own failure, which is a configuration
             * fault and not a reader's. Kept apart from
             * {@see LdapRejection::CredentialsRejected} so §8.12.19's probe can
             * say "DocUp cannot sign in to your directory" rather than
             * "that password is wrong".
             */
            throw LdapRefused::of(LdapRejection::BindFailed, self::diagnostic($handle));
        }

        return new self($handle);
    }

    /**
     * Search for exactly one entry, returning its DN and the attributes asked
     * for.
     *
     * 🛑 **Exactly one**, and two is a refusal rather than a choice — the same
     * reasoning §8.12.18 applies to SAML's "exactly one Assertion". A filter
     * matching two entries means the operator's uniqueness assumption is wrong,
     * and picking the first would authenticate whichever one the directory
     * happened to return: a coin toss between two people, deterministic enough
     * to look correct in testing.
     *
     * @param  list<string>  $attributes
     * @return array{dn: string, attributes: array<string, list<string>>}
     *
     * @throws LdapRefused
     */
    public function findOne(string $baseDn, string $filter, array $attributes): array
    {
        $result = @ldap_search(
            $this->handle,
            $baseDn,
            $filter,
            $attributes,
            0,
            2,                      // two is enough to detect "more than one"
            self::TIMEOUT_SECONDS,
        );

        /*
         * 🛑 `instanceof`, not `!== false`. `ldap_search()` returns an **array**
         * of results when it is handed an array of base DNs — a parallel search
         * across several trees — and `ldap_get_entries()` cannot read that.
         * This method searches one base DN, so an array here would mean a
         * caller changed that; refusing on the type rather than on `false`
         * catches it instead of passing the wrong shape on.
         */
        if (! $result instanceof Result) {
            throw LdapRefused::of(LdapRejection::SearchFailed, self::diagnostic($this->handle));
        }

        $entries = @ldap_get_entries($this->handle, $result);

        if (! is_array($entries) || ! isset($entries['count']) || ! is_int($entries['count'])) {
            throw LdapRefused::of(LdapRejection::SearchFailed, 'the directory returned nothing readable');
        }

        if ($entries['count'] === 0) {
            throw LdapRefused::of(LdapRejection::SubjectNotFound);
        }

        if ($entries['count'] > 1) {
            throw LdapRefused::of(LdapRejection::SubjectAmbiguous);
        }

        $entry = $entries[0];

        if (! is_array($entry) || ! is_string($entry['dn'] ?? null)) {
            throw LdapRefused::of(LdapRejection::SearchFailed, 'the matched entry carries no DN');
        }

        return ['dn' => $entry['dn'], 'attributes' => self::attributesOf($entry, $attributes)];
    }

    /**
     * 🛑 Verify a reader's password by binding **as them**, on a connection of
     * its own.
     *
     * A second connection rather than a re-bind on this one, and the reason is
     * not tidiness: `ldap_bind()` replaces the connection's identity, so
     * re-binding as the reader would leave the service account's privileges
     * behind and every later search on this handle would run as the reader —
     * silently returning fewer attributes, which presents as a group that
     * vanished.
     *
     * @throws LdapRefused
     */
    public static function verifyPassword(string $uri, string $dn, string $password): bool
    {
        /*
         * 🛑 An empty password is refused **before** it reaches the directory.
         * RFC 4511 §4.2 makes a simple bind with an empty password an
         * *anonymous* bind, which succeeds on most directories — so a reader
         * who submits no password would authenticate as nobody and DocUp would
         * read that as success. This is the single most important line in the
         * file.
         */
        if ($password === '') {
            throw LdapRefused::of(LdapRejection::CredentialsRejected);
        }

        try {
            self::open($uri, $dn, $password);

            return true;
        } catch (LdapRefused $refused) {
            if ($refused->rejection === LdapRejection::BindFailed) {
                /* The reader's password is wrong, which is not a fault. */
                return false;
            }

            throw $refused;
        }
    }

    /** Close the connection, which also drops the bound identity. */
    public function close(): void
    {
        @ldap_unbind($this->handle);
    }

    /**
     * One entry's attributes, lower-cased and flattened.
     *
     * 🛑 `ldap_get_entries()` lower-cases attribute names and returns each
     * value list with a `count` key alongside the values, which is the shape
     * that produces an off-by-one when read naively. Normalising here means no
     * caller has to know.
     *
     * @param  array<array-key, mixed>  $entry
     * @param  list<string>  $wanted
     * @return array<string, list<string>>
     */
    private static function attributesOf(array $entry, array $wanted): array
    {
        $attributes = [];

        foreach ($wanted as $name) {
            $key = mb_strtolower($name);
            $values = $entry[$key] ?? null;

            if (! is_array($values)) {
                continue;
            }

            $list = [];

            foreach ($values as $index => $value) {
                /* `count` is metadata; the values are at integer offsets. */
                if (is_int($index) && is_string($value)) {
                    $list[] = $value;
                }
            }

            if ($list !== []) {
                $attributes[$key] = $list;
            }
        }

        return $attributes;
    }

    /**
     * The directory's own error text, for an operator.
     *
     * 🛑 Never shown to a reader. It names hosts, DNs and sometimes the reason
     * an account is locked — operator-grade detail, which §8.12.19's health
     * page is for and a 404 is not.
     */
    private static function diagnostic(Connection $handle): string
    {
        $message = @ldap_error($handle);

        /*
         * 🛑 No `is_string()` guard: `ldap_error()` is declared to return a
         * string, so the check is one the analyser proves true — and §9.4 runs
         * this namespace at level 9, which reports exactly that. An assertion
         * the analyser can evaluate is an assertion that cannot fail, which
         * Phase 25 and Phase 26a each found the hard way.
         */
        return $message === '' ? 'the directory gave no reason' : $message;
    }
}
