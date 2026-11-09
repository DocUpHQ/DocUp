<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Ldap;

use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\Drivers\LdapDriver;
use App\Auth\Providers\Ldap\LdapConnection;
use App\Auth\Providers\Ldap\LdapFilter;
use App\Auth\Providers\Ldap\LdapRefused;
use App\Auth\Providers\Ldap\LdapRejection;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's LDAP clause, one test per requirement.
 *
 * > "**LDAP:** DN and filter escaping, bind credentials required, LDAPS or
 * > StartTLS with certificate verification, referral chasing off."
 *
 * ## 🛑 Why the escaping tests are the important ones
 *
 * LDAP filter injection is one of the oldest vulnerabilities in directory
 * services and the most likely to be reintroduced, because the unsafe form —
 * interpolating a username into a configured filter — is the *obvious* form.
 * So the hostile usernames here are the real published payloads rather than
 * invented ones, and each is asserted to produce a filter that matches the
 * literal string rather than a syntactically valid filter with new structure.
 *
 * ## 🛑 What these tests deliberately do NOT need
 *
 * A directory. Everything here is either pure (the escaping, the config
 * validation) or a refusal reached before any socket is opened (the extension
 * check, the empty-password check). The parts that need a real server —
 * StartTLS negotiation, certificate verification, the search — are
 * `LdapDirectoryTest`'s, behind a compose profile, for the reason Phase 24
 * stood up a real Keycloak rather than mocking one: a TLS posture asserted
 * against a fake is a posture nobody has tested.
 */
final class LdapBoundaryTest extends TestCase
{
    // ----------------------------------------- §8.12.18: filter escaping

    /**
     * 🛑 The published injection payloads, each neutralised.
     *
     * Interpolated raw into `(uid={username})`, the first of these becomes
     * `(uid=*)(uid=*))(|(uid=*)` — a valid filter matching **every** entry in
     * the directory. DocUp would then bind as whichever entry came back first.
     */
    public function test_a_hostile_username_cannot_restructure_the_filter(): void
    {
        $hostile = [
            '*)(uid=*))(|(uid=*',
            '*',
            'admin)(|(password=*',
            ')(cn=*',
            'x\\*',
            "nul\0byte",
        ];

        foreach ($hostile as $username) {
            $filter = LdapFilter::build('(uid={username})', ['username' => $username]);

            /*
             * 🛑 The assertion is on **structure**, not on the escaped bytes.
             * Counting parentheses is what catches a new clause; asserting an
             * exact escaped string would pass for an escaper that mangled the
             * value into something harmless but wrong, and would have to be
             * rewritten the next time PHP's escaper changes a hex case.
             */
            $this->assertSame(
                1,
                substr_count($filter, '('),
                'the hostile value opened a new clause: '.$filter,
            );
            $this->assertSame(1, substr_count($filter, ')'), 'the hostile value closed a clause early');

            /* And no bare wildcard survives, which is the match-everything case. */
            $this->assertStringNotContainsString(
                '=*',
                str_replace('\\2a', '', $filter),
                'an unescaped wildcard survived: '.$filter,
            );
        }
    }

    /** An ordinary username passes through recognisably, or the escaping is useless. */
    public function test_an_ordinary_username_is_not_mangled(): void
    {
        $this->assertSame(
            '(uid=alice)',
            LdapFilter::build('(uid={username})', ['username' => 'alice']),
        );

        /*
         * 🛑 And a value an operator will actually see: a UPN carries an `@`
         * and a dot, neither of which RFC 4515 escapes. A filter builder that
         * escaped them would break every Active Directory installation, which
         * is a failure mode worth a test of its own.
         */
        $this->assertSame(
            '(userPrincipalName=alice@example.test)',
            LdapFilter::build('(userPrincipalName={username})', ['username' => 'alice@example.test']),
        );
    }

    /** Every placeholder is escaped, not just the first. */
    public function test_every_placeholder_is_escaped(): void
    {
        $filter = LdapFilter::build(
            '(|(uid={username})(mail={username}))',
            ['username' => 'a*b'],
        );

        $this->assertStringNotContainsString('a*b', $filter);
        $this->assertSame(2, substr_count($filter, '\\2a'), 'both occurrences must be escaped');
    }

    /**
     * 🛑 A template naming a value nothing supplies is refused, rather than
     * leaving a literal `{username}` in the filter.
     *
     * That failure is silent and total: the filter matches nothing, every
     * reader is told their credentials are wrong, and the directory logs show
     * a search for a user called `{username}`.
     */
    public function test_a_template_with_an_unsupplied_placeholder_is_refused(): void
    {
        $this->expectException(BindingRefused::class);

        LdapFilter::build('(uid={username})', ['wrong_name' => 'alice']);
    }

    /** A DN component is escaped by RFC 4514's rules, which are not RFC 4515's. */
    public function test_a_dn_component_is_escaped_by_its_own_rules(): void
    {
        /*
         * 🛑 A comma is structural in a DN and ordinary in a filter; an
         * asterisk is the reverse. Using the wrong flag produces a value that
         * looks escaped and is not, which is why {@see LdapFilter} has two
         * methods rather than one with a parameter.
         */
        $escaped = LdapFilter::escapeDnComponent('Doe, Jane');

        $this->assertStringNotContainsString(', ', $escaped);
        $this->assertStringContainsString('\\2c', $escaped);
    }

    // ------------------------------------- §8.12.18: the filter must select

    /**
     * 🛑 A filter with no placeholder is refused at **write** time, and this is
     * the configuration mistake worth refusing loudest.
     *
     * `(objectClass=person)` is a valid filter. It matches the same entry for
     * every reader — so the first person in the tree becomes everybody — and it
     * **works** for one reader, which is how it reaches production.
     */
    public function test_a_filter_that_selects_nobody_in_particular_is_refused(): void
    {
        foreach (['(objectClass=person)', '(uid=admin)', 'cn=*'] as $template) {
            try {
                LdapFilter::assertUsable($template);
                $this->fail('"'.$template.'" names no placeholder and was accepted');
            } catch (BindingRefused $refused) {
                $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
            }
        }
    }

    /** Unbalanced parentheses are refused here rather than by the directory. */
    public function test_an_unbalanced_filter_is_refused(): void
    {
        $this->expectException(BindingRefused::class);

        LdapFilter::assertUsable('(uid={username}');
    }

    /**
     * 🛑 A wildcard beside the placeholder is refused rather than normalised.
     *
     * `(uid={username}*)` gives prefix matching the operator did not ask for:
     * `al` matches `alice`. Guessing which of the two they meant is how a
     * narrowing becomes a widening.
     */
    public function test_a_wildcard_beside_the_placeholder_is_refused(): void
    {
        $this->expectException(BindingRefused::class);

        LdapFilter::assertUsable('(uid={username}*)');
    }

    /** And a usable filter passes, or the three refusals above prove nothing. */
    public function test_a_usable_filter_is_accepted(): void
    {
        LdapFilter::assertUsable('(uid={username})');
        LdapFilter::assertUsable('(&(objectClass=person)(uid={username}))');
        LdapFilter::assertUsable('(|(uid={username})(mail={username}))');

        $this->expectNotToPerformAssertions();
    }

    // --------------------------------------- §8.12.18: the boundary has no opt-out

    /**
     * 🛑 §8.12.18's "framework-enforced, not driver-optional", asserted **by
     * name** over the namespace.
     *
     * Phase 25 established why a behavioural test is not enough: an unused
     * `$verifyCertificate` sitting in a signature passes every test and is the
     * first thing the next caller reaches for when a self-signed certificate
     * meets a deadline. So the names are asserted absent, and the architecture
     * test asserts the same thing over the whole namespace.
     */
    public function test_the_ldap_boundary_offers_nothing_to_opt_out_of(): void
    {
        $source = (string) file_get_contents(base_path('app/Auth/Providers/Ldap/LdapConnection.php'));

        /* Only the parts that are code, so a comment naming the risk is allowed. */
        $code = '';

        foreach (token_get_all($source) as $token) {
            if (is_array($token)) {
                if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                $code .= $token[1];

                continue;
            }

            $code .= $token;
        }

        foreach ([
            'verifyCertificate', 'allowPlaintext', 'followReferrals', 'insecure',
            'skipTls', 'allowSelfSigned', 'requireCert', 'relaxed', 'lenient',
        ] as $name) {
            $this->assertStringNotContainsString(
                '$'.$name,
                $code,
                '🛑 §8.12.18: `'.$name.'` would make a mandatory protection optional',
            );
        }

        /* And the protections themselves are present, or there is nothing to opt out of. */
        $this->assertStringContainsString('LDAP_OPT_X_TLS_REQUIRE_CERT', $code);
        $this->assertStringContainsString('LDAP_OPT_X_TLS_HARD', $code);
        $this->assertStringContainsString('LDAP_OPT_REFERRALS', $code);
        $this->assertStringContainsString('ldap_start_tls', $code);
    }

    // ------------------------------------- §8.12.18: bind credentials required

    /**
     * 🛑 An empty password is a **rejected credential**, not an anonymous bind.
     *
     * RFC 4511 §4.2 makes a simple bind with an empty password an anonymous
     * bind, which succeeds on most directories. So a reader who submits no
     * password would authenticate as nobody and DocUp would read that as
     * success — the single worst failure available in this driver, and one
     * reached before any socket is opened, which is why it is testable without
     * a directory.
     */
    public function test_an_empty_reader_password_is_refused_before_the_network(): void
    {
        if (! LdapConnection::available()) {
            $this->markTestSkipped('ext-ldap is absent; §11.2 makes it a suggest');
        }

        try {
            LdapConnection::verifyPassword('ldaps://nothing.invalid', 'uid=alice,dc=x', '');
            $this->fail('🛑 RFC 4511 §4.2: an empty password is an ANONYMOUS bind, never a success');
        } catch (LdapRefused $refused) {
            $this->assertSame(LdapRejection::CredentialsRejected, $refused->rejection);
        }
    }

    /** And §8.12.18's service-account credentials are required too. */
    public function test_a_missing_bind_credential_is_refused_before_the_network(): void
    {
        if (! LdapConnection::available()) {
            $this->markTestSkipped('ext-ldap is absent; §11.2 makes it a suggest');
        }

        try {
            LdapConnection::open('ldaps://nothing.invalid', '', 'secret');
            $this->fail('an anonymous bind was attempted');
        } catch (LdapRefused $refused) {
            $this->assertSame(LdapRejection::BindCredentialsMissing, $refused->rejection);
        }
    }

    // --------------------------------------------------- the driver's config

    /** §8.12.4: installation scope only, which is one method and the whole rule. */
    public function test_the_driver_refuses_project_scope(): void
    {
        $this->assertFalse(LdapDriver::allowsProjectScope());
        $this->assertSame('ldap', LdapDriver::type());
    }

    /**
     * 🛑 A plaintext `ldap://` URI is accepted at **write** time and upgraded
     * at connect time — it is not a second way to configure plaintext.
     *
     * The scheme decides whether StartTLS is negotiated or TLS is expected from
     * the first byte, and {@see LdapConnection::open()} refuses an `ldap://`
     * connection that cannot complete StartTLS. So the configuration has no
     * plaintext option while still accepting the port-389 address operators
     * actually have.
     */
    public function test_an_ldap_uri_is_accepted_and_an_http_one_is_not(): void
    {
        $driver = new LdapDriver;

        $config = $driver->validate($this->config(['uri' => 'ldap://directory.internal:389']));

        $this->assertSame('ldap://directory.internal:389', $config['uri']);

        foreach (['https://directory.internal', 'directory.internal', 'ldap:///', 'ldaps://x/base'] as $bad) {
            try {
                $driver->validate($this->config(['uri' => $bad]));
                $this->fail('"'.$bad.'" was accepted as an LDAP URI');
            } catch (BindingRefused $refused) {
                $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
            }
        }
    }

    /** The attribute names are bounded, so a typo is a refusal and not a silent miss. */
    public function test_an_attribute_name_is_validated(): void
    {
        $driver = new LdapDriver;

        $config = $driver->validate($this->config([]));

        $this->assertSame('uid', $config['subject_attribute']);
        $this->assertSame('memberOf', $config['groups_attribute']);

        foreach (['', '1bad', 'has space', 'semi;colon', str_repeat('a', 65)] as $bad) {
            try {
                $driver->validate($this->config(['groups_attribute' => $bad]));
                $this->fail('"'.$bad.'" was accepted as an attribute name');
            } catch (BindingRefused $refused) {
                $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
            }
        }
    }

    /** Each required setting is required, and named when it is missing. */
    public function test_every_required_setting_is_required(): void
    {
        $driver = new LdapDriver;

        foreach (['uri', 'base_dn', 'user_filter', 'bind_dn'] as $key) {
            $config = $this->config([]);
            unset($config[$key]);

            try {
                $driver->validate($config);
                $this->fail('a binding with no `'.$key.'` was accepted');
            } catch (BindingRefused $refused) {
                $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
                $this->assertStringContainsString($key, $refused->getMessage());
            }
        }
    }

    /**
     * 🛑 The probe refuses with a sentence naming the extension when it is
     * absent, rather than a fatal error.
     *
     * §11.2 makes `ext-ldap` a `suggest` (amended in Phase 26b), so an
     * installation without it is **supported** — and the operator is owed
     * something they can act on. Asserted on the explanation rather than by
     * removing the extension, which a test cannot do.
     */
    public function test_a_missing_extension_explains_itself(): void
    {
        $explanation = LdapRejection::ExtensionMissing->explain();

        $this->assertStringContainsString('ext-ldap', $explanation);
        $this->assertStringContainsString('suggest', $explanation);
        $this->assertTrue(LdapRejection::ExtensionMissing->isOperatorFault());
    }

    /**
     * 🛑 §8.12.19 and §8.12.23 need the faults sorted, because one gets a
     * branded 503 naming the binding and the other gets the project's
     * `deny_status` and an empty body.
     *
     * Reporting a reader's wrong password as a degraded provider would tell
     * every reader the directory is broken; reporting an unreachable directory
     * as a wrong password would send them to reset a password that works.
     */
    public function test_operator_faults_and_reader_faults_are_sorted(): void
    {
        foreach ([
            LdapRejection::ExtensionMissing,
            LdapRejection::Unreachable,
            LdapRejection::TlsUnavailable,
            LdapRejection::BindCredentialsMissing,
            LdapRejection::BindFailed,
            LdapRejection::SearchFailed,
            LdapRejection::SubjectAmbiguous,
        ] as $rejection) {
            $this->assertTrue($rejection->isOperatorFault(), $rejection->value.' is the operator to fix');
        }

        foreach ([LdapRejection::SubjectNotFound, LdapRejection::CredentialsRejected] as $rejection) {
            $this->assertFalse($rejection->isOperatorFault(), $rejection->value.' is the reader');
        }

        /* Every case is classified, so a new one cannot default into the wrong half. */
        foreach (LdapRejection::cases() as $rejection) {
            $this->assertNotSame('', $rejection->explain(), $rejection->value.' has no explanation');
        }
    }

    /**
     * 🛑 "no such account" and "wrong password" are the same answer to a
     * reader.
     *
     * The difference is an enumeration oracle for the operator's directory, and
     * the two cases exist separately only so §20.3's audit trail can tell them
     * apart. Asserted on the explanations an **operator** sees, which are
     * allowed to differ.
     */
    public function test_the_two_reader_faults_are_both_reader_faults(): void
    {
        $this->assertFalse(LdapRejection::SubjectNotFound->isOperatorFault());
        $this->assertFalse(LdapRejection::CredentialsRejected->isOperatorFault());

        $this->assertNotSame(
            LdapRejection::SubjectNotFound->explain(),
            LdapRejection::CredentialsRejected->explain(),
            'an operator may be told which; a reader may not',
        );
    }

    /**
     * A complete, valid configuration.
     *
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function config(array $overrides): array
    {
        return [
            'uri' => 'ldaps://directory.internal:636',
            'base_dn' => 'ou=people,dc=example,dc=test',
            'user_filter' => '(uid={username})',
            'bind_dn' => 'cn=docup,ou=services,dc=example,dc=test',
            ...$overrides,
        ];
    }
}
