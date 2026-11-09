<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\HeaderTrust;

use App\Auth\Providers\AttemptResult;
use App\Auth\Providers\BindingContext;
use App\Auth\Providers\BindingRefused;
use App\Auth\Providers\BindingRejection;
use App\Auth\Providers\BindingState;
use App\Auth\Providers\DriverRegistry;
use App\Auth\Providers\Drivers\HeaderTrustDriver;
use App\Auth\Providers\EdgeAssertion;
use App\Auth\Providers\Federation\ReaderSubject;
use App\Auth\Providers\ReaderPresentation;
use App\Credentials\SecretString;
use App\Http\Middleware\TrustEdgeProxies;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Symfony\Component\HttpFoundation\Response;
use Tests\TestCase;

/**
 * 🛑 §8.12.17's `header_trust`: the only driver in the table marked **"off by
 * default"**, and the only one whose identity column reads **"yes, by
 * assertion"**.
 *
 * ## 🛑 The attack this whole file is about
 *
 * An operator puts oauth2-proxy in front of DocUp and configures
 * `X-Auth-Request-User`. The attack is one curl:
 *
 * ```
 * curl https://docs.example.com/private/ -H 'X-Auth-Request-User: admin'
 * ```
 *
 * It works whenever the terminator sets the header **only for an authenticated
 * reader** — oauth2-proxy's default — because an unauthenticated request's
 * header passes through untouched. Trusting the peer address does not help: the
 * peer *is* the proxy.
 *
 * {@see self::test_the_subject_header_alone_authenticates_nobody()} is that
 * curl, and it is the test to read first.
 */
final class HeaderTrustTest extends TestCase
{
    private const string PROXY = '172.20.0.9';

    private const string TRUSTED = '172.20.0.0/16';

    private const string SUBJECT_HEADER = 'X-Auth-Request-User';

    private const string SECRET_HEADER = 'X-DocUp-Assertion';

    private const string SECRET = 'the-terminators-own-configuration-only';

    protected function setUp(): void
    {
        parent::setUp();

        /* A correctly-configured installation; each test narrows from here. */
        Config::set('docup.edge.trusted_proxies', self::TRUSTED);
        Config::set('docup.auth.asserted_identity.subject_header', self::SUBJECT_HEADER);
        Config::set('docup.auth.asserted_identity.secret_header', self::SECRET_HEADER);
    }

    // ------------------------------------------------ off by default, §8.12.17

    /**
     * 🛑 **Off by default**, and the mechanism had to be built because the
     * existing one pointed the other way.
     *
     * `DriverRegistry::allowedByInstallation()` treats an **unset**
     * `permitted_types` as "every registered type" — which is right for the
     * other ten drivers and would have turned `header_trust` **on** by merely
     * registering it. So the type must be **named**: neither the permissive
     * default nor an empty list reaches it.
     */
    public function test_it_is_off_until_the_installation_names_it(): void
    {
        /* The default: nothing named. */
        Config::set('docup.auth.permitted_types', []);
        $this->refusedAt('installation', BindingRejection::DriverTypeRestricted);

        /* A list that names other drivers is still not this one. */
        Config::set('docup.auth.permitted_types', ['password', 'oidc', 'mtls']);
        $this->refusedAt('installation', BindingRejection::DriverTypeRestricted);

        /* Named: permitted. */
        Config::set('docup.auth.permitted_types', ['password', 'header_trust']);
        $this->assertInstanceOf(
            HeaderTrustDriver::class,
            DriverRegistry::permittedAt('header_trust', 'installation'),
        );
    }

    /**
     * 🛑 And §8.22.11's blanket escape hatch does **not** reach it either.
     *
     * `DOCUP_DANGEROUSLY_ALLOW_UNLISTED_AUTH_TYPES` permits "driver types
     * outside the allowlist", and it deliberately stops short of a driver the
     * specification itself says is off by default: naming the type costs one
     * entry in one environment variable, and a flag meant for something else
     * should not sweep this in. §20.4's invariant is "no security control sits
     * behind a flag that defaults open" — this is the same instinct applied to
     * the hatch.
     */
    public function test_the_unsafe_flag_does_not_turn_it_on(): void
    {
        Config::set('docup.auth.permitted_types', []);
        Config::set('docup.unsafe.allow_unlisted_auth_types', true);

        $this->refusedAt('installation', BindingRejection::DriverTypeRestricted);

        /* And the flag still does what it is for, on a driver that is not off by default. */
        Config::set('docup.auth.permitted_types', ['password']);

        /*
         * 🛑 The driver's own type, not `assertNotNull`. `permittedAt()` returns
         * a non-nullable `AuthComponent`, so a null check is an assertion level
         * 8 proves can never fail — and CI proved exactly that about the first
         * version of this line. Asserting the type asserts something: that the
         * registry returned `mtls` and not merely something.
         */
        $this->assertSame('mtls', DriverRegistry::permittedAt('mtls', 'installation')::type());
    }

    /** 🛑 §8.12.4: installation scope only — "header-spoofing primitive" by name. */
    public function test_it_is_installation_scope_only(): void
    {
        Config::set('docup.auth.permitted_types', ['header_trust']);

        $this->refusedAt('project', BindingRejection::ScopeNotPermitted);

        $this->assertSame(
            'header_trust',
            DriverRegistry::permittedAt('header_trust', 'organisation')::type(),
        );
    }

    public function test_it_maps_no_dashboard_roles(): void
    {
        $this->assertFalse(HeaderTrustDriver::mayMapDashboardRoles());
    }

    // ------------------------------------------------ configuration refusals

    public function test_it_needs_a_known_subject_format(): void
    {
        foreach ([null, '', 'anything', 'uuid', 42] as $format) {
            try {
                (new HeaderTrustDriver)->validate(['subject_format' => $format]);
                $this->fail('accepted '.json_encode($format));
            } catch (BindingRefused $refused) {
                $this->assertSame(BindingRejection::ConfigInvalid, $refused->rejection);
            }
        }
    }

    /**
     * 🛑 A suffix on an opaque subject is **refused**, not ignored.
     *
     * An opaque subject has no parts to match, so the rule could never fire.
     * Dropping it silently would leave the operator believing they had narrowed
     * access — which is the exact failure mode this driver is written against.
     */
    public function test_a_suffix_on_an_opaque_subject_is_refused(): void
    {
        try {
            (new HeaderTrustDriver)->validate([
                'subject_format' => 'opaque',
                'subject_suffix' => '@example.com',
            ]);
            $this->fail('an unmatchable suffix was accepted');
        } catch (BindingRefused $refused) {
            $this->assertStringContainsString('no parts to match', $refused->getMessage());
        }
    }

    /** The stored form and the compared form are the same string. */
    public function test_a_suffix_is_stored_lower_cased(): void
    {
        $this->assertSame(
            ['subject_format' => 'email', 'subject_suffix' => '@example.com'],
            (new HeaderTrustDriver)->validate([
                'subject_format' => 'email',
                'subject_suffix' => '  @EXAMPLE.com ',
            ]),
        );
    }

    // --------------------------------------------------------------- the probe

    /**
     * 🛑 `*` and `private` are refused: an identity trusted by the *shape* of
     * the peer is one anybody of that shape can assert.
     */
    public function test_the_probe_fails_unless_the_terminator_is_pinned_by_address(): void
    {
        foreach (['', '*', 'private'] as $loose) {
            Config::set('docup.edge.trusted_proxies', $loose);

            $this->assertFalse(
                (new HeaderTrustDriver)->probe($this->binding())->passed,
                'the probe passed with trusted_proxies = '.json_encode($loose),
            );
        }
    }

    public function test_the_probe_fails_without_a_subject_header(): void
    {
        Config::set('docup.auth.asserted_identity.subject_header', '');

        $this->assertFalse((new HeaderTrustDriver)->probe($this->binding())->passed);
    }

    /** 🛑 §8.9.4's class: a header that names a host never names a reader. */
    public function test_the_probe_fails_on_a_header_name_docup_will_not_read(): void
    {
        foreach (['Host', 'X-Forwarded-Host', 'X-Original-Host', 'X-Forwarded-For', 'Cookie'] as $name) {
            Config::set('docup.auth.asserted_identity.subject_header', $name);

            $this->assertFalse(
                (new HeaderTrustDriver)->probe($this->binding())->passed,
                $name.' was accepted as a subject header',
            );
        }
    }

    /** 🛑 No shared-secret header, no activation. See the class note. */
    public function test_the_probe_fails_without_a_secret_header(): void
    {
        Config::set('docup.auth.asserted_identity.secret_header', '');

        $result = (new HeaderTrustDriver)->probe($this->binding());

        $this->assertFalse($result->passed);

        /*
         * The summary has to name the thing to set AND why, because an
         * operator who only reads "set this header" will set it to a constant
         * and believe they are done.
         */
        $this->assertStringContainsString('DOCUP_ASSERTED_SECRET_HEADER', $result->summary);
        $this->assertStringContainsString('passes an unauthenticated reader', $result->summary);
    }

    /** And no secret **on the binding** either. */
    public function test_the_probe_fails_without_a_secret_on_the_binding(): void
    {
        $result = (new HeaderTrustDriver)->probe($this->binding(secret: null));

        $this->assertFalse($result->passed);
        $this->assertStringContainsString('assertion_secret', $result->summary);
    }

    public function test_the_probe_passes_on_a_configured_installation(): void
    {
        $result = (new HeaderTrustDriver)->probe($this->binding());

        $this->assertTrue($result->passed);
        $this->assertStringContainsString(self::SUBJECT_HEADER, $result->summary);
    }

    // ------------------------------------------------------------- the attempt

    /**
     * 🛑 **The curl.** A subject header from the proxy, with no shared secret,
     * authenticates nobody.
     *
     * This is the whole reason the secret is mandatory. The peer is trusted —
     * it is the terminator — and the header names a reader. Without the
     * secret, every homegrown version of this driver admits that request.
     *
     * 🛑 **The asserted subject has to satisfy every other check**, and the
     * first version of this test did not notice that it did not. It sent
     * `admin` against a binding whose `subject_format` is `email`, so the
     * refusal came from the *shape* test and the secret was never what stopped
     * it: removing the secret requirement entirely left this test passing.
     * Found by planting exactly that bug — which is the only way to tell a
     * test that holds from a test that cannot fail.
     */
    public function test_the_subject_header_alone_authenticates_nobody(): void
    {
        $result = $this->drive([self::SUBJECT_HEADER => 'admin@example.com']);

        $this->assertFalse($result->satisfied);
        $this->assertFalse($result->credentialRejected);

        /*
         * And the control: the same request with the secret IS satisfied, so
         * the assertion above is about the secret and about nothing else.
         */
        $this->assertTrue($this->drive([
            self::SUBJECT_HEADER => 'admin@example.com',
            self::SECRET_HEADER => self::SECRET,
        ])->satisfied);
    }

    public function test_a_vouched_assertion_satisfies_the_binding(): void
    {
        $result = $this->drive([
            self::SUBJECT_HEADER => 'alice',
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'username']);

        $this->assertTrue($result->satisfied);
        $this->assertNotNull($result->subject);
    }

    public function test_a_wrong_secret_authenticates_nobody(): void
    {
        foreach (['', 'wrong', self::SECRET.'x', substr(self::SECRET, 0, -1)] as $guess) {
            $result = $this->drive([
                self::SUBJECT_HEADER => 'alice',
                self::SECRET_HEADER => $guess,
            ], config: ['subject_format' => 'username']);

            $this->assertFalse($result->satisfied, json_encode($guess).' was accepted as the secret');
        }
    }

    /** 🛑 An untrusted peer asserts nothing, secret or not. */
    public function test_an_untrusted_peer_asserts_nothing(): void
    {
        $result = $this->drive([
            self::SUBJECT_HEADER => 'alice',
            self::SECRET_HEADER => self::SECRET,
        ], peer: '198.51.100.7', config: ['subject_format' => 'username']);

        $this->assertFalse($result->satisfied);
    }

    /**
     * 🛑 A duplicated header is refused outright — both the subject and the
     * secret.
     *
     * `header_up +X-Foo` appends, and a terminator that sets the header only
     * for an authenticated reader passes a client's own value through. Taking
     * the first of two is choosing between the operator and an attacker on the
     * strength of whichever proxy ordered them.
     */
    public function test_a_duplicated_header_is_refused_outright(): void
    {
        /* The attacker appends their own subject to the terminator's. */
        $this->assertFalse($this->drive([
            self::SUBJECT_HEADER => ['alice', 'admin'],
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'username'])->satisfied);

        /* And appends a guessed secret to the terminator's real one. */
        $this->assertFalse($this->drive([
            self::SUBJECT_HEADER => 'admin',
            self::SECRET_HEADER => [self::SECRET, 'guess'],
        ], config: ['subject_format' => 'username'])->satisfied);
    }

    /**
     * The declared shape is enforced, and the value of that is entirely in the
     * day it stops being true.
     *
     * A proxy upgrade that starts sending a display name, a group, or `-` fails
     * closed here instead of authenticating a reader called `-`.
     */
    public function test_the_declared_subject_shape_is_enforced(): void
    {
        $cases = [
            ['email', 'alice@example.com', true],
            ['email', 'alice', false],
            ['email', 'alice@example', false],
            ['email', 'alice@@example.com', false],
            ['email', 'ali ce@example.com', false],
            ['email', '-', false],
            ['username', 'alice', true],
            ['username', 'alice.b_1-x', true],
            ['username', 'alice@example.com', false],
            ['username', '-', false],
            ['username', '.hidden', false],
            ['opaque', 'S-1-5-21-1004336348', true],
            ['opaque', 'anything/printable?yes', true],
            ['opaque', "has\tcontrol", false],
            ['opaque', 'has space', false],
        ];

        foreach ($cases as [$format, $subject, $expected]) {
            $result = $this->drive([
                self::SUBJECT_HEADER => $subject,
                self::SECRET_HEADER => self::SECRET,
            ], config: ['subject_format' => $format]);

            $this->assertSame(
                $expected,
                $result->satisfied,
                $format.' / '.json_encode($subject).' was '.($result->satisfied ? 'accepted' : 'refused'),
            );
        }
    }

    public function test_a_subject_over_the_ceiling_is_refused(): void
    {
        $this->assertFalse($this->drive([
            self::SUBJECT_HEADER => str_repeat('a', 300).'@example.com',
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'email'])->satisfied);
    }

    public function test_a_subject_suffix_narrows_the_audience(): void
    {
        $this->assertTrue($this->drive([
            self::SUBJECT_HEADER => 'alice@Example.COM',
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'email', 'subject_suffix' => '@example.com'])->satisfied);

        $this->assertFalse($this->drive([
            self::SUBJECT_HEADER => 'alice@elsewhere.test',
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'email', 'subject_suffix' => '@example.com'])->satisfied);
    }

    /**
     * 🛑 **This driver never rejects a credential, for any input in this
     * suite.**
     *
     * §8.12.23 permits a 401 when "a credential was presented and rejected",
     * and the reader did not present this — the terminator manufactured it. The
     * consequence of getting it wrong is quiet and large: a terminator forwards
     * the header on every request, so one `rejected()` would turn every private
     * 404 on the installation into a 401 and make the existence of every
     * private project observable.
     */
    public function test_it_never_rejects_a_credential(): void
    {
        $hostile = [
            [],
            [self::SUBJECT_HEADER => 'admin'],
            [self::SUBJECT_HEADER => ''],
            [self::SUBJECT_HEADER => '-'],
            [self::SUBJECT_HEADER => 'admin', self::SECRET_HEADER => 'wrong'],
            [self::SUBJECT_HEADER => ['a', 'b'], self::SECRET_HEADER => self::SECRET],
            [self::SECRET_HEADER => self::SECRET],
            [self::SUBJECT_HEADER => str_repeat('a', 5000), self::SECRET_HEADER => self::SECRET],
            [self::SUBJECT_HEADER => "alice\r\nX-Injected: 1", self::SECRET_HEADER => self::SECRET],
        ];

        foreach ($hostile as $index => $headers) {
            foreach (['email', 'username', 'opaque'] as $format) {
                $result = $this->drive($headers, config: ['subject_format' => $format]);

                $this->assertFalse(
                    $result->credentialRejected,
                    '🛑 case '.$index.' / '.$format.' challenged the reader, which leaks existence',
                );
            }
        }
    }

    /**
     * 🛑 The subject never leaves the driver as an email address.
     *
     * §8.12.1 forbids email "for linking or lookup", and an
     * {@see AttemptResult}'s subject travels into the reader's grant cookie — a
     * cookie is both.
     */
    public function test_the_subject_never_leaves_the_driver_as_an_email(): void
    {
        $result = $this->drive([
            self::SUBJECT_HEADER => 'alice@example.com',
            self::SECRET_HEADER => self::SECRET,
        ], config: ['subject_format' => 'email']);

        $this->assertTrue($result->satisfied);
        $this->assertNotNull($result->subject);
        $this->assertStringNotContainsString('alice', $result->subject);
        $this->assertStringNotContainsString('@', $result->subject);
        $this->assertStringStartsWith('header:', $result->subject);
    }

    /**
     * 🛑 Two bindings over the same terminator do not share a subject.
     *
     * {@see ReaderSubject} mixes the binding id
     * into the digest "so a join across two organisations' identity tables
     * would [not] reveal that one person reads both", and this is that property
     * reaching the driver.
     */
    public function test_the_same_reader_digests_differently_per_binding(): void
    {
        $headers = [
            self::SUBJECT_HEADER => 'alice@example.com',
            self::SECRET_HEADER => self::SECRET,
        ];

        $one = $this->drive($headers, config: ['subject_format' => 'email']);
        $two = $this->drive($headers, config: ['subject_format' => 'email'], bindingId: "\x7f");

        $this->assertTrue($one->satisfied);
        $this->assertTrue($two->satisfied);
        $this->assertNotSame($one->subject, $two->subject);
    }

    // ------------------------------------------------------------- fixtures

    /**
     * @param  array<string, string|list<string>>  $headers
     * @param  array<string, mixed>  $config
     */
    private function drive(
        array $headers,
        string $peer = self::PROXY,
        array $config = [],
        string $bindingId = "\x2a",
    ): AttemptResult {
        $request = Request::create('https://docs.example.test/x', 'GET', [], [], [], [
            'REMOTE_ADDR' => $peer,
        ]);

        foreach ($headers as $name => $value) {
            foreach (is_array($value) ? $value : [$value] as $index => $one) {
                /* `false` appends, which is how a duplicated header is built. */
                $request->headers->set($name, $one, $index === 0);
            }
        }

        (new TrustEdgeProxies)->handle($request, static fn (): Response => new Response);

        return (new HeaderTrustDriver)->attempt(
            $this->binding($config, bindingId: $bindingId),
            new ReaderPresentation(edge: EdgeAssertion::from($request)),
        );
    }

    /** @param  array<string, mixed>  $overrides */
    private function binding(
        array $overrides = [],
        ?string $secret = self::SECRET,
        string $bindingId = "\x2a",
    ): BindingContext {
        return new BindingContext(
            id: str_repeat($bindingId, 16),
            type: 'header_trust',
            name: 'Corporate SSO proxy',
            config: array_merge(['subject_format' => 'email'], $overrides),
            secrets: $secret === null ? [] : ['assertion_secret' => new SecretString($secret)],
            state: BindingState::Active,
        );
    }

    /**
     * @param  'installation'|'organisation'|'project'  $scope  🛑 the literal
     *                                                          union
     *                                                          {@see DriverRegistry::permittedAt()}
     *                                                          declares. A bare
     *                                                          `string` here
     *                                                          widens it at the
     *                                                          one call site
     *                                                          that must not,
     *                                                          and level 8 says
     *                                                          so.
     */
    private function refusedAt(string $scope, BindingRejection $expected): void
    {
        try {
            DriverRegistry::permittedAt('header_trust', $scope);
            $this->fail('header_trust was permitted at '.$scope);
        } catch (BindingRefused $refused) {
            $this->assertSame($expected, $refused->rejection);
        }
    }
}
