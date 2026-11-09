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
use App\Auth\Providers\EdgeAssertion;
use App\Auth\Providers\Federation\ReaderSubject;
use App\Auth\Providers\Mtls\MtlsRejection;
use App\Auth\Providers\ProbeResult;
use App\Auth\Providers\ReaderPresentation;

/**
 * 🛑 §8.12.17's `header_trust`: an identity the TLS terminator asserts in a
 * header. The only driver in the table whose identity column reads **"yes, by
 * assertion"**, and the only one marked **"off by default"**.
 *
 * Both of those are the specification being honest rather than cautious. This
 * driver's identity is exactly as good as the terminator's configuration, and
 * nothing DocUp does can make it better. What DocUp *can* do is refuse to
 * believe an assertion that is cheap to forge, and that is what this class is.
 *
 * ## 🛑 The attack this driver exists to survive
 *
 * An operator puts oauth2-proxy in front of DocUp and configures
 * `X-Auth-Request-User`. A naive driver reads that header. The attack is one
 * curl:
 *
 * ```
 * curl https://docs.example.com/private/ -H 'X-Auth-Request-User: admin'
 * ```
 *
 * It works whenever the terminator **sets the header only for an
 * authenticated reader** — which is oauth2-proxy's default — because an
 * unauthenticated request's header is passed through untouched. Trusting the
 * peer address does not help: the peer *is* the proxy. This is not a corner
 * case; it is the documented default behaviour of the most common deployment.
 *
 * So four things must all hold before this driver is satisfied, and every one
 * of them has killed a real deployment of somebody's homegrown version:
 *
 * 1. 🛑 **The hop is pinned by address.** `*` and `private` are refused —
 *    see {@see EdgeAssertion::terminatorIsPinned()}. An identity trusted by
 *    the *shape* of the peer is one anybody of that shape can assert.
 * 2. 🛑 **The header arrived exactly once.** Two values mean the terminator
 *    appended rather than replaced, so one of them is the client's.
 *    {@see EdgeAssertion} refuses both rather than choosing.
 * 3. 🛑 **A shared secret accompanies it**, in a second header, matched
 *    against this binding's sealed `assertion_secret`. A pass-through header
 *    cannot carry it, because the value exists only in the terminator's own
 *    configuration and in this binding's envelope-encrypted secret. This is
 *    the defence that closes the curl above, and it is **mandatory**: the
 *    probe fails without it and {@see self::attempt()} is never satisfied
 *    without it.
 * 4. **The subject has the shape the operator declared.** A terminator that
 *    starts sending a group name, a literal `-`, or an empty-but-present
 *    value fails closed instead of authenticating a reader called `-`.
 *
 * ## 🛑 This driver never rejects a credential, ever
 *
 * Every refusal is {@see AttemptResult::unsatisfied()} and none is
 * {@see AttemptResult::rejected()}. §8.12.23 permits a 401 when "a credential
 * was presented and rejected", and **the reader did not present this**. The
 * terminator manufactured it from a session the reader holds somewhere else.
 *
 * The consequence of getting this wrong would be severe and quiet: a
 * terminator forwards the header on every request, so one `rejected()` here
 * would turn every private 404 on the installation into a 401 and make the
 * existence of every private project observable to anybody. A test asserts the
 * property over every hostile input in the suite.
 *
 * ## Nothing here resolves a project
 *
 * §8.9.4 forbids any request header acting as a project, version or tenant
 * selector "in any environment". These headers name a *reader*;
 * {@see EdgeAssertion}'s denylist refuses every spelling of the host, and a
 * feature test configures the hostile name and proves the resolved project is
 * still the `Host`'s.
 */
final class HeaderTrustDriver implements AuthComponent
{
    /**
     * The shapes an asserted subject may have.
     *
     * 🛑 `opaque` is deliberately **not** "anything": it is printable
     * non-whitespace ASCII with a length bound. A format that accepted anything
     * would accept the empty-ish values a terminator emits when it has no
     * answer — `-` is Apache's and nginx's convention for "no value" in a log,
     * and more than one proxy copies that into a header.
     */
    private const array FORMATS = ['email', 'username', 'opaque'];

    /**
     * 🛑 A ceiling, applied to the asserted subject before anything else looks
     * at it.
     *
     * 320 is RFC 5321's maximum email address (64 local + @ + 255 domain), so
     * nothing legitimate is refused. Without a bound the ceiling would be the
     * terminator's header limit, which belongs to the operator's proxy and not
     * to DocUp — and the value reaches an HMAC and a log.
     */
    private const int MAX_SUBJECT = 320;

    public static function type(): string
    {
        return 'header_trust';
    }

    public static function leaf(): AccessLeaf
    {
        return AccessLeaf::Binding;
    }

    /**
     * 🛑 §8.12.4: installation scope only, and here the requirement's second
     * clause is the operative one.
     *
     * > "they reach into the operator's internal network or depend on facts
     * > only the TLS terminator can establish, so project-scope configuration
     * > would convert tenant self-service into an SSRF or **header-spoofing
     * > primitive**."
     *
     * Header-spoofing is this driver by name. A project admin who could create
     * one would be declaring which header DocUp believes about identity —
     * which is the whole of the authentication decision, handed to a tenant.
     */
    public static function allowsProjectScope(): bool
    {
        return false;
    }

    /**
     * 🛑 No dashboard roles from an asserted header.
     *
     * `ldap` returns true because a directory group is a statement by a system
     * whose business is group membership. This is a string in a header whose
     * trustworthiness is already the weakest in §8.12.17's table; letting it
     * grant a dashboard role would make the terminator's configuration a
     * privilege-granting interface for the whole installation.
     */
    public static function mayMapDashboardRoles(): bool
    {
        return false;
    }

    /**
     * @param  array<string, mixed>  $config
     * @return array{subject_format: string, subject_suffix?: string}
     */
    public function validate(array $config): array
    {
        $format = $config['subject_format'] ?? null;

        if (! is_string($format) || ! in_array($format, self::FORMATS, true)) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                '`subject_format` must be one of: '.implode(', ', self::FORMATS),
            );
        }

        $normalised = ['subject_format' => $format];

        $suffix = $config['subject_suffix'] ?? null;

        if ($suffix !== null && $suffix !== '') {
            if (! is_string($suffix)) {
                throw BindingRefused::of(BindingRejection::ConfigInvalid, '`subject_suffix` must be a string');
            }

            if ($format === 'opaque') {
                /*
                 * 🛑 Refused rather than ignored. A suffix on an opaque subject
                 * is a rule the operator believes is narrowing access; silently
                 * dropping it would leave them believing it while it did
                 * nothing, which is the failure mode this whole driver is
                 * written against.
                 */
                throw BindingRefused::of(
                    BindingRejection::ConfigInvalid,
                    '`subject_suffix` needs a `subject_format` of `email` or `username`: '
                    .'an opaque subject has no parts to match',
                );
            }

            /* Stored lower-cased, because it is compared case-insensitively. */
            $normalised['subject_suffix'] = mb_strtolower(trim($suffix));
        }

        return $normalised;
    }

    /**
     * 🛑 §8.12.19's automated half, checking the **installation** rather than
     * the binding — and refusing four configurations that would each make this
     * driver forgeable.
     *
     * §8.12.19 forbids leaving `verifying` until a probe passes, which makes
     * this the right place for all four: the binding never activates, rather
     * than activating and believing a curl.
     */
    public function probe(BindingContext $binding): ProbeResult
    {
        if (! EdgeAssertion::terminatorIsPinned()) {
            return ProbeResult::fail(MtlsRejection::TerminatorNotPinned->explain());
        }

        $subjectHeader = config('docup.auth.asserted_identity.subject_header');

        if (! is_string($subjectHeader) || trim($subjectHeader) === '') {
            return ProbeResult::fail(
                'Set `DOCUP_ASSERTED_SUBJECT_HEADER` to the header the terminator asserts the '
                .'reader in. Nothing is read until you do.',
            );
        }

        if (! EdgeAssertion::mayRead($subjectHeader)) {
            return ProbeResult::fail(MtlsRejection::HeaderNotReadable->explain());
        }

        $secretHeader = config('docup.auth.asserted_identity.secret_header');

        if (! is_string($secretHeader) || ! EdgeAssertion::mayRead($secretHeader)) {
            return ProbeResult::fail(
                'No shared-secret header is configured, and without one this driver believes any '
                .'request from the proxy that carries the subject header — including one a client '
                .'sent, because a terminator that sets the header only for an authenticated '
                .'reader passes an unauthenticated reader\'s own header through untouched. Set '
                .'`DOCUP_ASSERTED_SECRET_HEADER` and have the terminator send this binding\'s '
                .'`assertion_secret` in it.',
            );
        }

        if (($binding->secret('assertion_secret') ?? '') === '') {
            return ProbeResult::fail(
                'This binding holds no `assertion_secret`. Generate one, seal it on the binding, '
                .'and set the same value at the terminator — it is the only thing distinguishing '
                .'the terminator\'s assertion from a client\'s copy of the same header.',
            );
        }

        return ProbeResult::pass(
            'reading '.trim($subjectHeader).' as '
            .($binding->string('subject_format') ?? '?')
            .', vouched by a shared secret in '.trim($secretHeader),
        );
    }

    /**
     * 🛑 Every path returns {@see AttemptResult::unsatisfied()} or a
     * satisfaction, and **never** {@see AttemptResult::rejected()}.
     *
     * See the class note: the reader presented nothing, so §8.12.23's case (a)
     * cannot apply, and a 401 here would be an existence oracle for every
     * private project on the installation.
     */
    public function attempt(BindingContext $binding, ReaderPresentation $presented): AttemptResult
    {
        $edge = $presented->edge;

        if ($edge === null || ! $edge->fromTrustedProxy) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 The shared secret first, before the subject is looked at at all.
         * It is the one check that distinguishes the terminator from a client,
         * so nothing should depend on a value that has not passed it yet — not
         * even a length test whose timing could confirm a guessed subject.
         */
        if (! $this->vouched($edge->assertionSecret, $binding)) {
            return AttemptResult::unsatisfied();
        }

        $subject = $edge->assertedSubject;
        $format = $binding->string('subject_format');

        if ($subject === null || $format === null || strlen($subject) > self::MAX_SUBJECT) {
            return AttemptResult::unsatisfied();
        }

        if (! self::hasShape($subject, $format)) {
            return AttemptResult::unsatisfied();
        }

        $suffix = $binding->string('subject_suffix');

        if ($suffix !== null && ! str_ends_with(mb_strtolower($subject), $suffix)) {
            return AttemptResult::unsatisfied();
        }

        /*
         * 🛑 Keyed-hashed **here**, in the driver, because `subject_format:
         * email` makes this an email address and an `AttemptResult`'s subject
         * travels into {@see \App\Access\ReaderContext} and from there into the
         * grant token in the reader's browser. §8.12.1 forbids email "for
         * linking or lookup" and a cookie is both.
         *
         * The same reasoning and the same call as {@see MtlsDriver::attempt()}.
         */
        return AttemptResult::satisfiedBy(
            AccessLeaf::Binding,
            subject: 'header:'.bin2hex(ReaderSubject::hash($binding->id, $subject)),
        );
    }

    /**
     * Whether the terminator's shared secret accompanied the assertion.
     *
     * 🛑 Mandatory, and absent configuration fails **closed**: a binding
     * activated before the secret header existed authenticates nobody rather
     * than everybody. `hash_equals` because this is a secret comparison and the
     * only thing standing between a header and an identity.
     */
    private function vouched(?string $presented, BindingContext $binding): bool
    {
        $header = config('docup.auth.asserted_identity.secret_header');

        if (! is_string($header) || ! EdgeAssertion::mayRead($header)) {
            return false;
        }

        $expected = $binding->secret('assertion_secret');

        if ($expected === null || $expected === '' || $presented === null) {
            return false;
        }

        return hash_equals($expected, $presented);
    }

    /**
     * Whether an asserted subject has the shape the operator declared.
     *
     * 🛑 Shape, not validity. None of these is an attempt to decide whether an
     * address could receive mail; they decide whether the terminator sent the
     * kind of thing the operator said it would. The value of that is entirely
     * in the day it stops being true — a proxy upgrade that starts sending a
     * display name, a group, or `-` — where this fails closed and an operator
     * reads the probe instead of discovering that a reader called `-` can read
     * everything.
     */
    private static function hasShape(string $subject, string $format): bool
    {
        return match ($format) {
            /*
             * One `@`, no whitespace, a dot in the domain. Deliberately
             * stricter than RFC 5321 — which permits quoted local parts with
             * spaces and `@` — because no identity provider emits one and
             * accepting them would admit a value containing a header
             * separator.
             */
            'email' => preg_match('/^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$/D', $subject) === 1,
            'username' => preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/D', $subject) === 1,
            'opaque' => preg_match('/^[\x21-\x7e]{1,'.self::MAX_SUBJECT.'}$/D', $subject) === 1,
            default => false,
        };
    }
}
