<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Saml;

use App\Auth\Providers\Saml\AssertionReplayCache;
use App\Auth\Providers\Saml\ResponseValidator;
use App\Auth\Providers\Saml\SamlRefused;
use App\Auth\Providers\Saml\SamlRejection;
use App\Auth\Providers\Saml\SignatureVerifier;
use Illuminate\Support\Facades\Cache;
use Tests\Support\HostileSamlResponses;
use Tests\TestCase;

/**
 * 🛑 §8.12.18's SAML clause, one test per requirement, and §17's seven named
 * refusals each with its own event.
 *
 * `SignatureVerifierTest` covers the two signature requirements and
 * `SafeXmlTest` covers entity expansion and comment truncation. This file
 * covers the rest: exactly one Assertion, `Destination`, `Audience`,
 * `NotOnOrAfter`, `InResponseTo`, the ≤120-second skew, the replay cache, the
 * encrypted-assertion refusal, and IdP-initiated being off.
 *
 * 🛑 The accepted case is asserted first, in `setUp`'s shape, because a
 * validator that refused everything would pass every hostile test here.
 */
final class ResponseValidatorTest extends TestCase
{
    private HostileSamlResponses $idp;

    private ResponseValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();

        $this->idp = new HostileSamlResponses;
        $this->validator = new ResponseValidator(new SignatureVerifier, new AssertionReplayCache);
    }

    // ------------------------------------------------- the case that works

    /** A correct response validates, and returns the subject it carries. */
    public function test_a_correct_response_validates(): void
    {
        $claims = $this->validate($this->idp->valid());

        $this->assertSame(HostileSamlResponses::SUBJECT, $claims['subject']);
        $this->assertSame('assertion-1', $claims['id']);
    }

    // --------------------------------------- §8.12.18, requirement by requirement

    /** 🛑 "exactly one Assertion" — two is an ambiguity an attacker chooses. */
    public function test_two_assertions_are_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::AssertionCountWrong,
            $this->idp->two_assertions(),
            '🛑 §8.12.18: exactly one Assertion; two forces a choice',
        );
    }

    /** 🛑 `Destination` must be this installation's ACS. */
    public function test_a_wrong_destination_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::DestinationMismatch,
            $this->idp->wrong_destination(),
            '🛑 §8.12.18: a response addressed elsewhere is a replay from elsewhere',
        );
    }

    /** 🛑 `Audience` must name this service provider. */
    public function test_a_wrong_audience_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::AudienceMismatch,
            $this->idp->wrong_audience(),
            '🛑 §8.12.18: an assertion for another SP is valid and not ours',
        );
    }

    /** 🛑 An expired `NotOnOrAfter`. */
    public function test_an_expired_assertion_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::ConditionsExpired,
            $this->idp->expired_notonorafter(),
            '🛑 §8.12.18: the validity window is verified',
        );
    }

    /**
     * 🛑 §8.12.18's "≤120 s skew", asserted at **both** edges.
     *
     * A ceiling only matters if something is on each side of it: 130 seconds
     * must fail and 60 must pass, or the test would hold for any tolerance at
     * all — including infinite.
     */
    public function test_the_skew_ceiling_holds_at_both_edges(): void
    {
        $this->assertRefusal(
            SamlRejection::ConditionsExpired,
            $this->idp->clock_skew_130s(),
            '🛑 §8.12.18: 130 seconds exceeds the 120-second ceiling',
        );

        /* And inside the ceiling it is accepted, or the ceiling is infinite. */
        $claims = $this->validate($this->idp->valid(now: time() + 60));

        $this->assertSame(HostileSamlResponses::SUBJECT, $claims['subject']);
    }

    /**
     * 🛑 §8.12.18's "IdP-initiated off by default", which is the same fact as a
     * missing `InResponseTo`.
     */
    public function test_an_idp_initiated_response_is_refused(): void
    {
        $document = $this->idp->idp_initiated();

        try {
            $this->validator->validate(
                xml: $document,
                certificate: $this->idp->certificate(),
                audience: HostileSamlResponses::AUDIENCE,
                destination: HostileSamlResponses::ACS,
                /* No request was sent, which is what IdP-initiated means. */
                inResponseTo: null,
            );
            $this->fail('an IdP-initiated response was accepted');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::InResponseToUnknown, $refused->rejection);
        }
    }

    /** And an `InResponseTo` naming a request DocUp did not send. */
    public function test_an_unknown_in_response_to_is_refused(): void
    {
        try {
            $this->validator->validate(
                xml: $this->idp->valid(),
                certificate: $this->idp->certificate(),
                audience: HostileSamlResponses::AUDIENCE,
                destination: HostileSamlResponses::ACS,
                inResponseTo: 'some-other-request',
            );
            $this->fail('a response to another request was accepted');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::InResponseToUnknown, $refused->rejection);
        }
    }

    /** 🛑 "encrypted-assertion-without-signature rejected". */
    public function test_an_encrypted_assertion_is_refused(): void
    {
        $this->assertRefusal(
            SamlRejection::EncryptedWithoutSignature,
            $this->idp->encrypted_unsigned(),
            '🛑 §8.12.18: encryption is not authentication',
        );
    }

    /** An identity provider that refused says so, and DocUp does not guess. */
    public function test_a_failed_status_is_refused(): void
    {
        $xml = str_replace(
            'urn:oasis:names:tc:SAML:2.0:status:Success',
            'urn:oasis:names:tc:SAML:2.0:status:Requester',
            $this->idp->valid(),
        );

        /*
         * 🛑 The status is checked **before** the signatures, so a provider's
         * own refusal does not present as a signature failure — changing the
         * status breaks the signature, and reporting that would send an
         * operator looking for an attack instead of a misconfiguration.
         */
        $this->assertRefusal(
            SamlRejection::StatusNotSuccess,
            $xml,
            '🛑 a provider refusal is its own event, not a signature failure',
        );
    }

    // ------------------------------------- §8.12.18's replay cache

    /**
     * 🛑 "assertion-id replay cache": the same assertion twice is refused.
     *
     * The first presentation must succeed, which is what makes this a replay
     * test rather than a rejection test.
     */
    public function test_a_replayed_assertion_is_refused(): void
    {
        $xml = $this->idp->replayed_assertion_id();

        $first = $this->validate($xml);

        $this->assertSame('assertion-replayed', $first['id']);

        $this->assertRefusal(
            SamlRejection::AssertionReplayed,
            $xml,
            '🛑 §8.12.18: an assertion travels through the browser, so one use is all it gets',
        );
    }

    /**
     * 🛑 And a response refused for any **other** reason does not consume the
     * id.
     *
     * The ordering requirement, asserted directly: the replay cache is written
     * last, so an attacker cannot burn a legitimate assertion's id by sending a
     * broken response that happens to carry it. Without this, a refusal would
     * be a denial of service against the reader it was aimed at.
     */
    public function test_a_refused_response_does_not_consume_the_assertion_id(): void
    {
        $audience = HostileSamlResponses::AUDIENCE;

        /* Refused on the audience, which is checked before the cache is written. */
        try {
            $this->validator->validate(
                xml: $this->idp->valid(assertionId: 'assertion-precious'),
                certificate: $this->idp->certificate(),
                audience: 'https://somebody-else.example.test/saml/metadata',
                destination: HostileSamlResponses::ACS,
                inResponseTo: 'docup-request-1',
            );
            $this->fail('a wrong audience was accepted');
        } catch (SamlRefused $refused) {
            $this->assertSame(SamlRejection::AudienceMismatch, $refused->rejection);
        }

        /*
         * 🛑 And the id is still fresh, so the reader's real login works. A
         * validator that wrote the cache before checking the audience would
         * fail here — with a replay refusal for an assertion never accepted.
         */
        $claims = $this->validate($this->idp->valid(assertionId: 'assertion-precious'));

        $this->assertSame('assertion-precious', $claims['id']);
        $this->assertSame($audience, HostileSamlResponses::AUDIENCE);
    }

    /**
     * 🛑 Two identity providers may legitimately issue the same assertion id.
     *
     * Ids are unique only within an issuer, so a cache keyed on the id alone
     * would let one provider's traffic refuse another's — a cross-tenant denial
     * of service through a namespace collision.
     */
    public function test_two_providers_may_use_the_same_assertion_id(): void
    {
        $other = new HostileSamlResponses;

        $this->validate($this->idp->valid(assertionId: 'shared-id'));

        $claims = $this->validator->validate(
            xml: $other->valid(assertionId: 'shared-id'),
            certificate: $other->certificate(),
            audience: HostileSamlResponses::AUDIENCE,
            destination: HostileSamlResponses::ACS,
            inResponseTo: 'docup-request-1',
        );

        $this->assertSame('shared-id', $claims['id']);
    }

    // ---------------------------------------------------------- fixtures

    /** @return array{id: string, subject: string, attributes: array<string, list<string>>} */
    private function validate(string $xml): array
    {
        return $this->validator->validate(
            xml: $xml,
            certificate: $this->idp->certificate(),
            audience: HostileSamlResponses::AUDIENCE,
            destination: HostileSamlResponses::ACS,
            inResponseTo: 'docup-request-1',
        );
    }

    private function assertRefusal(SamlRejection $expected, string $xml, string $because): void
    {
        try {
            $this->validate($xml);
            $this->fail($because.' — but it validated');
        } catch (SamlRefused $refused) {
            $this->assertSame($expected, $refused->rejection, $because);
        }
    }
}
