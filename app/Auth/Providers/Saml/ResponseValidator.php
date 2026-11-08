<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

/**
 * 🛑 §8.12.18's SAML clause, in one place and with nothing optional.
 *
 * > "**SAML:** signature required on Response **and** Assertion, exactly one
 * > Assertion, `Destination`/`Audience`/`NotOnOrAfter`/`InResponseTo`
 * > verified, ≤120 s skew, assertion-id replay cache,
 * > encrypted-assertion-without-signature rejected, XML entity expansion
 * > disabled, IdP-initiated off by default."
 *
 * Eleven requirements in one sentence, and the requirement *about* them is the
 * one that shapes this class: "Protocol validation MUST be
 * **framework-enforced, not driver-optional**."
 *
 * So, exactly as `App\Auth\Providers\Oidc\IdTokenVerifier` does for OIDC:
 * this class is `final`, its one public method takes every input it needs, and
 * there is no option bag, no `$strict` and no setter. A driver cannot choose
 * which checks run, so neither can a future driver written by somebody in a
 * hurry.
 *
 * ## 🛑 The order is load-bearing
 *
 * Cheapest-and-most-structural first, cryptography last but one, and state
 * last:
 *
 * 1. the document parses at all, with no DTD ({@see SafeXml});
 * 2. it is a `Response`, with `Success` status;
 * 3. **exactly one** Assertion, as a direct child;
 * 4. the Response's signature covers the Response;
 * 5. the Assertion's signature covers the Assertion;
 * 6. `Destination`, `InResponseTo`, `Audience`, the validity window;
 * 7. the assertion id has not been seen before.
 *
 * Why this order and not another: (3) before (4) because "which element is
 * signed" is meaningless until there is one answer to "which element"; (4) and
 * (5) before (6) because every value read in (6) is only worth reading once
 * signed; and (7) last because it is the only step that **writes**, so a
 * response refused for any other reason must not consume a replay-cache entry
 * — otherwise a malformed response could burn a legitimate assertion's id.
 */
final readonly class ResponseValidator
{
    /**
     * 🛑 §8.12.18's skew ceiling, quoted exactly: "≤120 s skew".
     *
     * Unlike OIDC's — where §8.12.18 says nothing and
     * `IdTokenVerifier::LEEWAY_SECONDS` is a
     * decision — this number is the specification's. It is a *ceiling*, so a
     * smaller value would comply and a larger one would not.
     */
    public const int MAX_SKEW_SECONDS = 120;

    public function __construct(
        private SignatureVerifier $signatures,
        private AssertionReplayCache $replays,
    ) {}

    /**
     * Validate a SAML response and return the assertion's verified claims.
     *
     * @param  string  $xml  the raw response, already base64-decoded
     * @param  string  $certificate  PEM, from the binding's sealed config
     * @param  string  $issuer  the binding's configured `idp_entity_id`
     * @param  string  $audience  this installation's SAML entity id
     * @param  string  $destination  this installation's ACS URL
     * @param  string|null  $inResponseTo  the request id DocUp sent, or null —
     *                                     which §8.12.18 refuses, because
     *                                     IdP-initiated is off by default
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return array{id: string, subject: string, attributes: array<string, list<string>>}
     *
     * @throws SamlRefused
     */
    public function validate(
        string $xml,
        string $certificate,
        string $issuer,
        string $audience,
        string $destination,
        ?string $inResponseTo,
        ?int $now = null,
    ): array {
        $now ??= time();

        if ($certificate === '') {
            throw SamlRefused::of(SamlRejection::ConfigInvalid, 'the binding has no signing certificate');
        }

        /* 1. The parse, which is where §17's XXE proof lives. */
        $document = SafeXml::parse($xml);

        $response = $document->documentElement;

        if ($response === null
            || $response->localName !== 'Response'
            || $response->namespaceURI !== SamlNamespaces::PROTOCOL) {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the document is not a SAML Response');
        }

        /* 2. `Status`, before anything expensive. A refusal is not an attack. */
        $this->assertSuccess($response);

        /*
         * 3. 🛑 **Exactly one Assertion**, and an `EncryptedAssertion` refused
         * before it is counted — §8.12.18 names both.
         */
        $assertion = $this->theOneAssertion($response);

        /* 4 and 5. 🛑 Both signatures, which is §8.12.18's "**and**". */
        $this->signatures->assertCovers($response, $certificate);
        $this->signatures->assertCovers($assertion, $certificate);

        /*
         * 6. Everything the signatures now make worth reading — and nothing
         * before them, which is the ordering §8.12.18 is really about.
         */
        $this->assertIssuer($response, $assertion, $issuer);
        $this->assertDestination($response, $destination);
        $this->assertInResponseTo($response, $assertion, $inResponseTo);
        $this->assertAudience($assertion, $audience);
        $this->assertWindow($assertion, $now);

        $subject = $this->subject($assertion);
        $id = $assertion->getAttribute('ID');

        if ($id === '') {
            throw SamlRefused::of(SamlRejection::ResponseMalformed, 'the assertion carries no ID');
        }

        /*
         * 7. 🛑 **Last, because it writes.** A response refused above must not
         * consume a replay-cache entry: an attacker who could make DocUp
         * remember an id it never accepted would have a way to lock a
         * legitimate reader out of their own login.
         */
        $this->replays->remember($id, $certificate, $this->windowEnd($assertion, $now));

        return [
            'id' => $id,
            'subject' => $subject,
            'attributes' => $this->attributes($assertion),
        ];
    }

    /**
     * 🛑 §8.12.18's issuer check, on the Response **and** the Assertion.
     *
     * Both, because they are separately signed and therefore separately
     * forgeable: a Response issued by the configured provider may carry an
     * Assertion issued by another, and an SP that checked only the outer
     * element would trust the inner one's claims. The same argument that makes
     * the *signature* requirement read "Response **and** Assertion".
     *
     * 🛑 Required on the Assertion and tolerated-if-absent on the Response:
     * SAML Core §3.2.2 makes `<Issuer>` optional on a Response and mandatory on
     * an Assertion, so demanding it on both would refuse conforming providers.
     * What is *not* tolerated is a present-and-wrong one.
     *
     * @throws SamlRefused
     */
    private function assertIssuer(\DOMElement $response, \DOMElement $assertion, string $expected): void
    {
        if ($expected === '') {
            throw SamlRefused::of(SamlRejection::ConfigInvalid, 'the binding names no identity provider');
        }

        $outer = SafeXml::child($response, SamlNamespaces::ASSERTION, 'Issuer');

        if ($outer !== null && ! hash_equals($expected, SafeXml::text($outer))) {
            throw SamlRefused::of(
                SamlRejection::IssuerMismatch,
                'the response names an identity provider this binding is not configured for',
            );
        }

        $inner = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Issuer');

        if ($inner === null || ! hash_equals($expected, SafeXml::text($inner))) {
            throw SamlRefused::of(
                SamlRejection::IssuerMismatch,
                'the assertion names an identity provider this binding is not configured for',
            );
        }
    }

    /** @throws SamlRefused */
    private function assertSuccess(\DOMElement $response): void
    {
        $status = SafeXml::child($response, SamlNamespaces::PROTOCOL, 'Status');
        $code = $status === null ? null : SafeXml::child($status, SamlNamespaces::PROTOCOL, 'StatusCode');
        $value = $code?->getAttribute('Value') ?? '';

        if ($value !== 'urn:oasis:names:tc:SAML:2.0:status:Success') {
            /*
             * 🛑 The provider's `StatusMessage` is **not** included. §8.22.5
             * keeps free text out of the audit chain and that message is free
             * text somebody else wrote; the status URI is a fixed vocabulary
             * and says enough.
             */
            throw SamlRefused::of(
                SamlRejection::StatusNotSuccess,
                'the identity provider refused with status `'.($value === '' ? 'absent' : $value).'`',
            );
        }
    }

    /**
     * 🛑 Exactly one Assertion, as a **direct child**, and no encrypted one.
     *
     * @throws SamlRefused
     */
    private function theOneAssertion(\DOMElement $response): \DOMElement
    {
        /*
         * 🛑 §8.12.18: "encrypted-assertion-without-signature rejected", and
         * checked **first** so the refusal happens before any decryption is
         * contemplated. DocUp does not implement assertion decryption at all,
         * so an `EncryptedAssertion` is refused outright — which is the
         * stronger reading and leaves nothing to get wrong later.
         */
        $encrypted = SafeXml::children($response, SamlNamespaces::ASSERTION, 'EncryptedAssertion');

        if ($encrypted !== []) {
            throw SamlRefused::of(
                SamlRejection::EncryptedWithoutSignature,
                'an encrypted assertion cannot carry a signature DocUp can check before decrypting it',
            );
        }

        $assertions = SafeXml::children($response, SamlNamespaces::ASSERTION, 'Assertion');

        if (count($assertions) !== 1) {
            /*
             * 🛑 The ambiguity *is* the attack. A response with two assertions
             * forces the service provider to pick one, and an attacker who can
             * add the second gets to influence which — so "exactly one" is a
             * structural requirement rather than a tidiness one.
             */
            throw SamlRefused::of(
                SamlRejection::AssertionCountWrong,
                'the response carries '.count($assertions).' assertions; exactly one is permitted',
            );
        }

        return $assertions[0];
    }

    /** @throws SamlRefused */
    private function assertDestination(\DOMElement $response, string $destination): void
    {
        $actual = $response->getAttribute('Destination');

        /*
         * 🛑 Required, not optional. The SAML schema makes `Destination`
         * optional on a Response, and omitting the check is how a response
         * captured at one service provider is replayed at another. DocUp always
         * sends an `AssertionConsumerServiceURL`, so a provider answering
         * without a `Destination` is one DocUp cannot bind the response to.
         */
        if ($actual === '' || ! hash_equals($destination, $actual)) {
            throw SamlRefused::of(
                SamlRejection::DestinationMismatch,
                'the response is addressed to `'.($actual === '' ? 'nothing' : $actual).'`',
            );
        }
    }

    /**
     * 🛑 §8.12.18's `InResponseTo`, which is also how IdP-initiated is refused.
     *
     * > "IdP-initiated off by default."
     *
     * An IdP-initiated response carries no `InResponseTo` at all, so there is
     * no separate check and no separate flag: both facts are "DocUp did not ask
     * for this". The pairing is deliberate — a flag would be a thing to turn
     * on, and §8.12.18 says off by default without saying there is a switch.
     *
     * @throws SamlRefused
     */
    private function assertInResponseTo(\DOMElement $response, \DOMElement $assertion, ?string $expected): void
    {
        $actual = $response->getAttribute('InResponseTo');

        if ($expected === null) {
            throw SamlRefused::of(
                SamlRejection::InResponseToUnknown,
                $actual === ''
                    ? 'the response is IdP-initiated, which §8.12.18 refuses by default'
                    : 'the response answers a request DocUp has no record of',
            );
        }

        if ($actual === '' || ! hash_equals($expected, $actual)) {
            throw SamlRefused::of(
                SamlRejection::InResponseToUnknown,
                'the response answers `'.($actual === '' ? 'nothing' : $actual).'`',
            );
        }

        /*
         * 🛑 And on the `SubjectConfirmationData` too, which is where SAML
         * actually binds the assertion to the request. Checking only the
         * Response leaves an assertion that could be moved into another
         * response wholesale — and the Response's own signature would not
         * notice, because it would be re-signed by whoever moved it.
         */
        $subject = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Subject');
        $confirmation = $subject === null
            ? null
            : SafeXml::child($subject, SamlNamespaces::ASSERTION, 'SubjectConfirmation');
        $data = $confirmation === null
            ? null
            : SafeXml::child($confirmation, SamlNamespaces::ASSERTION, 'SubjectConfirmationData');

        if ($confirmation === null || $data === null) {
            throw SamlRefused::of(
                SamlRejection::SubjectConfirmationInvalid,
                'the assertion carries no subject confirmation',
            );
        }

        if ($confirmation->getAttribute('Method') !== 'urn:oasis:names:tc:SAML:2.0:cm:bearer') {
            throw SamlRefused::of(
                SamlRejection::SubjectConfirmationInvalid,
                'the subject confirmation is not `bearer`',
            );
        }

        $confirmed = $data->getAttribute('InResponseTo');

        if ($confirmed === '' || ! hash_equals($expected, $confirmed)) {
            throw SamlRefused::of(
                SamlRejection::SubjectConfirmationInvalid,
                'the subject confirmation answers a different request',
            );
        }
    }

    /** @throws SamlRefused */
    private function assertAudience(\DOMElement $assertion, string $audience): void
    {
        $conditions = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Conditions');

        if ($conditions === null) {
            throw SamlRefused::of(SamlRejection::AudienceMismatch, 'the assertion carries no conditions');
        }

        $restrictions = SafeXml::children($conditions, SamlNamespaces::ASSERTION, 'AudienceRestriction');

        if ($restrictions === []) {
            throw SamlRefused::of(
                SamlRejection::AudienceMismatch,
                'the assertion restricts no audience, so it is for anybody',
            );
        }

        /*
         * 🛑 **Every** restriction must admit DocUp, not any one of them. SAML
         * Core §2.5.1.4 makes multiple `AudienceRestriction` elements a
         * conjunction — each is a separate condition — so a reader admitted by
         * one while another excluded them would be admitted against the
         * identity provider's stated intent.
         */
        foreach ($restrictions as $restriction) {
            $found = false;

            foreach (SafeXml::children($restriction, SamlNamespaces::ASSERTION, 'Audience') as $candidate) {
                if (hash_equals($audience, SafeXml::text($candidate))) {
                    $found = true;
                    break;
                }
            }

            if (! $found) {
                throw SamlRefused::of(
                    SamlRejection::AudienceMismatch,
                    'an audience restriction does not name this service provider',
                );
            }
        }
    }

    /**
     * 🛑 §8.12.18's validity window, with the ≤120-second skew.
     *
     * Both ends, and both required. `NotOnOrAfter` absent would mean an
     * assertion that never expires, which is a bearer credential with no
     * lifetime — so its absence is a refusal rather than a default.
     *
     * @throws SamlRefused
     */
    private function assertWindow(\DOMElement $assertion, int $now): void
    {
        $conditions = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Conditions');

        if ($conditions === null) {
            throw SamlRefused::of(SamlRejection::ConditionsExpired, 'the assertion carries no conditions');
        }

        $notBefore = self::instant($conditions->getAttribute('NotBefore'));
        $notOnOrAfter = self::instant($conditions->getAttribute('NotOnOrAfter'));

        if ($notOnOrAfter === null) {
            throw SamlRefused::of(
                SamlRejection::ConditionsExpired,
                'the assertion has no `NotOnOrAfter`, so it would never expire',
            );
        }

        if ($now >= $notOnOrAfter + self::MAX_SKEW_SECONDS) {
            throw SamlRefused::of(SamlRejection::ConditionsExpired, 'the assertion has expired');
        }

        if ($notBefore !== null && $now < $notBefore - self::MAX_SKEW_SECONDS) {
            throw SamlRefused::of(SamlRejection::ConditionsExpired, 'the assertion is not yet valid');
        }

        /*
         * 🛑 And the `SubjectConfirmationData`'s own `NotOnOrAfter`, which is a
         * separate and usually shorter window. SAML Core §2.4.1.2 makes it the
         * bearer's lifetime; ignoring it means honouring a confirmation the
         * identity provider expired on purpose.
         */
        $subject = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Subject');
        $confirmation = $subject === null
            ? null
            : SafeXml::child($subject, SamlNamespaces::ASSERTION, 'SubjectConfirmation');
        $data = $confirmation === null
            ? null
            : SafeXml::child($confirmation, SamlNamespaces::ASSERTION, 'SubjectConfirmationData');

        if ($data !== null) {
            $bearerEnd = self::instant($data->getAttribute('NotOnOrAfter'));

            if ($bearerEnd !== null && $now >= $bearerEnd + self::MAX_SKEW_SECONDS) {
                throw SamlRefused::of(
                    SamlRejection::ConditionsExpired,
                    'the subject confirmation has expired',
                );
            }
        }
    }

    /** When the replay cache may forget this assertion. */
    private function windowEnd(\DOMElement $assertion, int $now): int
    {
        $conditions = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Conditions');
        $end = $conditions === null ? null : self::instant($conditions->getAttribute('NotOnOrAfter'));

        /*
         * 🛑 Plus the skew, because an assertion is replayable for exactly as
         * long as it would still be accepted — and `assertWindow()` accepts up
         * to `NotOnOrAfter` + skew. A cache that forgot a moment earlier would
         * leave a window in which a replay succeeded.
         */
        return ($end ?? $now) + self::MAX_SKEW_SECONDS;
    }

    /** @throws SamlRefused */
    private function subject(\DOMElement $assertion): string
    {
        $subject = SafeXml::child($assertion, SamlNamespaces::ASSERTION, 'Subject');
        $nameId = $subject === null ? null : SafeXml::child($subject, SamlNamespaces::ASSERTION, 'NameID');

        if ($nameId === null) {
            throw SamlRefused::of(SamlRejection::SubjectMissing, 'the assertion carries no NameID');
        }

        /*
         * 🛑 Read through `SafeXml::text()`, which refuses a value containing a
         * comment — CVE-2017-11427's family. This is the one place in the SAML
         * path where that matters most: the `NameID` *is* the identity.
         */
        $value = SafeXml::text($nameId);

        if ($value === '') {
            throw SamlRefused::of(SamlRejection::SubjectMissing, 'the assertion carries an empty NameID');
        }

        return $value;
    }

    /**
     * The assertion's attributes, for group mapping.
     *
     * 🛑 Every value read through `SafeXml::text()`, so a comment anywhere in
     * an attribute is refused too — not only in the `NameID`. An attribute
     * decides group membership, and group membership decides access.
     *
     * @return array<string, list<string>>
     *
     * @throws SamlRefused
     */
    private function attributes(\DOMElement $assertion): array
    {
        $out = [];

        foreach (SafeXml::children($assertion, SamlNamespaces::ASSERTION, 'AttributeStatement') as $statement) {
            foreach (SafeXml::children($statement, SamlNamespaces::ASSERTION, 'Attribute') as $attribute) {
                $name = $attribute->getAttribute('Name');

                if ($name === '' || mb_strlen($name) > 255) {
                    continue;
                }

                foreach (SafeXml::children($attribute, SamlNamespaces::ASSERTION, 'AttributeValue') as $value) {
                    $text = SafeXml::text($value);

                    if ($text !== '' && mb_strlen($text) <= 255) {
                        $out[$name][] = $text;
                    }
                }
            }
        }

        return $out;
    }

    /**
     * A SAML instant as unix seconds, or null.
     *
     * 🛑 `DateTimeImmutable` with an explicit UTC zone, never `strtotime`:
     * SAML instants are xsd:dateTime and always carry a zone, but a malformed
     * one must be *null* rather than whatever the parser guessed from the
     * server's locale. Phase 23 found the same trap in `Carbon::createFromFormat`.
     */
    private static function instant(string $value): ?int
    {
        if ($value === '') {
            return null;
        }

        try {
            return (new \DateTimeImmutable($value, new \DateTimeZone('UTC')))->getTimestamp();
        } catch (\Throwable) {
            return null;
        }
    }
}
