<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

/**
 * 🛑 Every way a SAML response can be refused, each a stable identifier.
 *
 * §17's Phase 25 exit criteria name seven by hand:
 *
 * > "A stripped signature, a wrapped signature, a replayed assertion, a wrong
 * > audience, an expired `NotOnOrAfter`, a comment-truncation payload and an
 * > XXE payload are each rejected with **distinct audit events**."
 *
 * The same argument `App\Auth\Providers\Oidc\OidcRejection` makes, and it
 * applies harder here. SAML's failure modes are not variations on one theme:
 * a wrapped signature is somebody exploiting a parser, a replayed assertion is
 * somebody reusing a capture, and an expired `NotOnOrAfter` is usually a clock.
 * An operator who cannot tell those apart from the audit chain cannot act on
 * any of them, and `saml.failed` would satisfy "rejected" while failing the
 * criterion.
 *
 * 🛑 **None of these values reaches a reader.** §8.12.23 makes a failed login
 * the project's `deny_status` with no detail; the reason goes to §8.22's chain,
 * where the person who can fix it will see it and the person probing will not.
 *
 * ## 🛑 Why there are so many
 *
 * §8.12.18's SAML clause lists eleven requirements in one sentence, and the
 * malicious-assertion corpus is a **release gate** (§17). A vocabulary that
 * collapsed two causes into one case would make the corpus unable to tell a
 * fixed control from a broken one — which is the property a release gate has
 * to have.
 */
enum SamlRejection: string
{
    // ------------------------------------- §17's seven, named one by one

    /**
     * 🛑 No signature at all, or a signature over neither the Response nor the
     * Assertion.
     *
     * §8.12.18: "signature required on Response **and** Assertion". The
     * stripped-signature attack is the simplest one there is — delete the
     * `<ds:Signature>` element and hope the service provider only checks when
     * one is present. Every library that ever shipped a `validate_signature`
     * option had this bug available by configuration.
     */
    case SignatureMissing = 'saml.signature_missing';

    /**
     * 🛑 A signature that verifies cryptographically over an element that is
     * **not** the one being trusted.
     *
     * The signature-wrapping family: the attacker keeps the IdP's real signed
     * assertion, and adds their own forged assertion that the signature does
     * not cover. The service provider verifies "a" signature, finds it valid,
     * and then reads claims from the wrong element.
     *
     * 🛑 This is why DocUp resolves the signed reference to an element **by
     * identity** and compares it to the element it is about to trust, rather
     * than asking a library "is this document signed". The question "is it
     * signed" has a useless answer.
     */
    case SignatureWrapped = 'saml.signature_wrapped';

    /** The signature does not verify under the binding's configured certificate. */
    case SignatureInvalid = 'saml.signature_invalid';

    /**
     * 🛑 An assertion id presented a second time.
     *
     * §8.12.18 requires an "assertion-id replay cache". A SAML assertion is a
     * bearer credential that travels through the browser, so a capture is
     * replayable for as long as its `NotOnOrAfter` allows — and the only thing
     * that makes a capture worthless is remembering that it has been used.
     */
    case AssertionReplayed = 'saml.assertion_replayed';

    /**
     * 🛑 `Audience` is not this service provider's entity id.
     *
     * The SAML equivalent of OIDC's `aud`: an assertion minted for another
     * service provider at the same identity provider is a correctly signed,
     * unexpired assertion that is simply not for DocUp.
     */
    case AudienceMismatch = 'saml.audience_mismatch';

    /** `NotOnOrAfter` has passed, or `NotBefore` has not arrived, beyond the skew. */
    case ConditionsExpired = 'saml.conditions_expired';

    /**
     * 🛑 The document carries a DTD, an entity declaration, or anything else
     * that would make a parser expand entities.
     *
     * §8.12.18: "XML entity expansion disabled". §17 goes further and demands
     * the XXE payload "provably never reaches an entity-expanding parser" —
     * which is why this refusal happens on the **bytes**, before any parser is
     * constructed. See {@see SafeXml}.
     */
    case EntityDeclarationRefused = 'saml.entity_declaration_refused';

    /**
     * 🛑 A comment node inside a value DocUp would otherwise read.
     *
     * CVE-2017-11427's family. `<NameID>admin<!--x-->@evil.test</NameID>` has
     * one text value to a signature verifier (which canonicalises) and another
     * to a naive `textContent` reader (which concatenates text nodes and skips
     * the comment) — so the signed value and the read value differ. Several
     * products were vulnerable at once because everybody read the value the
     * convenient way.
     *
     * Refused rather than normalised: a value containing a comment is not a
     * value anybody meant to send.
     */
    case CommentInValueRefused = 'saml.comment_in_value_refused';

    // ------------------------------------- the rest of §8.12.18's clause

    /** More than one `<Assertion>`, or none. §8.12.18: "exactly one Assertion". */
    case AssertionCountWrong = 'saml.assertion_count_wrong';

    /** `Destination` is not this installation's ACS URL. */
    case DestinationMismatch = 'saml.destination_mismatch';

    /**
     * 🛑 `InResponseTo` does not match an authentication request DocUp sent.
     *
     * Which is also how **IdP-initiated** sign-on is refused: §8.12.18 says it
     * is "off by default", and an IdP-initiated response carries no
     * `InResponseTo` at all. There is no separate case for it because it is the
     * same fact — DocUp did not ask for this.
     */
    case InResponseToUnknown = 'saml.in_response_to_unknown';

    /**
     * 🛑 An encrypted assertion with no signature over it.
     *
     * §8.12.18 names this exactly: "encrypted-assertion-without-signature
     * rejected". Encryption is not authentication, and an unsigned
     * `EncryptedAssertion` is a message anybody holding the SP's public key can
     * mint.
     */
    case EncryptedWithoutSignature = 'saml.encrypted_without_signature';

    /**
     * 🛑 A signature algorithm outside the allowlist.
     *
     * §8.12.18 wants "an algorithm allowlist excluding `none`" for OIDC and the
     * same reasoning applies here: XML-DSig's registry includes SHA-1 digests
     * and HMAC signatures, and an HMAC "signature" on a SAML assertion means
     * the verification key is a shared secret.
     */
    case AlgorithmNotAllowed = 'saml.algorithm_not_allowed';

    /** The response is not a SAML `Response` at all, or will not parse. */
    case ResponseMalformed = 'saml.response_malformed';

    /**
     * 🛑 `<Issuer>` is not the entity id this binding is configured for.
     *
     * The SAML face of `OidcRejection::IssuerMismatch`, and §8.12.18 asks for
     * the same thing on both sides — OIDC's "exact `iss`".
     *
     * 🛑 Not redundant with the signature check, and the case where it
     * matters is the one worth stating: a multi-tenant identity provider that
     * signs for several entity ids with **one** key. The certificate then proves
     * only "this provider", not "this tenant of this provider", so without this
     * check tenant A's correctly signed assertion would be accepted for a
     * binding configured against tenant B. Compared byte-for-byte, because
     * §8.3.6 makes an entity id an opaque URI and normalising one would be
     * inventing an equivalence SAML does not define.
     */
    case IssuerMismatch = 'saml.issuer_mismatch';

    /** `Status` is not `Success` — the IdP refused, and said so. */
    case StatusNotSuccess = 'saml.status_not_success';

    /** No `NameID`, or an empty one: §8.12.1 keys a reader identity on it. */
    case SubjectMissing = 'saml.subject_missing';

    /** `SubjectConfirmation` is missing, not bearer, or does not match. */
    case SubjectConfirmationInvalid = 'saml.subject_confirmation_invalid';

    /**
     * 🛑 A `RelayState` naming no exchange DocUp opened.
     *
     * SAML's analogue of OIDC's `state`, and the same refusal
     * `App\Auth\Providers\Oidc\OidcRejection::StateUnknown` makes: the value
     * round-trips through the identity provider, so on the way back it is
     * reader-supplied. ADR 0013 measured that Keycloak returns it unmodified —
     * which is what makes it usable as an index, and exactly why an
     * *unrecognised* one has to be refused rather than ignored.
     *
     * Distinct from {@see self::InResponseToUnknown}: that one is "DocUp did not
     * ask for this *assertion*", this one is "DocUp did not open this
     * *exchange*". A response can fail the second while passing the first —
     * a genuine assertion presented through a fabricated `RelayState` — and an
     * operator needs to see which.
     */
    case RelayStateUnknown = 'saml.relay_state_unknown';

    /**
     * 🛑 A `RelayState` whose exchange is spent, expired or out of attempts.
     *
     * Three causes, one case, deliberately — the shape
     * `App\Auth\Providers\Oidc\OidcExchange::consume()` argues for. The caller
     * cannot tell them apart because all three mean "this exchange is over",
     * and a vocabulary that distinguished them would tell a replayer whether
     * their captured `RelayState` was ever valid.
     */
    case RelayStateExpired = 'saml.relay_state_expired';

    /**
     * 🛑 §8.13.7's `disabled`, or an identity an operator deprovisioned.
     *
     * The SAML face of `ProvisioningRejection::ProvisioningDisabled`, which the
     * shared provisioning raises and this protocol's callback translates. It
     * has to exist as a *SAML* case rather than being audited in federation's
     * own vocabulary, because §17 wants the refusals an operator sees under one
     * prefix they can filter — and "the reader signed in and DocUp would not
     * create them" is a login refusal like any other.
     */
    case ProvisioningDisabled = 'saml.provisioning_disabled';

    /** The binding's configuration is unusable — no certificate, no entity id. */
    case ConfigInvalid = 'saml.config_invalid';

    /** The response exceeds the size DocUp will parse. */
    case ResponseTooLarge = 'saml.response_too_large';

    /**
     * The audit action for this rejection.
     *
     * 🛑 One action per case, which is what §17's "distinct audit events" means.
     * The value is already a dotted identifier in §8.22.5's style, so the
     * action **is** the case value — not a prefix plus a payload field, because
     * a payload field is not something an audit query can key on without
     * knowing to look for it.
     */
    public function auditAction(): string
    {
        return $this->value.'.refused';
    }
}
