# Connecting a SAML identity provider

[Connecting an identity provider](oidc.md) covers OpenID Connect.
This page is the same job over SAML 2.0, for the directories that speak it and
not the other.

DocUp is a SAML **service provider** in strict mode. There is no permissive
mode, and most of this page is about what that costs you as well as what it
buys — because SAML's history is service providers that validated their own XML,
and almost every well-known break was reachable by configuration.

## What you need

| From your provider | Into DocUp |
|---|---|
| The IdP entity ID | `idp_entity_id` |
| The single sign-on URL (HTTP-Redirect) | `sso_url` |
| The signing certificate | `certificate` |
| The ACS URL to register | `https://<your dashboard host>/_/auth/saml/acs` |
| The SP entity ID to register | `https://<your dashboard host>/saml/metadata` |

🛑 **One assertion consumer service URL, whatever custom domains your projects
serve.** You do not register one per documentation host. The provider never
learns which host began the flow: the originating domain travels in
`RelayState`, and DocUp reads the domain back from its own database rather than
from the parameter it just received.

This was measured, not assumed. Keycloak 26.0.8 issued assertions for readers
arriving from two different custom domains against a single registered ACS, and
refused an `AssertionConsumerServiceURL` that was not on its list with an HTTP
400 and no redirect. The control is the part that makes the result mean
something — a provider that simply ignored the parameter would have passed the
two successes too.

### The certificate, pasted however your provider gives it to you

```
-----BEGIN CERTIFICATE-----
MIID…
-----END CERTIFICATE-----
```

A bare base64 blob works as well: Keycloak shows one, Okta offers a `.pem`
download, and the two differ only in the armour, so DocUp adds the armour when
it is missing. What it will **not** do is accept something that is not a
certificate — it is parsed when you save, so a paste that lost a character
fails while you still have the provider's console open.

## What DocUp enforces, and will not let you turn off

These are not settings. There is no flag for any of them, and the classes that
implement them take no options at all — a test fails the build if one grows a
`$strict`, an `$allowUnsigned` or a `$validateSignature`.

| Check | What it stops |
|---|---|
| **Signature on the Response *and* the Assertion** | A signed envelope carrying an assertion somebody else wrote |
| **The signed element is the element DocUp reads** | Signature wrapping: a valid signature pointed at a decoy |
| **An algorithm allowlist** | SHA-1 digests, and HMAC "signatures" whose key is shared |
| **`<Issuer>` on both elements** | A multi-tenant provider's other tenant |
| **Exact `Destination`** | A response captured at another service provider and replayed here |
| **Exact `Audience`** | An assertion minted for another service provider at your provider |
| **`InResponseTo` matched to a request DocUp sent** | An assertion DocUp never asked for |
| **An assertion-id replay cache** | A captured assertion used twice inside its own validity window |
| **`NotBefore` / `NotOnOrAfter`, 120 s skew** | An assertion outside the window it was minted for |
| **No DTD, no entity declaration — ever** | XXE, and billion-laughs expansion |
| **No comment inside a value DocUp reads** | CVE-2017-11427: the signed value and the read value differing |
| **Exactly one `<Assertion>`** | An ambiguity the attacker gets to resolve |

### "Is this document signed" is the wrong question

It is worth one paragraph, because it is the trap the whole category is built
on. A signature-wrapping attack keeps your provider's real signature — it
verifies perfectly — and adds a second assertion the signature does not cover.
A service provider that asks a library "is this signed?" gets `true`, and then
reads its claims from the wrong element.

So DocUp resolves the signed reference to an element **by identity** and
compares it against the element it is about to trust. The two shapes of the
attack produce two different refusals, which is deliberate: hiding the real
assertion leaves the read element unsigned (`saml.signature_missing`), while
misdirecting the reference leaves it signed and wrong
(`saml.signature_wrapped`). Reporting either as the other would tell you you
were being attacked in a way you were not.

### The XML never reaches a parser that could expand an entity

Not "entity expansion is disabled" — the bytes are scanned for a DTD, an entity
declaration or a non-predefined entity reference **before a parser object
exists**. A payload that declares an entity is refused without anything having
been asked to read it, which is a stronger claim than any parser flag, and the
test that proves it asserts the parser's error list is empty.

## What DocUp cannot do, and will not pretend to

🛑 Read this list before you register the client, because two of these mean the
driver will not work with your provider at all.

- **DocUp does not sign its `<AuthnRequest>`.** If your provider *requires*
  signed requests, it will refuse DocUp's. There is no key to configure.
- **DocUp does not decrypt assertions.** `<EncryptedAssertion>` is refused
  outright, because an encrypted assertion carrying no signature DocUp can check
  first is a message anybody holding your SP's public key can mint. Turn
  encryption off for this client; the whole exchange is over TLS.
- **IdP-initiated sign-on is off**, and not by a flag: an unsolicited response
  carries no `InResponseTo`, so there is nothing for DocUp to match it against.
  Readers start at your documentation, not at your provider's application
  portal.
- **No HTTP-Artifact binding.** It needs a back-channel SOAP resolver, which
  would be a second outbound path for no benefit.
- **No Single Logout.** Signing out of DocUp ends DocUp's session.

### `NameID` must be `persistent`

DocUp asks for `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent`, and your
provider should be configured to send it.

🛑 Not `transient`, which is a different value on every login — the reader would
be a new identity each time and their group mappings would never accumulate.
And **not `emailAddress`**: reader identities are keyed on the `NameID`, never
on an email address, for the reason the OIDC page gives at the same place. A
project administrator controls their own directory, so an installation that
matched readers by email would let them claim any address they liked.

## Groups and provisioning

Identical to OIDC's, because it is the same code: the three provisioning modes,
the reconciliation that **adds and removes** on every login, the identity epoch
that makes a removal take effect on the next *request*, and the refusal to let a
project-scoped binding map a dashboard role. [Connecting an identity
provider](oidc.md) sets all of it out; nothing on this page changes it.

The one difference is the name of the setting, because SAML sends attributes
rather than claims:

| Setting | What it is | Default |
|---|---|---|
| `groups_attribute` | The attribute `Name` your provider puts group names in | `groups` |
| `provisioning` | `disabled`, `create_reader`, `create_reader_and_map_groups` | `disabled` |

Keycloak sends `groups`. ADFS sends a claim URI such as
`http://schemas.xmlsoap.org/claims/Group`, which is accepted as a `Name`.

A SAML attribute is always a list; a claim is not. DocUp flattens an attribute
that carries one value and keeps one that carries several, so a display name
arrives as a string and a group list arrives as a list without you configuring
which is which.

## Setting one up

1. **Register the client** at your provider: the SP entity ID and the one ACS
   URL from the table above, HTTP-POST binding for the response, `persistent`
   NameID, **sign the response and the assertion**, require no signed request,
   encrypt nothing.
2. **Create the binding** — it starts in `draft`.
3. **Probe it**:

   ```bash
   docker compose exec app php artisan docup:auth:probe "the engineering idp"
   ```

   🛑 The SAML probe makes **no outbound request**, because there is nothing to
   fetch: your trust anchor is the certificate you pasted, not a document at a
   URL. What it checks instead is that the certificate parses, that its key type
   is one DocUp can verify with, and **how long it has left** — a certificate
   that expires next week is the single most common way a working SAML
   integration stops working, and the probe is the only thing positioned to
   notice before a reader does. It also prints the ACS and SP entity ID, so you
   can compare them against what you registered.
4. **Complete a test login** yourself.
5. **Transition it to `active`.** Neither the probe nor the test login is enough
   alone — a provider pointed at the wrong directory passes every probe.

## When something goes wrong

🛑 **A reader is told nothing.** A failed login is the project's ordinary
refusal, with no detail and no hint about your configuration. The reason goes to
the audit chain, where you can see it and a stranger cannot — and nothing your
provider wrote reaches the chain either, because a `StatusMessage`, an attribute
value and a `NameID` are all free text somebody else controls.

Each failure has **its own** audit action, so a misconfiguration and an attack
do not look alike:

| Audit action | What it usually means |
|---|---|
| `saml.signature_missing.refused` | Signing not enabled on both elements — or a stripped signature |
| `saml.signature_wrapped.refused` | 🛑 Somebody is attacking you. Not a configuration error |
| `saml.signature_invalid.refused` | The wrong certificate, a rotation you have not applied, or tampering |
| `saml.issuer_mismatch.refused` | `idp_entity_id` and your provider disagree |
| `saml.audience_mismatch.refused` | The SP entity ID registered at your provider is not DocUp's |
| `saml.destination_mismatch.refused` | The registered ACS URL is not DocUp's |
| `saml.in_response_to_unknown.refused` | IdP-initiated sign-on, or a response for a login DocUp did not start |
| `saml.conditions_expired.refused` | Clock skew beyond 120 s, or a reader who took too long |
| `saml.assertion_replayed.refused` | A browser re-POSTed — or a captured assertion is being reused |
| `saml.relay_state_unknown.refused` | A POST naming no login DocUp started |
| `saml.relay_state_expired.refused` | The back button, a retry, or a replay |
| `saml.entity_declaration_refused.refused` | 🛑 An XXE payload. Not a configuration error |
| `saml.comment_in_value_refused.refused` | 🛑 A comment-truncation payload. Not a configuration error |
| `saml.encrypted_without_signature.refused` | Encryption is on for this client; turn it off |
| `saml.algorithm_not_allowed.refused` | Your provider signs with SHA-1, or with an HMAC |
| `saml.provisioning_disabled.refused` | Somebody signed in who has no reader identity |

```bash
docker compose exec app php artisan docup:audit:export --action-prefix saml.
```

Three of those are marked 🛑 because they are not things a correct provider
does. A `signature_wrapped`, an `entity_declaration_refused` or a
`comment_in_value_refused` is somebody sending DocUp a payload, and it is worth
looking at where it came from.

If the binding has gone `degraded` — which for SAML means the certificate
expired or stopped parsing — readers get a 503 naming it, and DocUp will
**not** fall back to another provider or to public. [Private without an
IdP](providers.md) explains why, and how to recover it.

## Which providers this has been tested against

🛑 **Keycloak 26.0.8, and nothing else.** Okta, Microsoft Entra and ADFS are the
three an enterprise SAML claim would actually meet, and none of them has been
measured — they need tenant accounts and a Windows server.

The risk is low and it is not zero. Strict ACS allowlisting with no knowledge of
the initiating host is what SAML Core §3.4.1 and the Web Browser SSO Profile
require, so a conforming provider behaves as Keycloak did — but that is an
argument from the specification rather than a measurement, and this page would
rather say so than imply otherwise. If your provider behaves differently, that
is worth reporting.
