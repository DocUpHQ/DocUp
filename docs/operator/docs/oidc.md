# Connecting an identity provider

[Private without an IdP](providers.md) covers passwords, share links and reader
tokens. This page is the other half: pointing a project — or your whole
installation — at an OpenID Connect provider.

DocUp speaks **authorisation code with PKCE**, and nothing else. There is no
implicit flow, no hybrid flow and no password grant, which is RFC 9700's
guidance and is not configurable.

## What you need

| From your provider | Into DocUp |
|---|---|
| The issuer URL | `issuer` |
| A client ID | `client_id` |
| A client secret, if you have a confidential client | `client_secret` (sealed) |
| The redirect URI to register | `https://<your dashboard host>/_/auth/oidc/callback` |

🛑 **One redirect URI, whatever custom domains your projects serve.** You do not
register one per documentation host, and you should not try — the provider never
learns which host began the flow, because the originating domain travels in
`state` and DocUp reads it back from its own database rather than from the
parameter.

This was measured rather than assumed: Keycloak 26.0.8 issued codes for readers
arriving from two different custom domains against a single registered URI, and
refused an unregistered per-domain URI as a control. If your provider behaves
differently, that is worth reporting as a bug in this assumption.

### The issuer must be exact

```
✅ https://idp.example.com/realms/engineering
❌ https://idp.example.com/realms/engineering/
❌ https://idp.example.com/realms/engineering?x=1
❌ http://idp.example.com/realms/engineering
```

DocUp compares the `iss` claim byte-for-byte against this value, and builds the
discovery URL from it. A trailing slash is refused rather than trimmed, so that
what you typed and what DocUp compares are the same string.

## What DocUp enforces, and will not let you turn off

These are not settings. There is no flag for any of them, because a protocol
check that can be switched off is one that eventually is.

| Check | What it stops |
|---|---|
| **PKCE S256, always** | An intercepted authorisation code being redeemable by whoever intercepted it |
| **Exact `iss`** | A provider claiming to be another provider; the suffix trick (`…example.com.attacker.test`) |
| **Exact `aud`, plus `azp`** | A token minted for another client at the same provider — valid, signed, and not for you |
| **Single-use `nonce`** | An id_token from an earlier login being injected into a later one |
| **`at_hash`** | An id_token and an access token being assembled from two different exchanges |
| **Signing-algorithm allowlist** | `alg: none`, and `HS256` signed with your own published public key |
| **JWKS pinned by `kid`** | A token choosing which key verifies it, or getting as many attempts as you have keys |
| **No implicit flow** | A token arriving in a URL, where it reaches browser history and every proxy log |

🛑 **The allowlist is asymmetric algorithms only** — `RS256`/`384`/`512` and
`ES256`/`384`/`512`. No `HS*`, because a symmetric id_token signature makes the
verification key a shared secret, and a key you publish in a JWKS is not a
secret. If your provider only offers `HS256`, DocUp cannot use it, and the probe
will tell you so rather than failing at a reader's first login.

A symmetric key published in your JWKS is ignored for the same reason, even if
you have marked it for signing.

### Key rotation needs nothing from you

DocUp caches your key set for an hour and re-fetches when a token names a `kid`
it has not seen. That re-fetch is **rate-limited to once a minute per binding**,
which matters for a reason worth knowing: without the limit, anybody who can
reach your documentation could mint tokens with random `kid`s and make DocUp
hammer your provider — breaking real logins and spending your rate limit.

Rotation still works automatically. Publish the new key before you sign with it,
as every major provider does, and the first token signed with it arrives long
after DocUp could have fetched it.

## Scope and claims

DocUp requests `openid profile`, and adds one scope of your choosing if your
provider needs one to release group claims.

🛑 **`email` is not requested**, and this is deliberate rather than an
oversight. Reader identities are keyed on `sub`, never on an email address — a
project administrator controls their own directory, so an installation that
matched readers by email would let them claim any address they liked. A scope
DocUp does not need is also personal data DocUp should not be holding.

The consequence you will notice: DocUp shows readers by a display name or a
short identifier, never by email. If you need to know who a reader is, your
directory is the place that knows.

| Setting | What it is | Default |
|---|---|---|
| `groups_claim` | The claim your provider puts group names in | `groups` |
| `groups_scope` | A scope to request so it is released | none |

Keycloak sends `groups`. Entra sends `roles`. Okta sends whatever your
administrator called it.

## Provisioning, and the three modes

| Mode | What happens on a login by somebody new |
|---|---|
| `disabled` *(default)* | Refused, and audited |
| `create_reader` | A reader identity is created; groups ignored |
| `create_reader_and_map_groups` | …and your group mappings are applied |

🛑 **`disabled` is the default** because it is the behaviour you would want
before you had thought about provisioning. A binding whose mode nobody set
admits only readers you created by hand, and the refusal is audited — which is
how you find out somebody who should have access does not, rather than from
them.

### Group mappings are reconciled, both ways

With `create_reader_and_map_groups`, every login compares what your provider
asserts against what DocUp has recorded and **adds and removes** accordingly.

🛑 A reader removed from a group at your provider loses it on their next login —
not merely "stops gaining it". This is the half that is easy to get wrong, and
the reason it matters is that removing somebody from a group at the identity
provider is, for most organisations, the whole of offboarding.

The change takes effect on the next **request**, not the next login after that:
DocUp bumps the project's identity epoch, so any short-lived grant the reader is
holding stops being honoured immediately.

### Mapping a dashboard role

An **installation**- or **organisation**-scoped binding may map a group to one
of DocUp's ten dashboard roles. A **project**-scoped binding may not, at all,
and no flag changes it.

🛑 The reason is arithmetic, not policy. A project administrator configures a
binding against a directory they control. If a project-scoped binding could map
a group to `installation_owner`, they would only have to add themselves to a
group in their own directory. DocUp refuses such a mapping when you save it,
again in the database schema, and again at login for any row that predates
both.

An organisation-scoped binding likewise cannot map an *installation*-scope role,
which is the same escalation one level up.

## Setting one up

1. **Register the client** at your provider with the one redirect URI above.
2. **Create the binding** — it starts in `draft`.
3. **Probe it**:

   ```bash
   docker compose exec app php artisan docup:auth:probe "the engineering realm"
   ```

   The probe fetches your discovery document and your key set, so a failure here
   is a configuration you can fix before any reader sees it. It reports whether
   DocUp sees a confidential or a public client, which is worth reading: if you
   configured a secret and it says "public client", the secret did not arrive.
4. **Complete a test login** yourself.
5. **Transition it to `active`.** Neither the probe nor the test login is enough
   alone — a provider configured against the wrong directory passes every probe.

## When something goes wrong

🛑 **A reader is told nothing.** A failed login is the project's ordinary
refusal, with no detail and no hint about your configuration. The reason goes to
the audit chain instead, where you can see it and a stranger cannot.

Each failure has **its own** audit action, so you can tell a misconfiguration
from an attack:

| Audit action | What it usually means |
|---|---|
| `oidc.issuer_mismatch.refused` | The issuer in DocUp and at the provider disagree |
| `oidc.audience_mismatch.refused` | Wrong `client_id`, or a token for a different client |
| `oidc.at_hash_invalid.refused` | Your provider is not sending `at_hash` |
| `oidc.key_not_pinned.refused` | A rotation DocUp has not caught up with, or a forged token |
| `oidc.algorithm_not_allowed.refused` | Your provider signs with something DocUp refuses |
| `oidc.nonce_replayed.refused`, `oidc.state_expired.refused` | A reader took too long, retried, or somebody is replaying |
| `oidc.provisioning_disabled.refused` | Somebody signed in who has no reader identity |
| `oidc.implicit_flow_refused.refused` | A token arrived in a callback query; DocUp never asks for one |

```bash
docker compose exec app php artisan docup:audit:export --action-prefix oidc.
```

If the binding has gone `degraded`, readers are getting a 503 naming it and
DocUp will **not** fall back to another provider or to public —
[Private without an IdP](providers.md) explains why, and how to recover it.

## What is not here

[SAML](saml.md) is the other protocol, and it is here now — the groups and
provisioning half of this page applies to it unchanged, because it is the same
code.

LDAP is a later phase. So is SCIM: group membership today is whatever your
provider asserts at login, reconciled then, which means a change at the provider
reaches DocUp when the reader next signs in rather than when you make it.
