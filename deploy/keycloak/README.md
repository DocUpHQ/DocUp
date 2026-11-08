# The two test realms

Imported by `--import-realm` when `compose.oidc.yaml` starts Keycloak, for
§17's Phase 24 exit criterion:

> "Two projects on one installation authenticate readers against two different
> Keycloak realms in one browser session."

🛑 **The reasoning lives here and not in the JSON**, because Keycloak's realm
importer rejects unknown fields — including a `_comment` key. The first version
of these files carried their commentary inline and Keycloak refused to start
with `Unrecognized field "_comment" (class RealmRepresentation)`. JSON has no
comments, so a file that needs explaining needs a file beside it.

## Why two realms rather than two clients

Two realms have **separate issuers, separate signing keys and separate user
directories**, so a token from one is wrong in every dimension at the other —
`iss`, the `kid`, the signature and the subject. Two clients on one realm would
share a key set and differ only by `aud`, which tests one check instead of four.

## What each realm holds

| | `acme` | `globex` |
|---|---|---|
| Client | `docup-acme` | `docup-globex` |
| Reader | `reader-at-acme` | `reader-at-globex` |
| Groups | `engineering`, `contractors` | `sales`, `engineering` |
| Reader is in | `engineering` | `sales` |

🛑 **Both realms publish an `engineering` group and only one reader is in it.**
That is deliberate: a reader admitted by one realm must not acquire the other
realm's mapping, which a fixture with disjoint group names could not show.

## Three things that will waste an afternoon if changed

**1. `requiredActions: []` and a complete profile on every user.** ADR 0008
recorded this after a false FAIL:

> "Keycloak 26 enables a **Verify Profile** required action by default, and a
> user without `firstName`/`lastName` is intercepted at
> `login-actions/required-action` *before* the code is issued. That presents
> almost identically to a `redirect_uri` rejection."

`deploy/verify-oidc.sh` detects that interruption and names this ADR in the
failure, so the afternoon is spent once.

**2. One `redirectUris` entry, on the dashboard origin.** Not one per
documentation host. ADR 0008 measured that a single registered URI serves
readers arriving from any number of custom domains, because the provider never
learns which host began the flow — and its control confirmed Keycloak enforces
the registered list strictly, so a per-domain design would need every custom
domain registered here.

**3. `pkce.code.challenge.method: S256` on the client.** DocUp makes PKCE
structurally mandatory — `AuthorisationRequest::url()` has no parameter that
could omit it — so this adds nothing to DocUp's guarantee. What it adds is a
check on the *test*: if a future change stopped sending a challenge, Keycloak
would refuse the exchange, where a permissive provider would let it pass
silently.

## The secrets in these files

Client secrets and reader passwords are here in clear, and that is correct for
this fixture: they exist only in a working copy and in a disposable
`start-dev` Keycloak with an in-memory database that is rebuilt on every start.
They are suffixed `-for-tests-only` so a grep for a leaked credential finds the
reason beside the value.

🛑 They are **not** an exception to §6's rule against committing secrets. That
rule is about secrets with power somewhere; these have power over nothing but a
container that forgets them when it stops. A real client secret would go through
§9.1.7's envelope, which is what `deploy/seed-oidc-fixture.php` does with these
on the way into `auth_provider_bindings`.
