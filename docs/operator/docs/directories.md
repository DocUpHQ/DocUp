# Enterprise directories, edge identity and token lifecycle

This page covers the four things Phase 26b added: the `ldap` driver, the two
edge-asserted drivers `mtls` and `header_trust`, API token families with
mandatory expiry and overlap rotation, and the break-glass override.

Read [Who may read it](access.md) first for the access model itself, and
[Private without an IdP](providers.md) for what a binding is. This page assumes
both.

## The three drivers you cannot configure per project

`ldap`, `mtls` and `header_trust` are **installation scope only**. A project
administrator cannot create one, and the escape hatch that permits other
unlisted driver types deliberately does not reach them.

The reason is not tidiness. Each of the three either reaches into your internal
network or trusts a fact only your TLS terminator can establish:

| driver | what a project admin could otherwise do |
|---|---|
| `ldap` | point DocUp's server at any host on your network and read the response through the error message — a server-side request forgery primitive handed to a tenant |
| `mtls` | choose which certificate authority is trusted for their project |
| `header_trust` | choose which header DocUp believes an identity from |

If you want per-project directory authentication, the answer is a per-project
`oidc` or `saml` binding against your directory's own front end, not a
per-project `ldap` binding.

`mtls` and `header_trust` are additionally **off until you name them**. Set
`DOCUP_PERMITTED_AUTH_TYPES` to include them; the permissive default does not,
and neither does the unlisted-types escape hatch. Everything below assumes you
have named the one you want.

## `ldap`

### What DocUp requires of your directory

Four things, and none of them is a toggle:

- **A service account.** DocUp binds with it to search; there is no anonymous
  path. An anonymous bind succeeds on many directories and returns a result
  stripped of the attributes your filter asked for, which presents as "the user
  does not exist" for every user — a total outage that looks like a filter
  mistake.
- **TLS.** `ldaps://` connects directly; `ldap://` is upgraded with StartTLS and
  **refused** if that fails. There is no cleartext fallback: a directory that
  did not offer StartTLS would otherwise leave the connection in the clear while
  the bind still succeeded, so the reader's password would cross your network in
  plaintext and everything would look like it worked.
- **A verifiable certificate.** DocUp requires a valid chain *and* a matching
  name. A self-signed certificate must be in the application container's trust
  store — Debian layout, `/usr/local/share/ca-certificates/` then
  `update-ca-certificates`. DocUp reads the system store; no `ldap.conf` edit is
  needed.
- **Referral chasing stays off.** A referral is your directory telling DocUp to
  go and ask a different server, which is the same forgery primitive the scope
  rule above exists to prevent.

### Configuration

| setting | meaning |
|---|---|
| `uri` | `ldaps://host:636` or `ldap://host:389`. No path, query or fragment — the base DN and filter are their own settings, and accepting them in the URI would give you two places to say the same thing. |
| `bind_dn`, `bind_password` | the service account. The password is envelope-encrypted and no API or UI returns it. |
| `base_dn` | where to search. Not validated as a DN: RFC 4514 permits escaped forms DocUp has no business re-deriving, and your directory is the authority. The probe is where it answers. |
| `user_filter` | an RFC 4515 filter with a `{username}` placeholder, for example `(&(objectClass=inetOrgPerson)(uid={username}))`. The placeholder's value is escaped for you. |
| `subject_attribute` | which attribute is the reader's stable identifier. Default `uid`. |
| `groups_attribute` | which attribute carries their groups. Default `memberOf`. |
| `display_attribute` | a human-readable label. Default `cn`. |
| `provisioning` | `disabled`, `create_reader`, or `create_reader_and_map_groups`. **Only the third reconciles groups** — see below. |

### 🛑 A filter that matches two entries is refused

Not resolved: refused. Two entries mean your uniqueness assumption is wrong, and
picking the first authenticates whichever one the directory happened to
return — a coin toss between two people, deterministic enough to look correct
while you test it.

If you see `ldap.subject_ambiguous`, two entries under your base DN share a
value for `subject_attribute`. Narrow the base DN or fix the duplicate.

### How a reader signs in

DocUp serves a credential page on the **dashboard** host, never on a
documentation host. A reader asking for a private page is redirected there,
types a username and password, and is redirected back with a one-use handoff
code.

The page carries **installation branding only** — no project name, no
organisation name, no logo — so a tenant-controlled domain can never present
something that looks like it collected the password.

### 🛑 Every failure says the same thing

A wrong password, a username with no entry, a directory that is down, a binding
deleted mid-flow and a locked-out client all show the reader one sentence.

That is deliberate. The page is reachable by anyone who can reach your dashboard
host, so a message that distinguished "no such user" would be an **enumeration
oracle over your employee directory**. The distinction is in the audit chain:
filter for `ldap.*` and you get one event per cause, with the reason in its own
field.

Attempts are rate-limited per credential and, much more tightly, per credential
and client address. The check happens **before** the bind, so a locked-out
client's guess never reaches your directory — which matters more here than for a
share link, because most directories have a lockout policy of their own and an
unthrottled endpoint would let anybody on the internet lock out a named
employee's real account.

### Groups

Set `provisioning` to `create_reader_and_map_groups`, then map each directory
group to a reader group. The provider group name is whatever your directory puts
in `groups_attribute` — for `memberOf` that is the group's **DN**, not its `cn`:

```
provider group: cn=docs-readers,ou=groups,dc=example,dc=com
reader group:   docs-readers
```

A mapping that names the bare `cn` will never match. There is deliberately no
suffix matching: a configuration mistake you can see beats one DocUp guesses
around.

Groups are reconciled on **every** sign-in, added *and* removed. A reader
removed from a group in your directory loses the access that group gave them at
their next decision, not at their next sign-in, because the removal moves the
identity epoch.

### 🛑 A reader identity belongs to the binding, not the project

An installation-scoped binding has no organisation, and a reader it vouches for
has none either. One person behind your directory is **one** reader identity
across every project the binding governs, keyed on the binding and a digest of
their subject. Their email is never used for linking or lookup, and never
stored.

## `mtls`

DocUp never sees your TLS handshake. Your terminator does, and `mtls` trusts
exactly what the terminator tells it — which is why two headers are mandatory
rather than one.

### 🛑 The certificate header alone is not enough, and this is the trap

nginx with `ssl_verify_client optional` forwards `$ssl_client_escaped_cert`
**even when verification failed**. The issuer DN inside a certificate is a field
in a document the client wrote. So a configuration that checked only the
certificate would accept a self-signed certificate an attacker minted with your
CA's name in it.

DocUp therefore requires a **verdict header** as well, and refuses to activate a
binding without one. Configure both:

```nginx
ssl_verify_client optional;

proxy_set_header X-Client-Certificate $ssl_client_escaped_cert;
proxy_set_header X-Client-Verify      $ssl_client_verify;
```

`$ssl_client_verify` is `SUCCESS`, `FAILED:<reason>` or `NONE`. DocUp admits only
the configured success value.

### Settings

`DOCUP_CLIENT_CERTIFICATE_HEADER`, `DOCUP_CLIENT_CERTIFICATE_FORMAT` (`pem` for
nginx's escaped form, `der` for Caddy's base64), `DOCUP_CLIENT_VERIFY_HEADER`
and `DOCUP_CLIENT_VERIFY_SUCCESS`. The binding then pins an issuer DN, optionally
a list of SHA-256 fingerprints, and which subject attribute is the identity.

### What is refused, and how

| cause | what the reader gets |
|---|---|
| no certificate offered | the project's default refusal — nothing was presented, so nothing was rejected |
| verdict absent or not the success value | the same |
| issuer DN does not match the pin | the same |
| fingerprint not in the pinned list | the same |
| certificate **expired** or **not yet valid** | a challenge: a credential was presented and rejected |
| certificate unparseable | the default refusal, **not** a challenge |

That last row is the one worth understanding. A terminator forwards its headers
on *every* request, so if an unparseable certificate were treated as a rejected
credential, a single typo in your terminator's configuration would turn every
private 404 on the installation into a 401 — and a 401 confirms the resource
exists.

## `header_trust`

For a terminator that has already authenticated the reader and forwards an
identity. Weaker than `mtls` by construction: DocUp can only believe the name.

### 🛑 The identity header alone authenticates nobody

A terminator that sets its identity header only for an *authenticated* reader
passes an **unauthenticated** reader's own header straight through. That is
oauth2-proxy's default behaviour and a one-request bypass.

So a shared secret is mandatory. Your terminator sends it on every proxied
request; DocUp compares it against the binding's sealed value and ignores the
identity header entirely unless it matches.

```caddyfile
reverse_proxy app:8080 {
    header_up -X-Forwarded-User
    header_up -X-Docup-Assertion
    header_up X-Forwarded-User   {http.auth.user.id}
    header_up X-Docup-Assertion  "{env.DOCUP_ASSERTION_SECRET}"
}
```

🛑 The two `header_up -` lines are not decoration. `header_up X-Foo` **appends**
when the client already sent `X-Foo`, and DocUp refuses a request carrying two
copies of either header rather than choosing between you and the client. Strip
first, then set.

`header_trust` never reports a rejected credential, for the disclosure reason
given above, one rung further along.

## API token families

Every token has a **mandatory expiry**. There is no non-expiring token and no
flag to create one.

Rotation mints a successor and records the lineage. The predecessor is
deliberately **not revoked**: both values work until the predecessor's own
expiry, so a deployment can roll the new value out without a window in which
neither works. You may shorten that overlap and not extend it.

A family rotates **once** — a token that already has a successor cannot be
rotated again — so a family holds at most two live secrets and "which of these
is current" always has one answer.

Rotation goes through the same minting path as a new token, so every
prohibition re-applies. A rotation can therefore fail: if the holder has lost a
capability the token carries, minting the successor is refused, and that is the
correct outcome rather than a quiet downgrade.

Tokens may be bound to a CIDR list. A bound token presented from an address
outside it is rejected, and a token whose address cannot be determined is
rejected too. 🛑 The list is matched literally: `::ffff:203.0.113.20` does **not**
match `203.0.113.0/24`. An allow list must refuse every spelling you did not
enter, so if your readers arrive over both families, list both.

## Break-glass

An installation owner may grant themselves 15 minutes of restricted access to
one project. It is a named, audited override, not an elevation.

Opening one requires all of:

- installation ownership;
- an enrolled second factor;
- a step-up confirmation within the last five minutes;
- a reason of at least 40 characters and four words.

It is limited to three per hour per person, and every installation owner is
notified when one opens.

🛑 Break-glass cannot override an outage. A degraded binding still returns its
503 and a stale search index still short-circuits, because break-glass is
evaluated after both — it grants access to content, not a way around a provider
that is not working. It is also never publicly cacheable, and the decision
header reports `allow:break_glass` so it is distinguishable from an ordinary
allow in your logs.

## SCIM, and the latency to expect

SCIM 2.0 is not in this release. What ships is the seam it will arrive through,
which matters now for one reason: it fixes what "deprovisioned" means and how
quickly it takes effect.

<!-- BEGIN GENERATED: deprovisioning-latency -->

A deprovisioned reader stops being able to read within 10 minutes at enforcement Tier A or B — the grant they already hold, since their sessions are revoked at once and cannot mint another. At Tier C the bound is unstated, because Tier C is refused without an epoch feed (§8.12.13). Were sessions left to expire instead of being revoked, it would be 24 hours.

<!-- END GENERATED: deprovisioning-latency -->

🛑 That paragraph is **generated from the configuration**, not written here. A
revocation bound restated as prose stops being true the day the grant TTL
changes, and prose does not fail a build.

The number excludes the refresh-session ceiling, and that exclusion is the
honest part: deprovisioning revokes sessions, so a reader who cannot mint a new
grant cannot extend the window past the one they already hold. The sentence says
what the bound would be if sessions were left to expire instead, so the cost of
ever making deprovisioning lazy is visible rather than discovered.
