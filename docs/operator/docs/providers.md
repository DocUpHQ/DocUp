# Private documentation with no identity provider

[Who may read it](access.md) describes the decision. This page describes what a
reader can *present* to satisfy it, and all of it works on a fresh install with
no OIDC, no SAML and no directory.

That is deliberate. A small team wanting one private guide should not have to
stand up an identity provider first, and an installation that only offered
enterprise single sign-on would push those teams back onto a public bucket with
a hard-to-guess URL.

## Bindings

A **binding** is one configured way of establishing a reader. Every binding has:

| Field | What it is |
|---|---|
| Scope | `installation`, `organisation` or `project` |
| Type | the driver — `public`, `portal_session`, `password`, `shared_link`, `reader_token`, `ip_allowlist` |
| Name | what readers see when it breaks, so make it something they can quote |
| State | one of five; see below |
| Shareable | whether share links may be minted against it (default **no**) |

Secrets a binding holds — a password hash, a client secret — are
envelope-encrypted. **No API, no UI and no command returns them**, including
redacted. `docup:auth:list` prints state, never material.

### How scope resolves

A project is governed by the **most specific binding of each type**. An
installation-wide `portal_session` and a project-level `password` both apply:
the project gets both.

🛑 **Of each type, not overall.** If resolution picked a single most-specific
binding, a project adding its own password would switch off the installation's
identity provider for its own documentation — a privilege change made by
configuring something unrelated. So a project binding only ever shadows another
binding **of its own type**.

## The five states

```
draft → verifying → active → degraded → disabled
```

A binding leaves `verifying` only when **both** halves are done:

1. an automated **probe** passes — `docup:auth:probe <name>`;
2. a human completes a **test login**.

Neither alone is enough, and the probe cannot promote a binding on its own. A
probe answers "could this provider work"; only a person opening the thing can
answer "does it admit the right people". A provider configured against the wrong
directory passes every probe.

### `degraded` denies, and does not fall back

After five consecutive failed probes an `active` binding becomes `degraded`.
A degraded binding answers readers with a **503 naming the binding**, and:

- it does **not** fall back to another provider;
- it does **not** fall back to public;
- it offers the reader no way around — no "continue as guest", no `WWW-Authenticate`;
- the page is never cached, so the outage cannot outlive itself.

🛑 This is the behaviour operators most often expect to be different, so it is
worth being explicit about why. Suppose a project has a working IP allowlist and
a broken portal. "Graceful degradation" would keep serving to the office
network — and a reader at home sees a 503 while a reader at a desk sees the
documentation, which is a privacy posture nobody chose and nobody can
reason about. A broken guard means the installation cannot currently tell who
you are, and the honest answer to that is 503.

A passing probe moves a degraded binding back to `verifying`, **not** to
`active`. A provider that failed five times and then answered once has not been
diagnosed.

### Recovering one

```bash
docker compose exec app php artisan docup:auth:probe "the client portal"
```

Then complete a test login, and transition it to `active`. The state change is
in the audit chain either way.

## What a reader can present

### A password

One password, shared with whoever should read the documentation. Hashed with
Argon2id at or above the OWASP floor (`m=19456, t=2, p=1`) — asserted by test,
and `docup:doctor` checks the configuration.

It is read from the request on every request rather than exchanged once for a
cookie. A share link's secret is in a URL and has to leave it; a password is
typed, and turning it into a long-lived cookie would mean storing a reusable
credential in the browser for a secret you can only rotate by telling everybody.

A password grants whatever the rule naming its binding grants — it carries no
scope of its own.

### A share link

A secret in a URL, for sending documentation to somebody outside the
organisation. Share links have:

- a **mandatory expiry**. There is no "never expires", at the application and
  at the database;
- optional **version and path scope** — `/guide/` but not `/internal/`;
- an optional **password** on top of the link;
- an optional **use count**, enforced atomically, so a one-use link admits
  exactly one reader even under a race;
- a **rate limiter**, per credential and per address.

A link only works against a binding explicitly marked shareable. A binding
nobody has considered in those terms does not acquire a credential class by
default.

#### A link in a URL becomes a cookie

A reader opening `https://docs.example.com/en/v1/?docup_share=…` is redirected
to the clean URL with the secret moved into a cookie, and their own query string
(`?highlight=…`) survives. The response is `no-store` with `no-referrer`, and
the secret is redacted from the logs.

That conversion happens even when the secret is invalid, because the point is
to get it out of the URL — it just sets no cookie.

#### An expired link gives a 404, not a 401

A share secret that does not resolve — expired, revoked, used up, or never
real — produces the project's ordinary refusal with no challenge.

🛑 A dead link answered with "authenticate here" would tell whoever now holds it
that the resource is real and guarded. An expired link **is** your revocation
taking effect, so that holder is someone you have decided should not have
access. A stop that still confirms existence is a weaker stop than you asked
for.

Present a **live** link with a wrong password and you do get a challenge, so the
password page can be offered. The line is proof of the link.

### A reader token

`Authorization: Bearer <token>` for a CI job, a link checker or a script.
Version- and path-scoped like a link, optionally capped by uses, and it
establishes **no session** — there is nowhere for a CI job to keep a cookie, so
the token travels on every request.

🛑 DocUp reads RFC 6750 `Bearer` only. Read the Docs' `Authorization: Token <T>`
and the token-as-Basic-username form are **not** supported, and this is a
documented incompatibility rather than an omission: a parser that accepts
several shapes is a parser whose shape an attacker chooses. Anything that is not
exactly one `Bearer` token is nothing at all — not an error.

### An IP allowlist

CIDR ranges, v4 and v6, compared on packed bytes.

🛑 **An allowlist is a gate, never an identity.** Satisfying one leaves a reader
at `public`: it narrows *where* a reader may be, and says nothing about *who*
they are. A rule that rests on an allowlist alone therefore authenticates
nobody, and DocUp **refuses to save one** unless the project has explicitly
enabled network-only access, which is flagged weak and audited.

The shape worth watching for is "from the office **or** signed in", which is an
operator writing what reads as an extra condition and means "from the office".

A v6 address never matches a v4 range and vice versa, including the
IPv4-mapped form `::ffff:10.0.0.1` — so an allowlist written in dotted quads
cannot be satisfied from a family you did not enter.

## Scope is a narrowing, not a grant

Two bounds apply to every credential, and both have to permit the request:

1. the **rule's** — which versions and paths the policy rule admits;
2. the **credential's** — which versions and paths this particular link or
   token carries.

A link issued for `/guide/` inside a rule admitting every path is still refused
on `/internal/`. A credential can only ever narrow what a rule already allowed.

🛑 And a rule may name a **specific binding**, so a reader holding both a share
link and a session is judged on the leaf that actually satisfied the rule, not
on the strongest thing they happen to hold.

## Seeing what is configured

```bash
docker compose exec app php artisan docup:auth:list
```

Every binding, its scope, its type, its state, whether its probe passed and
whether a human has completed a test login. `--project <slug>` narrows to the
bindings in scope **for** that project, which includes the installation and
organisation bindings governing it — not only the ones scoped to it.

🛑 It also carries two warnings no dashboard screen exists for yet:

- **a degraded binding**, which is answering readers with a 503 right now;
- **a reader policy with no rules**, which denies every reader. The denial is
  structural — a policy's default effect is `deny` and cannot be anything else —
  so this is the only place that tells you.

`--check` exits non-zero when either is true, which makes it usable from
monitoring. `--json` gives the same thing machine-readably.

```bash
docker compose exec app php artisan docup:auth:list --check
```

## Deleting things

A binding a policy rule names **cannot be deleted**. Remove the rule first.
Disabling the binding is the way to take it out of service while keeping the
rule, and `disabled` denies exactly like `degraded` without claiming an outage.

Expired credentials are swept thirty days after they expire, by the scheduled
`docup:readers:maintain`. The delay is so you can still answer "who had access
to this, and when did it lapse" — the audit chain holds the issue and the
revoke, but not the scope.

## What is not here

SAML and LDAP are later phases. Nothing on this page depends on them, and when
they arrive they are additional bindings resolved by the same rules.

**OIDC has arrived** — see [Connecting an IdP](oidc.md). It changes nothing on
this page: a project with a password binding and an installation with an
identity provider have both, because resolution is per type.
