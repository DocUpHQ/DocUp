# Who may read your documentation

DocUp decides every reader request with **one function**. Not one function per
surface, not one per feature — one, for the page proxy, the PDF download, the
search index and the addons payload alike. This page is what that function
decides and in what order, so that when a reader sees a 404 you can say why.

## The access lattice — four values, four columns

Four things carry an access level, and they all draw from the **same** ordered
scale:

| Level | Order | Means |
|---|---|---|
| `public` | 0 (weakest) | any reader, no credential |
| `authenticated` | 1 | any reader who satisfied any identity leaf of any binding in scope |
| `members` | 2 | a reader whose identity maps to a role assignment or group on this organisation |
| `restricted` | 3 (strongest) | only a reader satisfying an explicit allow rule **naming** this component or version |

The four columns are `projects.visibility`, `project_versions.visibility`,
`domain_mounts.mount_exposure` and `components.min_access`. One scale rather
than four means "permits", "stricter" and "narrows" are one relation, so there
is nothing to translate between them and nothing to get backwards.

**All four are authoritative.** None is derived from another at read time, and
the effective requirement is the **strongest** of them. That is what "access is
never widened" means in practice: adding a column can only tighten the answer.

`mount_exposure` additionally has an `inherit` value, which is the default and
means "take the project's". A mount may narrow access for one domain and
**never** widen it — a write that would is refused when you save it, not
ignored later.

### `restricted` is not just "very private"

The fourth level has a specific meaning worth knowing before you pick it: a
reader reaches a `restricted` resource only through a rule that **names the
version or the path**. A rule written with a wildcard version selector will not
admit anybody to a `restricted` version, however strong their identity.

Use it for the one directory that must be listed explicitly. Use `members` for
"our people only".

## The decision, in order

```
DENY unless ALL of:
  1. the project's visibility permits
  2. the first matching reader-policy rule says allow, and the reader
     satisfies its requirement
  3. the version's visibility permits
  4. the domain mount's exposure permits
  5. the component's min_access permits  — re-checked after the mount matched
  6. a share link's or bearer token's scope covers this path, if that is
     what let the reader in
```

The order does not change whether a request is allowed — all six must hold
either way. What it decides is **which refusal is reported**, which is what you
read when you are debugging.

Two things are checked before all of it:

- A **degraded identity binding** denies with `503`, naming the binding. It
  never falls back to another provider and never falls back to public. If your
  IdP is down, your private documentation is unavailable — which is the correct
  answer and not a reason to make it public.
- **Search is disabled** while its index generation lags your policy
  generation. A freshly tightened policy is in force for a page request
  immediately and is *not yet* in force for the index, so search returns
  nothing rather than returning documents the new policy refuses.

## Reader policy rules

A policy is an **ordered, first-match-wins** list, capped at 50 rules per
project, with a default effect of **deny**.

🛑 **First-match-wins means evaluation stops at the first rule whose selectors
match.** If that rule is a deny, a later allow does not rescue the request.
This is deliberate — it is what makes a deny rule something you can rely on —
and it is the opposite of how a list of allows reads.

A rule matches on a version selector and an optional list of path prefixes,
expressed **relative to a component mount**. Path matching is on **segment
boundaries and literal prefixes only**: `/internal` covers `/internal` and
`/internal/runbook.html` and does **not** cover `/internal-notes/`.

🛑 **There is no regex path matching, and there will not be.** A regex either
destroys the edge fast path or becomes an enumeration oracle. A pattern
containing regex metacharacters is refused when you save it rather than
silently stored as a literal that matches nothing.

### Requirements

Each rule carries a two-level boolean tree over five leaf kinds:

| Leaf | Produced by | Bears an identity? |
|---|---|---|
| `binding` | `portal_session`, `password`, `oidc`, `saml`, `ldap`, `mtls`, `header_trust` | yes |
| `share` | `shared_link` | yes |
| `bearer` | `reader_token` | yes |
| `gate` | `ip_allowlist` | **no** |
| `public` | the public terminal | **no** |

```json
{"all": [
  {"leaf": "gate", "driver": "ip_allowlist"},
  {"any": [
    {"leaf": "binding", "driver": "oidc", "binding_id": "…"},
    {"leaf": "bearer", "driver": "reader_token"}
  ]}
]}
```

🛑 **A requirement that an IP allowlist alone satisfies is refused when you
save it.** An IP address is a network fact, never a principal. The refusal
catches the shape that reads as safe and is not:

```json
{"any": [{"leaf": "gate"}, {"leaf": "binding"}]}
```

"From the office **or** signed in" is "from the office". Write `all`, not
`any`, and the rule means what you intended.

If you genuinely want network-only access, a per-project flag enables it. It is
flagged weak in the interface, it is audited, and it is off by default.

🛑 **An empty group is refused too.** `{"all": []}` reads as the strictest rule
anybody could write and, in logic, an empty conjunction is **true** — so it
would admit everybody. It is refused when you save it and evaluates false
anyway.

### Shadow rules

A rule marked `shadow` is evaluated and recorded and **never enforced**. It
does not consume the first-match slot, so it cannot deny anything behind it.
Use it to see what a rule *would* do before it does it.

## What a refused reader actually receives

**404 is the default**, for everything unauthorised or unresolvable. A refusal
is meant to be indistinguishable from absence.

A per-project `deny_status` of `403` is available — for **authenticated
principals only**. An anonymous reader always gets 404, whatever you configure,
because a 403 to an anonymous request confirms the resource exists.

A `401` challenge happens in exactly two cases:

1. A credential was presented and rejected — expired, revoked, or out of scope.
2. The resource's **existence** is already public, because the project appears
   in the public index, and only its content needs authentication.

In every other case the response is your `deny_status` with **no**
`WWW-Authenticate` header. The header is itself a disclosure: it tells a
crawler there is something here to authenticate for.

## Caching

A private response is never publicly cacheable, on either axis, and carries no
cache tag. A rule may declare itself publicly cacheable only when its
requirement is literally the public terminal — anything else is refused when
you save it, because a rule that demanded a credential and declared itself
publicly cacheable would put a private response into a shared cache.

🛑 **There is no public fast path.** A public project takes exactly the same
decision path as a private one. A cached "this is public" flag read stale in the
unsafe direction would serve private bytes with no decision at all, which is a
worse failure than a stale allow for a reader who was already authorised.

## When a change takes effect

Editing a policy, a rule or a visibility bumps the project's `authz_epoch`, and
the decision cache is keyed on it — so the change takes effect on the **next
request**. Nothing is purged and there is nothing to fail. A policy write also
bumps `policy_generation`, which is what disables search until the index
catches up.

## The decision table

Every combination below is asserted by the test suite, and this table is
generated from the same source the test drives — so it cannot drift from what
the code does.

The project is public in every row: `projects.visibility` dominates everything,
so varying it would give half the table the same answer. "private" below means
the version is at `members`.

<!-- BEGIN GENERATED: decision-table -->

| # | version | listed | reader | surface | result | status | publicly cacheable | reason |
|---|---|---|---|---|---|---|---|---|
| 1 | public | active | anonymous | `proxy` | **allow** | `200` | yes | `allowed` |
| 2 | public | active | anonymous | `download` | **allow** | `200` | yes | `allowed` |
| 3 | public | active | anonymous | `search` | **allow** | `200` | yes | `allowed` |
| 4 | public | active | anonymous | `addons` | **allow** | `200` | yes | `allowed` |
| 5 | public | active | non-member | `proxy` | **allow** | `200` | yes | `allowed` |
| 6 | public | active | non-member | `download` | **allow** | `200` | yes | `allowed` |
| 7 | public | active | non-member | `search` | **allow** | `200` | yes | `allowed` |
| 8 | public | active | non-member | `addons` | **allow** | `200` | yes | `allowed` |
| 9 | public | active | member | `proxy` | **allow** | `200` | yes | `allowed` |
| 10 | public | active | member | `download` | **allow** | `200` | yes | `allowed` |
| 11 | public | active | member | `search` | **allow** | `200` | yes | `allowed` |
| 12 | public | active | member | `addons` | **allow** | `200` | yes | `allowed` |
| 13 | public | hidden | anonymous | `proxy` | **allow** | `200` | yes | `allowed` |
| 14 | public | hidden | anonymous | `download` | **allow** | `200` | yes | `allowed` |
| 15 | public | hidden | anonymous | `search` | **allow** | `200` | yes | `allowed` |
| 16 | public | hidden | anonymous | `addons` | **allow** | `200` | yes | `allowed` |
| 17 | public | hidden | non-member | `proxy` | **allow** | `200` | yes | `allowed` |
| 18 | public | hidden | non-member | `download` | **allow** | `200` | yes | `allowed` |
| 19 | public | hidden | non-member | `search` | **allow** | `200` | yes | `allowed` |
| 20 | public | hidden | non-member | `addons` | **allow** | `200` | yes | `allowed` |
| 21 | public | hidden | member | `proxy` | **allow** | `200` | yes | `allowed` |
| 22 | public | hidden | member | `download` | **allow** | `200` | yes | `allowed` |
| 23 | public | hidden | member | `search` | **allow** | `200` | yes | `allowed` |
| 24 | public | hidden | member | `addons` | **allow** | `200` | yes | `allowed` |
| 25 | private | active | anonymous | `proxy` | **deny** | `404` | no | `version_visibility` |
| 26 | private | active | anonymous | `download` | **deny** | `404` | no | `version_visibility` |
| 27 | private | active | anonymous | `search` | **deny** | `404` | no | `version_visibility` |
| 28 | private | active | anonymous | `addons` | **deny** | `404` | no | `version_visibility` |
| 29 | private | active | non-member | `proxy` | **deny** | `404` | no | `version_visibility` |
| 30 | private | active | non-member | `download` | **deny** | `404` | no | `version_visibility` |
| 31 | private | active | non-member | `search` | **deny** | `404` | no | `version_visibility` |
| 32 | private | active | non-member | `addons` | **deny** | `404` | no | `version_visibility` |
| 33 | private | active | member | `proxy` | **allow** | `200` | no | `allowed` |
| 34 | private | active | member | `download` | **allow** | `200` | no | `allowed` |
| 35 | private | active | member | `search` | **allow** | `200` | no | `allowed` |
| 36 | private | active | member | `addons` | **allow** | `200` | no | `allowed` |
| 37 | private | hidden | anonymous | `proxy` | **deny** | `404` | no | `version_visibility` |
| 38 | private | hidden | anonymous | `download` | **deny** | `404` | no | `version_visibility` |
| 39 | private | hidden | anonymous | `search` | **deny** | `404` | no | `version_visibility` |
| 40 | private | hidden | anonymous | `addons` | **deny** | `404` | no | `version_visibility` |
| 41 | private | hidden | non-member | `proxy` | **deny** | `404` | no | `version_visibility` |
| 42 | private | hidden | non-member | `download` | **deny** | `404` | no | `version_visibility` |
| 43 | private | hidden | non-member | `search` | **deny** | `404` | no | `version_visibility` |
| 44 | private | hidden | non-member | `addons` | **deny** | `404` | no | `version_visibility` |
| 45 | private | hidden | member | `proxy` | **allow** | `200` | no | `allowed` |
| 46 | private | hidden | member | `download` | **allow** | `200` | no | `allowed` |
| 47 | private | hidden | member | `search` | **allow** | `200` | no | `allowed` |
| 48 | private | hidden | member | `addons` | **allow** | `200` | no | `allowed` |

<!-- END GENERATED: decision-table -->

## Reading the decision from outside

Every documentation response carries `X-DocUp-Decision`, naming the outcome, the
reason code, the rule position that decided it and the leaf that satisfied it:

```
X-DocUp-Decision: allow:allowed;rule=3;by=binding
X-DocUp-Decision: deny:version_visibility
X-DocUp-Decision: challenge:credential_rejected
```

The reason codes are a fixed vocabulary, one per conjunct of the decision. They
name **which check refused** and never what exists — `project_visibility` is
true of every path on a guarded project, including the thousands that do not
exist.

Denials and challenges are also recorded individually in `access_decisions`,
kept for 90 days. Allows are aggregated to one row per session, version, hour
and surface, because a reader opening a page with sixty assets authorises sixty
times and sixty rows per page view is the shape that makes an access log
unaffordable and then switched off.
