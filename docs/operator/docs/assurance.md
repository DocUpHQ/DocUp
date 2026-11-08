# Proving who may read it

You can configure access correctly and be wrong about it. The policy language
is first-match-wins over an ordered list, the lattice has four authoritative
columns, and a rule points at a binding that lives in another table — so a
policy that *reads* as a restriction can admit anybody, and a rule you wrote
last March can stop being reachable because of a rule somebody else wrote this
week.

This page is about the two tools that close that gap: the **policy simulator**,
which answers "as this identity, on this URL", and the **nightly linter**,
which tells you when an edit changed what a rule can do.

Neither of them is a second opinion. The simulator asks the same function a
real request asks, and the linter reads the same rules the same way. That is
deliberate: a tool that agreed with the product most of the time would be worse
than no tool, because you would believe it.

## The policy simulator

On any project you administer: **Policy → Simulate**.

You pick an identity and a URL. It answers with the verdict, the rule that
decided, the binding that satisfied it, and — the part people do not expect to
need — **how the URL was understood**.

```
Allowed
allow:allowed;rule=1;by=binding;binding=Acme employees

Rule                 rule 1 — employees read the handbook (allow)
Satisfied by         binding — binding "Acme employees"
Reason               allowed
Level                required restricted, established restricted
Resolved to          handbook · en/v1
Policy saw path      guide/index.html
Routed by            version.explicit
```

### Read the path line first

`Policy saw path` is the one that catches most mistakes. A reader types
`/en/v1/guide/index.html`; your rules are written **relative to the component
mount**, so the policy saw `guide/index.html`. A rule written `/en/v1/guide`
matches nothing at all — silently, with the section you meant to protect
governed by whatever rule comes next.

`Routed by` is the routing rule that chose the version and language. If the
simulator reports a version you did not expect, that line says which rule chose
it, and the problem is in your versioning scheme rather than your policy.

### What "as this identity" can and cannot mean

You can simulate:

- **Anonymous** — nobody. Run this one first, on every project you think is
  private. It is the question that catches the mistake that matters.
- **A documentation reader** — a real identity your IdP has vouched for, listed
  by its display label, with the groups it currently carries.
- **A dashboard member** — somebody with an account on this installation.

You can also give an address, which is evaluated against any `ip_allowlist`
binding. It sits beside the identity rather than inside it, because being on a
network does not make somebody anybody.

You **cannot** simulate "somebody holding a share link" or "somebody with a
reader token", and the simulator says so rather than guessing:

> A rule matching this URL depends on **bearer**, which no simulation can
> establish: those credentials are stored hashed, so there is nothing to
> present. A reader holding one may get a different answer.

That message matters as much as the verdict. Without it, two denials that look
identical mean opposite things — "your policy refuses this identity" and "this
identity was never the one that rule is for" — and you would go looking for a
bug in a rule that is working exactly as written.

### Things it will tell you that you may not believe

**"This URL resolves to nothing to authorise."** Not a denial. The URL reached
no published version, so the policy was never consulted. Editing the policy
will not help; check the version, the language and the mount.

**A `members` member refused by your own IdP rule.** The commonest surprise. If
you add a rule requiring your identity provider on a version, that rule matches
for *everybody* — and first-match-wins means it then decides. Your own staff,
signed in to the dashboard with a `members` role, do not carry that binding, so
they are refused by the rule you wrote to protect the page from strangers. The
simulator names the rule. Nothing else will.

**A shadow rule that would have matched.** Shown in blue, below the answer. It
is recorded and not enforced — it is what the policy would do if you promoted
it, which is the cheapest way to test a policy change.

### What it does not do

It mints nothing. No session, no grant, no cookie, and no row in the decision
log — so it is safe to run against production in the middle of an incident,
which is when you will want it. The only trace is one audit event recording
that you asked, because "who can read this" is a question worth having a record
of.

### Who can use it

`project.policy.simulate`, held by installation owners and security admins,
organisation admins and auditors, project admins and maintainers. Deliberately
**not** by `project_writer` or `project_reader`: answering the question means
listing the organisation's reader identities and their groups, which is a
membership list of everybody who has ever signed in to your documentation.

## The nightly linter

`docup:policy:lint` runs at 03:20 UTC. You do not need to configure it.

It does two things every night, and they are different:

1. **Re-validates every rule** against the world as it now is.
2. **Compares every rule to last night** and tells you what changed, and in
   which direction.

### Why re-validation finds things your editor cannot

When you save a rule, DocUp refuses a malformed requirement, a regex path
pattern, a tree satisfiable without any identity, and a binding named as the
wrong kind. Every one of those checks is still true tomorrow.

What is not a property of your rule is the thing it points at. Delete a binding,
disable one, move one out of scope, or change its driver type, and the rule is
still valid, still matches, still takes the first-match slot — and can no longer
be satisfied by anybody. Your project refuses every reader, and the cause is in
a different table.

| Finding | What happened | What to do |
|---|---|---|
| `binding_missing` | the rule names a binding that is gone or out of scope | re-point the rule, or restore the binding |
| `binding_not_active` | the binding exists and is not `active` | finish its verification, or re-point the rule |
| `binding_misclassified` | the binding's driver type changed under the rule | the rule names it as the wrong kind; rewrite the leaf |
| `requirement_unsatisfiable` | no credential could satisfy the tree at all | the above, usually |
| `expired` | `not_after` has passed; the rule can never match again | delete it, or extend it |
| `shadowed` | an earlier rule covers every URL this one selects | reorder, or narrow the earlier rule |

The first four and `expired` make the command **exit non-zero**, so your
monitoring sees them without anybody reading mail. `shadowed` does not: shadow
is often deliberate, and failing a nightly job on a configuration you chose is
how a nightly job gets switched off.

### Direction is the point

When something changes, the organisation's owners get one mail, and it leads
with the widenings:

> **[handbook] 1 access rule now admits more readers**
>
> **More readers can now read more. Check these first:**
>
> • rule 1 (employees read the handbook): widened

The two directions are not symmetric in consequence. A rule narrowed too far
produces a support ticket within the hour from somebody who cannot read their
own documentation. A rule widened too far produces **nothing at all** until it
is found by somebody who was not supposed to find it.

Four edits widen access, and three of them change no requirement:

- a rule's **selectors** widened — more versions, more languages, shorter path
  prefixes
- a rule's **requirement** weakened — most sharply, an identity leaf replaced by
  `public`
- a rule taken **out of shadow**, so it starts being enforced
- a **deny** rule narrowed, which widens access by shrinking a rule

That last one reads backwards and is reported correctly: widening a deny rule's
selectors **narrows** access, because more URLs are refused.

Where the direction cannot be established — you repointed a rule from one
provider to another, say, so a different population can read and neither word is
true — it says `changed` instead of guessing. An alert with the wrong label is
read and dismissed; an honest one gets looked at.

### Reordering is an edit

Under first-match-wins, position **is** semantics. Swap two rules and you have
changed which one decides without changing either, and the linter reports
`moved` on both.

### The first run says nothing

A project's first night records a baseline and alerts about none of it.
Otherwise you would get one mail listing every rule you have, once, and learn to
filter the linter — and its whole value is the one night the message is
different.

### Running it by hand

```
php artisan docup:policy:lint --project=<uuid>
php artisan docup:policy:lint --json
php artisan docup:policy:lint --quiet-alerts
```

`--quiet-alerts` analyses and records without mailing anybody, which is what you
want after a planned change: it moves the baseline forward so tomorrow's mail is
about tomorrow's edits.

## Multi-factor authentication

MFA is enforceable in two places, and both are needed.

**Per installation**, in the environment:

```
DOCUP_MFA_REQUIRED=true
```

**Per organisation**, by an organisation admin, in the organisation's settings.

The installation switch **dominates**: an organisation cannot opt out of what
the installation requires. The reverse ordering would make the per-organisation
setting a way for a tenant administrator to leave your security posture, which
is not a setting.

Both default to off. `MUST be enforceable` is not `MUST be enforced`, and an
upgrade that turned this on would lock out every administrator on the
installation — including the one who would have to turn it off.

### Who it applies to

Everybody holding a role **above `project_writer`**: every installation and
organisation role, and `project_admin` and `project_maintainer`.
`project_writer` and `project_reader` are exempt.

`org_member` is **not** exempt, which surprises people: it carries
`project.create`, and whoever creates a project administers it. A role that can
manufacture administrative scope is above a writer however modest its own list
looks.

The requirement attaches to the **role**, not to the page. If you administer one
organisation and read another, you are an administrator; you do not stop being
one while you are looking at the other.

### What a blocked person sees

A redirect to **Account → Two-factor authentication**, naming the role that
requires it. They are authorised; they have not finished setting up — so it is a
redirect to the page that fixes it rather than a refusal they would have to ask
you about.

The enrolment page, the two-factor endpoints, the password confirmation they
pass through, and logout stay reachable while somebody is blocked. A gate that
blocked the remedy would have to be removed from the database.

A scripted client gets `403` with `"code": "mfa_enrolment_required"` instead,
because there is nobody there to redirect.

### Enrolment is a confirmed secret

Scanning the QR code is not enrolment. The code has to be entered once and
verified. Somebody who opens the enrolment page and closes the tab holds a
secret no authenticator has, and treating that as enrolled would lock them out
with no way back except an operator clearing a column.

Recovery codes are shown **once**, on confirmation. Save them.

## What is not here

- **Passkeys.** Not shipped. The requirement reads "with passkeys where the
  library proves production-ready", and that verification has not been done —
  so TOTP is the only second factor, and enabling an unproven library on the
  authentication path is not a thing to do quietly.
- **A way to exempt one person.** There is none, deliberately. Break-glass
  access with its own audit trail and rate limit is a later phase; until then,
  the switch is per installation and per organisation and nothing finer.
- **Linter alerts to anybody but the organisation's owners.** Notification
  routing — preferences, digests, per-event subscriptions — is a later phase.
  The audit chain records every finding regardless, and `audit.read` reads it.
- **Simulating a share link or a reader token.** The secrets are stored hashed.
  The simulator reports what it cannot establish instead of pretending.
