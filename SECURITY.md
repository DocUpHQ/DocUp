<!-- SPDX-FileCopyrightText: 2026 The DocUp contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security policy

DocUp executes arbitrary code by design and serves attacker-controlled HTML on
operator-owned domains. We would rather hear about a problem early and awkwardly
than late and politely.

## Reporting a vulnerability

Use **GitHub private vulnerability reporting** on this repository
(Security → Report a vulnerability). That gives us a private fork to work in and
you a place to see progress.

Please do not open a public issue for anything exploitable.

If private reporting is unavailable to you, see `security.txt` for a contact
address.

## What to expect

| | |
|---|---|
| Acknowledgement | within 3 working days |
| Initial assessment | within 10 working days |
| Fix or mitigation plan | agreed with you before any disclosure |
| Credit | yours unless you ask otherwise |

We will agree an embargo date with you. If a fix is going to take longer than
90 days we will say so and explain why rather than letting the clock run.

## Scope

In scope, and taken seriously:

- Anything that lets one tenant read another tenant's private documentation.
- Anything that lets built documentation reach the dashboard session.
- Build sandbox escape, or a build reading credentials it was not given.
- Cache poisoning, or private content entering a shared cache.
- Authorisation bypass on the documentation serving path.

Known and documented, so not a report unless you can do better than the stated
limit:

- Path-prefix access rules are **best-effort** and cannot scrub cross-references
  or anchors out of surrounding HTML. The specification says so.
- An installation running `DOCUP_UNSAFE_SINGLE_ORIGIN` has deliberately traded
  the origin-separation invariant for a degraded, all-public mode.
- Anything behind a flag in the unsafe-modes registry, when that flag is set.

## Our own threat model

The specification carries it: the three structural facts, the leak register, and
the trap list of things that are expensive to discover late. If you are looking
for somewhere to start, start there.
