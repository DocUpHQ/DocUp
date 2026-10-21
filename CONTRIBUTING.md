<!-- SPDX-FileCopyrightText: 2026 The DocUp contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to DocUp

DocUp executes arbitrary code from untrusted repositories and serves
attacker-controlled HTML on operator-owned domains. Most of the rules below
exist because of that one sentence. Where a rule has a reason, the reason is
written next to it — a constraint whose reason is missing gets removed by
someone who cannot see what it was protecting.

Found a vulnerability? **Do not open an issue.** See [SECURITY.md](SECURITY.md).

---

## 1. Developer Certificate of Origin

Every commit must be signed off. DocUp uses the
[DCO](https://developercertificate.org/) — not a CLA. You keep your copyright;
you assert that you have the right to contribute the code.

```bash
git commit -s -m "Fix the thing"
```

That appends one line, which must match your commit author identity:

```
Signed-off-by: Jane Developer <jane@example.com>
```

Set it once and forget it:

```bash
git config user.name  "Jane Developer"
git config user.email "jane@example.com"
```

Forgot on the last commit? `git commit --amend -s --no-edit`. Forgot across
several? `git rebase --signoff main`.

CI checks every commit in the pull request, not just the tip. We would rather
the robot told you than a maintainer did.

**Why DCO and not a CLA.** A CLA asks you to assign rights to an entity, and an
entity that holds assigned rights can relicense. §4.4 of the specification
pledges that DocUp will not become open-core. Not collecting the rights that
would make that possible is a stronger guarantee than promising not to use them.

## 2. Before you start writing

Three documents, in this order:

1. **`_docs/01-CORE-SPECIFICATION.md`** — the single source of truth for what is
   being built, what is deliberately **out** of scope (§4.2 lists 26 exclusions,
   each with its reason), how it is modelled, and in what order (§17).
2. **`_docs/readme.md`** — the build log. Where the build actually stands now.
   The specification is the plan; the build log is the record.
3. **`_docs/adr/`** — why a decision was made, with the rejected alternative
   named. §19 holds the index.

The specification is numbered so it can be cited precisely. Cite sections
(§8.9.6) in commit messages, code comments and pull requests rather than
paraphrasing them.

**If the specification is wrong, say so.** §1.1 defines the amendment protocol:
a failed assumption is struck in place, marked **FAILED** with its phase and
date, and what it cost is recorded. A failed assumption with its consequence
written down is more valuable than a deleted one. Silently diverging from the
specification is the one thing that will get a pull request closed unread.

Open an issue before a large change. A rejected pull request is a worse outcome
for you than a redirected issue, and scope is the usual reason for rejection.

## 3. Local setup

```bash
cp .env.example .env
docker compose -f compose.yaml -f compose.dev.yaml up -d
docker compose exec app php artisan docup:install
docker compose exec app php artisan docup:doctor
```

`compose.dev.yaml` adds MailPit and phpMyAdmin, both bound to loopback only.
🛑 They are **absent from `compose.yaml` as images**, not merely disabled, and a
test asserts both halves — absent from production, present in development.
A test that only checked absence would pass if someone deleted them from both.

🛑 **The dashboard and documentation origins must be different registrable
domains or the application refuses to boot** (§8.1.4). `app.example.com` and
`docs.example.com` are *not* separate — they share `example.com`, so a cookie
or a stored XSS crosses between them. This will be the first thing that stops
your container starting, and it is working as intended.

## 4. The quality gates

§9.4 defines three tiers. The baseline tier runs on every push, and you can run
all of it locally:

| Gate | Command |
|---|---|
| Style | `./vendor/bin/pint` |
| Static analysis, level 8 repo-wide | `./vendor/bin/phpstan analyse` |
| Static analysis, level 9 in the strict namespaces | `./vendor/bin/phpstan analyse -c phpstan-strict.neon` |
| Tests | `./vendor/bin/pest` |
| Data classification | `php artisan docup:classify --check` |
| Dependency advisories | `composer audit` |

Level 9 applies in `app/Serving`, `app/Auth`, `app/Artifacts` and `app/Config`.
Each of those directories has a `README.md` saying why. Code that decides
whether a byte is public does not get to be vague about a type.

🛑 **Never lower a gate to make a change pass.** Thresholds are committed
configuration, and CI fails when one decreases — the check needs two approvals
under `CODEOWNERS`, because the change that lowers the bar is the change that
would be reviewing its own pull request. If a gate is genuinely wrong, propose
the amendment and say what it costs. Do not route around it.

## 5. Tests

Every behaviour change ships with tests **in the same commit**. Not the next
one.

- Every requirement marked 🛑 in the specification gets at least one test that
  would **fail if the requirement were violated**. A test that passes whether or
  not the rule holds is worse than no test, because it reads like coverage.
- Security-critical changes additionally append a named case to the permanent
  **abuse corpus** (§9.4). The corpus is **append-only**: cases are never
  deleted, never rewritten, and never relaxed to accommodate a change in
  behaviour. It is the project's memory of every hostile input anyone has
  thought of.
- Every migration that creates columns classifies them **in the same migration**
  (§8.22.7). An unclassified column cannot be covered by subject-access export
  or erasure, and the first one forgotten is the one that matters.
- Tests that exercise `BINARY(16)` keys, generated columns or `FULLTEXT` run
  against **real MySQL**. SQLite would pass while proving nothing.

### Scope the run

A full suite run is a release activity, not a per-change reflex.

| When | Run |
|---|---|
| While working | `./vendor/bin/pest --dirty` or `--filter=...` |
| Finishing a unit of work | The affected suites, plus Pint, PHPStan and the architecture tests |
| Touching a frozen interface, or before a release | `./vendor/bin/pest --parallel` |

🛑 **Three things always run, however narrow the change**, because they are fast
and they guard the catastrophic class:

- the **architecture tests** (`./vendor/bin/pest --filter=Arch`);
- the **private-asset containment self-test** (§8.12.22) — fetches a known
  private asset through the real edge with no credentials and fails on any
  `200`;
- the **build-network isolation self-test** (§8.5.12).

CI runs the full suite on every push. That is CI's job; you do not need to
duplicate it locally.

## 6. Code

Code is written to be read, audited and maintained by people who did not write
it.

- **Comments explain *why*, never *what*.** The code already says what. Where
  code implements a 🛑 requirement or a non-obvious security boundary, cite the
  section — for example, a comment reading "§8.9.6 — reject before any cache
  lookup; this ordering is the whole defence".
- **PHPDoc on every public method**, with the types and the exceptions thrown.
- **Match the surrounding code.** Its naming, its idiom, its comment density.
  Consistency beats personal preference, including ours.
- **SPDX headers on every new first-party file**, before `declare(strict_types=1)`.
- Some invariants are enforced by architecture test rather than by review, and
  they are listed in §4.3. Do not fight them: UUIDv7 `BINARY(16)` keys with
  exactly one allowlisted `AUTO_INCREMENT`; security tokens CSPRNG, stored
  hashed and **never** UUIDv7 (v7 embeds a readable timestamp); one
  `ArtifactIngestor`, one `Resolver`, one `EffectiveAccess`, one
  `HardenedEgressClient`, each the sole call site; documentation bytes never
  traverse PHP; no trusted project-resolution request header, in any
  environment; private content never carrying a public cache directive; and no
  `EntitlementResolver` or licence-key path, because there is no open core.

## 7. Commits and pull requests

- **Branch per unit of work.** `main` is always releasable (§15.6).
- **Imperative subject**, with the phase and the specification section in the
  body:

  ```
  Add the credential-free artifact fetcher

  Phase 06: §8.5.7. Credentials reach the fetcher only through a file
  descriptor, never the environment or the command line, because both are
  readable from inside the build container.

  Signed-off-by: Jane Developer <jane@example.com>
  ```

- 🛑 **Stage explicit paths.** Never `git add -A`, `git add .` or `git commit -a`.
  One careless bulk add is how a secret or a scratch file enters history
  permanently. Run `git status --short` before every commit and read it;
  anything unexpected is a stop, not a shrug.
- 🛑 **Never commit secrets** — no `.env`, no keys, no certificates, no tokens.
  Not in fixtures, not in test data, not commented out. Use the project's seed
  and example-config files for test values.
- Keep pull requests to one concern. Say what you verified and what you could
  not. "I could not test the nginx profile" is useful; silence is not.

## 8. Reviews

Maintainers aim to triage within the SLAs in §15.6. A review that asks for
changes is not a rejection — most changes to the serving and authentication
paths go round twice, including ours.

If a review asks "why is this safe?", the answer belongs in a comment in the
code, not only in the pull request thread. The next reader will not have the
thread.

## 9. Licence and marks

Contributions are licensed under Apache-2.0 (`LICENSE`). You retain your
copyright. The licence covers the software, not the name or the logo — see
[TRADEMARKS.md](TRADEMARKS.md), which also confirms that forking is always
allowed, including in disagreement with us.
