# The abuse corpus

A permanent, append-only library of hostile inputs. Authored in Phase 00 **before** any
production code, so that later phases append cases rather than inventing attacks under
time pressure (§9.4).

## The rules

1. 🛑 **Append only.** A case is never deleted and never weakened. If a case is wrong,
   add the corrected case and mark the original `superseded_by`. The corpus is evidence;
   shrinking it destroys the evidence.
2. **Every case names the requirement it defends.** A case with no `defends` field cannot
   be reviewed, because nobody can tell what a pass means.
3. **Every case states its expected outcome precisely** — a status code, a stable error
   identifier, or `reject`. "Should fail" is not an expected outcome.
4. 🛑 **Security-critical phases must append at least one case** (§9.4). The phases are
   named there: resolver/edge, runner, sandbox, composition, domains, authorisation,
   reader sessions, identity providers, search.
5. **Cases run in CI on every push** and are a release gate at Phase 37. They are among
   the three suites that always run however narrow the change (CLAUDE.md rule 5), because
   they are fast and they guard the catastrophic class.

## Layout

| Path | Contents |
|---|---|
| `corpus.json` | The machine-readable case index. The single source of truth. |
| `saml/build_saml.py` | Emits the malicious SAML assertions from one valid base by named mutation. Generated, not committed, so the mutation *is* the reviewable artefact. |
| `archives/build_archives.py` | Emits the hostile archives (zip-slip, symlink, hardlink, ratio bomb, reserved filenames). Binary, so generated rather than committed. **Reference only** — see below. |
| `../../Support/HostileArchives.php` | The same archives, in PHP. This is the one CI runs. |
| `../../Support/ArchiveWriter.php` | Writes tar and zip headers by hand, because no library will emit a zip-slip entry or a hard link. |

Run `python saml/build_saml.py` to materialise the XML fixtures into `_generated/`, which is
git-ignored.

### 🛑 The archive builders are PHP, not Python (Phase 03)

`archives/build_archives.py` was written in Phase 00 and **cannot run where it matters**:
neither the application container nor CI has a Python interpreter, so a corpus that depended
on it would have been a corpus that never ran. `tests/Support/HostileArchives.php` emits the
same fixtures, one method per `builder` name, and `ArtifactIngestorTest` drives every
`archive` case in `corpus.json` through it — failing loudly when the corpus names a builder
that does not exist, because a case without a fixture stops running while the suite still
reports green.

The Python script is kept for inspecting a fixture by hand outside the suite. It is not the
gate. If the two disagree, `corpus.json` and the PHP builders are right.

## Categories and what they defend

| Category | Defends | Phase that must not regress |
|---|---|---|
| `path` | §8.9.6 byte-canonical path rejection, before any cache lookup | 04 |
| `cache_deception` | §9.3.2, and the two real Read the Docs advisories (§3.3) | 04 |
| `host` | §8.9.3 host resolution order, §8.10.7 confusable rejection | 04, 18 |
| `archive` | §8.8.2 the single `ArtifactIngestor`, §8.4.5 the output contract | 03 |
| `redirect` | §8.11.3 cycle detection, §8.11.4 regex containment | 20 |
| `config` | §8.4.9 out-of-sandbox parsing under hard caps | 09 |
| `saml` | §8.12.18 framework-enforced protocol validation | 25 |
| `git_url` | §8.3.4 protocol and SSRF rejection | 05 |
| `header` | §8.9.5 inbound header stripping, §8.9.4 no trusted resolver | 04 |

## Adding a case

Append to `corpus.json`. Give it the next free `id` in its category, name the requirement
in `defends`, and state `expect` as a status code or a stable error identifier. If the case
needs a binary or XML artefact, add the named mutation to the relevant builder rather than
committing the artefact.
