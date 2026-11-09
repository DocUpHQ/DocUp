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
| `../../Support/BrandingHostiles.php` | The hostile SVGs, the GIF/HTML polyglot and the pixel bomb, one method per `builder` name. PHP, for the reason the archive builders are. |

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
| `runner` | §8.5.13 the typed run specification and fixed argv template, §8.5.7 credential separation, §8.5.21 log caps | 06, 07 |
| `provider` | §8.12.4 the installation-scope narrowing, §8.12.18 framework-enforced protocol validation, §8.12.19 the binding lifecycle, §8.12.23 the disclosure boundary | 23, 26b |
| `branding` | §8.14.2 the token grammar, §8.14.3 structured chrome content, §8.14.8 no tenant code below installation, §8.14.11 the asset pipeline, §8.14.13 email slots, §8.14.16 frame-ancestors | 27 |

### Phase 05 restated the `git_url` expectations

`git_url-001` to `-008` were authored in Phase 00 and say only `reject`, which rule 3
asks us to improve on: an expected outcome is a status code or a **stable error
identifier**. Phase 05's exit criteria require five named vectors — `ext::sh -c id`,
`file:///etc/passwd`, a `169.254.169.254` host, a TTL-0 rebind target and a redirect into
private space — to be refused **with distinct errors**, and `reject` cannot tell five
controls apart. One surviving control would keep all five cases green while four had
regressed.

`git_url-009` to `-017` therefore restate those vectors against the exact
`App\Source\SourceRejection` identifier each must produce, and add the encodings a deny
list written in dotted quads does not recognise (IPv4-mapped, NAT64). The originals are
kept, per rule 1: they are coarse, not wrong, and they still pass.

### Phase 06 added the `runner` category

Six cases covering the build pipeline's own attack surface: a `build.os` value
carrying extra `docker run` flags, a command argument spelled like a flag, control
characters in argv, a run specification asking for a credential in the build stage, the
`post_checkout` credential probe that is Phase 06's own exit criterion, and the §8.5.21
log caps.

🛑 Two of them are **not** "reject" cases, and the distinction is the interesting part.
`runner-002` asserts a flag-shaped argument is accepted *as an argument* and lands after
the image, where Docker does not read it — refusing every argument that starts with a
dash would break legitimate build commands. `runner-006` asserts a 12 MB log is **capped
rather than failed**: a chatty generator has not done anything wrong, and turning
verbosity into a build failure would be worse than a truncated log.

`runner-005` runs in the `runner` container rather than the application one, because
§8.5.13 keeps the Docker client out of every other image — a test that could drive
containers from the application container would itself be evidence the separation had
been lost.

### Phase 25 restated the `saml` expectations, and the corpus became a gate

`saml-001` to `-014` were authored in Phase 00 and say only `reject` — the same
shortcoming Phase 05 found in `git_url`, and here it matters more, because §17 makes
this category a **release gate**: "adding a case that passes incorrectly fails CI."

`reject` cannot tell fourteen controls apart. One surviving control would keep every
case green while thirteen had regressed, which is exactly what "passes incorrectly"
means. So `saml-015` to `-035` restate each vector against the exact
`App\Auth\Providers\Saml\SamlRejection` identifier it must produce, and
`tests/Feature/Saml/SamlCorpusTest.php` enforces four things a review cannot:

1. every `expect` is an identifier the enum really has, so a rename breaks the build
   rather than orphaning a case;
2. **a case numbered above the originals may not say `reject`** — "do not weaken a
   case" is not "may stay coarse for ever", and the boundary is where Phase 00 ends;
3. every case names a proof that exists, and every proof a case;
4. §17's seven named failures are each proved **at the route**, because an audit event
   is something an HTTP request raises — a controller that swallowed the reason or
   recorded one shared action would keep an exception-level test green.

The originals are kept, per rule 1: they are coarse, not wrong, and they still pass.
Each original and its restatement share one proof, because they are one vector asserted
at two precisions.

🛑 Five of the twenty-one are **new vectors**, not restatements, and each came out of
building Phase 25 rather than out of a list:

- `saml-018` is the second signature-wrapping variant. `saml-003` hides the real
  assertion and leaves the read element unsigned, so it is correctly a
  `signature_missing` — the *wrapped* report needs an attack that keeps the signature
  valid and misdirects its reference. Two variants, two outcomes; reporting either as
  the other would tell an operator they were being attacked in a way they were not.
- `saml-027` is entity expansion with **no external entity**, which a network-level
  defence does not see at all.
- `saml-031` and `-032` are a multi-tenant identity provider signing for several entity
  ids with one key: the certificate then proves "this provider" and not "this tenant",
  so `<Issuer>` is checked on the Response *and* the Assertion. The two elements are
  separately signed and therefore separately forgeable.
- `saml-033` to `-035` are the exchange rather than the document: a forged `RelayState`,
  the same response POSTed twice, and one exchange's assertion presented with another's
  `RelayState`.

### Phase 26b added ten `provider` cases, and two of them are not attacks

🛑 **Eight are.** Four come from the two authentication bypasses this phase
closed, and both are bypasses of a *default configuration* rather than of code:

- `provider-014` — nginx's `ssl_verify_client optional` forwards
  `$ssl_client_escaped_cert` **even when verification failed**, and the issuer DN
  is a field in a document the attacker wrote. The verdict header is mandatory
  because of this, not as hardening.
- `provider-015` — a terminator that sets its identity header only for an
  *authenticated* reader passes an unauthenticated reader's own header straight
  through. oauth2-proxy's default, and a one-curl bypass.
- `provider-016` — `header_up +X-Foo` **appends**, so a conditional terminator
  lets a client's value through beside the operator's. Taking the first of two is
  choosing between them on an ordering nothing guarantees.
- `provider-017` — the disclosure boundary in the *other* direction: an
  unparseable certificate must be `unsatisfied`, never `rejected`, because a
  terminator forwards headers on every request and one wrong `rejected()` turns
  every private 404 into a 401.

Three more are the directory's: `provider-018`, `provider-019` and
`provider-020` — the username oracle, the empty-password anonymous bind, and the
ambiguous `uid`. `provider-021` is the mixed-case attribute name that made every
group arrive empty.

🛑 **And two are not attacks at all**, which is a deliberate widening of what
this corpus holds. `provider-022` is an installation-scoped binding that could
not provision a reader, and `provider-023` is a CSRF exemption that named the
wrong class and exempted nothing. Neither is something an attacker does; both are
a control written at one end with nothing at the other honouring it — the shape
this phase found six times. A corpus that only held attacks would have no room
for the defect class that produced most of them.

Rule 3 still holds for all ten: each names a status code or a stable identifier.
Two vocabularies were **declared** rather than described in prose for this
— `LdapRejection` and `MtlsRejection` — so a case naming an outcome that no
longer exists fails CI instead of reading as plausible.

### Phase 27 added forty `branding` cases, and five of them are not rejections

🛑 **Those five are the interesting part**, and they are why this category needed
two declared non-rejection outcomes rather than one coarse `reject`:

- `branding-019` — an announcement carrying a `<script>` and an `onerror` image
  is **sanitised**, not refused. §8.14.3 gives the announcement "a tiny
  inline-tag allowlist", so the emphasis survives and the script does not.
  Refusing the whole announcement would be easier to implement and would mean
  every tenant whose rich-text editor emitted a stray tag got an error they
  could not act on.
- `branding-023`, `-024`, `-027` to `-030` — an SVG logo carrying script, an
  event handler, a `foreignObject`, an external `<use>`, a SMIL `animate`
  writing `href`, or a `style` attribute with a remote `url()` is
  **sanitised**. §17's own criterion is "sanitised **and renders**", so a case
  asserting a refusal would assert the opposite of the requirement.
- `branding-032` — a GIF whose bytes continue into an HTML document with a
  script is **accepted**. §8.14.11 re-encodes rather than inspects, so the
  stored bytes are a PNG DocUp wrote from pixels and the attacker's bytes are
  simply not in it. The test asserts that of the **stored** file, which is what
  the claim actually is; asserting only that the upload succeeded would pass for
  a pipeline that stored the polyglot verbatim.
- `branding-039` — an email slot carrying raw HTML is **accepted** and inert.
  §8.14.13 is "Markdown with HTML **disabled**", and disabled means the text is
  escaped before any construct is matched, so by the time a pattern runs every
  `<` is already `&lt;`.

🛑 **And three are refusals where the rest of the pipeline sanitises**, which is
the one asymmetry worth understanding. `branding-025` (a DOCTYPE declaring an
external entity), `branding-026` (entity expansion with no external entity) and
`branding-031` (an HTML root element) are refused outright, because a DOCTYPE
acts on the **parser** — upstream of any allowlist — and a document whose
meaning depends on a declaration DocUp refuses to expand is better refused than
silently reinterpreted.

Rule 3 holds for all forty: each names an exact `App\Branding\TokenRejection`
value or one of the two declared outcomes, `sanitised` and `accepted`.
`BrandingCorpusTest` enforces four things a review cannot — every `expect` is an
outcome that exists, every case names a `subject` the test has a driver for,
every `builder` a case names exists, and every case produces what it claims.

🛑 One case records a mistake rather than an attack. `branding-040`'s first draft
used `scheme.default` at mount scope and was **wrong**: §8.14.1 gives that token
*version* depth, and a version is deeper than a mount, so the write is correctly
allowed. The case now uses `security.frame-ancestors`, which §8.14.16 makes per
project — and the note keeps the error, because a depth check has two directions
and it is easy to test only one.

## Adding a case

Append to `corpus.json`. Give it the next free `id` in its category, name the requirement
in `defends`, and state `expect` as a status code or a stable error identifier. If the case
needs a binary or XML artefact, add the named mutation to the relevant builder rather than
committing the artefact.
