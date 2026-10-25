# app/Composition

🛑 **PHPStan level 9 applies here**, not the repository-wide level 8 (SPEC 9.4),
raised in Phase 13 on SPEC 8.7.7's own words: an unchecked mount is "a
declassification primitive in a product whose headline feature is per-project
authentication".

Owner phases: components and one-repository-to-many-projects → P13;
many-repositories-to-one-project (`mount` mode) → P14; `single_pass` → P15;
collections and translations → P16.

## SPEC 8.7.13 — the mode × behaviour matrix

> "The system MUST document, as a table in the operator documentation and
> asserted by tests, how each mode behaves for: navigation source, search
> document provenance, the 404 chain, cross-reference mechanism, offline-format
> emission, provenance record, the effect of one contributor build failing, and
> fragment cacheability. The two modes are different products; leaving the
> difference implicit is the single largest specification risk in the
> composition area."

🛑 **This table is generated from `App\Composition\ModeBehaviour` and must not be
edited by hand.** `ModeBehaviourTest` re-renders it and compares, so the code and
the documentation are one statement with two readers rather than two statements
that drift. Change `ModeBehaviour::table()` and run the test; it will tell you
what this file should say.

Both columns are **behaviour** as of Phase 15. Phase 14 shipped `mount` and wrote
the `single_pass` column as a statement of intent, which is what SPEC 8.7.13 asks
for — the difference has to be explicit before anyone builds against it. Phase 15
built it, and `ModeBehaviour::implementedIn()` now answers true for both.

| Behaviour | `mount` (default, serve-time) | `single_pass` (opt-in, build-time) |
|---|---|---|
| **Navigation source** | Per-component nav fragments (§8.7.6), spliced into the project version's layout tree with each mount's prefix applied to every href. | The one generator's own navigation for the whole site. There is one build, so there is one nav and nothing to splice. |
| **Search document provenance** | Each document belongs to the component whose build produced it, so a result can name the contributing repository and commit. | Documents belong to the composed build. The contributing source is recoverable only from the path, because one build produced them all. |
| **404 chain** | Longest-prefix mount match, then that build's file manifest, then the primary mount's 404.html (§8.7.3). A miss inside one mount never falls through to another mount's content. | One file manifest for the whole version, so the 404 chain has one step and the 404.html is the composed build's. |
| **Cross-reference mechanism** | Serve-time 302 through /_/x/{component_key}/{path} against the published manifest, with objects.inv served directly (§8.7.16). | Resolved inside the build by the generator's own mechanism — Antora xref, real intersphinx — so no redirect is involved. |
| **Offline-format emission** | Primary mount only (§8.7.19). A non-primary mount's pdf, epub or htmlzip is not served. | The composed build's, covering every source at once, which is the one thing single_pass gives that mount cannot. |
| **Provenance record** | One provenance.json per component build, and the version manifest names which build served which mount (§8.7.21). | One provenance.json naming every contributing source and commit, because one container saw them all. |
| **One contributor build failing** | The live composition keeps serving: the failed build is not a selector candidate, so the mount resolves to its previous success (§8.7.20). | The whole publication fails. One sandbox, one exit code — which is the cost of the shared namespace single_pass exists for. |
| **Fragment cacheability** | Cacheable per source (§8.5.19), and shareable between projects when base_url_mode is relative. | Not cacheable per source: the output of one source depends on the others, which is what the shared pass is for. |

`overlay` is absent because SPEC 8.7.12 defers it past 1.0: "it is a shadow-content
vector by construction, including replacement of another team's security notices,
for a capability nobody asked for."

## SPEC 8.7.12 — who writes the source list, per preset

> "with **DocUp generating the playbook or include file from the resolved plan**
> so a contributing repository cannot redirect sources or add a fourth
> repository."

🛑 **This table is generated from `App\Composition\SinglePass\Composer::PRECEDENCE`.**
It is a **closed** table: every shipped preset has an entry, and a preset with no
generator is **refused** rather than built. That is the whole of the mode's safety
argument in one place — a toolchain DocUp cannot write the source list for is a
toolchain where the repository writes it.

A refusal rather than a fallback to `mount`, for the reason the matrix above
exists: a project set to `single_pass` and quietly served under `mount`'s rules
would have a different 404 chain, a different cross-reference mechanism and a
different failure domain from the one its operator chose.

| Preset | `single_pass` | What happens to the repository's own configuration |
|---|---|---|
| `antora` | **supported** | DocUp writes the playbook into `/workspace/composition` and points Antora at it with no `--fetch`. A repository's own `antora-playbook.yml` stays on disk and is **never read**, so it can neither add a source nor redirect one. Each source's own `antora.yml` is still authoritative for its component name, version and nav — that is the source's own content, not the site's shape. |
| `mkdocs` | refused | Not supported. `mkdocs-monorepo-plugin` composes through `!include`, which reads a path out of the included file — so a contributing repository would be able to name a fourth source from inside its own `mkdocs.yml`, which §8.7.12 forbids. Composing MkDocs safely means DocUp generating a file per source and discarding each repository's own, and that is a different feature from including theirs. |
| `sphinx` | refused | Not supported. §8.7.12 names `sphinx-multiproject`, but that extension selects **one** docset per build through a `PROJECT` environment variable — it is a one-repository-many-docsets tool, not a many-repositories-one-site one. Sphinx's actual answer to this shape is intersphinx, which is `mount` mode plus §8.7.16. Recorded as a proposed amendment to §8.7.12. |
| `mdbook` | refused | Not supported. mdBook has one `SUMMARY.md` and one source root by design. |
| `docusaurus` | refused | Not supported. Multi-instance plugins compose docsets inside one repository, not across checkouts, and the configuration that would do it is the repository's own JavaScript. |
| `vitepress` | refused | Not supported, for the same reason as Docusaurus: the configuration is executable and is the repository's. |
| `starlight` | refused | Not supported, for the same reason as Docusaurus. |

### How the Antora guarantee actually holds

Two properties, and neither is "Antora is well behaved":

1. **The generated playbook lives at `/workspace/composition`**, a sibling of the
   checkouts. No contributing repository can contain that path, so none can ship a
   file that is mistaken for it or overwrite it before the generator reads it.
2. **Antora is pointed at that file and at nothing else**, and the preset does not
   pass `--fetch`. A repository's own `antora-playbook.yml` is still on disk and is
   simply never named.

`SinglePassCompositionTest` asserts it from the other side: a fixture whose own
playbook lists a fourth content source builds a site with three.

## Phase 17 moves this

SPEC 8.7.13 says "the operator documentation", and this repository has no
published manual yet — Phase 17 is where DocUp's own documentation is split
across three repositories and served by the installation itself. This file is the
convention the other namespaces already use (`app/Serving/README.md`,
`app/Artifacts/README.md`), and both tables move into the manual then; the
generators and their tests move with them.
