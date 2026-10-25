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

🛑 The `single_pass` column is **Phase 15's behaviour, written down now**, which
is what SPEC 8.7.13 asks for: the difference has to be explicit before anyone
builds against it. `ModeBehaviour::implementedIn()` says which column is live, so
no test can assert an aspiration by accident.

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

## Phase 17 moves this

SPEC 8.7.13 says "the operator documentation", and this repository has no
published manual yet — Phase 17 is where DocUp's own documentation is split
across three repositories and served by the installation itself. This file is the
convention the other namespaces already use (`app/Serving/README.md`,
`app/Artifacts/README.md`), and the table moves into the manual then; the
generator and its test move with it.
