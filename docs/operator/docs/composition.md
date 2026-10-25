# Composition modes

One DocUp project can serve documentation from several repositories as one
site. A repository contributes a **component**: an identity that belongs to
your organisation rather than to a repository, so moving the code somewhere
else changes one row and no URL.

A project version then **mounts** components at path prefixes. Three
repositories mounted at `""`, `author` and `reference` serve as one manual, and
a reader never learns there were three.

## Two modes, and they are different products

`mount` is the default and composes at **serve time**: each component builds on
its own, and the project's published manifest routes each URL prefix to the
build behind it. `single_pass` composes at **build time**: every source is
checked out side by side in one sandbox and one toolchain run produces the
whole site.

Pick `mount` unless your generator's own cross-source machinery is the reason
you are here. `single_pass` exists for Antora, where a site is a playbook over
several content sources and splitting it would lose exactly the feature you
wanted.

!!! note "Choosing is not a formatting preference"

    The two modes differ in where navigation comes from, what happens when one
    contributor's build fails, and whether a broken cross-reference is a link
    issue or a build failure. Read the table before switching a live project.

### The behaviour matrix

<!-- BEGIN GENERATED: mode-matrix -->

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

<!-- END GENERATED: mode-matrix -->

### Which generators `single_pass` supports

`single_pass` is not a fallback. A preset DocUp cannot compose safely is
**refused** rather than quietly served under `mount`'s rules, because a silent
fallback would give a project a different 404 chain, a different
cross-reference mechanism and a different failure domain from the one you
chose.

<!-- BEGIN GENERATED: single-pass-precedence -->

| Preset | `single_pass` | What happens to the repository's own configuration |
|---|---|---|
| `antora` | **supported** | DocUp writes the playbook into `/workspace/composition` and points Antora at it with no `--fetch`. A repository's own `antora-playbook.yml` stays on disk and is **never read**, so it can neither add a source nor redirect one. Each source's own `antora.yml` is still authoritative for its component name, version and nav — that is the source's own content, not the site's shape. |
| `mkdocs` | refused | Not supported. `mkdocs-monorepo-plugin` composes through `!include`, which reads a path out of the included file — so a contributing repository would be able to name a fourth source from inside its own `mkdocs.yml`, which §8.7.12 forbids. Composing MkDocs safely means DocUp generating a file per source and discarding each repository's own, and that is a different feature from including theirs. |
| `sphinx` | refused | Not supported. §8.7.12 names `sphinx-multiproject`, but that extension selects **one** docset per build through a `PROJECT` environment variable — it is a one-repository-many-docsets tool, not a many-repositories-one-site one. Sphinx's actual answer to this shape is intersphinx, which is `mount` mode plus §8.7.16. Recorded as a proposed amendment to §8.7.12. |
| `mdbook` | refused | Not supported. mdBook has one `SUMMARY.md` and one source root by design. |
| `docusaurus` | refused | Not supported. Multi-instance plugins compose docsets inside one repository, not across checkouts, and the configuration that would do it is the repository's own JavaScript. |
| `vitepress` | refused | Not supported, for the same reason as Docusaurus: the configuration is executable and is the repository's. |
| `starlight` | refused | Not supported, for the same reason as Docusaurus. |

<!-- END GENERATED: single-pass-precedence -->

## What a collision does

Two components that both produce `index.html` at the same URL fail the build,
naming **both** sources and the exact path. That is the default and it is the
right one: the alternative is a site where which repository won depends on the
order two builds finished.

A new mount whose path is a prefix of an existing one — `api` under `api/v2` —
is refused for the same reason, unless you override it explicitly. The override
is audited and generates redirects so the shadowed paths keep resolving.

## Seeing what is actually served

`/_/composition` on the documentation host answers "which commit of which
repository produced this URL?" for every published version: each component, the
resolved ref, the commit, the build id and the build time. It is the answer to
an auditor's question, and it is readable without the dashboard.
