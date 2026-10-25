# Operating DocUp

DocUp is a self-hosted documentation portal: a Read the Docs alternative you
run yourself, under Apache-2.0, with no open core and no licence key.

This guide is for the person who installs and runs it. **Writing for DocUp**
is for the person who writes documentation in a repository, and the
**`.docup.yaml` reference** is the per-key contract. Both are in the
navigation beside this guide.

!!! note "Why those two are not links"

    This manual is three repositories composed into one site, and a
    cross-repository link has no spelling that is correct in both places: a
    relative path is wrong once a component is mounted somewhere else, and
    the serve-time form DocUp provides for exactly this
    (`/_/x/<component>/<path>`) is a dead link in the plain `mkdocs build`
    fallback. Moving between guides is the navigation's job, which is the
    layer designed to span components.

## Two origins, and why that is not negotiable

DocUp serves from **two registrable domains** and refuses to boot if you give
it one:

| Origin | What it serves |
|---|---|
| the dashboard | the application: sign-in, projects, builds, settings |
| the documentation apex | built documentation, on per-project subdomains and custom domains |

Built documentation is attacker-controlled HTML and JavaScript. On a shared
registrable domain it can set cookies the dashboard will read, `Clear-Site-Data`
across tenants, and reach anything a subdomain of the dashboard is trusted for.
Separating the origins is what makes "any repository may publish here" safe,
so the boot assertion is deliberate rather than fussy.

There is one escape hatch, `DOCUP_UNSAFE_SINGLE_ORIGIN`, and it forces every
project public and disables private sharing and tenant CSS. It exists for a
laptop, not for an installation.

## What DocUp does not do

Stated here because an operator evaluating it deserves the boundaries up
front, not after the migration:

- **No serve-time rewriting of documentation.** Nothing in the request path
  reads or modifies a documentation byte: the application authorises and the
  web server sends the file. Reader chrome is injected once, at artifact
  ingest.
- **No open core.** There is no entitlement check, no licence path and no
  feature behind a plan. An architecture test fails the build if one appears.
- **No unsigned webhook endpoint.** Every incoming hook is signed and
  replay-checked; the generic unsigned endpoint other products ship is a
  build-trigger oracle and does not exist here.

## Where to go next

- [Installing](installing.md) — the compose stack, the one manual step, and
  what `docup:doctor` checks.
- [Composition modes](composition.md) — how one project serves several
  repositories, and the behaviour table that differs between the two modes.
- [Running it](operations.md) — the scheduler, backups, the build sandbox.
