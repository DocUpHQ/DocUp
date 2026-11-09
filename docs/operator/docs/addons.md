<!-- SPDX-FileCopyrightText: 2026 The DocUp contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reader chrome

Chrome is what DocUp puts on a page of your documentation: the version flyout,
the search control, the notification banners, your brand. It is built from two
tags injected into every HTML document at ingest, plus one request the reader's
browser makes for everything else.

This page is for the operator who needs to know why chrome is missing, how to
turn it off, and — if you are moving from Read the Docs — which of your CSS
overrides still mean something.

## How it works, in one paragraph

When an artifact is ingested, DocUp inserts exactly two tags before the first
`</head>` of every HTML document: a deferred `<script>` at `/_/addons/docup.js`
and `<meta name="docup" content="b=<build id>">`. Neither names your project or
your version — that is deliberate, because an artifact carrying a project
identifier could not be shared between projects, and a stylesheet reference
baked into HTML could not be rebranded without a rebuild. Everything that
varies arrives at runtime from `GET /_/addons`, which is resolved from the
request's own hostname and path and authorised exactly as the document was.

The practical consequence is the one worth remembering: **chrome changes
without a rebuild.** A new logo, a different palette, a banner switched off, the
whole of chrome removed — all of it takes effect on the next request, with not
one byte of your artifacts changed.

## Chrome modes

Set per project.

| Mode | What a reader gets | When to use it |
|---|---|---|
| `injected` | DocUp's chrome, rendered in a closed shadow root. The default. | Almost always. |
| `api_only` | No chrome. The payload still answers, so you can render your own header from it. | You have a design system and want your own chrome. The payload contract is versioned — see below. |
| `off` | No chrome and nothing touched. No cross-reference rewriting, no search takeover, no beacon. | Your theme already does all of this, or you are debugging. |

Switching to `off` removes chrome on the next request. The two injected tags
stay in the artifact — artifacts are immutable, and DocUp never rewrites
documentation at serve time — but the runtime reads the mode from the payload
and does nothing.

### `api_only` and the payload contract

`GET /_/addons` returns a versioned document. `contract` is the envelope's
version and `branding_contract` is the theme payload's; they move independently,
because a new notification banner and a new branding token are changes for
different consumers. Adding a key is not a breaking change. Removing one,
changing a value's grammar, or changing a nested shape is, and gets a new
version with the old one keeping its meaning.

`resources/themes/api-only-reference.json` in the source tree is a complete
worked example, generated from the real token registry, and a test asserts it
matches what DocUp emits.

## Why chrome might be missing

Four reasons, in rough order of likelihood.

**1. The artifact could not be injected.** Some documents have no `<head>`
element, are not valid UTF-8, or are larger than the configured ceiling. DocUp
**will not** insert bytes into a document it cannot read safely — a mis-declared
character set is an injection vector, so a non-UTF-8 document is left exactly as
it was built. If any document in a build is affected, that build falls back to
`api_only` for the whole version, because chrome appearing on some pages and not
others is worse than chrome being absent.

Check the project endpoint:

```bash
curl -s https://<dashboard>/api/v3/organisations/<org>/projects/<project> | jq .data.chrome
```

`mode` is what the project asked for; `mode_applied` is what readers get. The
`warning` names the affected files, per version. A build's own figures are on
`/api/v3/builds/<build>` under `chrome`.

**2. Navigational stubs are not a problem.** A document with no `<head>` whose
body is only a redirect — what Antora writes at a site root, and what no reader
ever sees — is recorded and deliberately **does not** warn. If every Antora
build warned forever, you would learn to ignore the warning, and then you would
ignore the one that mattered.

**3. The project is on `off` or `api_only`.** See the table above.

**4. The artifact predates a change to the injector.** Every build records the
version of the injector that processed it. When an upgrade changes what is
injected or where, older artifacts keep the older behaviour — artifacts are
immutable, so there is nothing to edit. `stale: true` on the build or a non-zero
`stale_builds` on the project is what to look for, and the remedy is below.

!!! warning "Every build from before this release reports as stale"

    The injector is at version 2. Version 1 inserted the two tags before the
    first `</head>` **wherever it appeared** — including inside an HTML comment
    or inside a `<script>` string. A page documenting HTML templating, with
    `<script>var s = "</head>";</script>` in its head, had the tags inserted
    into that string literal, and the `</script>` in the loader tag then
    terminated the script element: the page was visibly broken, and the
    coverage record said it had been injected successfully. A `</head>` inside a
    comment was worse — the loader was commented out, so chrome was silently
    absent with the record still claiming success.

    Version 2 skips comments, CDATA sections, `<script>` and `<style>` content,
    and refuses a document whose only `</head>` sits inside one of them.

    **The stamp cannot tell which artifacts were actually affected**, only which
    predate the fix. Most of your builds were fine. Re-ingesting them all is the
    thorough answer; re-ingesting none of them is fine if no document of yours
    writes `</head>` inside a comment or a script. There is no way for DocUp to
    tell you which without re-reading every stored document, and
    over-reporting is the honest direction to err in.

## Re-ingesting an older artifact

```bash
php artisan docup:reingest-chrome
```

Reports what is stale and changes nothing. It re-publishes from the **stored
bytes**, so it needs no repository — which matters for versions uploaded
directly and for repositories that have since moved or been deleted. A rebuild
would also pick up upstream changes nobody asked for; this does not.

```bash
php artisan docup:reingest-chrome --publish --limit=100
```

Actually does it. Each version re-ingested gets a new build, a new manifest and
a pointer flip, which means a **new ETag on every document in it** — so every
reader's cache and every CDN entry for that project is invalidated at once. On a
large installation, do it in batches at a time you choose. Nothing schedules
this for you, deliberately: an upgrade that republished every version during its
own deployment window would be the worst possible moment for it.

`--project=<slug>` limits it to one project.

## The notification banners

Three of them, each with a stated trigger and a per-project switch.

| Banner | Fires when | Column |
|---|---|---|
| You are reading an old version | The version is not the project's default version **and** sorts older than it under the project's own version comparator | `notify_old_version` |
| This is the development version | The version is the project's resolved `latest` channel, tracks a **branch**, and the project has a different resolved `stable` | `notify_development_version` |
| This is a pull-request build | The request arrived on the installation's preview host | `notify_pull_request` |

The comparator is in the first trigger rather than a date, and that is the
substance of it: DocUp supports five version orderings, and `v1.10` sorting
below `v1.9` is the first bug report every documentation host receives. A banner
that decided "old" by creation time would fire on a long-term-support branch
patched yesterday and stay silent on a two-year-old tag imported last week.

The second has three clauses for a reason worth knowing: without the third, a
project with one version would carry "this is the development version" on every
page forever, with nowhere to send the reader.

There is a fourth banner with **no** switch: a page requested in a language the
project publishes, which is not translated yet, gets a 404 **plus** a banner
naming the languages it does exist in. DocUp never silently serves the English
page at a Japanese URL, and that is not configurable.

## Search

The chrome search control ships in this release; the search **index** does not.
Until it does, the payload says `"enabled": false` and the control says so
rather than querying an endpoint that is not there.

When a generator ships its own search box, chrome takes it over — intercepting
focus and click rather than removing the control, so that if chrome fails to
open you are left with a working generator search rather than a dead one. The
selector defaults to `input[type='search'], [role='search'] input` and is
per-project. With `addons_search_takeover` off, or `chrome_mode: off`, the
generator's own search is left completely alone.

## Keyboard and accessibility

Chrome is operable by keyboard throughout, and the behaviour is tested rather
than asserted:

- The version switcher is a button and a listbox. Arrow keys move, `Home` and
  `End` jump, both wrap. `Escape` closes it and returns focus to the button.
- The search control is an ARIA combobox. Arrow keys move the active option
  while **focus stays in the input**, so you can keep typing; the result count
  is announced in a live region. `Escape` closes the modal and returns focus to
  whatever opened it.
- `Tab` is never captured. Chrome closes and lets the browser move on — a
  control that trapped `Tab` would strand a keyboard reader inside DocUp's
  furniture on your documentation.
- `prefers-reduced-motion` is honoured by having no animation at all unless the
  reader has expressed no preference.
- `prefers-color-scheme` is reconciled with the project's `scheme.default`: a
  project that says `light` or `dark` gets what it asked for, and `system`
  defers to the reader.
- Right-to-left is supported from the document's own `dir`, or inferred from its
  `lang` when there is none. The chrome stylesheet uses logical properties
  throughout, so there is no mirrored stylesheet to keep in step.

## Documentation CSP

Every documentation response carries a `Content-Security-Policy` with three
directives:

```
frame-ancestors <your project's token>; base-uri 'self'; object-src 'none'
```

`frame-ancestors` is a branding token, `security.frame-ancestors`, defaulting to
`'self'`. It is what stops your documentation — and the reader's authentication
state inside DocUp's chrome — being framed by somebody else's page. An explicit
origin allowlist is accepted; `*` is refused, both when the token is written and
again when the header is built.

The policy is **permissive on purpose.** A strict CSP breaks Sphinx's inline
scripts, MathJax and Mermaid, and an operator who hits that flood of bug reports
disables CSP entirely — which is strictly worse than a short policy nobody
disables. `DOCUP_CSP_DOCUMENTATION_STRICT=true` adds `img-src`, `font-src` and
`connect-src`, which exist to kill CSS exfiltration. That vector arrives with
per-project custom CSS, which DocUp does not ship, so most installations gain
nothing from it today and may lose a generator's inlined font.

CSP `sandbox` is never sent on documentation, at any setting. It creates an
opaque origin, and an opaque origin cannot read the cookie a private reader's
session depends on — so it would silently log out every reader of every private
project.

## Your documentation's CSS cannot restyle the chrome

Chrome renders inside a **closed** shadow root. Your documentation's
stylesheets, your theme's stylesheets and your own CSS cannot select anything
inside it, cannot reach it through `::part`, and cannot hide it with
`!important` on the element it sits in — chrome re-declares its own token values
and resets every inheritable property on its host, which wins because a shadow
tree's important declarations beat the document's for the host element.

This is the mechanism, not a courtesy: a reader needs to be able to trust that
the version they are told they are reading is the version they are reading.

Two honest limits:

- **JavaScript on your documentation page can remove chrome.** Your built
  documentation runs with full control of its own page, and no shadow root
  changes that. What the closed root buys is that documentation script cannot
  **read or alter** the real chrome — so your version list and your readers'
  authentication state cannot be changed under them. If a page replaces
  `Element.prototype.attachShadow` to force an open root, chrome detects it and
  renders **nothing**, because a visible absence is better than a switcher
  somebody else controls.
- **An overlay is mitigated, not prevented.** The search modal uses the
  browser's top layer, which no `z-index` can paint above. The header bar sits
  at the maximum `z-index` instead, which a determined stylesheet can match.

## Moving from Read the Docs

Read the Docs' addons are themed with CSS custom properties, and most migrating
projects have a block of them. DocUp's equivalents are branding tokens rather
than CSS you write — the values are validated, contrast-checked and compiled
once at release time, not parsed per tenant on a request path.

The table below is the translation. Where a row says *no equivalent*, the Notes
column says why rather than inventing one: DocUp's registry is closed at roughly
forty-five tokens on purpose, and a property styling a surface DocUp's chrome
does not have has no counterpart.

<!-- BEGIN GENERATED: readthedocs-mapping -->

| Read the Docs property | Group | DocUp token | Notes |
|---|---|---|---|
| `--readthedocs-font-size` | Global | `font.size.root` | Both are the root font size every chrome measurement derives from. |
| `--readthedocs-flyout-background-color` | Flyout | `color.surface.raised` | DocUp paints the flyout on the raised surface, so one token covers the flyout, the header bar and the banners. |
| `--readthedocs-flyout-color` | Flyout | `color.text.primary` | Body text inside the flyout. |
| `--readthedocs-flyout-current-version-color` | Flyout | `color.brand.on-primary` | The current version is the selected option, painted on `color.brand.primary` — so the text colour is its pair. |
| `--readthedocs-flyout-font-family` | Flyout | `font.body` | Chrome uses one body family. |
| `--readthedocs-flyout-font-size` | Flyout | `font.size.root` | Derived, not independent — see the note below the table. |
| `--readthedocs-flyout-header-font-size` | Flyout | *no equivalent* | DocUp has no separate flyout header. §8.14.1 confines type scale to `font.size.root` and a weight token, so a second size would be a forty-sixth token with nothing to justify it. |
| `--readthedocs-flyout-item-link-color` | Flyout | `color.text.link` | Every link in chrome. |
| `--readthedocs-flyout-link-color` | Flyout | `color.text.link` | The same token: DocUp does not distinguish an item link from a section link. |
| `--readthedocs-flyout-section-heading-color` | Flyout | `color.text.secondary` | The flyout's notes and headings are secondary text. |
| `--readthedocs-notification-background-color` | Notifications | `color.surface.sunken` | §8.15.6's banners sit on the sunken surface, which is what distinguishes them from the header bar above. |
| `--readthedocs-notification-color` | Notifications | `color.text.primary` | Banner text. |
| `--readthedocs-notification-font-family` | Notifications | `font.body` | One body family. |
| `--readthedocs-notification-font-size` | Notifications | `font.size.root` | Derived. |
| `--readthedocs-notification-link-color` | Notifications | `color.text.link` | The banner's one action link. |
| `--readthedocs-notification-title-background-color` | Notifications | `banner.tone` | 🛑 **Not a colour in DocUp.** §8.14.1 makes the banner's emphasis a **tone** — `notice`, `warning`, `danger`, `success` — which selects `color.state.*`. A tenant choosing an arbitrary colour could paint a pull-request build in the success tone, which §8.15.6's `BannerKind` refuses by fixing the tone per kind. |
| `--readthedocs-notification-title-color` | Notifications | `color.text.primary` | See the row above: the tone decides the accent, not the text. |
| `--readthedocs-notification-toast-font-size` | Notifications | *no equivalent* | DocUp renders no toast. §8.15.6's banners are in the document flow at the top of the page, because a floating toast over third-party documentation covers content the reader came for. |
| `--readthedocs-search-font-family` | Search | `font.body` | One body family. |
| `--readthedocs-search-font-size` | Search | `font.size.root` | Derived. |
| `--readthedocs-search-color` | Search | `color.text.primary` | Text in the search modal. |
| `--readthedocs-search-content-background-color` | Search | `color.surface.page` | The modal is painted on the page surface so it reads as a sheet above the document. |
| `--readthedocs-search-content-border-color` | Search | `color.border.strong` | The modal's own border. |
| `--readthedocs-search-input-background-color` | Search | `color.surface.page` | The input shares the modal's surface. |
| `--readthedocs-search-result-section-color` | Search | `color.text.primary` | A result's title. |
| `--readthedocs-search-result-section-subheading-color` | Search | `color.text.secondary` | A result's breadcrumb. |
| `--readthedocs-search-result-section-highlight-color` | Search | `color.brand.accent` | The matched term. §8.14.5 judges the accent against both surfaces, so a highlight is legible by the same gate that judges everything else. |
| `--readthedocs-search-result-section-border-color` | Search | `color.border.subtle` | Between results. |
| `--readthedocs-search-backdrop-color` | Search | `color.surface.sunken` | DocUp derives the backdrop from the sunken surface at reduced opacity. |
| `--readthedocs-search-filters-border-color` | Search | *no equivalent* | Search filters are Phase 30's and are not a styled surface of their own in DocUp's chrome. |
| `--readthedocs-search-footer-background-color` | Search | *no equivalent* | DocUp's search modal has no footer: the keyboard hints §8.15.8 requires are announced through the live region rather than printed in a bar. |
| `--readthedocs-search-footer-code-background-color` | Search | *no equivalent* | See the row above — no footer, so no key legend to style. |
| `--readthedocs-search-footer-code-border-color` | Search | *no equivalent* | See the row above. |

Read the Docs documents 33 addon CSS custom properties. 27 have a DocUp token; the rest have no equivalent, and the Notes column says why rather than inventing one.

<!-- END GENERATED: readthedocs-mapping -->

Three of those rows map a **font size** onto `font.size.root`. DocUp has one
root size and derives chrome's sizes from it, so reducing the flyout's type
independently of the notification's is not expressible. If that matters to you,
it is the kind of thing to raise before you migrate rather than after.

And one row maps a colour onto something that is not a colour:
`--readthedocs-notification-title-background-color` becomes `banner.tone`, which
selects from a fixed set of state colours. A tenant who could choose an
arbitrary banner colour could paint a pull-request build in the success tone,
and a reader would believe a preview was a release.
