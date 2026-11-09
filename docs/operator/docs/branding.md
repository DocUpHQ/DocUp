<!-- SPDX-FileCopyrightText: 2026 The DocUp contributors -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Branding and themes

Two projects on one DocUp installation can look completely different while
serving **the same build artifact**. Nothing about a project's appearance is
baked into what the build produced, so rebranding a project is a save, not a
rebuild — and a project that shares a build with another project (a component
mounted twice, a monorepo built once) can still carry its own logo and palette.

This page is the reference for what you can change, how far down it cascades,
and what DocUp refuses to let you change.

## The shape of it

Branding is a **closed registry of typed design tokens**. There are forty-five
of them. Each one has a name, a type, a grammar that decides what values it
accepts, and a cascade level that decides how deep it can be set.

A key that is not in the registry is **rejected**, not ignored. A theme that
saved `colour.brand.primary` — the British spelling — and silently did nothing
would be a theme you went looking for in the CSS.

### The cascade

Tokens resolve through four levels, each overriding the one above it:

1. **Installation** — your defaults, for every tenant.
2. **Organisation** — one tenant's.
3. **Project** — one project's.
4. **Domain mount** — one project served at one host and path. This is the rung
   that makes a white label possible: the same project at `docs.example.com` and
   at `docs.acme.example` can look like two different products.

Two tokens get a fifth, narrower rung: a **project version** may set the
colour-scheme default and a banner, and nothing else. A version is content a
build produced; a theme is a decision you made.

### Locking a path

Any level may **lock** a token, and no level below it may then set that token.
An organisation that has signed off a brand guideline locks
`color.brand.primary` and `asset.logo`, and its project owners keep the other
forty-three.

A lock takes effect on readers immediately, including for projects that had
already overridden the token — the override is dropped at resolution, not just
refused on the next save. So locking is something you can do after the fact.

You can lock a whole group by its heading (`Surfaces`, `Typography`), which is
expanded to the tokens it holds at the moment you save it. A later DocUp release
that adds a token to that group does **not** widen a lock you already reviewed.

### Light and dark are one token

A colour token carries two values, one per colour scheme. They are set together
and inherited together: there is no spelling by which a project overrides the
light value and inherits the dark one, because that produces a palette nobody
designed and a dark scheme nobody checked.

## The token table

<!-- BEGIN GENERATED: token-table -->

### Identity

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `brand.name` | text | plain text to the token's length; no angle brackets, control characters or bidi overrides (≤ 60 characters) | installation → mount | `DocUp` |
| `asset.logo` | asset | a `logo` asset id | installation → mount | _none until uploaded_ |
| `asset.logo.dark` | asset | a `logo` asset id | installation → mount | _none until uploaded_ |
| `asset.favicon` | asset | a `favicon` asset id | installation → mount | _none until uploaded_ |
| `asset.social.card` | asset | a `social_card` asset id | installation → mount | _none until uploaded_ |

- `brand.name` — The wordmark, used wherever no logo asset is set and as the logo’s alt text.
- `asset.logo` — The light-scheme logo. Rendered via `<img src>` from the asset host (§8.14.11).
- `asset.logo.dark` — The dark-scheme logo. Falls back to `asset.logo` when unset.
- `asset.favicon` — The favicon, re-encoded to PNG at ingest.
- `asset.social.card` — The Open Graph and social card image (§8.14.7).

### Surfaces

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `color.surface.page` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#ffffff` / `#0b0e14` |
| `color.surface.raised` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#f6f7f9` / `#141a23` |
| `color.surface.sunken` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#eceef2` / `#05080c` |
| `color.border.subtle` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#dfe3e8` / `#242c38` |
| `color.border.strong` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#767f8c` / `#6b7687` |
| `color.focus.ring` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#0b5cd5` / `#79b8ff` |

- `color.surface.page` — The page background, and the backdrop every text pair in the contrast matrix is judged against.
- `color.surface.raised` — Cards, the header and the flyout.
- `color.surface.sunken` — Wells and inset regions.
- `color.border.subtle` — Dividers that separate without being seen.
- `color.border.strong` — Control outlines. Judged as a non-text pair at WCAG 1.4.11’s 3:1.
- `color.focus.ring` — 🛑 The focus indicator. §9.5’s WCAG 2.2 AA posture makes this a requirement, not a preference.

### Text

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `color.text.primary` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#16191f` / `#e7eaf0` |
| `color.text.secondary` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#4b5563` / `#a9b2c1` |
| `color.text.inverse` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#ffffff` / `#0b0e14` |
| `color.text.link` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#0b5cd5` / `#79b8ff` |

- `color.text.primary` — Body copy.
- `color.text.secondary` — Metadata and captions. Still held to 4.5:1 — small text is where a muted palette fails readers.
- `color.text.inverse` — Text on an accent fill.
- `color.text.link` — Links in chrome.

### Brand and state

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `color.brand.primary` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#0b5cd5` / `#4d93ff` |
| `color.brand.on-primary` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#ffffff` / `#06111f` |
| `color.brand.accent` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#a21f6b` / `#f58ac2` |
| `color.state.success` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#0f6b35` / `#5bd98d` |
| `color.state.warning` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#8a4b00` / `#e8a33d` |
| `color.state.danger` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#b3261e` / `#ff8f85` |

- `color.brand.primary` — Primary fills and the active state.
- `color.brand.on-primary` — Text on `color.brand.primary`. Its own token because deriving it is how a button ends up unreadable.
- `color.brand.accent` — The secondary brand fill.
- `color.state.success` — A build that passed, a verified domain.
- `color.state.warning` — A degraded binding, a stale version notice.
- `color.state.danger` — A failed build, a refusal.

### Code

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `color.code.surface` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#f3f4f6` / `#10151d` |
| `color.code.text` | colour | `#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics | installation → mount | `#16191f` / `#e7eaf0` |

- `color.code.surface` — The background of chrome’s own code spans. A generator styles its own blocks.
- `color.code.text` — Monospace text on `color.code.surface`.

### Typography

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `font.body` | font_stack | comma-separated catalogue names, CSS generics or `asset:<id>`; no URL ever | installation → mount | `system-ui, sans-serif` |
| `font.heading` | font_stack | comma-separated catalogue names, CSS generics or `asset:<id>`; no URL ever | installation → mount | `system-ui, sans-serif` |
| `font.mono` | font_stack | comma-separated catalogue names, CSS generics or `asset:<id>`; no URL ever | installation → mount | `ui-monospace, monospace` |
| `font.size.root` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (12–24) | installation → mount | `16px` |
| `font.weight.heading` | count | an integer in the token's range (100–900) | installation → mount | `650` |
| `font.line-height.body` | ratio | a plain decimal in the token's range, no unit (1–2.5) | installation → mount | `1.6` |

- `font.body` — Body text. 🛑 Catalogue names or `asset:<id>` only — DocUp never fetches a remote font (§8.14.2).
- `font.heading` — Headings.
- `font.mono` — Code and identifiers.
- `font.size.root` — The root font size every `rem` is relative to.
- `font.weight.heading` — Heading weight, as a variable-font axis value.
- `font.line-height.body` — 🛑 Unitless, so it scales when a reader enlarges the text (WCAG 2.2 SC 1.4.12).

### Shape and space

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `radius.small` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (0–24) | installation → mount | `4px` |
| `radius.medium` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (0–48) | installation → mount | `8px` |
| `space.unit` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (2–16) | installation → mount | `4px` |
| `border.width` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (0–8) | installation → mount | `1px` |

- `radius.small` — Inputs, badges and tags.
- `radius.medium` — Cards, the flyout and modals.
- `space.unit` — The spacing step every chrome gap is a multiple of.
- `border.width` — Default border thickness.

### Layout and chrome

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `layout.content.width` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (20–120) | installation → mount | `48rem` |
| `layout.sidebar.width` | length | a positive number in the token's range plus `px`, `rem`, `em`, `ch` or `%`; bare `0` (10–32) | installation → mount | `18rem` |
| `chrome.header.style` | option | `solid` / `bordered` / `transparent` | installation → mount | `bordered` |
| `chrome.header.sticky` | flag | `true` or `false` | installation → mount | `true` |
| `chrome.sidebar.position` | option | `start` / `end` / `none` | installation → mount | `start` |
| `chrome.footer.style` | option | `solid` / `bordered` / `minimal` | installation → mount | `bordered` |

- `layout.content.width` — The measure chrome’s own text columns are capped at.
- `layout.sidebar.width` — The navigation column’s width.
- `chrome.header.style` — How the header separates from the page.
- `chrome.header.sticky` — Whether the header stays on screen while the reader scrolls.
- `chrome.sidebar.position` — 🛑 `start`/`end`, not left/right, because §9.5 requires RTL and the sides swap.
- `chrome.footer.style` — How the footer separates from the page (§8.14.7).

### Scheme and behaviour

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `scheme.default` | option | `light` / `dark` / `system` | installation → version | `system` |
| `scheme.toggle` | flag | `true` or `false` | installation → mount | `true` |
| `motion.allow` | flag | `true` or `false` | installation → mount | `true` |
| `banner.text` | text | plain text to the token's length; no angle brackets, control characters or bidi overrides (≤ 160 characters) | installation → version | _unset_ |
| `banner.tone` | option | `notice` / `warning` / `danger` | installation → version | `notice` |

- `scheme.default` — 🛑 One of the two things §8.14.1 lets a **version** set. Reconciled with `prefers-color-scheme` per §8.15.8.
- `scheme.toggle` — Whether chrome offers the reader a scheme switch.
- `motion.allow` — False suppresses chrome animation for every reader. `prefers-reduced-motion` is honoured regardless (§8.15.8).
- `banner.text` — 🛑 The other thing §8.14.1 lets a version set. Plain text; §8.14.3’s inline allowlist is for the announcement, not here.
- `banner.tone` — Which state colour the banner takes.

### Security

| Token | Type | Grammar | Cascade level | Default (light / dark) |
|---|---|---|---|---|
| `security.frame-ancestors` | origin_list | `'self'`, `'none'` or `https://` origins; never a wildcard | installation → project | `'self'` |

- `security.frame-ancestors` — 🛑 §8.14.16: per project, an explicit allowlist, never a wildcard. **Stored and validated; not yet enforced** — §8.14.15’s documentation Content-Security-Policy is the header that carries it and ships with the chrome runtime. Until then this value protects nothing.

**45 tokens.** §8.14.1 budgets "roughly 45", and `TokenRegistryTest` asserts the count — so a forty-sixth is a decision somebody makes rather than one that happens. Every token is a row in this table, a value the contrast gate may have to reason about, and a property a migrating theme has to find a counterpart for.

<!-- END GENERATED: token-table -->

## What a value may say

Validation is a **grammar**, not a filter. DocUp does not scan your value for
things that look dangerous; it parses it into the thing the token is, and emits
CSS rebuilt from the parse. A value that does not parse is refused with a
reason, and a value that parses is re-serialised — so `#FFF` comes back as
`#ffffff` and `rgb(11, 92, 213)` comes back as `rgb(11 92 213)`.

There is no production in any of these grammars that can express a function
call. `url(...)`, `var(...)`, `calc(...)`, `env(...)`, `attr(...)` and
`expression(...)` are not refused by a check you could get past with a different
encoding — they are inexpressible. The check that names them exists so the error
message tells you which one you used.

### Fonts

A font is a **catalogue name**, one of CSS's generic families, or a WOFF2 file
you uploaded. It is never a URL.

DocUp will not fetch a remote font, and the reason is two reasons. A remote font
URL is a request every reader's browser makes to a third party on every page,
which is a data transfer you did not agree to on your readers' behalf. And a
`url()` in a font declaration is the one place CSS fetches a binary that gets
handed to the operating system's font engine.

To self-host a family for the whole installation, add it to `font_catalogue` in
`config/branding.php` and put the files where your edge serves them. A catalogue
entry whose font is missing gives every reader a silent fallback, so add the name
and the bytes together.

## Uploads

A logo, a favicon, a social card or a font.

**Rasters are re-encoded, not inspected.** DocUp decodes the image to pixels and
writes a new PNG from them. Everything that was not a pixel is gone: EXIF with
its GPS coordinates, the colour profile, an XMP packet, a ZIP archive appended
after the image data. There is no list of metadata to remember, and a file whose
first bytes are an image and whose later bytes are an HTML document stops being
both.

So your 180 KB JPEG logo may come back as a slightly larger PNG. That is the
re-encode, not a bug.

**SVG is sanitised and re-serialised.** A logo may be an SVG. DocUp parses it,
copies the elements and attributes on its allowlist into a **new** document and
serves that. Script, event handlers, `<style>`, `<foreignObject>`, SMIL
animation, filters and external references are not copied. The upload succeeds
and the logo still draws; the response tells you what was dropped.

A document with a `DOCTYPE` or an entity declaration is **refused** rather than
sanitised, because those act on the parser before any allowlist runs.

A `url(#gradient)` reference is kept — that is how every gradient in every SVG
works. A `url()` naming anything but a local fragment is dropped.

**A favicon or a social card may not be an SVG.** A favicon is fetched by a
`<link rel=icon>` that some browsers handle outside the page's content policy,
and a social card is fetched and re-served by crawlers whose own handling DocUp
knows nothing about.

**Fonts are checked, not re-encoded.** A font upload must be WOFF2 and is
verified by its signature. DocUp does not re-encode it: there is no safe
pure-PHP WOFF2 decoder, and adding a font parser to the attack surface in order
to reduce it is not a trade worth making. What protects a reader is that the
font is served from your own origin as bytes the browser's font engine sandboxes.

### The asset host

Uploaded images are served from a **dedicated host**, set by
`DOCUP_ASSET_HOST`, and rendered only through `<img src>`. Every response from
it carries:

- `Content-Security-Policy: default-src 'none'; sandbox` — it may fetch nothing,
  and it runs in an opaque origin with scripting off.
- `X-Content-Type-Options: nosniff` — the declared type is the type.
- `Cache-Control: public, max-age=31536000, immutable` — the URL is a hash of
  the bytes, so they cannot change.
- No cookies, in either direction: the routes are in no session group.

If `DOCUP_ASSET_HOST` is unset, assets are served from the dashboard origin
instead. That works and it is a degradation: `docup doctor` reports it.

## Contrast

At publish, DocUp computes WCAG 2.2 contrast ratios over a fixed set of
foreground/background pairs, in **both** colour schemes.

- Below **3:1** — publication is **refused**. You can override it; the override
  is recorded on the theme and written to the audit log with the reason you gave.
- Below **4.5:1** for a text pair — published, with a warning.
- A focus ring and a control outline are judged at WCAG's 3:1 for non-text
  contrast, so they are refused below 3:1 and never merely warned about.

### 🛑 This gate is a safety net, and it still lets you ship a theme that fails AA

Please read this paragraph rather than trusting the green tick.

The gate judges **chrome**, not content. Your documentation body is styled by
your generator's own CSS, which DocUp never rewrites — so a theme that passes
every pair here can sit above a page that fails.

It judges **the pairs in its matrix** and no others. A combination chrome does
not render is not checked.

It judges every text pair at the **small-text** threshold, because a token
carries no font size. A heading that would pass at 3:1 under the large-text
allowance is still warned about.

It cannot see **text over an image**. A logo with words baked into it is outside
this gate entirely.

It measures the **sRGB reduction** of each colour. A wide-gamut `oklch()` value
is judged at its clamped sRGB value, which is at least as favourable as what the
display shows — never more.

An accessible theme is one somebody checked. This gate stops the worst of it.

## Draft, preview, publish

A theme revision starts as a **draft** and affects nothing. You can preview it:
the preview resolves your draft at **its own level** with every other level as
published, so what you see is what publishing would actually do — not what the
draft looks like in isolation, and not a composite of every level's unpublished
work.

Publishing supersedes the previous revision rather than deleting it. A reader
may hold a year-long cache entry for a stylesheet addressed by the old theme's
hash, and the bytes behind an address never change.

### Why a token edit needs nothing purged

Each resolved theme publishes as a stylesheet whose URL is a hash of its own
contents, cached for a year as `immutable`. Edit a token and the hash changes,
so the next page carries a new URL and the old one is simply never requested
again. Two projects that resolve to the same values share one URL and one cache
entry, which is why five hundred projects cost one chrome bundle and however
many distinct themes you actually have.

## Chrome content

Navigation links, footer links, an announcement and homepage blocks. All of it
is **structured data**: a link is a label and a target, a block is a type from a
closed list with typed fields. None of it is HTML.

The announcement is the one exception and it is a small one: five inline
elements (`strong`, `em`, `code`, `a`, `br`) and one attribute (`href`). It is
parsed with a real HTML parser and re-serialised from the allowlist, so what
DocUp emits is what DocUp wrote.

### The 404 page

A heading and a sentence, both plain text. DocUp serves your build's own
`404.html` where there is one and the primary mount's otherwise; this is what
chrome renders when there is neither, and it is the case that would otherwise
be an unstyled page served from a URL depth nobody chose.

There is no link list on it, deliberately. A 404 is served for a path that does
not exist, so every link on it has to be correct from an unknown base — and the
navigation and footer chrome renders around it is already the way back.

Write it in your documentation's language rather than the operator's: a
reader-facing 404 uses the language of the documentation they were looking for.

### 🛑 There is no tenant JavaScript, at any scope, ever

Not behind a flag, not for a project, not for an organisation. This is permanent.

The argument for it is always "we already run JavaScript in our build", and that
is exactly the reason: your build's JavaScript is contained in the documentation
origin, where DocUp's threat model already assumes it is hostile. A chrome slot
puts code in the same DOM as the version switcher and the reader's
authentication state.

Raw HTML in the page head is available at **installation** scope only, behind
`DOCUP_ALLOW_RAW_HTML_BRANDING`. That flag is documented as code execution
because that is what it is.

### Per-project custom CSS is not available

It is in the specification (§8.14.9) and it is not built. It depends on a CSS
parser that is bounded in time and memory against malformed and deeply nested
input, and whose serialiser never re-emits a construct the filter dropped —
and that assumption (§18.22) is unverified. Its pre-decided consequence was to
ship the token system alone, which is what this is.

## Credential pages carry installation branding only

A login page — yours or a reader's — renders **your** installation's branding
and nothing of a tenant's. No project name, no organisation name, no tenant
logo, whichever domain the reader arrived from.

This is not a style choice. A tenant controls their own custom domain and their
own theme; if a credential page inherited the tenant's theme, that tenant could
make a login form on **your** dashboard host carry their logo and their wording.
The password would still go to the right place, which is what makes it hard to
notice — and the tenant would have been handed the ability to phrase an
authentication prompt however they like, on an origin they do not own.

## Email

Email customisation is **slot overrides**, not templates. You supply the
greeting, a paragraph before the action, a paragraph after it, a sign-off and a
footer note. DocUp supplies the layout, the button, and its own footer — which
you cannot remove, because an email with no route back to the operator is an
email recipients report as spam.

Slots are Markdown with HTML disabled: emphasis, a link and a paragraph break.
Placeholders like `{project}` are substituted from a fixed, per-slot, pre-escaped
map; a placeholder a slot does not offer is refused when you save, not left as
literal text in a thousand sent emails.

There is no placeholder for a recipient's name or address, at any slot.

## Shipping your own chrome

Set `chrome_mode: api_only` on a project and DocUp injects nothing. Your
front end reads a versioned payload — token values in both schemes, asset URLs
with their dimensions, the structured navigation and footer, the announcement,
the scheme default and the version banner — and renders whatever you like.

A complete worked example ships in the repository:

- `resources/themes/api-only-reference.json` — the payload.
- `resources/themes/reference-chrome.html` — that payload rendered as chrome,
  with every accessibility decision annotated.

Both are generated from the real registry and a test asserts they match what
DocUp emits, so they cannot drift from the implementation.

The payload's `contract` field is its version. Added keys are not a breaking
change; removed keys and changed grammars are, and they get a new version.

## Weakening options, in one place

These are the per-project and per-component options that trade a default
protection for something else. None of them is an environment flag — those are
in the unsafe-modes registry under [Running it](operations.html) — but each is
audited when it changes and surfaced in the project's settings as a weakening.

| Option | What it gives up | Where |
|---|---|---|
| Shell semantics opt-out | A build command is parsed by a shell rather than as a typed argument list | per project (§8.4.10) |
| Collision precedence | A later component mount may overwrite an earlier one's files | per project (§8.7.14) |
| Shadowing override | A component may shadow a path another component owns | per component (§8.7.15) |
| `allow_network_only_access` | A reader on an allowlisted network needs no identity | per project (§8.12.6) |
| Contrast override | A theme below 3:1 may be published | per theme revision (§8.14.5) |
| Custom-CSS policy | Per-project CSS, when an installation enables it | not built; see above (§8.14.9) |
