// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * 🛑 §8.15's reader chrome: the runtime every injected documentation page loads.
 *
 * This file is served, as authored, at §8.15.1's stable non-content-hashed path
 * `/_/addons/docup.js` by App\Http\Controllers\Serving\ChromeLoaderController,
 * whose docblock records why there is no bundler between this source and the
 * reader.
 *
 * ## What it does
 *
 * 1. Reads `<meta name="docup" content="b=<build_uuid>">` — §8.15.1 permits that
 *    and nothing else in the artifact, so this is the whole of what the page can
 *    tell us.
 * 2. Fetches `GET /_/addons?path=<this document's path>` — §8.15.2 makes that
 *    endpoint the single source of every request-scoped fact.
 * 3. Renders chrome inside a 🛑 **closed shadow root** (§8.15.5).
 * 4. Rewrites `/_/x/…` cross-references in the document (§8.7.17), leaving the
 *    server's 302 as the no-JavaScript path.
 * 5. Takes over the generator's own search control where configured (§8.15.12).
 *
 * ## 🛑 The isolation argument, which is §18.11
 *
 * §8.15.5: "Chrome MUST render inside a **closed shadow root**, so tenant CSS,
 * documentation CSS and a project's own theme cannot restyle, hide or overlay
 * the version switcher, search modal or authentication state."
 *
 * §18.11 lists the four ways that could fail and names the mitigation: "Chrome
 * explicitly resets inheritable properties and re-declares its own token values
 * inside the shadow root. Cost is CSS volume, not architecture." All four are
 * answered here:
 *
 * - **`::part`** — nothing in the shadow tree carries a `part` attribute, so the
 *   document has no selector that reaches inside. A closed root also refuses
 *   `::part` in practice, but the absence is the control: adding one part would
 *   open exactly one hole and look harmless.
 * - **Inherited custom properties** — a documentation page may define
 *   `--docup-color-surface-page` on `:root` and it would inherit through the
 *   shadow boundary. So chrome does **not** read its tokens from the document:
 *   {@link hostTokens} re-declares every token from the payload on `:host` with
 *   `!important`, which is the inner tree and therefore wins (CSS Scoping §3.4).
 * - **`!important` on inheritable properties** — `color`, `font`, `direction`,
 *   `visibility`, `line-height` and the rest inherit from the host element,
 *   where a documentation selector CAN match. {@link RESET} declares every one
 *   of them on `:host` with `!important`; for the host element, an important
 *   declaration in the shadow tree beats an important declaration in the
 *   document, which is the only reason this works and is why the `!important` is
 *   not decoration.
 * - **DOM traversal** — `mode: 'closed'`, so `element.shadowRoot` is `null` for
 *   every script in the page. Nothing is exposed on `window`, nothing is stored
 *   on the element, and the root is held in a module-scoped `WeakMap` that no
 *   page script can reach.
 *
 * 🛑 **Not an iframe** (§8.15.5: "Iframed chrome MUST NOT be used (clickjacking,
 * keyboard traps)").
 *
 * ## What is deliberately absent
 *
 * §4.2 puts visual diff, file-tree diff, link previews and hotkeys permanently
 * out of scope, and §8.14.8 puts tenant JavaScript at any scope below
 * installation permanently out of scope. There is no extension point here, by
 * design: this file evaluates nothing it did not ship with, and every string it
 * puts in the DOM goes in as `textContent` or through the one allowlisted
 * fragment parser ({@link setAnnouncement}).
 */

const TAG = 'docup-chrome'
const PAYLOAD_PATH = '/_/addons'
const XREF_PREFIX = '/_/x/'

/*
 * 🛑 The shadow roots, held where no page script can read them.
 *
 * A `WeakMap` in module scope and nothing on the element. Storing the root as a
 * property — `this._root` — would undo `mode: 'closed'` completely: a
 * documentation script could read it, query inside it and hide the switcher,
 * which is the attack §8.15.5 exists to stop. The module has no exports and
 * nothing is assigned to `window`, so this binding is unreachable from outside.
 */
const roots = new WeakMap()

/*
 * 🛑 Every inheritable CSS property chrome depends on, reset on `:host`.
 *
 * §18.11's consequence column in one constant. Each of these inherits from the
 * host element, which is in the document's tree and therefore matchable by a
 * documentation selector — `* { font-family: Comic Sans !important }` is a real
 * thing real stylesheets do. An important declaration here beats an important
 * declaration there, because the host element's cascade prefers the inner tree
 * at equal importance (CSS Scoping §3.4).
 *
 * `direction` and `unicode-bidi` are reset to `inherit` rather than to a value,
 * because §8.15.8 requires RTL support and the document's own direction is the
 * right answer — see {@link applyDirection}, which copies it onto the host
 * deliberately instead of letting an arbitrary selector decide it.
 *
 * 🛑 This list is asserted by tests/Js/chrome-isolation.test.mjs, which fails if
 * a property is dropped. It is the test for §17's exit criterion "A
 * documentation page's CSS with `!important` cannot restyle or hide the version
 * switcher", together with the closed root itself.
 */
const RESET = [
    /*
     * 🛑 `all` FIRST, and the order inside this block is the mechanism.
     *
     * `all: initial` resets every property the host could have inherited in one
     * declaration — which is the only way to be complete, because the list of
     * inheritable properties grows with every CSS release and a hand-kept list
     * is a list that is out of date. Everything after it is a later declaration
     * of the same importance in the same block, so it wins: this is a reset
     * followed by chrome's own values, not a reset that undoes them.
     *
     * 🛑 Putting it last — which the first draft of this file did — would have
     * wiped every declaration below it and left chrome with `display: inline`
     * and no colour. CSS's own definition of `all` is the other half of why the
     * explicit entries are still needed: it excludes `direction` and
     * `unicode-bidi`, which §8.15.8's RTL support turns on.
     */
    ['all', 'initial'],
    ['display', 'block'],
    ['visibility', 'visible'],
    ['opacity', '1'],
    ['color', 'var(--docup-color-text-primary)'],
    ['font-family', 'var(--docup-font-body)'],
    ['font-size', 'var(--docup-font-size-root)'],
    ['font-style', 'normal'],
    ['font-weight', '400'],
    ['font-variant', 'normal'],
    ['font-stretch', 'normal'],
    ['letter-spacing', 'normal'],
    ['line-height', 'var(--docup-font-line-height-body)'],
    ['text-align', 'start'],
    ['text-transform', 'none'],
    ['text-indent', '0'],
    ['text-shadow', 'none'],
    ['white-space', 'normal'],
    ['word-spacing', 'normal'],
    ['word-break', 'normal'],
    ['overflow-wrap', 'normal'],
    ['list-style', 'none'],
    ['cursor', 'auto'],
    ['pointer-events', 'auto'],
    ['border-collapse', 'separate'],
    ['caption-side', 'top'],
    ['empty-cells', 'show'],
    ['quotes', 'auto'],
    ['tab-size', '4'],
    ['hyphens', 'manual'],
    ['writing-mode', 'horizontal-tb'],
    ['color-scheme', 'light dark'],
    ['contain', 'style'],
    ['isolation', 'isolate'],
]

/*
 * 🛑 The chrome stylesheet, inside the shadow root.
 *
 * Plain CSS in a template literal rather than a `.css` file, because the shadow
 * root does not see the document's stylesheets and this runtime is one served
 * file (see the loader controller for why). `resources/css/chrome.css` is the
 * other half of §8.14.4's one bundle — it styles the §8.14.14 reference page,
 * which is a whole document; this styles the chrome inside the shadow root.
 *
 * Every colour, length and family is a `var(--docup-*)`. The values come from
 * `:host` ({@link hostTokens}), never from the document, which is the second
 * half of §18.11's answer.
 */
const CSS = `
:host {
${RESET.map(([property, value]) => `  ${property}: ${value} !important;`).join('\n')}
  direction: inherit !important;
  unicode-bidi: isolate !important;
  position: relative !important;
  z-index: 2147483647 !important;
}

* { box-sizing: border-box; margin: 0; }

.bar {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: calc(var(--docup-space-unit) * 2);
  padding: calc(var(--docup-space-unit) * 2) calc(var(--docup-space-unit) * 4);
  background: var(--docup-color-surface-raised);
  color: var(--docup-color-text-primary);
  border-block-end: var(--docup-border-width) solid var(--docup-color-border-subtle);
  font-size: calc(var(--docup-font-size-root) * 0.875);
}

.brand { font-weight: var(--docup-font-weight-heading); }
.spacer { flex: 1 1 auto; }

button, .control {
  font: inherit;
  color: var(--docup-color-text-primary);
  background: var(--docup-color-surface-page);
  border: var(--docup-border-width) solid var(--docup-color-border-strong);
  border-radius: var(--docup-radius-small);
  padding: calc(var(--docup-space-unit) * 1) calc(var(--docup-space-unit) * 2);
  cursor: pointer;
}

/*
 * 🛑 A visible focus indicator on everything focusable, using the token the
 * §8.14.5 contrast gate judges against both surfaces. WCAG 2.2 SC 2.4.11 and
 * 1.4.11 make it a requirement rather than a preference, and the gate is what
 * makes the ring actually visible rather than merely present.
 */
:focus-visible {
  outline: 2px solid var(--docup-color-focus-ring);
  outline-offset: 2px;
}

[hidden] { display: none !important; }

.listbox {
  position: absolute;
  inset-inline-start: auto;
  margin-block-start: calc(var(--docup-space-unit) * 1);
  min-inline-size: 12rem;
  max-block-size: 60vh;
  overflow-y: auto;
  padding: calc(var(--docup-space-unit) * 1);
  background: var(--docup-color-surface-page);
  color: var(--docup-color-text-primary);
  border: var(--docup-border-width) solid var(--docup-color-border-strong);
  border-radius: var(--docup-radius-medium);
  list-style: none;
}

.option {
  display: flex;
  align-items: baseline;
  gap: calc(var(--docup-space-unit) * 2);
  padding: calc(var(--docup-space-unit) * 1) calc(var(--docup-space-unit) * 2);
  border-radius: var(--docup-radius-small);
  color: var(--docup-color-text-link);
  text-decoration: none;
  cursor: pointer;
}

.option[aria-selected='true'], .option.active {
  background: var(--docup-color-brand-primary);
  color: var(--docup-color-brand-on-primary);
}

.option .note {
  color: var(--docup-color-text-secondary);
  font-size: 0.875em;
}

.option[aria-selected='true'] .note, .option.active .note {
  color: var(--docup-color-brand-on-primary);
}

.banners { display: flex; flex-direction: column; }

.banner {
  padding: calc(var(--docup-space-unit) * 2) calc(var(--docup-space-unit) * 4);
  border-block-end: var(--docup-border-width) solid var(--docup-color-border-subtle);
  background: var(--docup-color-surface-sunken);
  color: var(--docup-color-text-primary);
  font-size: calc(var(--docup-font-size-root) * 0.875);
}

.banner[data-tone='warning'] { border-inline-start: 4px solid var(--docup-color-state-warning); }
.banner[data-tone='danger'] { border-inline-start: 4px solid var(--docup-color-state-danger); }
.banner[data-tone='success'] { border-inline-start: 4px solid var(--docup-color-state-success); }
.banner[data-tone='notice'] { border-inline-start: 4px solid var(--docup-color-brand-accent); }
.banner a { color: var(--docup-color-text-link); }

.announcement { background: var(--docup-color-surface-sunken); }
.announcement code {
  background: var(--docup-color-code-surface);
  color: var(--docup-color-code-text);
  font-family: var(--docup-font-mono);
}

/* §8.15.5's search modal. Top layer via popover, so no documentation z-index
 * can paint over it — see {@link SearchModal}. */
.modal {
  inline-size: min(40rem, 92vw);
  padding: calc(var(--docup-space-unit) * 4);
  background: var(--docup-color-surface-page);
  color: var(--docup-color-text-primary);
  border: var(--docup-border-width) solid var(--docup-color-border-strong);
  border-radius: var(--docup-radius-medium);
}

.modal::backdrop { background: rgb(0 0 0 / 45%); }

.modal input {
  inline-size: 100%;
  font: inherit;
  padding: calc(var(--docup-space-unit) * 2);
  color: var(--docup-color-text-primary);
  background: var(--docup-color-surface-page);
  border: var(--docup-border-width) solid var(--docup-color-border-strong);
  border-radius: var(--docup-radius-small);
}

.results { list-style: none; padding: 0; margin-block-start: calc(var(--docup-space-unit) * 2); }

.status {
  margin-block-start: calc(var(--docup-space-unit) * 2);
  color: var(--docup-color-text-secondary);
  font-size: 0.875em;
}

/*
 * The visually-hidden pattern, for the live region and the skip target.
 * 'clip-path' rather than 'display: none', because a hidden element is not
 * announced and a live region that is not announced is decoration.
 */
.sr {
  position: absolute;
  inline-size: 1px;
  block-size: 1px;
  overflow: hidden;
  clip-path: inset(50%);
  white-space: nowrap;
}

/*
 * 🛑 §8.15.8: "Chrome MUST honour 'prefers-reduced-motion'."
 *
 * Expressed as the default having no animation at all and motion being added
 * only when it is NOT reduced. Written the other way round — transitions by
 * default, suppressed in the query — a property added later gets animation for
 * free and nobody notices, which is how this requirement decays.
 *
 * 'motion.allow' is a token too (§8.14.1): an operator may switch chrome
 * motion off for everybody, and a reader's own setting always wins because this
 * query cannot be overridden by one.
 */
@media (prefers-reduced-motion: no-preference) {
  :host([data-motion='allow']) .listbox,
  :host([data-motion='allow']) .modal {
    transition: opacity 120ms ease-out;
  }
}
`

/** The two tags §8.15.1 injects are the only contract with the page. */
function buildId() {
    const meta = document.querySelector('meta[name="docup"]')
    const content = meta ? meta.getAttribute('content') : null

    if (!content) {
        return null
    }

    // `b=<uuid>` and nothing else, per §8.15.1.
    const match = /^b=([0-9a-fA-F-]{36})$/.exec(content.trim())

    return match ? match[1] : null
}

/**
 * Fetch §8.15.2's payload for the document being read.
 *
 * 🛑 `credentials: 'same-origin'` is the default and is load-bearing: §8.15.2
 * requires the payload to be "authorised identically to the HTML", which means
 * the reader's `__Host-` grant cookie has to travel. The URL is origin-relative
 * for the same reason — a configured host would be cross-origin on a custom
 * domain and would carry no cookie at all.
 */
async function fetchPayload() {
    const url = PAYLOAD_PATH + '?path=' + encodeURIComponent(location.pathname)
    const response = await fetch(url, {
        headers: { Accept: 'application/json' },
        credentials: 'same-origin',
    })

    if (!response.ok) {
        return null
    }

    return response.json()
}

/**
 * 🛑 Every token re-declared on `:host`, from the payload.
 *
 * This is §18.11's "re-declares its own token values inside the shadow root".
 * A documentation page that defines `--docup-color-surface-page: red` on
 * `:root` cannot reach chrome, because chrome never reads the inherited value:
 * the property is set again here, in the inner tree, with `!important`.
 *
 * 🛑 The value is validated before it is written. The payload is DocUp's own
 * JSON over the reader's own origin, so this is not the primary defence —
 * §8.14.2's grammar is, and it refuses `url()`, `var()` and the rest at the
 * point of authoring. But a custom property is one of the few places a CSS
 * value reaches a browser's parser without passing a property-specific grammar,
 * so the shape is checked again at the point of use: belt and braces across a
 * trust boundary that a later release might move.
 */
function hostTokens(tokens, scheme) {
    const declarations = []

    for (const [name, pair] of Object.entries(tokens || {})) {
        const value = scheme === 'dark' ? (pair.dark ?? pair.light) : (pair.light ?? pair.dark)

        if (typeof value !== 'string' || !safeTokenValue(value)) {
            continue
        }

        declarations.push('--docup-' + name.replace(/\./g, '-') + ': ' + value + ' !important;')
    }

    return ':host {\n  ' + declarations.join('\n  ') + '\n}'
}

/**
 * Whether a token value may be written into a stylesheet.
 *
 * 🛑 A denylist of the characters that change a declaration's meaning, not an
 * allowlist of the ten §8.14.2 grammars: this runs in the browser and
 * re-implementing ten grammars here would be a second implementation of the one
 * §8.14.2 insists is the single parse site. What it refuses is anything that
 * could escape the declaration — a brace, a semicolon, an `@`, a comment
 * delimiter — and anything that could reach the network, which is the
 * `url()`/`image-set()` family. §8.14.10's `img-src` kills the exfiltration
 * channel at the header; this closes the authoring channel.
 */
function safeTokenValue(value) {
    if (value.length > 512) {
        return false
    }

    if (/[{};@\\]|\/\*|\*\//.test(value)) {
        return false
    }

    return !/\b(url|image-set|src|element|expression)\s*\(/i.test(value)
}

/**
 * 🛑 §8.15.8: "reconcile `prefers-colour-scheme` with the project's colour-scheme
 * default".
 *
 * Reconciled rather than chosen: `scheme.default` of `light` or `dark` is the
 * project stating what its documentation looks like, and `system` is the project
 * deferring to the reader. So the reader's preference is consulted exactly when
 * the project said to consult it — which is what "reconcile" means, and is also
 * the only reading under which a project that ships a dark-only theme gets what
 * it asked for.
 */
function resolveScheme(payload) {
    const configured = payload?.branding?.scheme?.default ?? 'system'

    if (configured === 'light' || configured === 'dark') {
        return configured
    }

    return window.matchMedia?.('(prefers-color-scheme: dark)')?.matches ? 'dark' : 'light'
}

/**
 * 🛑 §8.15.8: "MUST support RTL."
 *
 * The document's own direction, copied onto the host rather than inherited.
 * Inheriting would be correct until a documentation stylesheet set `direction`
 * on a wrapper element — and chrome sits inside `<body>`, so a wrapper is
 * exactly where it would sit. Copying from `<html>` is reading the one place
 * the language of the document is actually declared.
 *
 * The CSS is written in logical properties throughout (`inset-inline-start`,
 * `border-inline-start`, `margin-block-start`), so the direction is the whole
 * of the RTL support: no mirrored stylesheet, nothing to keep in step.
 */
function applyDirection(host) {
    const root = document.documentElement
    const explicit = root.getAttribute('dir')

    if (explicit === 'rtl' || explicit === 'ltr' || explicit === 'auto') {
        host.setAttribute('dir', explicit)

        return
    }

    /*
     * No `dir` on the document. The language is the next best evidence, and the
     * list is the right-to-left scripts a documentation site plausibly uses.
     * Guessing from content is not attempted: `dir="auto"` exists for that and
     * chrome's own text is not the document's.
     */
    const lang = (root.getAttribute('lang') || '').toLowerCase()
    const rtl = ['ar', 'he', 'fa', 'ur', 'ps', 'sd', 'ug', 'yi', 'dv', 'ckb']
    const base = lang.split('-')[0]

    host.setAttribute('dir', rtl.includes(base) ? 'rtl' : 'ltr')
}

/** A node with text, never markup. */
function el(tag, attributes = {}, text = null) {
    const node = document.createElement(tag)

    for (const [name, value] of Object.entries(attributes)) {
        if (value !== null && value !== false && value !== undefined) {
            node.setAttribute(name, value === true ? '' : String(value))
        }
    }

    if (text !== null) {
        node.textContent = text
    }

    return node
}

/**
 * 🛑 §8.14.3's announcement: the only markup in the whole payload, and it is
 * DocUp's own output rather than a tenant's input.
 *
 * `App\Branding\Chrome\InlineMarkup` parsed the tenant's value with a real
 * HTML5 parser and re-serialised it from a five-element allowlist, so what
 * arrives here has already been through the control. It is still parsed here
 * rather than assigned, and still filtered to the same five elements, because
 * 🛑 the trust boundary is the network: this runtime executes on a page where a
 * service worker or a proxy could have altered the response, and "the server
 * already checked" is the assumption every XSS in a single-page application is
 * built on.
 */
function setAnnouncement(container, markup) {
    const allowed = new Set(['EM', 'STRONG', 'CODE', 'A', 'BR'])
    const template = document.createElement('template')

    template.innerHTML = String(markup)

    const copy = (source, target) => {
        for (const child of Array.from(source.childNodes)) {
            if (child.nodeType === Node.TEXT_NODE) {
                target.appendChild(document.createTextNode(child.nodeValue))

                continue
            }

            if (child.nodeType !== Node.ELEMENT_NODE || !allowed.has(child.tagName)) {
                // Not refused: unwrapped. The reader keeps the words.
                copy(child, target)

                continue
            }

            const node = document.createElement(child.tagName.toLowerCase())

            if (child.tagName === 'A') {
                const href = child.getAttribute('href') || ''

                /*
                 * 🛑 Same-origin or `https:` only, and `rel` set by us. A
                 * `javascript:` href is the one thing an allowlisted `<a>` can
                 * still do, and it survives every element filter.
                 */
                if (/^(https:\/\/|\/|#)/.test(href)) {
                    node.setAttribute('href', href)
                    node.setAttribute('rel', 'noopener nofollow')
                }
            }

            copy(child, node)
            target.appendChild(node)
        }
    }

    container.replaceChildren()
    copy(template.content, container)
}

/**
 * §8.6.5's version switcher.
 *
 * 🛑 A **button plus listbox**, not a combobox: the reader is choosing from a
 * known list rather than filtering it, and ARIA's combobox pattern is for a
 * control with a text input. §8.15.8 asks for the combobox pattern for
 * "search-as-you-type" specifically, which is {@link SearchModal}.
 *
 * Keyboard behaviour, all of it required by §8.15.8 ("Escape closes, focus
 * returns, no trap"):
 *
 * - `Enter`, `Space`, `ArrowDown`, `ArrowUp` open the list and move into it.
 * - `ArrowDown`/`ArrowUp` move, `Home`/`End` jump, both wrapping.
 * - `Escape` closes **and returns focus to the button**.
 * - `Tab` closes and lets the browser move on — 🛑 no trap. A menu that trapped
 *   Tab would strand a keyboard reader inside DocUp's chrome on somebody else's
 *   documentation, which is worse than the menu not working.
 */
class VersionSwitcher {
    constructor(payload) {
        this.versions = payload?.flyout?.versions ?? []
        this.current = this.versions.find((version) => version.current)
        this.open = false
        this.index = -1

        const label = this.current ? this.current.slug : 'version'

        this.button = el(
            'button',
            {
                type: 'button',
                'aria-expanded': 'false',
                'aria-haspopup': 'listbox',
                'aria-controls': 'docup-versions',
                'data-docup-switcher': '',
            },
            label,
        )

        this.list = el('ul', { id: 'docup-versions', role: 'listbox', class: 'listbox', hidden: true })
        this.options = this.versions.map((version, position) => {
            const option = el('li', {
                role: 'option',
                id: 'docup-version-' + position,
                class: 'option',
                'aria-selected': version.current ? 'true' : 'false',
                'data-href': version.href,
            })

            option.appendChild(el('span', {}, version.slug))

            /*
             * 🛑 §8.6.11: "when a reader switches version and the page is
             * absent, the flyout MUST say so from the per-build file manifest
             * rather than delivering a bare 404." Said in the option itself,
             * because a reader deciding where to go needs it before the click
             * and not after.
             */
            if (!version.page_exists) {
                option.appendChild(el('span', { class: 'note' }, 'page not in this version'))
            } else if (version.channel) {
                option.appendChild(el('span', { class: 'note' }, version.channel))
            }

            option.addEventListener('click', () => this.choose(position))

            return option
        })

        for (const option of this.options) {
            this.list.appendChild(option)
        }

        this.wrapper = el('div', { class: 'control-group', style: 'position:relative' })
        this.wrapper.append(this.button, this.list)

        this.button.addEventListener('click', () => this.toggle())
        this.button.addEventListener('keydown', (event) => this.onButtonKey(event))
        this.list.addEventListener('keydown', (event) => this.onListKey(event))
    }

    get node() {
        return this.wrapper
    }

    toggle(force) {
        this.open = force === undefined ? !this.open : force
        this.list.hidden = !this.open
        this.button.setAttribute('aria-expanded', this.open ? 'true' : 'false')

        if (!this.open) {
            this.highlight(-1)
        }
    }

    onButtonKey(event) {
        if (event.key === 'ArrowDown' || event.key === 'ArrowUp' || event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            this.toggle(true)
            this.highlight(event.key === 'ArrowUp' ? this.options.length - 1 : 0)
        }
    }

    onListKey(event) {
        if (event.key === 'Escape') {
            event.preventDefault()
            this.toggle(false)
            // 🛑 §8.15.8: "focus returns".
            this.button.focus()

            return
        }

        if (event.key === 'Tab') {
            // 🛑 No trap. Close and let the browser do what Tab does.
            this.toggle(false)

            return
        }

        const last = this.options.length - 1

        if (event.key === 'ArrowDown') {
            event.preventDefault()
            this.highlight(this.index >= last ? 0 : this.index + 1)
        } else if (event.key === 'ArrowUp') {
            event.preventDefault()
            this.highlight(this.index <= 0 ? last : this.index - 1)
        } else if (event.key === 'Home') {
            event.preventDefault()
            this.highlight(0)
        } else if (event.key === 'End') {
            event.preventDefault()
            this.highlight(last)
        } else if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault()
            this.choose(this.index)
        }
    }

    highlight(index) {
        this.index = index

        for (const [position, option] of this.options.entries()) {
            const active = position === index

            option.classList.toggle('active', active)
            option.setAttribute('tabindex', active ? '0' : '-1')

            if (active) {
                option.focus()
            }
        }
    }

    choose(index) {
        const version = this.versions[index]

        if (version) {
            location.assign(version.href)
        }
    }
}

/**
 * §8.15.6's search-as-you-type control, as 🛑 ARIA's combobox pattern.
 *
 * §8.15.8: "The search-as-you-type control MUST implement the ARIA combobox
 * pattern with announced result counts." So:
 *
 * - the input is `role="combobox"` with `aria-expanded`, `aria-controls` and
 *   `aria-autocomplete="list"`;
 * - the results are a `listbox` of `option`s;
 * - the active option is named by `aria-activedescendant` and 🛑 **focus stays in
 *   the input**, which is what the pattern requires and what lets a reader keep
 *   typing while moving through results;
 * - the count goes into an `aria-live="polite"` region, which is the "announced
 *   result counts" half.
 *
 * 🛑 **`popover`, so the modal is in the browser's top layer.** §8.15.5 requires
 * that documentation CSS cannot "overlay" chrome, and a z-index — even
 * 2147483647 — can be matched by a documentation element that paints later. The
 * top layer is outside the page's stacking contexts entirely, so nothing in the
 * document can be painted above it. That is the strongest answer CSS has, and it
 * is why the modal is a popover rather than a positioned `<div>`.
 *
 * 🛑 Escape closes it and focus returns to whatever opened it — §17's exit
 * criterion for this phase, and asserted by
 * tests/Js/chrome-keyboard.test.mjs.
 */
class SearchModal {
    constructor(payload) {
        this.config = payload?.search ?? { enabled: false }
        this.opener = null
        this.results = []
        this.index = -1

        this.input = el('input', {
            type: 'search',
            role: 'combobox',
            'aria-expanded': 'false',
            'aria-controls': 'docup-results',
            'aria-autocomplete': 'list',
            'aria-label': 'Search this documentation',
            'data-docup-search': '',
        })

        this.list = el('ul', { id: 'docup-results', role: 'listbox', class: 'results' })

        /*
         * 🛑 `role="status"` AND `aria-live="polite"`. The role is what older
         * screen readers act on and the attribute is what current ones do;
         * either alone leaves a reader population unannounced, and §8.15.8's
         * requirement is that the count is announced rather than that it is
         * marked up.
         */
        this.status = el('p', { class: 'status', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true' })

        this.modal = el('div', {
            class: 'modal',
            popover: 'auto',
            id: 'docup-search',
            role: 'dialog',
            'aria-modal': 'true',
            'aria-label': 'Search',
        })

        /*
         * 🛑 Does this browser have the top layer? §18.4 allows "browsers
         * released within roughly two years", which is where `popover` lands —
         * so the attribute is set unconditionally and the fallback exists for
         * the tail. Detected rather than assumed, because the fallback has to
         * hide the element itself: a browser that ignores `popover` renders the
         * modal inline and open, which would put a search box in the middle of
         * every page.
         */
        this.usesPopover = typeof this.modal.showPopover === 'function'

        if (!this.usesPopover) {
            this.modal.setAttribute('hidden', '')
        }

        this.modal.append(this.input, this.list, this.status)

        this.input.addEventListener('input', () => this.query())
        this.input.addEventListener('keydown', (event) => this.onKey(event))

        /*
         * 🛑 The native `toggle` event, so a close by ANY route returns focus —
         * Escape, a click outside, `hidePopover()`, or the browser closing the
         * top layer for its own reasons. Handling only the Escape key would
         * leave a keyboard reader's focus on a removed element in three of those
         * four cases.
         */
        this.modal.addEventListener('toggle', (event) => {
            if (event.newState === 'closed') {
                this.restoreFocus()
            }
        })
    }

    get node() {
        return this.modal
    }

    show(opener) {
        this.opener = opener ?? null

        if (this.usesPopover) {
            this.modal.showPopover()
        } else {
            // No top layer available. The modal still opens and still behaves;
            // what is lost is the overlay guarantee, not the feature.
            this.modal.removeAttribute('hidden')
        }

        this.input.focus()
        this.announce()
    }

    hide() {
        if (this.usesPopover) {
            /*
             * `hidePopover()` throws on an already-closed popover, and a double
             * Escape is an ordinary thing a reader does.
             */
            if (this.modal.matches(':popover-open')) {
                this.modal.hidePopover()
            }

            // The `toggle` listener returns focus — see the constructor.
            return
        }

        this.modal.setAttribute('hidden', '')
        this.restoreFocus()
    }

    /** Whether the modal is currently showing, however it is being shown. */
    get isOpen() {
        return this.usesPopover
            ? this.modal.matches(':popover-open')
            : !this.modal.hasAttribute('hidden')
    }

    /** 🛑 §8.15.8: "Escape closes, focus returns, no trap." */
    restoreFocus() {
        if (this.opener && typeof this.opener.focus === 'function') {
            this.opener.focus()
        }
    }

    onKey(event) {
        if (event.key === 'Escape') {
            event.preventDefault()
            this.hide()

            return
        }

        if (event.key === 'Tab') {
            // No trap, for the reason VersionSwitcher gives.
            return
        }

        const last = this.results.length - 1

        if (event.key === 'ArrowDown') {
            event.preventDefault()
            this.activate(this.index >= last ? 0 : this.index + 1)
        } else if (event.key === 'ArrowUp') {
            event.preventDefault()
            this.activate(this.index <= 0 ? last : this.index - 1)
        } else if (event.key === 'Enter' && this.index >= 0) {
            event.preventDefault()
            const chosen = this.results[this.index]

            if (chosen?.href) {
                location.assign(chosen.href)
            }
        }
    }

    /**
     * Run the query, or say plainly that search is not available.
     *
     * 🛑 `search.enabled` is false until Phase 29 ships the index, and the
     * control says so rather than pretending. §17 puts the `SearchEngine` seam
     * and the query path in Phase 29 and the search UX in Phase 30; what this
     * phase owes is §8.15.8's combobox behaviour, which is exercised in full by
     * the keyboard and the announcement whether or not an engine answers.
     */
    async query() {
        const term = this.input.value.trim()

        if (!this.config.enabled || !this.config.endpoint) {
            this.render([])
            this.status.textContent = term === ''
                ? 'Type to search.'
                : 'Search is not configured for this project.'

            return
        }

        if (term === '') {
            this.render([])
            this.announce()

            return
        }

        try {
            const response = await fetch(
                this.config.endpoint + '?q=' + encodeURIComponent(term),
                { headers: { Accept: 'application/json' }, credentials: 'same-origin' },
            )

            this.render(response.ok ? ((await response.json())?.results ?? []) : [])
        } catch {
            /*
             * A failed query is reported as a failed query. Rendering an empty
             * list would tell the reader there are no results, which is a
             * different and false statement.
             */
            this.render([])
            this.status.textContent = 'Search is unavailable.'

            return
        }

        this.announce()
    }

    render(results) {
        this.results = Array.isArray(results) ? results : []
        this.index = -1
        this.list.replaceChildren()

        for (const [position, result] of this.results.entries()) {
            const option = el('li', {
                role: 'option',
                id: 'docup-result-' + position,
                class: 'option',
                'aria-selected': 'false',
            })

            option.appendChild(el('span', {}, String(result.title ?? result.href ?? '')))
            this.list.appendChild(option)
        }

        this.input.setAttribute('aria-expanded', this.results.length > 0 ? 'true' : 'false')
        this.input.removeAttribute('aria-activedescendant')
    }

    activate(index) {
        this.index = index

        for (const [position, option] of Array.from(this.list.children).entries()) {
            const active = position === index

            option.setAttribute('aria-selected', active ? 'true' : 'false')
            option.classList.toggle('active', active)

            if (active) {
                // 🛑 The pattern's own rule: the input keeps focus and names the
                // active option. Moving focus into the list would stop the
                // reader typing, which is what "search-as-you-type" is.
                this.input.setAttribute('aria-activedescendant', option.id)
            }
        }
    }

    /** 🛑 §8.15.8's "announced result counts". */
    announce() {
        const count = this.results.length

        this.status.textContent = count === 1 ? '1 result' : String(count) + ' results'
    }
}

/**
 * 🛑 §8.7.17's cross-reference rewriter.
 *
 * > "The addons payload MUST carry the per-version cross-reference map so the
 * > client progressively rewrites visible hrefs for humans, with the 302
 * > remaining the no-JavaScript and AI-agent path."
 *
 * **Progressively**, which is the word that decides the design: the link already
 * works before this runs, because the server answers `/_/x/…` with a 302. So
 * this is an improvement to a working page and must never make one worse — a
 * component absent from the map is left exactly as it was, and nothing is
 * invented. §8.7.16's argument is that "sending every typo to the home page is
 * how a broken link becomes invisible", and a rewriter that guessed would do
 * precisely that on the client.
 *
 * 🛑 It rewrites `href` only. Not `src`, not a form action, not an element it
 * created: the requirement is about "visible hrefs for humans", and rewriting
 * anything that fetches would change what the page loads.
 */
function rewriteCrossReferences(map) {
    if (!map || Object.keys(map).length === 0) {
        return 0
    }

    let rewritten = 0

    for (const anchor of document.querySelectorAll('a[href]')) {
        const href = anchor.getAttribute('href')

        if (!href || !href.startsWith(XREF_PREFIX)) {
            continue
        }

        const rest = href.slice(XREF_PREFIX.length)
        const slash = rest.indexOf('/')
        const component = (slash === -1 ? rest : rest.slice(0, slash)).toLowerCase()
        const base = map[component]

        if (!base) {
            // Unknown component: left alone, so the server still 404s it.
            continue
        }

        anchor.setAttribute('href', base + (slash === -1 ? '' : rest.slice(slash + 1)))
        anchor.setAttribute('data-docup-xref', component)
        rewritten += 1
    }

    return rewritten
}

/**
 * §8.15.6's analytics beacon.
 *
 * 🛑 **Gated, and the gate is off with no setting that opens it.** §17 puts the
 * rollup tables, the consent hook and the salt rotation in Phase 31, whose exit
 * criteria include "Analytics is **off on a fresh install**" and "no IP,
 * user-agent or cookie column anywhere". So this phase ships the beacon and the
 * flag, and ships no operator toggle at all — see
 * `App\Addons\AddonsPayload::analytics()` for why a toggle that recorded nothing
 * would be worse than its absence.
 *
 * `sendBeacon` rather than `fetch`, because a page view is sent as the reader
 * leaves and a `fetch` is cancelled by the navigation. The body carries the
 * build id and the path and 🛑 nothing identifying: no referrer, no screen
 * dimensions, no client hints. §8.17's compliance posture is the reason the
 * payload is this thin, and it is thin here rather than filtered at the server
 * so that there is nothing to filter.
 */
function sendBeacon(payload) {
    const analytics = payload?.analytics

    if (!analytics?.enabled || !analytics.endpoint || typeof navigator.sendBeacon !== 'function') {
        return false
    }

    return navigator.sendBeacon(
        analytics.endpoint,
        new Blob(
            [JSON.stringify({ build: payload.build ?? null, path: location.pathname })],
            { type: 'application/json' },
        ),
    )
}

/**
 * 🛑 §8.15.12's takeover of the generator's own search control.
 *
 * > "Where a generator ships its own search affordance, the addons runtime
 * > SHOULD take it over via a configurable per-project selector defaulting to
 * > `input[type='search'], [role='search'] input`, and MUST leave the
 * > generator's own search working untouched when `chrome_mode` is `off` or
 * > takeover is disabled."
 *
 * The `MUST` is the half with teeth, and it is why this function returns early
 * on one boolean the server computed: `search.takeover` is already false when
 * `chrome_mode` is `off`, so the runtime cannot implement half the rule by
 * checking one condition and forgetting the other.
 *
 * 🛑 Taking over means **intercepting focus and click**, never removing or
 * disabling the control. If chrome's modal fails to open — an old browser, a
 * thrown error — the reader is left with a working generator search box rather
 * than a dead one. Removing it would be the version of this feature that breaks
 * search for the readers it was meant to help.
 */
function takeOverSearch(config, onOpen) {
    if (!config?.takeover || !config.selector) {
        return 0
    }

    let found

    try {
        found = document.querySelectorAll(config.selector)
    } catch {
        /*
         * The selector is per-project configuration and reaches here as a
         * string. An invalid one is a configuration mistake, not a reason to
         * stop rendering chrome — and it leaves the generator's own search
         * working, which is the §8.15.12 MUST.
         */
        return 0
    }

    let taken = 0

    for (const control of found) {
        // Chrome's own input matches the default selector. It must not take
        // itself over.
        if (control.hasAttribute('data-docup-search')) {
            continue
        }

        control.addEventListener('focus', (event) => {
            event.preventDefault()
            control.blur()
            onOpen(control)
        })

        control.addEventListener('click', (event) => {
            event.preventDefault()
            onOpen(control)
        })

        control.setAttribute('data-docup-takeover', '')
        taken += 1
    }

    return taken
}

/**
 * The custom element. Everything a reader sees is inside its closed root.
 *
 * 🛑 `<docup-chrome>` renders at the **start of `<body>`** and is not inserted
 * into the documentation's own layout. §4.3/6 and §8.9.8 forbid rewriting
 * documentation, and moving a generator's nodes to fit chrome around them would
 * be exactly that, done by JavaScript instead of at ingest. The document is
 * untouched; chrome sits above it.
 */
class DocUpChrome extends HTMLElement {
    connectedCallback() {
        if (roots.has(this)) {
            return
        }

        // 🛑 Closed. See the module docblock: this is the whole of §8.15.5.
        const root = this.attachShadow({ mode: 'closed' })

        /*
         * 🛑 And then VERIFIED closed, which is not paranoia about our own
         * argument — it closes a real hole.
         *
         * Documentation JavaScript runs before this script does: an inline
         * script executes during parsing and this file is `defer`. So a page
         * can replace `Element.prototype.attachShadow` with a wrapper that
         * forces `{ mode: 'open' }`, and every guarantee in §8.15.5 would be
         * gone — `host.shadowRoot` would hand the page the version switcher to
         * read, restyle and hide, and nothing would look wrong.
         *
         * There is no way to recover a pristine `attachShadow` once the realm
         * has been patched; same-origin script owns the realm, and §14's threat
         * model already says documentation is "attacker-controlled HTML and
         * JavaScript on your own domain". What IS available is to notice. A
         * closed root makes `this.shadowRoot` null by definition, so a non-null
         * value here means the root we were handed is open — and chrome then
         * renders **nothing**.
         *
         * That turns a silent compromise into a visible absence, which is the
         * trade worth making every time: a reader who sees no version switcher
         * knows something is wrong, and a reader shown a switcher somebody else
         * controls does not.
         */
        if (this.shadowRoot !== null) {
            return
        }

        roots.set(this, root)
    }
}

/**
 * Render chrome into a host's closed root.
 *
 * 🛑 A module-scoped function rather than a method on the element, and that is
 * a deliberate narrowing. `customElements.define` makes the class reachable
 * from any page script as `customElements.get('docup-chrome')`, so a `static
 * render` would have been a documented way for a documentation page to build
 * convincing fake chrome out of a payload it chose. It could draw a fake
 * switcher anyway — same origin, same DOM — but it should not be handed DocUp's
 * own renderer to do it with.
 */
function render(host, payload) {
    const root = roots.get(host)

    if (!root) {
        return
    }

    const scheme = resolveScheme(payload)

    host.setAttribute('data-docup-scheme', scheme)
    host.setAttribute('data-motion', payload?.branding?.theme?.tokens?.['motion.allow']?.light === '1' ? 'allow' : 'deny')
    applyDirection(host)

    const style = document.createElement('style')

    /*
     * 🛑 The token block comes AFTER the stylesheet, so a later declaration
     * of the same custom property wins without needing a specificity
     * argument. Both are `!important` and both match `:host`, so order is
     * the tie-break — and this is the order that makes the payload the
     * authority over the defaults.
     */
    style.textContent = CSS + '\n' + hostTokens(payload?.branding?.theme?.tokens, scheme)

    const banners = el('div', { class: 'banners' })

    for (const banner of payload?.notifications ?? []) {
        banners.appendChild(renderBanner(banner))
    }

    const announcement = payload?.branding?.chrome?.announcement

    if (announcement?.markup) {
        const node = el('div', { class: 'banner announcement', 'data-tone': announcement.tone ?? 'notice' })

        setAnnouncement(node, announcement.markup)
        banners.appendChild(node)
    }

    const bar = el('div', { class: 'bar' })
    const brandName = payload?.branding?.theme?.tokens?.['brand.name']?.light

    bar.appendChild(el('span', { class: 'brand' }, String(brandName ?? payload?.project?.name ?? 'Documentation')))

    for (const link of payload?.branding?.chrome?.navigation ?? []) {
        bar.appendChild(el('a', { class: 'option', href: link.href }, String(link.label ?? '')))
    }

    bar.appendChild(el('span', { class: 'spacer' }))

    const switcher = new VersionSwitcher(payload)
    const search = new SearchModal(payload)
    const searchButton = el('button', { type: 'button', 'aria-haspopup': 'dialog' }, 'Search')

    searchButton.addEventListener('click', () => search.show(searchButton))

    bar.append(searchButton, switcher.node)

    for (const download of payload?.downloads ?? []) {
        bar.appendChild(el('a', { class: 'option', href: download.href }, String(download.format)))
    }

    root.append(style, banners, bar, search.node)

    /*
     * The takeover is wired after the modal exists, so a reader who clicks
     * the generator's box before chrome finished rendering gets the
     * generator's own search — which is the degradation §8.15.12 asks for.
     */
    takeOverSearch(payload?.search, (opener) => search.show(opener))
}

/** One notification banner (§8.15.6), as text and at most one link. */
function renderBanner(banner) {
    const node = el('div', {
        class: 'banner',
        'data-tone': banner.tone ?? 'notice',
        'data-kind': banner.kind,
        role: banner.tone === 'warning' || banner.tone === 'danger' ? 'alert' : 'status',
    })

    node.appendChild(el('span', {}, bannerText(banner)))

    if (banner.href) {
        node.append(document.createTextNode(' '), el('a', { href: banner.href }, bannerAction(banner)))
    }

    return node
}

/*
 * 🛑 The banner sentences, in one table.
 *
 * §8.14.3 makes chrome content structured data, so the payload carries a key and
 * substitutions rather than a sentence (`App\Addons\Banner`). The English text
 * lives here because this runtime is a static file: it cannot read `lang/`, and a
 * payload that carried the rendered sentence would be a payload an `api_only`
 * consumer could not localise.
 *
 * The consequence is stated plainly rather than hidden: chrome's own strings are
 * English until a later phase ships a translation route for them. The
 * documentation's language is the document's; this is DocUp's voice inside it.
 */
const BANNER_TEXT = {
    'addons.old_version': (values) =>
        'You are reading version ' + (values.version ?? '') + ', which is not the current version.',
    'addons.development_version': (values) =>
        'This is the development version (' + (values.version ?? '') + '). It may describe unreleased behaviour.',
    'addons.pull_request': () => 'This is a pull-request build. It is not published documentation.',
    'addons.page_untranslated': (values) =>
        'This page is not available in ' + (values.requested ?? 'this language') + '.',
}

const BANNER_ACTION = {
    'addons.old_version': 'Go to the current version',
    'addons.page_untranslated': 'Read it in another language',
}

function bannerText(banner) {
    const render = BANNER_TEXT[banner.kind]

    return render ? render(banner.values ?? {}) : ''
}

function bannerAction(banner) {
    return BANNER_ACTION[banner.kind] ?? 'Go there'
}

/**
 * The entry point.
 *
 * 🛑 §8.15.7's three modes decide whether anything happens at all:
 *
 * - `injected` — chrome renders. The default.
 * - `api_only` — nothing renders, because the project is shipping its own
 *   chrome from the same payload (§8.14.14). The runtime still fetched the
 *   payload, which is harmless and is also how a historical artifact that
 *   carries the tags behaves after a project switches mode: no rebuild, no
 *   chrome, exactly as §8.15.7 intends.
 * - `off` — nothing renders and 🛑 **nothing is touched**: no cross-reference
 *   rewrite, no search takeover, no beacon. §8.15.12 requires the generator's
 *   own search to be "untouched" in this mode, and §17's exit criterion is that
 *   "per-project opt-out removes chrome on the next request with no rebuild" —
 *   which this is, because the mode arrives in the payload rather than in the
 *   artifact.
 */
async function start() {
    if (!buildId()) {
        return
    }

    let payload

    try {
        payload = await fetchPayload()
    } catch {
        /*
         * The payload is unreachable. Chrome is absent and the documentation is
         * untouched, which is the correct degradation: §8.15.4's whole posture
         * is that a reader without chrome still has their page.
         */
        return
    }

    if (!payload || payload.chrome_mode === 'off') {
        return
    }

    /*
     * The rewriter and the beacon run in `api_only` too. The map and the opt-in
     * are request-scoped facts about the document (§8.15.2), not chrome — and a
     * project shipping its own header has the same broken cross-references as
     * one using DocUp's.
     */
    rewriteCrossReferences(payload.cross_references)
    sendBeacon(payload)

    if (payload.chrome_mode !== 'injected') {
        return
    }

    const tag = defineElement()

    if (tag === null) {
        return
    }

    const host = document.createElement(tag)

    document.body.prepend(host)
    render(host, payload)
}

/**
 * Define the custom element, and survive the name already being taken.
 *
 * 🛑 A documentation page can call `customElements.define('docup-chrome', …)`
 * before this script runs, and then `createElement` would build **their**
 * element: `roots` would hold nothing for it and chrome would be silently
 * absent. So a taken name falls back to a suffixed one.
 *
 * 🛑 **And the honest limit, stated rather than implied.** This defends against
 * squatting, not against documentation JavaScript in general. §14's threat model
 * is explicit that "built documentation is attacker-controlled HTML and
 * JavaScript on your own domain", and a script on the page can remove the host
 * element, or draw a convincing fake switcher of its own, and no shadow root
 * prevents either. What §8.15.5 buys is that documentation CSS and
 * documentation script cannot **read or restyle** the real chrome — which is
 * what stops a reader's authentication state and version list being altered
 * under them. Removing chrome is vandalism a reader can see; silently changing
 * it is not.
 */
function defineElement() {
    const existing = customElements.get(TAG)

    if (existing === DocUpChrome) {
        return TAG
    }

    if (existing === undefined) {
        customElements.define(TAG, DocUpChrome)

        return TAG
    }

    const fallback = TAG + '-' + Math.random().toString(36).slice(2, 10)

    try {
        customElements.define(fallback, DocUpChrome)
    } catch {
        return null
    }

    return fallback
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', start, { once: true })
} else {
    start()
}
