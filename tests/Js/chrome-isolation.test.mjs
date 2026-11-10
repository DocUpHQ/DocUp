// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * 🛑 §17's Phase 28 exit criterion, and §18.11's verification:
 *
 * > "A documentation page's CSS with `!important` cannot restyle or hide the
 * > version switcher."
 *
 * §18.11 is the assumption behind it — "A closed shadow root is sufficient
 * isolation for chrome against documentation CSS and JavaScript — against
 * `::part`, inherited custom properties, `!important` on inheritable properties
 * and DOM traversal" — and its stated test is "an adversarial fixture page
 * attempting all four". This file is that page, four times over.
 *
 * ## 🛑 What is proven here and what is argued
 *
 * Stated plainly, because the distinction is the honest part of this file.
 *
 * **Proven, at runtime, against a real DOM:** the root is closed; the document
 * cannot find the switcher by any selector, by tag name, by `shadowRoot`, or by
 * walking the tree; nothing exposes a `part`; nothing is reachable on `window`;
 * and a page that patches `attachShadow` to force an open root gets **no
 * chrome** rather than readable chrome.
 *
 * **Argued, from the stylesheet's text:** that a documentation `!important`
 * cannot win. jsdom has no cascade, so no assertion here can watch two
 * `!important` declarations compete. What is asserted instead is that the
 * mechanism is present and complete — every inheritable property reset on
 * `:host`, every one of them `!important`, and the token values re-declared
 * from the payload rather than inherited. The cascade rule those lean on is CSS
 * Scoping §3.4: for the host element, an important declaration in the shadow
 * tree beats an important declaration in the outer tree.
 *
 * No browser renders any of this in CI, and the build log says so. A structural
 * assertion that would fail the moment somebody dropped the `!important` is
 * worth considerably more than nothing, and considerably less than a browser.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import { hostOf, payload, run, runtimeSource, shadowCss } from './harness.mjs'

/** The hostile stylesheet, attempting every CSS route §18.11 names. */
const HOSTILE_CSS = `<style>
  /* 1. Brute force over everything, which real documentation themes do. */
  * { font-family: Comic Sans MS !important; color: #ff00ff !important; }

  /* 2. The host element by tag name — the one element a document CAN match. */
  docup-chrome { display: none !important; visibility: hidden !important; opacity: 0 !important; }
  docup-chrome * { display: none !important; }

  /* 3. Inherited custom properties: redefine every token chrome uses. */
  :root {
    --docup-color-surface-page: #ff0000 !important;
    --docup-color-text-primary: #ff0000 !important;
    --docup-font-body: Comic Sans MS !important;
    --docup-space-unit: 0px !important;
  }

  /* 4. ::part, in case anything is exposed. */
  docup-chrome::part(bar) { display: none !important; }
  docup-chrome::part(switcher) { display: none !important; }

  /* 5. An overlay, which is the other half of "restyle, hide or overlay". */
  .docup-overlay { position: fixed; inset: 0; z-index: 2147483647; background: #000; }

  /* 6. Reach into the shadow tree by every selector that has ever worked. */
  docup-chrome >>> .bar { display: none !important; }
  docup-chrome /deep/ .bar { display: none !important; }
  ::slotted(*) { display: none !important; }
</style>`

test('the shadow root is closed, and the mode is the runtime\'s own', async () => {
    const context = await run({ head: HOSTILE_CSS })

    assert.ok(context.shadow, 'chrome attached a shadow root')
    assert.equal(context.shadowInit.mode, 'closed', '§8.15.5 requires a CLOSED shadow root')

    const host = hostOf(context)

    assert.ok(host, 'the chrome host element is in the document')

    // 🛑 The defining property of a closed root, asserted rather than assumed.
    assert.equal(host.shadowRoot, null, 'a closed root must not be reachable as .shadowRoot')

    context.close()
})

test('the version switcher is unreachable from the document (§18.11, DOM traversal)', async () => {
    const context = await run({ head: HOSTILE_CSS })
    const { document } = context

    // It exists — inside the root the test was handed by its own wrapper.
    assert.ok(
        context.shadow.querySelector('[data-docup-switcher]'),
        'the switcher is rendered inside the shadow root',
    )

    // And it is invisible to every route a page script has.
    assert.equal(document.querySelector('[data-docup-switcher]'), null, 'querySelector must not find it')
    assert.equal(document.querySelectorAll('button').length, 0, 'no chrome button is in the document tree')
    assert.equal(document.getElementsByTagName('ul').length, 0, 'no chrome listbox is in the document tree')
    assert.equal(document.querySelectorAll('[role="listbox"]').length, 0, 'no chrome role is in the document tree')

    const host = hostOf(context)

    assert.equal(host.children.length, 0, 'the host has no light-DOM children to walk')
    assert.equal(host.innerHTML, '', 'the host renders nothing into the document tree')
    assert.equal(host.textContent, '', 'chrome text is not readable from the document')

    // A full tree walk, which is what a determined page script would do.
    const walker = document.createTreeWalker(document.body)
    let found = 0

    while (walker.nextNode()) {
        if (walker.currentNode.nodeType === 1 && walker.currentNode.hasAttribute?.('data-docup-switcher')) {
            found += 1
        }
    }

    assert.equal(found, 0, 'a tree walk from body must not reach the switcher')

    context.close()
})

test('nothing exposes a ::part, and nothing is reachable on window (§18.11, ::part)', async () => {
    const context = await run({ head: HOSTILE_CSS })

    const parts = context.shadow.querySelectorAll('[part], [exportparts]')

    assert.equal(parts.length, 0, '§8.15.5: no part may be exposed, or the document gets one selector in')

    // Nor a slot, which is the other documented way content crosses the boundary.
    assert.equal(context.shadow.querySelectorAll('slot').length, 0, 'chrome uses no slots')

    for (const name of ['docup', 'DocUp', '__docup', 'docupChrome']) {
        assert.equal(context.window[name], undefined, `the runtime must not expose window.${name}`)
    }

    context.close()
})

test('every token is re-declared on :host from the payload (§18.11, inherited custom properties)', async () => {
    const context = await run({ head: HOSTILE_CSS })
    const css = shadowCss(context)

    /*
     * 🛑 The declaration has to be present AND important. Present alone would
     * lose to the document's `:root { --docup-…: #ff0000 !important }`, because
     * an important declaration in the outer tree beats a normal one in the
     * inner tree — the asymmetry only runs chrome's way at equal importance.
     */
    for (const token of ['color-surface-page', 'color-text-primary', 'font-body', 'space-unit']) {
        assert.match(
            css,
            new RegExp('--docup-' + token + ':\\s*[^;]+!important;'),
            `--docup-${token} must be re-declared on :host with !important`,
        )
    }

    // And the values are the payload's, not the hostile stylesheet's.
    assert.match(css, /--docup-color-text-primary:\s*#16191f\s*!important/)
    assert.ok(!css.includes('#ff0000'), 'the document\'s token values must not appear in the shadow stylesheet')

    context.close()
})

test('every inheritable property is reset on :host with !important (§18.11)', async () => {
    const context = await run()
    const css = shadowCss(context)
    const hostBlock = /:host \{([\s\S]*?)\n\}/.exec(css)

    assert.ok(hostBlock, 'the shadow stylesheet opens with a :host block')

    const block = hostBlock[1]

    /*
     * 🛑 `all: initial` must come FIRST. It is the only complete answer — the
     * set of inheritable properties grows with every CSS release and a
     * hand-kept list goes stale — and a declaration placed after it would be
     * wiped. Both halves are asserted, because the first draft of the runtime
     * had `all` last and silently lost every reset below it.
     */
    const declarations = block
        .split('\n')
        .map((line) => line.trim())
        .filter((line) => line !== '')

    assert.match(declarations[0], /^all: initial !important;$/, '`all: initial` must be the first declaration')

    /*
     * The properties CSS's `all` deliberately excludes, plus the ones chrome
     * needs a specific value for. §18.11's "`!important` on inheritable
     * properties" is the vector; this is the list that answers it.
     */
    for (const property of [
        'direction', 'unicode-bidi', 'display', 'visibility', 'opacity', 'color',
        'font-family', 'font-size', 'line-height', 'text-align', 'white-space',
        'letter-spacing', 'word-spacing', 'text-transform', 'cursor',
        'pointer-events', 'writing-mode', 'list-style',
    ]) {
        assert.ok(
            declarations.some((line) => new RegExp('^' + property + ':\\s.*!important;$').test(line)),
            `:host must reset ${property} with !important (§18.11)`,
        )
    }

    // Nothing in the :host block may be left un-important: one normal
    // declaration there is one property a documentation !important can win.
    for (const line of declarations) {
        assert.match(line, /!important;$/, `every :host declaration must be !important — found: ${line}`)
    }

    context.close()
})

test('a page that forces an OPEN shadow root gets no chrome at all', async () => {
    /*
     * 🛑 The attack the runtime's own check exists for. Documentation
     * JavaScript runs before a deferred script, so a page can replace
     * `Element.prototype.attachShadow` with a wrapper that forces
     * `{ mode: 'open' }` — and every guarantee above would be gone silently.
     *
     * The runtime cannot recover a pristine `attachShadow`; same-origin script
     * owns the realm. What it does is notice, and refuse. A reader who sees no
     * version switcher knows something is wrong; a reader shown a switcher the
     * page controls does not.
     */
    const context = await run({
        before: `
            const original = Element.prototype.attachShadow
            Element.prototype.attachShadow = function (init) {
                return original.call(this, { ...init, mode: 'open' })
            }
        `,
    })

    const host = hostOf(context)

    assert.ok(host, 'the host element is still created')
    assert.ok(host.shadowRoot, 'the page did manage to force an open root')
    assert.equal(host.shadowRoot.childNodes.length, 0, 'and chrome refused to render into it')

    context.close()
})

test('the runtime does nothing without §8.15.1\'s meta tag', async () => {
    const context = await run({ meta: false })

    assert.equal(hostOf(context), null, 'no meta tag means no chrome')
    assert.equal(context.requests.length, 0, 'and no payload request')

    context.close()
})

test('the served runtime contains no eval and no remote import', async () => {
    const source = runtimeSource()

    /*
     * 🛑 `template.innerHTML` is the ONE permitted use, in setAnnouncement(),
     * and it is removed before the sweep below so that a second use anywhere
     * else fails. Asserted first, so the exemption cannot quietly disappear and
     * leave a check that passes because the thing it exempted is gone.
     */
    assert.ok(
        source.includes('template.innerHTML = String(markup)'),
        'the one permitted innerHTML is setAnnouncement allowlisted parse',
    )

    const swept = source.replace('template.innerHTML = String(markup)', '')

    /*
     * 🛑 §8.14.8 forbids tenant JavaScript in chrome at every scope below
     * installation, on the argument that a chrome slot "puts it in the same
     * DOM". A runtime with an evaluator in it would be that slot, arrived at
     * from the other direction — so the absence is asserted rather than assumed
     * from the fact that nobody added one yet.
     */
    for (const forbidden of ['eval(', 'new Function(', 'innerHTML', 'outerHTML', 'document.write', 'insertAdjacentHTML']) {
        assert.ok(
            !swept.includes(forbidden),
            `the chrome runtime must not use ${forbidden} — §8.14.8`,
        )
    }

    // No module graph: the loader is one file by design (see the controller).
    assert.ok(!/^\s*import\s/m.test(source), 'the runtime must be one self-contained file')
    assert.ok(!/^\s*export\s/m.test(source), 'the runtime must export nothing')

    assert.ok(
        !/https?:\/\/(?!creativecommons|www\.w3)/.test(source.replace(/\/\*[\s\S]*?\*\//g, '')),
        'the runtime must fetch nothing from a third-party origin',
    )
})

test('an announcement\'s script and handlers do not survive (§8.14.3)', async () => {
    const context = await run({
        data: payload({
            branding: {
                ...payload().branding,
                chrome: {
                    navigation: [],
                    footer: [],
                    announcement: {
                        markup:
                            'Read <strong onmouseover="steal()">this</strong>'
                            + '<script>steal()</script>'
                            + '<a href="javascript:steal()">now</a>'
                            + '<a href="/en/v2/">and this</a>',
                        tone: 'notice',
                    },
                    homepage: [],
                    not_found: null,
                },
                scheme: { default: 'light', toggle: true },
                banner: null,
            },
        }),
    })

    const node = context.shadow.querySelector('.announcement')

    assert.ok(node, 'the announcement renders')
    assert.equal(node.querySelectorAll('script').length, 0, 'no script element survives')
    assert.equal(node.querySelector('strong').getAttribute('onmouseover'), null, 'no event handler survives')

    const hrefs = Array.from(node.querySelectorAll('a')).map((a) => a.getAttribute('href'))

    assert.ok(!hrefs.includes('javascript:steal()'), 'a javascript: href must be dropped')
    assert.ok(hrefs.includes('/en/v2/'), 'a same-origin href survives')
    assert.equal(node.querySelector('a[href="/en/v2/"]').getAttribute('rel'), 'noopener nofollow')

    // The words survive even where the element did not — the filter unwraps
    // rather than deletes, so a reader is never shown a sentence with a hole.
    assert.match(node.textContent, /Read this/)
    assert.match(node.textContent, /and this/)

    context.close()
})
