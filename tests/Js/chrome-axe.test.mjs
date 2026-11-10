// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * 🛑 §9.5.1's axe run, over the chrome a reader actually gets.
 *
 * > §9.5.1: "WCAG 2.2 AA for the dashboard, the default documentation theme and
 * > all **injected chrome**, with axe reporting zero violations in CI."
 *
 * `npm run axe` checks §8.14.14's rendered reference theme — a whole document,
 * generated from the real registry and the real chrome stylesheet. It cannot
 * check **injected chrome**, because injected chrome does not exist until the
 * runtime builds it in a shadow root at runtime, and Phase 27's build log
 * recorded exactly that gap: "Focus order, keyboard traps, `prefers-reduced-
 * motion` honouring and §8.15.8's combobox behaviour are runtime properties
 * Phase 28 ships and none is asserted."
 *
 * So this runs the real runtime, takes the shadow root it built, and audits the
 * markup inside it.
 *
 * ## 🛑 What is NOT checked, said rather than implied
 *
 * **Colour contrast.** Disabled, for the reason `tests/Accessibility/axe.mjs`
 * records at length: jsdom resolves neither CSS custom properties nor
 * inheritance well enough for the answer to mean anything, so axe reports
 * `incomplete` rather than `pass`. §8.14.5's own gate computes WCAG ratios from
 * the parsed token values over a fixed matrix in both schemes and refuses
 * publication below 3:1, which is a stronger check than axe-in-jsdom could be.
 * Reporting an `incomplete` as a pass would be a green run that checked nothing.
 *
 * **Anything needing layout.** Target size, reflow and focus-appearance are
 * WCAG 2.2 criteria that need a layout engine. jsdom has none, and no
 * assertion here pretends otherwise.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import axe from 'axe-core'
import { payload, run } from './harness.mjs'

/** WCAG 2.2 AA: A and AA at 2.0, 2.1 and 2.2, as `npm run axe` uses. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']

const RULES = {
    // See the file header. Covered by §8.14.5's gate instead.
    'color-contrast': { enabled: false },
}

/**
 * Audit one shadow root's contents.
 *
 * 🛑 axe is installed on the window it audits and pointed at the host element,
 * so it walks **into** the shadow root — axe supports shadow DOM traversal, and
 * that is the only reason this file can exist. Auditing `document` would find
 * an empty documentation page and report zero violations for the wrong reason.
 */
async function audit(context) {
    const { window } = context

    window.eval(axe.source)

    /*
     * A container inside the root. axe needs an element it can treat as the
     * tree's root, and the ShadowRoot itself is a DocumentFragment rather than
     * an Element — so the audit runs over the root's children, which is all of
     * chrome.
     */
    const fragment = window.document.createElement('div')

    for (const child of Array.from(context.shadow.children)) {
        if (child.tagName.toLowerCase() !== 'style') {
            fragment.appendChild(child.cloneNode(true))
        }
    }

    window.document.body.appendChild(fragment)

    const results = await window.axe.run(fragment, { runOnly: { type: 'tag', values: TAGS }, rules: RULES })

    /*
     * Spread into an array of THIS realm. axe runs inside the jsdom window, so
     * `results.violations` is a jsdom-realm Array whose prototype is not Node's
     * — and `assert.deepEqual` from `node:assert/strict` compares prototypes,
     * so an empty result failed against an empty literal. Cost twenty minutes,
     * and would have cost more if the test had been written to pass.
     */
    return [...results.violations]
}

/** A violation, as a line somebody can act on. */
function describe(violation) {
    const where = violation.nodes.map((node) => node.html.slice(0, 120)).join('\n      ')

    return `${violation.id} (${violation.impact}): ${violation.help}\n      ${where}`
}

test('the rendered chrome has no WCAG 2.2 AA violations', async () => {
    const context = await run({
        /*
         * Chrome with everything in it: navigation links, an announcement, all
         * four banners and the downloads. An audit of the empty case would pass
         * for a header with nothing in it to get wrong.
         */
        data: payload({
            branding: {
                ...payload().branding,
                chrome: {
                    navigation: [
                        { label: 'Guide', href: '/en/v1/' },
                        { label: 'Reference', href: '/en/v1/reference.html' },
                    ],
                    footer: [],
                    announcement: {
                        markup: 'Version <code>2.0</code> is out. <a href="/en/v2/">Read the notes</a>.',
                        tone: 'notice',
                    },
                    homepage: [],
                    not_found: null,
                },
                scheme: { default: 'light', toggle: true },
                banner: null,
            },
            notifications: [
                {
                    kind: 'addons.old_version',
                    key: 'addons.banners.old_version',
                    tone: 'warning',
                    href: '/en/v2/guide.html',
                    values: { version: 'v1', default: 'v2' },
                },
                {
                    kind: 'addons.development_version',
                    key: 'addons.banners.development_version',
                    tone: 'notice',
                    href: null,
                    values: { version: 'main' },
                },
                {
                    kind: 'addons.pull_request',
                    key: 'addons.banners.pull_request',
                    tone: 'notice',
                    href: null,
                    values: {},
                },
                {
                    kind: 'addons.page_untranslated',
                    key: 'addons.banners.page_untranslated',
                    tone: 'warning',
                    href: 'https://demo.docs.test/en/v1/guide.html',
                    values: { requested: 'ja', available: 'en', code: 'translation.page_untranslated' },
                },
            ],
            downloads: [
                { format: 'pdf', href: '/_/downloads/en/v1/pdf', content_type: 'application/pdf' },
                { format: 'epub', href: '/_/downloads/en/v1/epub', content_type: 'application/epub+zip' },
            ],
        }),
    })

    assert.ok(context.shadow, 'chrome rendered')

    const violations = await audit(context)

    assert.deepEqual(
        violations.map(describe),
        [],
        `axe found ${violations.length} violation(s) in the rendered chrome`,
    )

    context.close()
})

test('the search modal, open, has no WCAG 2.2 AA violations', async () => {
    /*
     * The modal is audited OPEN and with results, because that is the state a
     * reader is in when the combobox matters — and `aria-activedescendant`,
     * `aria-expanded` and the live region only exist in it.
     */
    const context = await run({
        data: payload({
            search: { enabled: true, endpoint: '/_/search', takeover: false, selector: "input[type='search']" },
        }),
    })

    const button = Array.from(context.shadow.querySelectorAll('button'))
        .find((node) => node.textContent === 'Search')

    button.click()

    context.window.fetch = () => Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
            results: [
                { title: 'Installing', href: '/en/v1/install.html' },
                { title: 'Configuring', href: '/en/v1/configure.html' },
            ],
        }),
    })

    const input = context.shadow.querySelector('[data-docup-search]')

    input.value = 'install'
    input.dispatchEvent(new context.window.Event('input', { bubbles: true }))

    await new Promise((resolve) => setTimeout(resolve, 0))

    const violations = await audit(context)

    assert.deepEqual(
        violations.map(describe),
        [],
        `axe found ${violations.length} violation(s) in the open search modal`,
    )

    context.close()
})

test('the checker still finds a planted violation', async () => {
    /*
     * 🛑 A green accessibility run proves nothing unless the checker is known to
     * be looking. Phase 27 verified `npm run axe` the same way — against an
     * `<img>` with no alt and a `<button>` with no name — and the same argument
     * applies here with more force, because this audit walks into a shadow root
     * and could silently be auditing an empty fragment.
     */
    const context = await run()

    const planted = context.document.createElement('div')

    planted.innerHTML = '<img src="x.png"><button></button>'
    context.shadow.appendChild(planted)

    const violations = await audit(context)
    const ids = violations.map((violation) => violation.id)

    assert.ok(ids.includes('image-alt'), 'axe must find an image with no alternative text')
    assert.ok(ids.includes('button-name'), 'axe must find a button with no accessible name')

    context.close()
})
