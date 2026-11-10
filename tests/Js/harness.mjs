// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * The jsdom harness for §8.15's chrome runtime.
 *
 * 🛑 **The runtime under test is the file that is served.** There is no bundler
 * and no test build: `resources/js/chrome/docup.js` is read from disk and
 * evaluated in a jsdom window, which is exactly what
 * `App\Http\Controllers\Serving\ChromeLoaderController` sends to a reader. A
 * harness that imported a module-shaped copy would be testing something nobody
 * runs.
 *
 * ## 🛑 How a test sees inside a closed shadow root
 *
 * It cannot, and that is the feature. So the harness wraps
 * `Element.prototype.attachShadow` **before** the runtime runs and keeps the
 * root it returns — while passing the runtime's own `{ mode: 'closed' }`
 * through untouched, so `host.shadowRoot` stays `null` and the runtime's own
 * open-root check (see its `connectedCallback`) still passes.
 *
 * That is a legitimate seam because the test owns the window and runs before
 * the script. A documentation page can do the same thing, which is precisely
 * why the runtime checks — see `attachShadow` in `docup.js`, and
 * `chrome-isolation.test.mjs`, which asserts the refusal.
 *
 * ## What jsdom cannot answer
 *
 * jsdom has no cascade and no layout, so it cannot evaluate whether a
 * documentation `!important` beats chrome's. That half of §18.11 is asserted
 * structurally, over the stylesheet text, in `chrome-isolation.test.mjs`. What
 * jsdom CAN answer for real is every DOM-level claim: the root is closed, the
 * switcher is unreachable, Escape closes and focus returns, the combobox
 * attributes are right and the live region is updated.
 */

import { readFileSync } from 'node:fs'
import { JSDOM, VirtualConsole } from 'jsdom'

export const RUNTIME = 'resources/js/chrome/docup.js'

export const runtimeSource = () => readFileSync(RUNTIME, 'utf8')

/**
 * A payload shaped like the real one, with everything overridable.
 *
 * Mirrors `App\Addons\AddonsPayload` — `addons-payload-shape.test.mjs` is not a
 * thing, because the PHP side owns the shape; `AddonsPayloadTest` asserts the
 * key set there. This is the client's view of it.
 */
export function payload(overrides = {}) {
    return {
        contract: 1,
        chrome_mode: 'injected',
        build: '0192f0a0-0000-7000-8000-000000000001',
        injector_version: 1,
        project: { slug: 'demo', name: 'Demo' },
        version: { slug: 'v1', language: 'en', kind: 'release', root: '/en/v1/' },
        canonical: 'https://demo.docs.test/en/v1/guide.html',
        branding: {
            contract: 1,
            theme: {
                hash: 'a'.repeat(64),
                stylesheet: '/_/theme/' + 'a'.repeat(64) + '.css',
                tokens: {
                    'brand.name': { light: 'Demo Docs', dark: 'Demo Docs' },
                    'color.surface.page': { light: '#ffffff', dark: '#0b0e14' },
                    'color.text.primary': { light: '#16191f', dark: '#e7eaf0' },
                    'color.focus.ring': { light: '#0b5cd5', dark: '#79b8ff' },
                    'font.body': { light: 'system-ui, sans-serif', dark: 'system-ui, sans-serif' },
                    'font.size.root': { light: '16px', dark: '16px' },
                    'font.line-height.body': { light: '1.6', dark: '1.6' },
                    'space.unit': { light: '4px', dark: '4px' },
                    'motion.allow': { light: '1', dark: '1' },
                },
            },
            assets: {},
            chrome: { navigation: [], footer: [], announcement: null, homepage: [], not_found: null },
            scheme: { default: 'light', toggle: true },
            banner: null,
        },
        flyout: {
            configuration: { comparator: 'semver', pin_channels_to_top: true },
            versions: [
                { slug: 'v2', language: 'en', kind: 'release', href: '/en/v2/guide.html', current: false, page_exists: true, channel: 'stable' },
                { slug: 'v1', language: 'en', kind: 'release', href: '/en/v1/guide.html', current: true, page_exists: true, channel: null },
                { slug: 'v0', language: 'en', kind: 'release', href: '/en/v0/', current: false, page_exists: false, channel: null },
            ],
        },
        notifications: [],
        search: { enabled: false, endpoint: null, takeover: true, selector: "input[type='search'], [role='search'] input" },
        navigation: [],
        cross_references: {},
        downloads: [],
        analytics: { enabled: false, endpoint: null },
        ...overrides,
    }
}

/**
 * Build a page, run the runtime in it, and hand back the handles a test needs.
 *
 * @param {object} options
 * @param {string} options.body      the documentation page's `<body>` markup
 * @param {string} options.head      extra `<head>` markup (hostile CSS goes here)
 * @param {object|null} options.data the payload the stubbed endpoint returns
 * @param {string} options.before    JavaScript the page runs BEFORE the runtime
 * @param {boolean} options.meta     whether §8.15.1's `<meta name="docup">` is present
 */
export async function run(options = {}) {
    const {
        body = '<h1>Guide</h1>',
        head = '',
        data = payload(),
        before = '',
        meta = true,
        dir = null,
        lang = 'en',
    } = options

    const metaTag = meta ? '<meta name="docup" content="b=0192f0a0-0000-7000-8000-000000000001">' : ''
    const html = `<!doctype html>
<html lang="${lang}"${dir ? ` dir="${dir}"` : ''}>
<head><meta charset="utf-8">${metaTag}${head}</head>
<body>${body}</body>
</html>`

    /*
     * Console output is captured rather than printed: a jsdom "Could not parse
     * CSS stylesheet" warning for hostile CSS a test planted on purpose is not
     * a failure, and a test run full of them is one nobody reads.
     */
    const virtualConsole = new VirtualConsole()
    const messages = []

    virtualConsole.on('jsdomError', (error) => messages.push(String(error)))
    virtualConsole.on('error', (...args) => messages.push(args.join(' ')))

    const dom = new JSDOM(html, {
        url: 'https://demo.docs.test/en/v1/guide.html',
        pretendToBeVisual: true,
        runScripts: 'outside-only',
        virtualConsole,
    })

    const { window } = dom

    /* The closed roots the runtime creates. See the file docblock. */
    const roots = []
    const originalAttachShadow = window.Element.prototype.attachShadow

    window.Element.prototype.attachShadow = function (init) {
        const root = originalAttachShadow.call(this, init)

        if (this.tagName.toLowerCase().startsWith('docup-chrome')) {
            roots.push({ root, init })
        }

        return root
    }

    /* §8.15.2's endpoint, stubbed. The request itself is recorded, because
     * "resolved from the request's host and path" is a claim about the URL. */
    const requests = []

    window.fetch = (url, init) => {
        requests.push({ url: String(url), init })

        if (data === null) {
            return Promise.resolve({ ok: false, status: 404, json: () => Promise.resolve(null) })
        }

        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(data) })
    }

    const beacons = []

    window.navigator.sendBeacon = (url, blob) => {
        beacons.push({ url: String(url), blob })

        return true
    }

    /*
     * 🛑 Navigation is NOT stubbed, and that is a deliberate limit rather than
     * an omission. jsdom's `location.assign` is non-configurable, so there is
     * no honest way to observe a navigation here — and patching the runtime to
     * make one observable would be testing a seam that does not exist in
     * production.
     *
     * So the tests assert what the DOM says instead: the option carries the
     * href the payload gave it, and the keyboard moves the selection to the
     * option the reader means. That the browser then navigates to an `href` is
     * the browser's job and not a claim this suite makes.
     */

    if (before !== '') {
        window.eval(before)
    }

    window.eval(runtimeSource())

    // The runtime awaits a promise before rendering; let the microtasks drain.
    await new Promise((resolve) => setTimeout(resolve, 0))

    return {
        window,
        document: window.document,
        host: window.document.querySelector('[id], docup-chrome') && window.document.body.firstElementChild,
        shadow: roots[0]?.root ?? null,
        shadowInit: roots[0]?.init ?? null,
        requests,
        beacons,
        messages,
        close: () => dom.window.close(),
    }
}

/**
 * The body of a captured beacon, as text.
 *
 * 🛑 Read with the jsdom window's own `FileReader` rather than `Blob.text()`:
 * the blob is constructed inside that realm and jsdom's `Blob` does not expose
 * `text()`. Worth a helper rather than a line in each test, because the failure
 * — `blob.text is not a function` — reads like a Node version problem and is
 * not one.
 */
export function beaconText(context, index) {
    const { blob } = context.beacons[index]

    return new Promise((resolve, reject) => {
        const reader = new context.window.FileReader()

        reader.onload = () => resolve(String(reader.result))
        reader.onerror = () => reject(reader.error)
        reader.readAsText(blob)
    })
}

/** The chrome element the runtime prepended, whatever name it settled on. */
export function hostOf(context) {
    for (const child of context.document.body.children) {
        if (child.tagName.toLowerCase().startsWith('docup-chrome')) {
            return child
        }
    }

    return null
}

/** The `<style>` text the runtime put inside the shadow root. */
export function shadowCss(context) {
    const style = context.shadow?.querySelector('style')

    return style ? style.textContent : ''
}
