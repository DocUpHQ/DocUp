// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * The four §17 Phase 28 deliverables that are runtime behaviour and nothing
 * else: the cross-reference rewriter (§8.7.17), the analytics beacon (§8.15.6),
 * the search takeover (§8.15.12) and `chrome_mode` (§8.15.7).
 *
 * Each is a claim about what the runtime does to **somebody else's page**, so
 * each is tested against one — a document with a generator's own markup in it,
 * not a fixture shaped for the assertion.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import { beaconText, hostOf, payload, run } from './harness.mjs'

/**
 * A page as MkDocs Material writes one, with a cross-reference in it.
 *
 * The search markup is Material's real shape, and the `role="search"` on the
 * wrapper is the load-bearing part: Material's input is `type="text"`, so
 * §8.15.12's documented default selector —
 * `input[type='search'], [role='search'] input` — reaches it through the
 * SECOND half of that pair and not the first. A fixture without the role
 * passed the takeover test for the wrong reason, which is how this was found.
 */
const MKDOCS = '<div class="md-search__inner" role="search">'
    + '<form class="md-search__form" name="search">'
    + '<input type="text" class="md-search__input" name="query" placeholder="Search" aria-label="Search">'
    + '</form></div>'
    + '<main>'
    + '<a id="xref" href="/_/x/handbook/guide/auth.html">the handbook</a>'
    + '<a id="xref-root" href="/_/x/handbook/">the handbook root</a>'
    + '<a id="unknown" href="/_/x/no-such/page.html">a typo</a>'
    + '<a id="ordinary" href="/en/v1/other.html">an ordinary link</a>'
    + '<img id="asset" src="/_/x/handbook/logo.png" alt="logo">'
    + '</main>'

const MAP = { handbook: '/en/v1/handbook/' }

test('§8.7.17: the rewriter resolves a known component and leaves the rest alone', async () => {
    const context = await run({ body: MKDOCS, data: payload({ cross_references: MAP }) })
    const { document } = context

    assert.equal(
        document.getElementById('xref').getAttribute('href'),
        '/en/v1/handbook/guide/auth.html',
        'a known component is rewritten to base + path',
    )

    assert.equal(
        document.getElementById('xref-root').getAttribute('href'),
        '/en/v1/handbook/',
        'a reference to the component root resolves to the base',
    )

    /*
     * 🛑 An unknown component is LEFT ALONE, so the server still answers it with
     * §8.7.16's 404. §8.7.16: "sending every typo to the home page is how a
     * broken link becomes invisible" — and a client-side guess would make that
     * invisible twice over, because nobody sees a 404 that never happens.
     */
    assert.equal(document.getElementById('unknown').getAttribute('href'), '/_/x/no-such/page.html')

    assert.equal(document.getElementById('ordinary').getAttribute('href'), '/en/v1/other.html')

    /*
     * 🛑 `href` only. §8.7.17 asks for "visible hrefs for humans"; rewriting a
     * `src` would change what the page FETCHES, and the 302 already answers it
     * correctly for a no-JavaScript reader.
     */
    assert.equal(document.getElementById('asset').getAttribute('src'), '/_/x/handbook/logo.png')

    // The rewritten links are marked, so the change is attributable in a DOM
    // somebody is debugging.
    assert.equal(document.getElementById('xref').getAttribute('data-docup-xref'), 'handbook')

    context.close()
})

test('§8.7.17: an empty map rewrites nothing', async () => {
    const context = await run({ body: MKDOCS })

    assert.equal(context.document.getElementById('xref').getAttribute('href'), '/_/x/handbook/guide/auth.html')

    context.close()
})

test('§8.15.6: the analytics beacon is silent while analytics is off', async () => {
    const context = await run({ body: MKDOCS })

    assert.deepEqual(context.beacons, [], 'nothing is sent with analytics off')

    context.close()
})

test('§8.15.6: the beacon carries the build and the path and nothing identifying', async () => {
    /*
     * The flag is set here by the test, because §17 puts the rollup tables, the
     * consent hook and the salt rotation in Phase 31 and there is deliberately
     * no operator toggle yet — see `AddonsPayload::analytics()`. What this phase
     * owes is the beacon, so the beacon is what is asserted.
     */
    const context = await run({
        body: MKDOCS,
        data: payload({ analytics: { enabled: true, endpoint: '/_/analytics' } }),
    })

    assert.equal(context.beacons.length, 1, 'one beacon per page view')
    assert.equal(context.beacons[0].url, '/_/analytics')

    const body = JSON.parse(await beaconText(context, 0))

    /*
     * 🛑 Two keys, and the SHAPE is the control. §8.17's compliance posture is
     * why the payload is this thin, and it is thin here rather than filtered at
     * the server so that there is nothing to filter: no referrer, no screen
     * dimensions, no client hints, no identifier of any kind.
     */
    assert.deepEqual(Object.keys(body).sort(), ['build', 'path'])
    assert.equal(body.path, '/en/v1/guide.html')

    context.close()
})

test('§8.15.12: the takeover intercepts the generator control without removing it', async () => {
    const context = await run({ body: MKDOCS })
    const control = context.document.querySelector('.md-search__input')

    assert.ok(control, 'the generator control is still in the document')
    assert.equal(control.getAttribute('data-docup-takeover'), '', 'and is marked as taken over')

    /*
     * 🛑 Intercepted, not removed or disabled. If chrome's modal fails to open —
     * an old browser, a thrown error — the reader is left with a working
     * generator search rather than a dead box. Removing it would break search
     * for exactly the readers the feature is for.
     */
    assert.equal(control.hasAttribute('disabled'), false)
    assert.equal(control.isConnected, true)

    control.click()

    const modal = context.shadow.querySelector('#docup-search')

    assert.ok(modal, 'chrome has a search modal')
    assert.equal(modal.hasAttribute('hidden'), false, 'clicking the generator control opens it')

    context.close()
})

test('§8.15.12: takeover disabled leaves the generator control untouched', async () => {
    const context = await run({
        body: MKDOCS,
        data: payload({
            search: { enabled: false, endpoint: null, takeover: false, selector: "input[type='search']" },
        }),
    })

    const control = context.document.querySelector('.md-search__input')

    assert.equal(control.hasAttribute('data-docup-takeover'), false, '§8.15.12: "untouched"')

    context.close()
})

test('§8.15.12: an invalid selector does not stop chrome rendering', async () => {
    /*
     * The selector is per-project configuration and arrives as a string. An
     * invalid one is a configuration mistake, not a reason to lose the version
     * switcher — and it leaves the generator's own search working, which is
     * §8.15.12's MUST.
     */
    const context = await run({
        body: MKDOCS,
        data: payload({
            search: { enabled: false, endpoint: null, takeover: true, selector: 'input[type=' },
        }),
    })

    assert.ok(context.shadow?.querySelector('[data-docup-switcher]'), 'chrome still rendered')
    assert.equal(
        context.document.querySelector('.md-search__input').hasAttribute('data-docup-takeover'),
        false,
    )

    context.close()
})

test('§8.15.7: chrome_mode off touches nothing at all', async () => {
    const context = await run({
        body: MKDOCS,
        data: payload({ chrome_mode: 'off', cross_references: MAP, analytics: { enabled: true, endpoint: '/_/a' } }),
    })

    assert.equal(hostOf(context), null, 'no chrome element')
    assert.equal(context.shadow, null, 'no shadow root')

    /*
     * 🛑 "Nothing" means nothing: §8.15.12 requires the generator's own search
     * to be untouched in this mode, §17's criterion is that the opt-out
     * "removes chrome", and a rewriter or a beacon still running would be a
     * project that opted out and is still being acted upon.
     */
    assert.equal(context.document.getElementById('xref').getAttribute('href'), '/_/x/handbook/guide/auth.html')
    assert.equal(context.document.querySelector('.md-search__input').hasAttribute('data-docup-takeover'), false)
    assert.deepEqual(context.beacons, [])

    context.close()
})

test('§8.15.7: chrome_mode api_only renders nothing but still rewrites and reports', async () => {
    const context = await run({
        body: MKDOCS,
        data: payload({
            chrome_mode: 'api_only',
            cross_references: MAP,
            analytics: { enabled: true, endpoint: '/_/a' },
        }),
    })

    assert.equal(hostOf(context), null, 'the project ships its own chrome, so DocUp renders none')

    /*
     * 🛑 But the rewriter and the beacon DO run. The cross-reference map and the
     * analytics opt-in are request-scoped facts about the document (§8.15.2)
     * rather than chrome — a project shipping its own header has the same
     * broken cross-references as one using DocUp's, and no way of its own to
     * resolve them.
     */
    assert.equal(context.document.getElementById('xref').getAttribute('href'), '/en/v1/handbook/guide/auth.html')
    assert.equal(context.beacons.length, 1)

    context.close()
})

test('an unreachable payload leaves the documentation untouched', async () => {
    /*
     * §8.15.4's posture applied to a network failure: "a reader of a
     * non-injectable artifact gets no injected chrome". The same is true of a
     * reader whose payload request failed, and the page they came for must
     * survive it intact.
     */
    const context = await run({ body: MKDOCS, data: null })

    assert.equal(hostOf(context), null)
    assert.equal(context.document.getElementById('xref').getAttribute('href'), '/_/x/handbook/guide/auth.html')
    assert.equal(context.document.querySelector('main').children.length, 5, 'the document is intact')

    context.close()
})

test('the payload is requested for the document being read, with credentials', async () => {
    const context = await run({ body: MKDOCS })

    assert.equal(context.requests.length, 1, 'one payload request per page')

    const { url, init } = context.requests[0]

    /*
     * 🛑 Origin-relative and `same-origin`, both load-bearing. §8.15.2 requires
     * the payload to be "authorised identically to the HTML", which means the
     * reader's `__Host-` grant cookie has to travel — and a configured absolute
     * host would be cross-origin on a custom domain and carry no cookie at all.
     */
    assert.ok(url.startsWith('/_/addons?path='), url)
    assert.equal(url, '/_/addons?path=' + encodeURIComponent('/en/v1/guide.html'))
    assert.equal(init.credentials, 'same-origin')

    context.close()
})
