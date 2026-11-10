// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * 🛑 §8.15.8, and §17's Phase 28 exit criterion:
 *
 * > §8.15.8: "Keyboard operation and focus management of chrome **inside the
 * > closed shadow root** MUST be specified and tested: Escape closes, focus
 * > returns, no trap. The search-as-you-type control MUST implement the ARIA
 * > combobox pattern with announced result counts. Chrome MUST honour
 * > `prefers-reduced-motion` and reconcile `prefers-color-scheme` with the
 * > project's colour-scheme default, and MUST support RTL."
 *
 * > §17: "Escape closes the search modal and returns focus; result counts are
 * > announced."
 *
 * Phase 27's build log recorded all of this as unasserted: "Focus order,
 * keyboard traps, `prefers-reduced-motion` honouring and §8.15.8's combobox
 * behaviour are runtime properties Phase 28 ships and none is asserted." This
 * file is that assertion.
 *
 * ## What jsdom gives and what it does not
 *
 * jsdom implements `activeElement` inside a shadow root, `focus()`, event
 * dispatch and `KeyboardEvent`, so every claim below about focus and keys is
 * checked for real. It does not implement the top layer, so
 * `showPopover`/`hidePopover` are absent — the runtime's own fallback path runs
 * instead, which is the path a browser without `popover` support takes. 🛑 So
 * what is asserted is that **closing by any route returns focus**, which is the
 * requirement, rather than that one particular API was called.
 */

import { strict as assert } from 'node:assert'
import test from 'node:test'
import { payload, run } from './harness.mjs'

/** A key, dispatched the way a browser dispatches one. */
function press(target, key) {
    const event = new target.ownerDocument.defaultView.KeyboardEvent('keydown', {
        key,
        bubbles: true,
        cancelable: true,
    })

    target.dispatchEvent(event)

    return event
}

/** Whatever has focus, following the shadow boundary. */
function focused(context) {
    const outer = context.document.activeElement

    return outer?.shadowRoot?.activeElement ?? context.shadow?.activeElement ?? outer
}

test('Escape closes the search modal and returns focus (§17 exit criterion)', async () => {
    const context = await run()
    const button = Array.from(context.shadow.querySelectorAll('button'))
        .find((node) => node.textContent === 'Search')

    assert.ok(button, 'chrome renders a search opener')

    button.click()

    const input = context.shadow.querySelector('[data-docup-search]')

    assert.ok(input, 'the modal carries the combobox input')
    assert.equal(context.shadow.activeElement, input, 'opening moves focus into the input')

    const event = press(input, 'Escape')

    assert.ok(event.defaultPrevented, 'Escape is handled rather than left to the page')

    // 🛑 Closed…
    const modal = context.shadow.querySelector('#docup-search')

    assert.ok(modal.hasAttribute('hidden'), 'Escape closes the modal')

    // …and 🛑 focus returned to the control that opened it.
    assert.equal(context.shadow.activeElement, button, 'Escape returns focus to the opener')

    context.close()
})

test('the search control is an ARIA combobox (§8.15.8)', async () => {
    const context = await run()
    const input = context.shadow.querySelector('[data-docup-search]')

    assert.equal(input.getAttribute('role'), 'combobox')
    assert.equal(input.getAttribute('aria-expanded'), 'false')
    assert.equal(input.getAttribute('aria-autocomplete'), 'list')
    assert.ok(input.getAttribute('aria-label'), 'the input has an accessible name')

    const list = context.shadow.querySelector('#' + input.getAttribute('aria-controls'))

    assert.ok(list, 'aria-controls names an element that exists')
    assert.equal(list.getAttribute('role'), 'listbox')

    const modal = context.shadow.querySelector('#docup-search')

    assert.equal(modal.getAttribute('role'), 'dialog')
    assert.equal(modal.getAttribute('aria-modal'), 'true')
    assert.ok(modal.getAttribute('aria-label'), 'the dialog has an accessible name')

    context.close()
})

test('result counts are announced in a live region (§8.15.8, §17)', async () => {
    /*
     * The endpoint is stubbed as enabled here. §8.15's search ENGINE is Phase
     * 29's and the payload says `enabled: false` in production until then — but
     * §8.15.8's announcement requirement is this phase's, and it is a property
     * of the control rather than of the engine. So the control is exercised
     * against a transport the test supplies, which is what the server will
     * supply later.
     */
    const context = await run({
        data: payload({
            search: {
                enabled: true,
                endpoint: '/_/search',
                takeover: false,
                selector: "input[type='search']",
            },
        }),
    })

    const input = context.shadow.querySelector('[data-docup-search]')
    const status = context.shadow.querySelector('[role="status"]')

    assert.ok(status, 'chrome renders a live region for the count')
    assert.equal(status.getAttribute('aria-live'), 'polite')
    assert.equal(status.getAttribute('aria-atomic'), 'true')

    context.window.fetch = () => Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
            results: [
                { title: 'Installing', href: '/en/v1/install.html' },
                { title: 'Configuring', href: '/en/v1/configure.html' },
                { title: 'Deploying', href: '/en/v1/deploy.html' },
            ],
        }),
    })

    input.value = 'install'
    input.dispatchEvent(new context.window.Event('input', { bubbles: true }))

    await new Promise((resolve) => setTimeout(resolve, 0))

    assert.equal(status.textContent, '3 results', 'the count is announced')
    assert.equal(input.getAttribute('aria-expanded'), 'true', 'the combobox expands when there are results')
    assert.equal(context.shadow.querySelectorAll('[role="option"]:not([id^="docup-version"])').length, 3)

    // 🛑 Singular is not "1 results". A count read aloud is read by a person.
    context.window.fetch = () => Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ results: [{ title: 'Installing', href: '/en/v1/install.html' }] }),
    })

    input.value = 'installing'
    input.dispatchEvent(new context.window.Event('input', { bubbles: true }))

    await new Promise((resolve) => setTimeout(resolve, 0))

    assert.equal(status.textContent, '1 result')

    context.close()
})

test('arrow keys move the active option and focus stays in the input (§8.15.8)', async () => {
    const context = await run({
        data: payload({
            search: { enabled: true, endpoint: '/_/search', takeover: false, selector: "input[type='search']" },
        }),
    })

    const input = context.shadow.querySelector('[data-docup-search]')
    const button = Array.from(context.shadow.querySelectorAll('button'))
        .find((node) => node.textContent === 'Search')

    button.click()

    context.window.fetch = () => Promise.resolve({
        ok: true,
        status: 200,
        json: () => Promise.resolve({
            results: [{ title: 'A', href: '/a' }, { title: 'B', href: '/b' }],
        }),
    })

    input.value = 'a'
    input.dispatchEvent(new context.window.Event('input', { bubbles: true }))
    await new Promise((resolve) => setTimeout(resolve, 0))

    press(input, 'ArrowDown')

    const first = context.shadow.querySelector('#docup-result-0')

    assert.equal(first.getAttribute('aria-selected'), 'true')
    assert.equal(input.getAttribute('aria-activedescendant'), 'docup-result-0')

    /*
     * 🛑 The pattern's own rule: focus does NOT move into the list. Moving it
     * would stop the reader typing, and "search-as-you-type" is the feature.
     */
    assert.equal(context.shadow.activeElement, input, 'focus stays in the combobox input')

    press(input, 'ArrowDown')
    assert.equal(input.getAttribute('aria-activedescendant'), 'docup-result-1')

    // Wrapping, so a reader holding ArrowDown is never stuck at the end.
    press(input, 'ArrowDown')
    assert.equal(input.getAttribute('aria-activedescendant'), 'docup-result-0')

    press(input, 'ArrowUp')
    assert.equal(input.getAttribute('aria-activedescendant'), 'docup-result-1')

    context.close()
})

test('Tab is never trapped, in either control (§8.15.8 "no trap")', async () => {
    const context = await run()
    const input = context.shadow.querySelector('[data-docup-search]')
    const button = Array.from(context.shadow.querySelectorAll('button'))
        .find((node) => node.textContent === 'Search')

    button.click()

    const tab = press(input, 'Tab')

    /*
     * 🛑 NOT prevented. A chrome that swallowed Tab would strand a keyboard
     * reader inside DocUp's furniture on somebody else's documentation — worse
     * than the control not working, because the page becomes unusable rather
     * than merely less useful.
     */
    assert.equal(tab.defaultPrevented, false, 'Tab must reach the browser from the search input')

    const switcher = context.shadow.querySelector('[data-docup-switcher]')

    press(switcher, 'ArrowDown')

    const option = context.shadow.querySelector('#docup-version-0')
    const switcherTab = press(option, 'Tab')

    assert.equal(switcherTab.defaultPrevented, false, 'Tab must reach the browser from the version list')
    assert.equal(switcher.getAttribute('aria-expanded'), 'false', 'and the list closes behind it')

    context.close()
})

test('the version switcher is a button-and-listbox with full keyboard support (§8.6.5)', async () => {
    const context = await run()
    const switcher = context.shadow.querySelector('[data-docup-switcher]')

    assert.equal(switcher.getAttribute('aria-expanded'), 'false')
    assert.equal(switcher.getAttribute('aria-haspopup'), 'listbox')
    assert.equal(switcher.textContent, 'v1', 'the button names the version being read')

    const list = context.shadow.querySelector('#' + switcher.getAttribute('aria-controls'))

    assert.equal(list.getAttribute('role'), 'listbox')
    assert.ok(list.hidden, 'the list starts closed')

    press(switcher, 'ArrowDown')

    assert.equal(switcher.getAttribute('aria-expanded'), 'true')
    assert.equal(list.hidden, false)
    assert.equal(context.shadow.activeElement.id, 'docup-version-0', 'ArrowDown moves into the list')

    const options = Array.from(list.querySelectorAll('[role="option"]'))

    assert.equal(options.length, 3, 'every authorised version is an option')

    // §8.6.5's order: the payload's order is rendered as given, because the
    // server applied the comparator (VersionOrder) and the client must not
    // re-sort — a second ordering is §8.6.4's named failure.
    assert.deepEqual(
        options.map((option) => option.textContent.replace('stable', '').replace('page not in this version', '').trim()),
        ['v2', 'v1', 'v0'],
    )

    // 🛑 §8.6.11: the version that does not hold this page says so.
    assert.match(options[2].textContent, /page not in this version/)
    assert.equal(options[2].getAttribute('data-href'), '/en/v0/', 'and links to the version root instead')

    // The current version is the selected option.
    assert.equal(options[1].getAttribute('aria-selected'), 'true')

    press(context.shadow.activeElement, 'End')
    assert.equal(context.shadow.activeElement.id, 'docup-version-2', 'End jumps to the last option')

    press(context.shadow.activeElement, 'Home')
    assert.equal(context.shadow.activeElement.id, 'docup-version-0', 'Home jumps to the first')

    press(context.shadow.activeElement, 'ArrowUp')
    assert.equal(context.shadow.activeElement.id, 'docup-version-2', 'ArrowUp wraps')

    // 🛑 Escape closes and focus returns, for the switcher as well as the modal.
    press(context.shadow.activeElement, 'Escape')

    assert.equal(switcher.getAttribute('aria-expanded'), 'false')
    assert.equal(context.shadow.activeElement, switcher, 'Escape returns focus to the button')

    context.close()
})

test('prefers-reduced-motion is honoured by construction (§8.15.8)', async () => {
    const context = await run()
    const css = context.shadow.querySelector('style').textContent

    /*
     * 🛑 Asserted as the SHAPE of the rule, not as a computed style — jsdom has
     * no cascade. The shape is the requirement: motion is added only inside
     * `(prefers-reduced-motion: no-preference)`, so there is no transition to
     * suppress. Written the other way round, a property added later would get
     * animation for free and a reader who asked for less motion would get more.
     */
    assert.match(css, /@media \(prefers-reduced-motion: no-preference\)/)

    /*
     * Comments stripped first: the prose above the query explains why motion is
     * opt-in and therefore contains the word, and a check that read its own
     * explanation as a violation would be unfixable.
     */
    const outside = css
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/@media \(prefers-reduced-motion: no-preference\)[\s\S]*?\n\}/g, '')

    for (const animating of ['transition', 'animation', '@keyframes']) {
        assert.ok(
            !outside.includes(animating),
            `${animating} must appear only inside the no-preference query — §8.15.8`,
        )
    }

    context.close()
})

test('prefers-color-scheme is reconciled with the project default (§8.15.8)', async () => {
    const base = payload()

    /*
     * A project that stated `dark` gets dark whatever the reader prefers: that
     * is the project describing its own documentation. §8.15.8 says
     * "reconcile", and this is the half of reconciliation that is not "defer".
     */
    const dark = await run({
        data: payload({ branding: { ...base.branding, scheme: { default: 'dark', toggle: true } } }),
    })

    const host = dark.document.body.firstElementChild

    assert.equal(host.getAttribute('data-docup-scheme'), 'dark')
    assert.match(
        dark.shadow.querySelector('style').textContent,
        /--docup-color-text-primary:\s*#e7eaf0/,
        'the dark value of every paired token is the one written to :host',
    )

    dark.close()

    // `system` defers to the reader. jsdom's matchMedia always reports no
    // match, which is the light branch — asserted as the branch rather than as
    // a preference, because the preference is the browser's to report.
    const system = await run({
        data: payload({ branding: { ...base.branding, scheme: { default: 'system', toggle: true } } }),
    })

    assert.equal(system.document.body.firstElementChild.getAttribute('data-docup-scheme'), 'light')

    system.close()
})

test('RTL comes from the document, and the stylesheet is written logically (§8.15.8)', async () => {
    const rtl = await run({ dir: 'rtl', lang: 'ar' })

    assert.equal(rtl.document.body.firstElementChild.getAttribute('dir'), 'rtl')

    const css = rtl.shadow.querySelector('style').textContent

    /*
     * 🛑 No physical direction anywhere in the chrome stylesheet. A mirrored
     * stylesheet would be a second stylesheet to keep in step; logical
     * properties make `dir` the whole of the RTL support.
     */
    for (const physical of [
        'margin-left', 'margin-right', 'padding-left', 'padding-right',
        'border-left:', 'border-right:', 'left:', 'right:', 'text-align: left', 'text-align: right',
    ]) {
        assert.ok(!css.includes(physical), `the chrome stylesheet must not use ${physical} — §8.15.8 RTL`)
    }

    rtl.close()

    // No `dir` on the document: the language decides, and Arabic is RTL.
    const inferred = await run({ lang: 'ar-EG' })

    assert.equal(inferred.document.body.firstElementChild.getAttribute('dir'), 'rtl')
    inferred.close()

    const ltr = await run({ lang: 'en-GB' })

    assert.equal(ltr.document.body.firstElementChild.getAttribute('dir'), 'ltr')
    ltr.close()
})
