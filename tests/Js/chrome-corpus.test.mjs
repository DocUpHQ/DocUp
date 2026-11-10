// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

/*
 * 🛑 §9.4's abuse corpus, the `chrome_css` half.
 *
 * `tests/Feature/Addons/AddonsCorpusTest.php` drives the `injection` and
 * `addons_path` subjects; this drives the one PHP cannot be pointed at, because
 * a closed shadow root only exists in a DOM.
 *
 * 🛑 **One corpus, one index, two runners.** Both read
 * `tests/Fixtures/AbuseCorpus/corpus.json`, and each asserts that every case is
 * claimed by one of them — so a case cannot be added with a subject nobody
 * drives and sit there looking like coverage.
 *
 * ## What a `chrome_survives` case asserts
 *
 * The documentation page is built with the case's hostile CSS in its head and
 * its hostile script running **before** the runtime, exactly as an inline
 * script in a generator's output would. Then:
 *
 * - chrome rendered at all;
 * - the switcher is inside the root and unreachable from the document;
 * - the shadow stylesheet still carries chrome's own values rather than the
 *   document's.
 *
 * 🛑 jsdom has no cascade, so none of this watches two `!important` declarations
 * compete. What it proves is that **the document's selectors cannot reach the
 * subject at all**, which is the primary defence; the cascade half is asserted
 * structurally in `chrome-isolation.test.mjs`, and that file is explicit about
 * the boundary. No browser renders any of this in CI and the build log says so.
 */

import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { hostOf, run, shadowCss } from './harness.mjs'

const CORPUS = 'tests/Fixtures/AbuseCorpus/corpus.json'

/** The `chrome_css` cases, from the one corpus index. */
function cases() {
    const corpus = JSON.parse(readFileSync(CORPUS, 'utf8'))

    return corpus.cases.filter((entry) => entry.category === 'addons' && entry.subject === 'chrome_css')
}

/** Every `addons` case, for the mirror of the PHP runner's driver check. */
function allAddonsCases() {
    const corpus = JSON.parse(readFileSync(CORPUS, 'utf8'))

    return corpus.cases.filter((entry) => entry.category === 'addons')
}

test('the corpus has chrome_css cases and every addons case has a driver', () => {
    const mine = cases()

    assert.ok(mine.length > 0, 'the category carries cases for this runner')

    /*
     * 🛑 The mirror of `AddonsCorpusTest::test_every_case_has_a_driver_somewhere`.
     * Both runners assert the whole set, so adding a subject to one without
     * telling the other fails here.
     */
    const driven = new Set(['injection', 'addons_path', 'chrome_css'])

    for (const entry of allAddonsCases()) {
        assert.ok(driven.has(entry.subject), `${entry.id} has a subject no runner drives`)
    }

    for (const entry of mine) {
        assert.ok(['chrome_survives', 'chrome_refuses'].includes(entry.expect), `${entry.id} names an outcome`)
        assert.ok(entry.css || entry.script, `${entry.id} must carry hostile CSS or a hostile script`)
        assert.ok(String(entry.note).trim() !== '', `${entry.id} must say why it matters`)
    }
})

test('every chrome_css case produces its stated outcome', async () => {
    const failures = []

    for (const entry of cases()) {
        const context = await run({
            head: entry.css ? `<style>${entry.css}</style>` : '',
            before: entry.script ?? '',
        })

        const host = hostOf(context)
        const outcome = describe(context, host)

        if (outcome !== entry.expect) {
            failures.push(`${entry.id}: expected ${entry.expect}, got ${outcome}`)
            context.close()

            continue
        }

        if (entry.expect === 'chrome_survives') {
            /*
             * 🛑 The subject of §8.15.5 by name — "the version switcher, search
             * modal or authentication state" — asserted as present inside and
             * absent outside.
             */
            if (!context.shadow?.querySelector('[data-docup-switcher]')) {
                failures.push(`${entry.id}: the switcher is not in the shadow root`)
            }

            if (context.document.querySelector('[data-docup-switcher]') !== null) {
                failures.push(`${entry.id}: the switcher is reachable from the document`)
            }

            if (host.shadowRoot !== null) {
                failures.push(`${entry.id}: the root is not closed`)
            }

            // The document's token values must not be what chrome painted with.
            if (entry.css && entry.css.includes('#ff0000') && shadowCss(context).includes('#ff0000')) {
                failures.push(`${entry.id}: the document's token values reached the shadow stylesheet`)
            }

            // Nothing exposes a part, whatever the case tried to select.
            if (context.shadow?.querySelectorAll('[part], [exportparts]').length !== 0) {
                failures.push(`${entry.id}: a part is exposed`)
            }
        }

        context.close()
    }

    assert.deepEqual(failures, [], failures.join('\n'))
})

/**
 * Which outcome this page produced.
 *
 * `chrome_refuses` is a host element with an EMPTY root: the runtime noticed it
 * had been handed an open root and rendered nothing. `chrome_survives` is a
 * closed root with chrome in it. Anything else is neither, and is reported as
 * such rather than guessed at — a case that produced no host at all would
 * otherwise read as a refusal and pass the wrong assertion.
 */
function describe(context, host) {
    if (host === null) {
        return 'no_chrome_element'
    }

    const root = host.shadowRoot ?? context.shadow

    if (root === null || root === undefined) {
        return 'no_shadow_root'
    }

    return root.childNodes.length === 0 ? 'chrome_refuses' : 'chrome_survives'
}
