<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Branding\TokenRegistry;
use App\Docs\GeneratedBlocks;

/**
 * 🛑 §8.15.9's documented mapping, as data.
 *
 * > "The ~45 branding tokens MUST be published with a documented mapping to
 * > Read the Docs' **33 addon CSS custom properties**, so a migrating project's
 * > custom CSS has a stated translation."
 *
 * ## Where the 33 came from
 *
 * Read verbatim from Read the Docs' own reference — the "CSS variables
 * reference" dropdown in `docs/user/addons.rst`, whose RST source records that
 * the list was generated from the addons CSS with
 * `grep -ho -- '--readthedocs-[a-zA-Z0-9-]*' *.css | sort -u`. The groups are
 * theirs: one global variable, nine flyout, eight notification, fifteen search.
 * 🛑 **Thirty-three exactly**, which is the number §8.15.9 states — asserted by
 * `ReadTheDocsMappingTest` so a typo cannot quietly make the published mapping
 * incomplete.
 *
 * Read the Docs documents no default values and no descriptions for them; the
 * defaults live in its addons source. So this table carries their names and
 * DocUp's answer, and nothing it would be inventing.
 *
 * ## 🛑 Why some entries map to nothing, and why that is the useful part
 *
 * A mapping that forced all 33 onto a DocUp token would be a lie in the
 * direction that costs a migrating team the most: they would write the override,
 * see no change, and conclude the mapping was wrong rather than that the
 * concept does not exist here.
 *
 * Three honest kinds of entry, and {@see MappingKind} names them:
 *
 * - **Mapped** — a DocUp token covers it. The migration is a rename.
 * - **Covered** — DocUp has no token for it because the value is not a tenant's
 *   to set. Chrome's internal structure is §8.15.5's closed shadow root and
 *   §8.14.1's registry is deliberately closed at ~45 tokens: §8.14.1 budgets
 *   the count, and Phase 27 dropped a forty-sixth rather than let the registry
 *   grow by accretion. A `--readthedocs-search-footer-code-border-color` has no
 *   counterpart because DocUp does not offer one, which is the answer.
 * - **Absent** — the feature itself is not built yet, so there is nothing to
 *   map. Search is Phase 29's and Phase 30's.
 *
 * Stating which of the three applies is what makes this a translation rather
 * than a wish list.
 */
final readonly class ReadTheDocsMapping
{
    /**
     * Read the Docs' 33 properties, in their own groups and order.
     *
     * @return list<array{property: string, group: string, kind: MappingKind, token: string|null, note: string}>
     */
    public static function all(): array
    {
        return [
            // ── Global variables (1) ──────────────────────────────────────
            self::mapped(
                '--readthedocs-font-size',
                'Global',
                'font.size.root',
                'Both are the root font size every chrome measurement derives from.',
            ),

            // ── Flyout menu (9) ──────────────────────────────────────────
            self::mapped(
                '--readthedocs-flyout-background-color',
                'Flyout',
                'color.surface.raised',
                'DocUp paints the flyout on the raised surface, so one token covers '
                .'the flyout, the header bar and the banners.',
            ),
            self::mapped('--readthedocs-flyout-color', 'Flyout', 'color.text.primary', 'Body text inside the flyout.'),
            self::mapped(
                '--readthedocs-flyout-current-version-color',
                'Flyout',
                'color.brand.on-primary',
                'The current version is the selected option, painted on '
                .'`color.brand.primary` — so the text colour is its pair.',
            ),
            self::mapped('--readthedocs-flyout-font-family', 'Flyout', 'font.body', 'Chrome uses one body family.'),
            self::mapped('--readthedocs-flyout-font-size', 'Flyout', 'font.size.root', 'Derived, not independent — see the note below the table.'),
            self::covered(
                '--readthedocs-flyout-header-font-size',
                'Flyout',
                'DocUp has no separate flyout header. §8.14.1 confines type scale to '
                .'`font.size.root` and a weight token, so a second size would be a '
                .'forty-sixth token with nothing to justify it.',
            ),
            self::mapped('--readthedocs-flyout-item-link-color', 'Flyout', 'color.text.link', 'Every link in chrome.'),
            self::mapped('--readthedocs-flyout-link-color', 'Flyout', 'color.text.link', 'The same token: DocUp does not distinguish an item link from a section link.'),
            self::mapped(
                '--readthedocs-flyout-section-heading-color',
                'Flyout',
                'color.text.secondary',
                'The flyout\'s notes and headings are secondary text.',
            ),

            // ── Notifications (8) ────────────────────────────────────────
            self::mapped(
                '--readthedocs-notification-background-color',
                'Notifications',
                'color.surface.sunken',
                '§8.15.6\'s banners sit on the sunken surface, which is what '
                .'distinguishes them from the header bar above.',
            ),
            self::mapped('--readthedocs-notification-color', 'Notifications', 'color.text.primary', 'Banner text.'),
            self::mapped('--readthedocs-notification-font-family', 'Notifications', 'font.body', 'One body family.'),
            self::mapped('--readthedocs-notification-font-size', 'Notifications', 'font.size.root', 'Derived.'),
            self::mapped('--readthedocs-notification-link-color', 'Notifications', 'color.text.link', 'The banner\'s one action link.'),
            self::mapped(
                '--readthedocs-notification-title-background-color',
                'Notifications',
                'banner.tone',
                '🛑 **Not a colour in DocUp.** §8.14.1 makes the banner\'s emphasis a '
                .'**tone** — `notice`, `warning`, `danger`, `success` — which selects '
                .'`color.state.*`. A tenant choosing an arbitrary colour could paint a '
                .'pull-request build in the success tone, which §8.15.6\'s `BannerKind` '
                .'refuses by fixing the tone per kind.',
            ),
            self::mapped('--readthedocs-notification-title-color', 'Notifications', 'color.text.primary', 'See the row above: the tone decides the accent, not the text.'),
            self::covered(
                '--readthedocs-notification-toast-font-size',
                'Notifications',
                'DocUp renders no toast. §8.15.6\'s banners are in the document flow at '
                .'the top of the page, because a floating toast over third-party '
                .'documentation covers content the reader came for.',
            ),

            // ── Search (15) ──────────────────────────────────────────────
            self::mapped('--readthedocs-search-font-family', 'Search', 'font.body', 'One body family.'),
            self::mapped('--readthedocs-search-font-size', 'Search', 'font.size.root', 'Derived.'),
            self::mapped('--readthedocs-search-color', 'Search', 'color.text.primary', 'Text in the search modal.'),
            self::mapped(
                '--readthedocs-search-content-background-color',
                'Search',
                'color.surface.page',
                'The modal is painted on the page surface so it reads as a sheet above '
                .'the document.',
            ),
            self::mapped('--readthedocs-search-content-border-color', 'Search', 'color.border.strong', 'The modal\'s own border.'),
            self::mapped('--readthedocs-search-input-background-color', 'Search', 'color.surface.page', 'The input shares the modal\'s surface.'),
            self::mapped('--readthedocs-search-result-section-color', 'Search', 'color.text.primary', 'A result\'s title.'),
            self::mapped('--readthedocs-search-result-section-subheading-color', 'Search', 'color.text.secondary', 'A result\'s breadcrumb.'),
            self::mapped(
                '--readthedocs-search-result-section-highlight-color',
                'Search',
                'color.brand.accent',
                'The matched term. §8.14.5 judges the accent against both surfaces, so '
                .'a highlight is legible by the same gate that judges everything else.',
            ),
            self::mapped('--readthedocs-search-result-section-border-color', 'Search', 'color.border.subtle', 'Between results.'),
            self::mapped('--readthedocs-search-backdrop-color', 'Search', 'color.surface.sunken', 'DocUp derives the backdrop from the sunken surface at reduced opacity.'),
            self::covered(
                '--readthedocs-search-filters-border-color',
                'Search',
                'Search filters are Phase 30\'s and are not a styled surface of their own '
                .'in DocUp\'s chrome.',
            ),
            self::covered(
                '--readthedocs-search-footer-background-color',
                'Search',
                'DocUp\'s search modal has no footer: the keyboard hints §8.15.8 requires '
                .'are announced through the live region rather than printed in a bar.',
            ),
            self::covered('--readthedocs-search-footer-code-background-color', 'Search', 'See the row above — no footer, so no key legend to style.'),
            self::covered('--readthedocs-search-footer-code-border-color', 'Search', 'See the row above.'),
        ];
    }

    /**
     * The mapping as a Markdown table, for the operator documentation.
     *
     * 🛑 Generated rather than written, through the same {@see GeneratedBlocks}
     * mechanism §8.7.13's mode matrix and §8.14.1's token table use. §17's
     * Phase 17 entry records what the alternative cost: a hand-written table
     * beside the data it describes is two sources of truth, and the one in the
     * documentation is the one that goes stale.
     */
    public static function toMarkdown(): string
    {
        $lines = [
            '| Read the Docs property | Group | DocUp token | Notes |',
            '|---|---|---|---|',
        ];

        foreach (self::all() as $entry) {
            $token = match ($entry['kind']) {
                MappingKind::Mapped => '`'.($entry['token'] ?? '').'`',
                MappingKind::Covered => '*no equivalent*',
                MappingKind::Absent => '*not built yet*',
            };

            $lines[] = '| `'.$entry['property'].'` | '.$entry['group'].' | '.$token.' | '.$entry['note'].' |';
        }

        $mapped = count(array_filter(
            self::all(),
            static fn (array $entry): bool => $entry['kind'] === MappingKind::Mapped,
        ));

        $lines[] = '';
        $lines[] = 'Read the Docs documents '.count(self::all()).' addon CSS custom properties. '
            .$mapped.' have a DocUp token; the rest have no equivalent, and the Notes column '
            .'says why rather than inventing one.';

        return implode("\n", $lines);
    }

    /**
     * Every DocUp token this mapping names, for the test that checks they exist.
     *
     * 🛑 A mapping that pointed at a token the registry does not define would
     * be documentation telling a migrating team to set something that does
     * nothing — the same failure §8.14.16's token had before Phase 28, arrived
     * at from the documentation side.
     *
     * @return list<string>
     */
    public static function tokens(): array
    {
        $tokens = [];

        foreach (self::all() as $entry) {
            if ($entry['token'] !== null) {
                $tokens[] = $entry['token'];
            }
        }

        return array_values(array_unique($tokens));
    }

    /**
     * Every token in the registry that no Read the Docs property maps onto.
     *
     * @return list<string>
     */
    public static function unmatchedTokens(): array
    {
        return array_values(array_diff(array_keys(TokenRegistry::all()), self::tokens()));
    }

    /**
     * @return array{property: string, group: string, kind: MappingKind, token: string|null, note: string}
     */
    private static function mapped(string $property, string $group, string $token, string $note): array
    {
        return [
            'property' => $property,
            'group' => $group,
            'kind' => MappingKind::Mapped,
            'token' => $token,
            'note' => $note,
        ];
    }

    /**
     * @return array{property: string, group: string, kind: MappingKind, token: string|null, note: string}
     */
    private static function covered(string $property, string $group, string $note): array
    {
        return [
            'property' => $property,
            'group' => $group,
            'kind' => MappingKind::Covered,
            'token' => null,
            'note' => $note,
        ];
    }
}
