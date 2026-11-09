<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.5's "**fixed** foreground/background matrix".
 *
 * > "WCAG 2.2 contrast MUST be computed over a fixed foreground/background
 * > matrix in both colour schemes at publish."
 *
 * **Fixed** is the operative word and the reason this is a constant rather
 * than something computed from the palette. A matrix derived from "every
 * colour token against every other" would be 361 pairs for nineteen colours,
 * most of them combinations chrome never paints — and the noise would bury the
 * dozen that matter. Worse, it would move: adding a colour token would change
 * which pairs a theme is judged on, so a theme that published yesterday could
 * be refused today by a release that added a token nobody used.
 *
 * So the pairs are enumerated, each one a combination DocUp's own chrome
 * actually renders, and adding a pair is a deliberate change with a test
 * behind it.
 *
 * ## 🛑 What the documentation must say, and §8.14.5 insists on it
 *
 * > "The documentation MUST state honestly that this gate is a safety net and
 * > still permits shipping AA-failing themes."
 *
 * It does, and {@see self::LIMITS} is the machine-readable version of why: the
 * matrix covers chrome's own fixed combinations in two schemes at two
 * thresholds. It does not see the documentation body, which a generator
 * styles; it does not see text over an image; it does not know which text is
 * large-scale, so it judges everything at the small-text threshold; and it
 * cannot see a combination chrome has not been told about. A theme can pass
 * every pair here and still fail WCAG on a page.
 */
final class ContrastMatrix
{
    /**
     * The honest limits of this gate, for the operator documentation.
     *
     * @var list<string>
     */
    public const LIMITS = [
        'It judges chrome, not content. The documentation body is the generator’s CSS and DocUp never rewrites it (§4.3/2).',
        'It judges the pairs below and no others. A combination chrome does not render is not checked, and neither is one it renders that nobody added here.',
        'It judges every text pair at the small-text threshold, because a token carries no font size. A heading that passes at 3:1 under SC 1.4.3’s large-text allowance is still warned about.',
        'It cannot see text over an image or a gradient. A logo with text baked into it is outside this gate entirely.',
        'It is computed from the sRGB reduction of each colour. A wide-gamut colour is judged at its clamped sRGB value, which is at least as favourable as what the display shows.',
    ];

    /**
     * The matrix: foreground token, background token, role, and what renders it.
     *
     * @return list<array{foreground: string, background: string, role: ContrastRole, surface: string}>
     */
    public static function pairs(): array
    {
        return [
            // Body copy, on both the page and the raised surfaces chrome uses.
            self::pair('color.text.primary', 'color.surface.page', ContrastRole::Text, 'body copy on the page'),
            self::pair('color.text.primary', 'color.surface.raised', ContrastRole::Text, 'body copy in a card or the header'),
            self::pair('color.text.primary', 'color.surface.sunken', ContrastRole::Text, 'body copy in a well'),

            /*
             * 🛑 Secondary text is judged at the same 4.5:1 as primary. A
             * "muted" palette is where contrast failures live, precisely
             * because the designer's intent is that it recede — and a reader
             * with low vision does not get to opt out of the metadata.
             */
            self::pair('color.text.secondary', 'color.surface.page', ContrastRole::Text, 'metadata on the page'),
            self::pair('color.text.secondary', 'color.surface.raised', ContrastRole::Text, 'metadata in a card'),

            self::pair('color.text.link', 'color.surface.page', ContrastRole::Text, 'a chrome link on the page'),
            self::pair('color.text.link', 'color.surface.raised', ContrastRole::Text, 'a chrome link in the header'),

            // The primary action, and the one pair where both colours are brand.
            self::pair('color.brand.on-primary', 'color.brand.primary', ContrastRole::Text, 'a primary button’s label'),
            self::pair('color.text.inverse', 'color.brand.accent', ContrastRole::Text, 'a label on the accent fill'),

            // The three state colours, as text on the page.
            self::pair('color.state.success', 'color.surface.page', ContrastRole::Text, 'a success message'),
            self::pair('color.state.warning', 'color.surface.page', ContrastRole::Text, 'a warning message'),
            self::pair('color.state.danger', 'color.surface.page', ContrastRole::Text, 'a failure message'),

            // Chrome's own inline code.
            self::pair('color.code.text', 'color.code.surface', ContrastRole::Text, 'an inline code span'),

            /*
             * 🛑 The two non-text pairs, and the reason they are in the same
             * matrix rather than a second one: §8.14.5's refusal floor applies
             * to them identically. {@see ContrastRole} carries the difference
             * in the warning threshold, where WCAG puts it.
             */
            self::pair('color.border.strong', 'color.surface.page', ContrastRole::NonText, 'a control outline'),
            self::pair('color.focus.ring', 'color.surface.page', ContrastRole::NonText, 'the focus indicator'),
            self::pair('color.focus.ring', 'color.surface.raised', ContrastRole::NonText, 'the focus indicator in the header'),
        ];
    }

    /**
     * The colour tokens the matrix reads, so a caller can check it has them all.
     *
     * @return list<string>
     */
    public static function tokens(): array
    {
        $names = [];

        foreach (self::pairs() as $pair) {
            $names[] = $pair['foreground'];
            $names[] = $pair['background'];
        }

        return array_values(array_unique($names));
    }

    /**
     * @return array{foreground: string, background: string, role: ContrastRole, surface: string}
     */
    private static function pair(string $foreground, string $background, ContrastRole $role, string $surface): array
    {
        return [
            'foreground' => $foreground,
            'background' => $background,
            'role' => $role,
            'surface' => $surface,
        ];
    }
}
