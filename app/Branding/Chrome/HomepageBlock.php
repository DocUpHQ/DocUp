<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Chrome;

use App\Branding\Values\ShortTextValue;

/**
 * 🛑 §8.14.3's "homepage blocks **from a registry**".
 *
 * A closed set of block types, each with typed fields. The alternative — a
 * block whose body is markup — is the free HTML §8.14.3 forbids, arrived at by
 * calling it a block.
 *
 * Six types, chosen to cover what a documentation landing page actually needs:
 * a hero, a grid of links, a list of versions, a search prompt, a prose
 * paragraph, and a call to action. A seventh is a change to this enum with a
 * test, which is the friction the requirement is asking for.
 */
enum HomepageBlock: string
{
    /** A heading, a sentence and up to two actions. */
    case Hero = 'hero';

    /** A grid of titled links into the documentation. */
    case Cards = 'cards';

    /** The project's versions, rendered by chrome from the resolver. */
    case Versions = 'versions';

    /** A search field, wired to §8.16's endpoint. */
    case Search = 'search';

    /** One heading and one paragraph of plain text. */
    case Prose = 'prose';

    /** A single prominent link. */
    case Callout = 'callout';

    /**
     * The fields this block type carries, and the type of each.
     *
     * 🛑 Declared here so {@see ChromeContent} validates a block without a
     * `match` per type, and so an operator-facing description of what a block
     * takes is generated rather than written twice. `text` fields go through
     * {@see ShortTextValue}'s rules and `href` fields
     * through {@see SafeHref}.
     *
     * @return array<string, array{type: string, max?: int, required?: bool}>
     */
    public function fields(): array
    {
        return match ($this) {
            self::Hero => [
                'heading' => ['type' => 'text', 'max' => 90, 'required' => true],
                'body' => ['type' => 'text', 'max' => 240],
                'primary_label' => ['type' => 'text', 'max' => 40],
                'primary_href' => ['type' => 'href'],
                'secondary_label' => ['type' => 'text', 'max' => 40],
                'secondary_href' => ['type' => 'href'],
            ],
            self::Cards => [
                'heading' => ['type' => 'text', 'max' => 90],
                'cards' => ['type' => 'card_list', 'max' => 9, 'required' => true],
            ],
            self::Versions => [
                'heading' => ['type' => 'text', 'max' => 90],
                'limit' => ['type' => 'count', 'max' => 20],
            ],
            self::Search => [
                'placeholder' => ['type' => 'text', 'max' => 90],
            ],
            self::Prose => [
                'heading' => ['type' => 'text', 'max' => 90],
                'body' => ['type' => 'text', 'max' => 600, 'required' => true],
            ],
            self::Callout => [
                'label' => ['type' => 'text', 'max' => 60, 'required' => true],
                'href' => ['type' => 'href', 'required' => true],
            ],
        };
    }
}
