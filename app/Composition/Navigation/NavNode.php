<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\Navigation;

/**
 * One entry in a navigation tree (§8.7.6).
 *
 * Three shapes in one class, because they differ only in which fields are
 * present and a hierarchy of three would make every consumer switch on the
 * type to read a label:
 *
 *  - a **page**: a label and an href.
 *  - a **section**: a label and children.
 *  - a **labelled section with no content**: a label alone, which is what
 *    §8.7.6 degrades a missing fragment to.
 */
final readonly class NavNode
{
    /**
     * @param  string|null  $href  relative to the component root inside a
     *                             fragment; relative to the version root once spliced
     * @param  list<NavNode>  $children
     */
    public function __construct(
        public string $label,
        public ?string $href = null,
        public array $children = [],
    ) {}

    /** The same node with its href prefixed and its children prefixed too. */
    public function withPrefix(string $prefix): self
    {
        if ($prefix === '') {
            return $this;
        }

        return new self(
            $this->label,
            $this->href === null ? null : $prefix.'/'.$this->href,
            array_map(static fn (self $child): self => $child->withPrefix($prefix), $this->children),
        );
    }

    /**
     * This node's href and every descendant's, depth first.
     *
     * A section node has none and contributes nothing — it is a heading,
     * not a page, so there is nothing for a caller to check against a file
     * manifest.
     *
     * @return list<string>
     */
    public function hrefs(): array
    {
        $hrefs = $this->href === null ? [] : [$this->href];

        foreach ($this->children as $child) {
            $hrefs = array_merge($hrefs, $child->hrefs());
        }

        return $hrefs;
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        $node = ['label' => $this->label];

        if ($this->href !== null) {
            $node['href'] = $this->href;
        }

        if ($this->children !== []) {
            $node['children'] = array_map(static fn (self $child): array => $child->toArray(), $this->children);
        }

        return $node;
    }
}
