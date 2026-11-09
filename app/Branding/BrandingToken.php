<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * One entry in §8.14.1's closed registry of typed design tokens.
 *
 * 🛑 **The registry is the contract, and every column of §17's documentation
 * table is a property here.** §17's deliverable is "the ~45-token registry
 * itself, published as a table in the operator documentation with each token's
 * name, type, grammar and cascade level". Those four live on this object, so
 * the page and the validator read one source. A table written by hand beside a
 * registry written in code is two registries, and the one in the documentation
 * is the one that goes stale.
 *
 * 🛑 **Light and dark are one token, not two.** §8.14.7 asks for "light/dark
 * pairing (explicit pairs or a stated derivation rule)" and this registry
 * chooses **explicit pairs**: a colour token carries two values and
 * {@see self::$dark} is the second. The alternative — deriving dark from light
 * — produces a palette nobody designed and makes §8.14.5's contrast gate judge
 * a scheme the operator never saw. Pairing them under one name is also what
 * keeps the count near 45 rather than near 90, which is the number §8.14.1
 * fixes.
 *
 * 🛑 **`deepest` is how §8.14.1's version restriction and §8.14.8's raw-HTML
 * restriction are expressed as data** rather than as two special cases in the
 * cascade. A token whose `deepest` is `Installation` cannot be written by a
 * tenant at all, and the only two tokens whose `deepest` is `Version` are the
 * colour-scheme default and the banner — which is §8.14.1's sentence,
 * mechanised.
 */
final readonly class BrandingToken
{
    /**
     * @param  string  $name  the dotted registry key, e.g. `color.brand.primary`
     * @param  TokenType  $type  which grammar parses it
     * @param  string  $group  the documentation table's section
     * @param  string  $default  the installation default, in the token's own grammar
     * @param  string|null  $dark  the dark-scheme value, for a paired colour; null
     *                             when the token has one value in both schemes
     * @param  CascadeLevel  $deepest  the deepest scope that may set it
     * @param  string  $purpose  one line, for the documentation table
     * @param  list<string>  $options  for {@see TokenType::Option}; empty otherwise
     * @param  float  $minimum  for a length, ratio or count
     * @param  float  $maximum  for a length, ratio or count
     * @param  int  $maxLength  for {@see TokenType::Text}, in characters
     * @param  string|null  $assetKind  for {@see TokenType::Asset}: which
     *                                  `theme_assets.kind` the reference must name
     */
    public function __construct(
        public string $name,
        public TokenType $type,
        public string $group,
        public string $default,
        public ?string $dark = null,
        public CascadeLevel $deepest = CascadeLevel::Mount,
        public string $purpose = '',
        public array $options = [],
        public float $minimum = 0.0,
        public float $maximum = 0.0,
        public int $maxLength = 0,
        public ?string $assetKind = null,
    ) {}

    /**
     * The CSS custom property this token emits.
     *
     * 🛑 Derived from the name rather than stored beside it, so the two cannot
     * disagree. The `--docup-` prefix is what keeps a token out of the way of
     * a generator's own custom properties — Sphinx's Furo theme and Docusaurus
     * both define dozens, and §8.15.9 will have to map Read the Docs' 33 onto
     * these, which only works if DocUp's are namespaced.
     */
    public function customProperty(): string
    {
        return '--docup-'.str_replace('.', '-', $this->name);
    }

    /** Whether this token differs between the light and dark schemes. */
    public function isPaired(): bool
    {
        return $this->dark !== null;
    }

    /**
     * Whether `$level` may set this token.
     *
     * 🛑 Installation may always set a token, whatever its `deepest` — it is
     * the shallowest rung and the default's home. What `deepest` bounds is how
     * far **down** a token travels.
     */
    public function settableAt(CascadeLevel $level): bool
    {
        return ! $level->isDeeperThan($this->deepest);
    }

    /**
     * The levels this token may be set at, for the documentation table.
     *
     * @return list<CascadeLevel>
     */
    public function levels(): array
    {
        return array_values(array_filter(
            CascadeLevel::inOrder(),
            fn (CascadeLevel $level): bool => $this->settableAt($level),
        ));
    }

    /** The cascade-level column of §17's table: `installation → mount`. */
    public function levelLabel(): string
    {
        return $this->deepest === CascadeLevel::Installation
            ? 'installation only'
            : 'installation → '.$this->deepest->value;
    }
}
