<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\TokenValue;

/**
 * The outcome of §8.14.1's cascade: every token, with where it came from.
 *
 * 🛑 **Provenance is part of the result, not a debugging extra.** An operator
 * looking at a project theme needs to know which of these forty-five values is
 * theirs, which came from their organisation and which is the installation's
 * default — otherwise "change the brand colour" is a guess about which page to
 * open. The dashboard renders it, and so does `docup:theme show`.
 *
 * 🛑 **Content-addressed.** {@see self::contentHash()} is what makes §8.14.4's
 * "immutable content-addressed stylesheet" possible: two projects whose
 * cascades resolve to identical values share one stylesheet URL and one cache
 * entry, which is the difference between 500 projects costing 500 files and
 * 500 projects costing however many distinct themes there actually are.
 */
final readonly class ResolvedTheme
{
    /**
     * @param  array<string, TokenPair>  $tokens  every registry token
     * @param  array<string, CascadeLevel>  $provenance  which level each came from
     * @param  ThemeLocks  $locks  the union of every level's locks
     * @param  array<string, string>  $revisionIds  level value => revision id
     */
    public function __construct(
        public array $tokens,
        public array $provenance,
        public ThemeLocks $locks,
        public array $revisionIds = [],
    ) {}

    /** @throws TokenRefused when the registry has no such token */
    public function value(string $name, ColourScheme $scheme = ColourScheme::Light): TokenValue
    {
        $pair = $this->tokens[$name] ?? null;

        if (! $pair instanceof TokenPair) {
            throw TokenRefused::of(TokenRejection::UnknownToken, $name, 'not present in the resolved theme');
        }

        return $pair->for($scheme);
    }

    public function has(string $name): bool
    {
        return array_key_exists($name, $this->tokens);
    }

    /**
     * The serialised value, or null when the token is unset.
     *
     * Asset and text tokens have no default, so "unset" is a real state and
     * the caller has to handle it — a logo nobody uploaded, a banner nobody
     * wrote. Returning null rather than an empty string keeps the two apart:
     * an empty banner is not a banner, and an empty asset id is not an asset.
     */
    public function serialised(string $name, ColourScheme $scheme = ColourScheme::Light): ?string
    {
        $pair = $this->tokens[$name] ?? null;

        return $pair instanceof TokenPair ? $pair->for($scheme)->serialise() : null;
    }

    /**
     * One scheme's values, for the §8.14.5 gate and the stylesheet.
     *
     * @return array<string, TokenValue>
     */
    public function scheme(ColourScheme $scheme): array
    {
        $values = [];

        foreach ($this->tokens as $name => $pair) {
            $values[$name] = $pair->for($scheme);
        }

        return $values;
    }

    /**
     * 🛑 §8.14.4's content address, over the **re-serialised** values.
     *
     * Over the serialised output and not over the authored input, which is the
     * point: two themes that typed `#FFF` and `#ffffff` are the same theme and
     * must share a stylesheet. Hashing the input would mint two URLs for one
     * set of bytes, and the operator who corrected their capitalisation would
     * invalidate every reader's cache for nothing.
     *
     * The hash covers the token names too, so a release that adds a token
     * changes every theme's address — which is correct, because the stylesheet
     * those themes publish now carries a property it did not before.
     */
    public function contentHash(): string
    {
        $names = array_keys($this->tokens);
        sort($names);

        $parts = [];

        foreach ($names as $name) {
            $pair = $this->tokens[$name];
            $parts[] = $name.'=L:'.$pair->light->serialise().'|D:'.$pair->dark->serialise();
        }

        return hash('sha256', implode("\n", $parts));
    }

    /**
     * Which level set a token, for the dashboard and `docup:theme show`.
     *
     * {@see CascadeLevel::Installation} when nothing overrode the default.
     */
    public function origin(string $name): CascadeLevel
    {
        return $this->provenance[$name] ?? CascadeLevel::Installation;
    }

    /**
     * Every token with its value in both schemes and its origin.
     *
     * @return array<string, array{light: string, dark: string, origin: string, locked: bool}>
     */
    public function describe(): array
    {
        $rows = [];

        foreach ($this->tokens as $name => $pair) {
            $rows[$name] = [
                'light' => $pair->light->serialise(),
                'dark' => $pair->dark->serialise(),
                'origin' => $this->origin($name)->value,
                'locked' => $this->locks->locks($name),
            ];
        }

        return $rows;
    }
}
