<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Docs;

use App\Composition\ModeBehaviour;
use App\Composition\SinglePass\Composer;

/**
 * The blocks of DocUp's own documentation that are generated, not written.
 *
 * 🛑 **Three requirements make this a correctness mechanism rather than a
 * convenience.** §8.7.13 says the mode × behaviour matrix MUST be "a table in
 * the operator documentation and asserted by tests"; §8.4.2 makes the JSON
 * Schema the single statement of the `.docup.yaml` contract; and §8.7.12's
 * per-preset `single_pass` precedence is a closed table whose whole point is
 * that adding a preset forces a decision. Each of the three is a place where
 * a hand-maintained page becomes a second source of truth, and a second
 * source of truth that is **wrong** is worse than an absent one — an operator
 * reading a stale matrix switches modes on it.
 *
 * So each block lives between a pair of HTML comments in a committed page,
 * `docup:docs:render` fills them, `--check` reports a difference, and a test
 * runs `--check`. The pages stay readable in the repository without running
 * anything, which is the property a generated-at-build-time page loses.
 */
final class GeneratedBlocks
{
    /**
     * Where each block lives, as `page => [block name => renderer]`.
     *
     * Paths are relative to the repository root. Listed here rather than
     * discovered, so a block whose markers were deleted is a failing check
     * rather than a block that silently stops being generated.
     *
     * @return array<string, array<string, callable(): string>>
     */
    public static function all(): array
    {
        return [
            'docs/operator/docs/composition.md' => [
                'mode-matrix' => ModeBehaviour::toMarkdown(...),
                'single-pass-precedence' => Composer::precedenceMarkdown(...),
            ],
            'docs/reference/docs/index.md' => [
                'docup-yaml' => self::schemaReference(...),
            ],
        ];
    }

    /** The `.docup.yaml` reference, from the schema that enforces it. */
    public static function schemaReference(): string
    {
        $path = base_path('resources/schema/docup-yaml-v1.schema.json');

        /** @var array<string, mixed> $schema */
        $schema = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

        return SchemaReference::render($schema);
    }

    /**
     * Replace one marked block in a page's contents.
     *
     * @throws \RuntimeException when the markers are missing, because a page
     *                           that lost them would otherwise be silently
     *                           left with whatever it last contained
     */
    public static function replace(string $contents, string $block, string $body): string
    {
        $begin = '<!-- BEGIN GENERATED: '.$block.' -->';
        $end = '<!-- END GENERATED: '.$block.' -->';

        $from = strpos($contents, $begin);
        $to = strpos($contents, $end);

        if ($from === false || $to === false || $to < $from) {
            throw new \RuntimeException('no "'.$block.'" markers to fill');
        }

        return substr($contents, 0, $from + strlen($begin))
            ."\n\n".trim($body)."\n\n"
            .substr($contents, $to);
    }
}
