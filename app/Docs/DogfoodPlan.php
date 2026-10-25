<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Docs;

/**
 * DocUp's own manual, as a composition (§17 Phase 17).
 *
 * > "DocUp's own documentation split across three repositories, composed
 * > into one project, served by the installation itself."
 *
 * 🛑 **A data file, not a seeder.** The three guides, their mount paths and
 * the §8.7.6 layout tree that arranges them by topic are facts about the
 * manual, and they are needed in three places: the command that provisions a
 * real installation, the test that asserts the composed site serves, and the
 * test that asserts the plain `mkdocs build` fallback covers the same pages.
 * Three copies of "the author guide is mounted at `author`" is how the
 * fallback silently stops covering a guide.
 *
 * 🛑 **The operator guide is the primary mount**, at `''`. §8.7.3 makes the
 * primary mount the owner of the root `index.html`, the fallback `404.html`
 * and the theme assets — so the choice is not cosmetic, and the operator
 * guide is the right root because it is the page somebody arriving at the
 * manual without a question in mind should land on.
 */
final class DogfoodPlan
{
    /** The project slug the manual is served under. */
    public const PROJECT = 'docup';

    /**
     * The three guides, in presentation order.
     *
     * `directory` is where the guide lives in this repository; in a real
     * installation each is the root of a repository of its own, which is why
     * `source_path` is empty there and the directory is only how the
     * monorepo and the fallback build find the pages.
     *
     * @return list<array{key: string, name: string, mount: string, directory: string, repository: string, pages: list<string>}>
     */
    public static function guides(): array
    {
        return [
            [
                'key' => 'docup-operator',
                'name' => 'Operating DocUp',
                'mount' => '',
                'directory' => 'docs/operator',
                'repository' => 'https://github.com/DocUpHQ/docup-docs-operator',
                'pages' => ['index', 'installing', 'composition', 'operations'],
            ],
            [
                'key' => 'docup-author',
                'name' => 'Writing for DocUp',
                'mount' => 'author',
                'directory' => 'docs/author',
                'repository' => 'https://github.com/DocUpHQ/docup-docs-author',
                'pages' => ['index', 'builds', 'navigation'],
            ],
            [
                'key' => 'docup-reference',
                'name' => '.docup.yaml reference',
                'mount' => 'reference',
                'directory' => 'docs/reference',
                'repository' => 'https://github.com/DocUpHQ/docup-docs-reference',
                'pages' => ['index'],
            ],
        ];
    }

    /**
     * §8.7.6's layout tree: the three guides arranged by **topic**.
     *
     * 🛑 The headings are the project's words and none of them is a
     * component key. That is the whole point of the two layers — a reader
     * sees "Running it" and "Writing documentation", not "repository one"
     * and "repository two", and neither repository had to know what the
     * other was called.
     *
     * @return list<array<string, mixed>>
     */
    public static function layout(): array
    {
        return [
            [
                'label' => 'Running it',
                'children' => [['include' => 'docup-operator']],
            ],
            [
                'label' => 'Writing documentation',
                'children' => [['include' => 'docup-author']],
            ],
            [
                'label' => 'Reference',
                'children' => [['include' => 'docup-reference']],
            ],
        ];
    }

    /**
     * Every page of the manual, as a path relative to the repository root.
     *
     * @return list<string>
     */
    public static function sourcePages(): array
    {
        $pages = [];

        foreach (self::guides() as $guide) {
            foreach ($guide['pages'] as $page) {
                $pages[] = $guide['directory'].'/docs/'.$page.'.md';
            }
        }

        return $pages;
    }
}
