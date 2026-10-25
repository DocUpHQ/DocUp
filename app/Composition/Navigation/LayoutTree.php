<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\Navigation;

use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;

/**
 * 🛑 §8.7.6's second layer: the project's own arrangement of contributed
 * navigation.
 *
 * > "Each project version holds a **layout tree** whose nodes are labels,
 * > literal links or `{"include": "<component key>"}` placeholders, spliced
 * > in with that mount's prefix applied to every href. The project
 * > therefore arranges contributing content **by topic** — which is what
 * > 'one coherent navigation tree' means — while repositories keep their
 * > internal ordering."
 *
 * That sentence is the whole feature and it is worth reading twice. Without
 * the layout tree, a project composed of three repositories gets three
 * sections named after three repositories, which is a directory, not a
 * manual. With it, the project says "Getting started", "Reference",
 * "Operations", and each of those pulls whichever component's fragment
 * belongs there — so a reader never learns that the reference section comes
 * from a different repository, which is the point.
 *
 * 🛑 **Two degradation rules, and they are not symmetric** (§8.7.6):
 *
 *  - "A missing fragment degrades to a labelled section." The component is
 *    mounted, its build simply has no nav. The reader sees the heading and
 *    the content is still reachable; nothing fails.
 *  - "An unresolvable include on a **required** mount fails the publish."
 *    The include names a component this version does not mount at all.
 *    On a required mount that is a composition the operator believes they
 *    have and do not — so it fails closed, which is also what §8.7.20 says
 *    about required mounts that cannot resolve.
 */
final readonly class LayoutTree
{
    /** The operator's tree is bounded too; a different limit from a fragment's. */
    public const MAX_DEPTH = 8;

    public const MAX_NODES = 500;

    /**
     * Splice a layout against the fragments the composition resolved.
     *
     * @param  mixed  $layout  `project_versions.layout_json`, or null for none
     * @param  array<string, NavFragment>  $fragments  component key => its fragment,
     *                                                 already prefixed with that mount's path
     * @param  array<string, bool>  $required  component key => whether the mount is required
     * @return list<NavNode>
     *
     * @throws CompositionRefused when a required include names no mounted component
     */
    public static function splice(mixed $layout, array $fragments, array $required): array
    {
        if (! is_array($layout) || $layout === []) {
            return self::degenerate($fragments);
        }

        $budget = self::MAX_NODES;

        return self::spliceList($layout, $fragments, $required, 1, $budget);
    }

    /**
     * No layout: the mounts in the order the manifest lists them.
     *
     * 🛑 This is the shape every project has had since Phase 03 and the one
     * a single-component project keeps forever. §8.7.6's two layers are
     * worth their complexity only when there is something to arrange; a
     * project with one component gets its fragment, unwrapped, and no
     * heading it did not ask for.
     *
     * @param  array<string, NavFragment>  $fragments
     * @return list<NavNode>
     */
    private static function degenerate(array $fragments): array
    {
        if (count($fragments) === 1) {
            return array_values($fragments)[0]->nodes;
        }

        $nodes = [];

        foreach ($fragments as $key => $fragment) {
            $nodes[] = new NavNode($key, null, $fragment->nodes);
        }

        return $nodes;
    }

    /**
     * @param  array<array-key, mixed>  $layout
     * @param  array<string, NavFragment>  $fragments
     * @param  array<string, bool>  $required
     * @return list<NavNode>
     *
     * @throws CompositionRefused
     */
    private static function spliceList(
        array $layout,
        array $fragments,
        array $required,
        int $depth,
        int &$budget,
    ): array {
        if ($depth > self::MAX_DEPTH) {
            return [];
        }

        $nodes = [];

        foreach ($layout as $item) {
            if ($budget <= 0) {
                break;
            }

            if (! is_array($item)) {
                continue;
            }

            $include = $item['include'] ?? null;

            if (is_string($include)) {
                foreach (self::resolveInclude($include, $item, $fragments, $required) as $node) {
                    $budget--;
                    $nodes[] = $node;
                }

                continue;
            }

            $label = $item['label'] ?? null;

            if (! is_string($label)) {
                continue;
            }

            $budget--;
            $children = $item['children'] ?? null;

            $nodes[] = new NavNode(
                self::label($label),
                self::link($item['link'] ?? null),
                is_array($children) ? self::spliceList($children, $fragments, $required, $depth + 1, $budget) : [],
            );
        }

        return $nodes;
    }

    /**
     * One `{"include": "<component key>"}` placeholder.
     *
     * An include may carry a `label`, in which case the component's nodes
     * become that section's children; without one they are spliced inline,
     * which is how a project puts one component's pages directly under a
     * heading it already wrote.
     *
     * @param  array<array-key, mixed>  $item
     * @param  array<string, NavFragment>  $fragments
     * @param  array<string, bool>  $required
     * @return list<NavNode>
     *
     * @throws CompositionRefused
     */
    private static function resolveInclude(
        string $key,
        array $item,
        array $fragments,
        array $required,
    ): array {
        $fragment = $fragments[$key] ?? null;

        if (! $fragment instanceof NavFragment) {
            /*
             * 🛑 §8.7.6: "an unresolvable include on a required mount fails
             * the publish." Required is the condition, and `$required` holds
             * only the mounts this version actually has — so a key that is
             * absent from both maps is an include naming a component that is
             * not mounted at all. That is the case the rule is for.
             */
            if (($required[$key] ?? false) === true) {
                throw CompositionRefused::of(
                    CompositionRejection::NavIncludeUnresolvable,
                    '"'.$key.'" is included by the layout and is a required mount with no navigation',
                );
            }

            return [];
        }

        $label = $item['label'] ?? null;

        if (is_string($label)) {
            return [new NavNode(self::label($label), null, $fragment->nodes)];
        }

        if ($fragment->isEmpty()) {
            // §8.7.6's "degrades to a labelled section", with the component
            // key as the label: the operator wrote no heading, so the only
            // honest one is the component's own name.
            return [new NavNode(self::label($key))];
        }

        return $fragment->nodes;
    }

    /**
     * A literal link from the layout.
     *
     * Looser than {@see NavFragment}'s href rule, and deliberately: a
     * layout is **operator-written** rather than repository-supplied, and an
     * operator putting "Status page" in the sidebar is pointing somewhere
     * else by definition. `javascript:` and `data:` are still refused,
     * because a link in a project's chrome is one no reader inspects.
     */
    private static function link(mixed $raw): ?string
    {
        if (! is_string($raw) || trim($raw) === '') {
            return null;
        }

        $link = trim($raw);

        if (preg_match('#^(https?:)?//#i', $link) === 1 || ! str_contains($link, ':')) {
            return $link;
        }

        return null;
    }

    private static function label(string $raw): string
    {
        $label = trim(preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $raw) ?? $raw);

        return $label === '' ? '—' : mb_strcut($label, 0, NavFragment::MAX_LABEL_BYTES);
    }
}
