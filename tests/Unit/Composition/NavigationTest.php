<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;
use App\Composition\MountShadowing;
use App\Composition\Navigation\LayoutTree;
use App\Composition\Navigation\NavFragment;
use App\Composition\Navigation\NavNode;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.7.6's two layers, and the trust boundary between them.
 *
 * A nav fragment is **repository content** by requirement — §8.7.6 lifts it
 * from `.docup.yaml`, `mkdocs.yml`, `SUMMARY.md` or `sidebars.js` — and it
 * is spliced into a project's navigation beside other teams' sections. So
 * the normalisation is a control, not a tidy-up, and these are the cases it
 * exists for.
 */
final class NavigationTest extends TestCase
{
    /**
     * 🛑 An href that is not relative to the component root is dropped, and
     * the node survives as a label.
     *
     * Dropped rather than sanitised: prefixing `https://evil.example/x`
     * with `guide/` produces nonsense, and §8.7.6's one rule — "hrefs
     * relative to the component root" — has to stay true for every href
     * downstream of this method.
     */
    #[DataProvider('refusedHrefs')]
    public function test_an_href_that_is_not_component_relative_is_dropped(string $href): void
    {
        $fragment = NavFragment::normalise([['label' => 'Somewhere', 'href' => $href]]);

        $this->assertCount(1, $fragment->nodes, 'the node survives');
        $this->assertNull($fragment->nodes[0]->href, 'and loses only its href: '.$href);
    }

    /** @return iterable<string, array{string}> */
    public static function refusedHrefs(): iterable
    {
        yield 'absolute http' => ['https://evil.example/x'];
        yield 'javascript' => ['javascript:alert(1)'];
        yield 'data' => ['data:text/html,<script>'];
        yield 'protocol relative' => ['//evil.example/x'];
        yield 'root relative' => ['/en/latest/other.html'];
        yield 'parent traversal' => ['../../other/page.html'];
        yield 'backslash' => ['guide\\page.html'];
        yield 'fragment only' => ['#section'];
        yield 'query only' => ['?q=1'];
    }

    /** The shapes every source produces, all normalising to the same thing. */
    public function test_the_loose_shapes_all_normalise(): void
    {
        $mkdocs = NavFragment::normalise([
            ['Getting started' => 'intro.html'],
            ['Reference' => [['API' => 'api.html']]],
        ]);

        $explicit = NavFragment::normalise([
            ['label' => 'Getting started', 'href' => 'intro.html'],
            ['label' => 'Reference', 'children' => [['label' => 'API', 'href' => 'api.html']]],
        ]);

        $this->assertSame($explicit->toArray(), $mkdocs->toArray());
    }

    /** A bare path labels itself, which is what every generator does. */
    public function test_a_bare_path_becomes_its_own_label(): void
    {
        $fragment = NavFragment::normalise(['intro.html']);

        $this->assertSame('intro.html', $fragment->nodes[0]->label);
        $this->assertSame('intro.html', $fragment->nodes[0]->href);
    }

    /**
     * 🛑 Depth and breadth are bounded, so a contributing repository cannot
     * make the dashboard that renders this tree into a denial of service.
     */
    public function test_the_tree_is_bounded(): void
    {
        $deep = ['label' => 'L0', 'href' => 'a.html'];

        for ($i = 0; $i < 40; $i++) {
            $deep = ['label' => 'L'.$i, 'children' => [$deep]];
        }

        $fragment = NavFragment::normalise([$deep]);
        $node = $fragment->nodes[0];
        $depth = 1;

        while ($node->children !== []) {
            $node = $node->children[0];
            $depth++;
        }

        $this->assertLessThanOrEqual(NavFragment::MAX_DEPTH, $depth);

        $wide = [];

        for ($i = 0; $i < NavFragment::MAX_NODES * 2; $i++) {
            $wide[] = ['label' => 'Page '.$i, 'href' => 'p'.$i.'.html'];
        }

        $this->assertLessThanOrEqual(NavFragment::MAX_NODES, count(NavFragment::normalise($wide)->nodes));
    }

    /** Control characters never reach a label. */
    public function test_labels_are_plain_text(): void
    {
        $fragment = NavFragment::normalise([['label' => "Guide\x00\x1b[31mRed\x07", 'href' => 'g.html']]);
        $label = $fragment->nodes[0]->label;

        $this->assertSame(0, preg_match('/[\x00-\x1F\x7F]/', $label), 'no control character survives');
        $this->assertStringStartsWith('Guide', $label, 'and the visible text is kept');
        $this->assertStringContainsString('Red', $label);
    }

    /** 🛑 §8.7.6: "with that mount's prefix applied to every href". */
    public function test_prefixing_reaches_every_href_at_every_depth(): void
    {
        $fragment = NavFragment::normalise([
            ['label' => 'Top', 'href' => 'index.html', 'children' => [
                ['label' => 'Deep', 'href' => 'a/b.html'],
            ]],
        ])->withPrefix('glossary');

        $this->assertSame('glossary/index.html', $fragment->nodes[0]->href);
        $this->assertSame('glossary/a/b.html', $fragment->nodes[0]->children[0]->href);
    }

    /** The root mount prefixes nothing, which is the degenerate case. */
    public function test_the_root_prefix_leaves_hrefs_alone(): void
    {
        $fragment = NavFragment::normalise([['label' => 'Top', 'href' => 'index.html']])->withPrefix('');

        $this->assertSame('index.html', $fragment->nodes[0]->href);
    }

    /** 🛑 §8.7.6: "A missing fragment degrades to a labelled section." */
    public function test_a_missing_fragment_degrades_to_a_labelled_section(): void
    {
        $nodes = LayoutTree::splice(
            [['include' => 'glossary']],
            ['glossary' => NavFragment::empty()],
            ['glossary' => true],
        );

        $this->assertCount(1, $nodes);
        $this->assertSame('glossary', $nodes[0]->label);
        $this->assertNull($nodes[0]->href);
        $this->assertSame([], $nodes[0]->children);
    }

    /**
     * 🛑 §8.7.6: "an unresolvable include on a **required** mount fails the
     * publish."
     */
    public function test_an_unresolvable_include_on_a_required_mount_fails(): void
    {
        try {
            LayoutTree::splice(
                [['include' => 'glossary']],
                [],
                ['glossary' => true],
            );

            $this->fail('§8.7.6 fails the publish on a required include that cannot resolve');
        } catch (CompositionRefused $refused) {
            $this->assertSame(CompositionRejection::NavIncludeUnresolvable, $refused->rejection);
        }
    }

    /** And an optional one is simply absent, which is the asymmetry. */
    public function test_an_unresolvable_include_on_an_optional_mount_is_dropped(): void
    {
        $nodes = LayoutTree::splice(
            [['label' => 'Topic', 'children' => [['include' => 'glossary']]]],
            [],
            ['glossary' => false],
        );

        $this->assertCount(1, $nodes);
        $this->assertSame('Topic', $nodes[0]->label);
        $this->assertSame([], $nodes[0]->children);
    }

    /**
     * 🛑 No layout at all: one component's fragment, unwrapped.
     *
     * The shape every project has had since Phase 03, and the one a
     * single-component project keeps. A heading nobody asked for would be
     * a regression for every existing project.
     */
    public function test_one_component_with_no_layout_is_unwrapped(): void
    {
        $fragment = NavFragment::normalise([['label' => 'Intro', 'href' => 'intro.html']]);

        $nodes = LayoutTree::splice(null, ['only' => $fragment], ['only' => true]);

        $this->assertCount(1, $nodes);
        $this->assertSame('Intro', $nodes[0]->label);
    }

    /** Several components with no layout: one section each, by key. */
    public function test_several_components_with_no_layout_are_sectioned_by_key(): void
    {
        $nodes = LayoutTree::splice(
            null,
            [
                'handbook' => NavFragment::normalise([['label' => 'Intro', 'href' => 'intro.html']]),
                'glossary' => NavFragment::normalise([['label' => 'Terms', 'href' => 'terms.html']]),
            ],
            ['handbook' => true, 'glossary' => true],
        );

        $this->assertSame(['handbook', 'glossary'], array_map(
            static fn (NavNode $node): string => $node->label,
            $nodes,
        ));
    }

    /**
     * An operator's literal link may point outside; a repository's may not.
     *
     * The asymmetry is deliberate and is the whole reason the layout has
     * its own href rule: a layout is operator-written, and an operator
     * putting "Status page" in the sidebar is pointing elsewhere by
     * definition.
     */
    public function test_a_layout_link_may_be_external_but_never_a_scheme_handler(): void
    {
        $nodes = LayoutTree::splice(
            [
                ['label' => 'Status', 'link' => 'https://status.example.com'],
                ['label' => 'Script', 'link' => 'javascript:alert(1)'],
            ],
            [],
            [],
        );

        $this->assertSame('https://status.example.com', $nodes[0]->href);
        $this->assertNull($nodes[1]->href, 'a scheme handler is refused even from an operator');
    }

    /**
     * 🛑 §8.7.15's prefix test, on SEGMENT boundaries.
     *
     * `guide` does not shadow `guidelines`, because no path under
     * `guidelines/` is ever matched by a mount at `guide` — §7.3's rule,
     * applied to mount paths.
     */
    #[DataProvider('shadowPairs')]
    public function test_shadowing_is_decided_on_segment_boundaries(string $a, string $b, bool $conflicts): void
    {
        $this->assertSame($conflicts, MountShadowing::conflict($a, $b), $a.' vs '.$b);
        $this->assertSame($conflicts, MountShadowing::conflict($b, $a), 'and symmetrically');
    }

    /** @return iterable<string, array{string, string, bool}> */
    public static function shadowPairs(): iterable
    {
        yield 'nested' => ['guide', 'guide/advanced', true];
        yield 'deeply nested' => ['a', 'a/b/c', true];
        yield 'siblings' => ['guide', 'reference', false];
        yield 'a longer sibling name' => ['guide', 'guidelines', false];
        yield 'identical' => ['guide', 'guide', false];

        // 🛑 The root is excluded: §8.7.3 mandates one mount there and
        // §8.7.12 resolves by longest prefix, so every deeper mount is a
        // deliberate narrowing rather than a collision. What the root
        // actually loses is decided at publish, from the file manifests.
        yield 'the root never shadows' => ['', 'guide', false];
    }
}
