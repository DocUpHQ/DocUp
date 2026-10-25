<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * 🛑 §8.7.13's mode × behaviour matrix, as data.
 *
 * > "The system MUST document, as a table in the operator documentation and
 * > asserted by tests, how each mode behaves for: navigation source, search
 * > document provenance, the 404 chain, cross-reference mechanism,
 * > offline-format emission, provenance record, the effect of one
 * > contributor build failing, and fragment cacheability. The two modes are
 * > different products; leaving the difference implicit is the single
 * > largest specification risk in the composition area."
 *
 * "The single largest specification risk in the composition area" is the
 * requirement's own assessment, and this class is the answer to it: the
 * table lives **once**, here, and both the operator documentation and the
 * test read it. A table in Markdown and a behaviour in code are two
 * statements that drift; a table in code rendered into Markdown and
 * asserted by a test is one statement with two readers.
 *
 * 🛑 The `single_pass` column describes Phase 15's behaviour, written down
 * **now** because §8.7.13's whole point is that the difference must be
 * explicit before anyone builds against it. Each `single_pass` cell is what
 * P15 must implement, and {@see self::implementedIn()} says which rows are
 * live today so a test cannot quietly assert an aspiration.
 */
final readonly class ModeBehaviour
{
    /** §8.7.12's two modes. `overlay` is deferred past 1.0. */
    public const MODES = ['mount', 'single_pass'];

    /**
     * §8.7.13's eight axes, in the order the requirement lists them.
     *
     * The order is kept because the requirement's order is how an operator
     * will read the table, and a reordering would make a diff of the
     * generated documentation unreadable for no gain.
     *
     * @return list<string>
     */
    public static function axes(): array
    {
        return array_keys(self::table());
    }

    /**
     * The whole matrix: axis => mode => behaviour.
     *
     * @return array<string, array{label: string, mount: string, single_pass: string}>
     */
    public static function table(): array
    {
        return [
            'navigation_source' => [
                'label' => 'Navigation source',
                'mount' => 'Per-component nav fragments (§8.7.6), spliced into the project '
                    .'version\'s layout tree with each mount\'s prefix applied to every href.',
                'single_pass' => 'The one generator\'s own navigation for the whole site. There is '
                    .'one build, so there is one nav and nothing to splice.',
            ],
            'search_provenance' => [
                'label' => 'Search document provenance',
                'mount' => 'Each document belongs to the component whose build produced it, so a '
                    .'result can name the contributing repository and commit.',
                'single_pass' => 'Documents belong to the composed build. The contributing source '
                    .'is recoverable only from the path, because one build produced them all.',
            ],
            'not_found_chain' => [
                'label' => '404 chain',
                'mount' => 'Longest-prefix mount match, then that build\'s file manifest, then the '
                    .'primary mount\'s 404.html (§8.7.3). A miss inside one mount never falls '
                    .'through to another mount\'s content.',
                'single_pass' => 'One file manifest for the whole version, so the 404 chain has one '
                    .'step and the 404.html is the composed build\'s.',
            ],
            'cross_reference' => [
                'label' => 'Cross-reference mechanism',
                'mount' => 'Serve-time 302 through /_/x/{component_key}/{path} against the '
                    .'published manifest, with objects.inv served directly (§8.7.16).',
                'single_pass' => 'Resolved inside the build by the generator\'s own mechanism — '
                    .'Antora xref, real intersphinx — so no redirect is involved.',
            ],
            'offline_formats' => [
                'label' => 'Offline-format emission',
                'mount' => 'Primary mount only (§8.7.19). A non-primary mount\'s pdf, epub or '
                    .'htmlzip is not served.',
                'single_pass' => 'The composed build\'s, covering every source at once, which is '
                    .'the one thing single_pass gives that mount cannot.',
            ],
            'provenance' => [
                'label' => 'Provenance record',
                'mount' => 'One provenance.json per component build, and the version manifest '
                    .'names which build served which mount (§8.7.21).',
                'single_pass' => 'One provenance.json naming every contributing source and commit, '
                    .'because one container saw them all.',
            ],
            'contributor_build_failure' => [
                'label' => 'One contributor build failing',
                'mount' => 'The live composition keeps serving: the failed build is not a selector '
                    .'candidate, so the mount resolves to its previous success (§8.7.20).',
                'single_pass' => 'The whole publication fails. One sandbox, one exit code — which '
                    .'is the cost of the shared namespace single_pass exists for.',
            ],
            'fragment_cacheability' => [
                'label' => 'Fragment cacheability',
                'mount' => 'Cacheable per source (§8.5.19), and shareable between projects when '
                    .'base_url_mode is relative.',
                'single_pass' => 'Not cacheable per source: the output of one source depends on the '
                    .'others, which is what the shared pass is for.',
            ],
        ];
    }

    /**
     * Which axes are live behaviour today rather than P15's statement of
     * intent.
     *
     * 🛑 Every `mount` cell is implemented and tested in Phase 14. No
     * `single_pass` cell is, because `single_pass` itself is Phase 15 — and
     * saying so here is what keeps the table honest: a test that asserted
     * the `single_pass` column would be asserting documentation.
     */
    public static function implementedIn(string $mode): bool
    {
        return $mode === 'mount';
    }

    /**
     * The table as the Markdown §8.7.13 asks the operator documentation to
     * carry.
     *
     * Generated rather than hand-written, and the generated file is
     * committed so the documentation is readable without running anything.
     * A test re-renders it and compares, so the two cannot diverge.
     */
    public static function toMarkdown(): string
    {
        $lines = [
            '| Behaviour | `mount` (default, serve-time) | `single_pass` (opt-in, build-time) |',
            '|---|---|---|',
        ];

        foreach (self::table() as $axis) {
            $lines[] = '| **'.$axis['label'].'** | '
                .self::cell($axis['mount']).' | '
                .self::cell($axis['single_pass']).' |';
        }

        return implode("\n", $lines)."\n";
    }

    /** A cell, with the pipe escaped so one sentence cannot split a column. */
    private static function cell(string $text): string
    {
        return str_replace('|', '\\|', $text);
    }
}
