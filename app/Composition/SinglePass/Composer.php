<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\SinglePass;

use App\Builds\Toolchain\ToolchainPreset;
use App\Composition\CompositionRefused;
use App\Composition\CompositionRejection;
use App\Composition\ModeBehaviour;
use App\Config\DocupConfig;

/**
 * 🛑 §8.7.12's "DocUp generating the playbook or include file", and the
 * per-preset precedence §17's Phase 15 asks to be documented.
 *
 * > "**Deliverables:** … **server-generated** playbook and include files
 * > from the resolved plan, with documented per-preset precedence when a
 * > repository ships its own"
 *
 * The precedence is {@see self::PRECEDENCE} and it is a **closed table**:
 * every shipped preset has an entry, and a preset with no generator is
 * refused rather than built. That is the whole of the phase's safety
 * argument in one place — a toolchain DocUp cannot write the source list
 * for is a toolchain where the repository writes it, which is precisely
 * what §8.7.12 forbids.
 *
 * 🛑 **A refusal is the right answer for the other six**, not a fallback to
 * `mount`. Falling back would mean a project set to `single_pass` quietly
 * serving the other mode's behaviours — different 404 chain, different
 * cross-reference mechanism, different failure domain — which is the
 * ambiguity §8.7.13 calls "the single largest specification risk in the
 * composition area".
 */
final readonly class Composer
{
    /**
     * What happens to a repository's own generator configuration, per
     * preset. Rendered into the operator documentation and asserted by a
     * test, for the reason §8.7.13 gives about the mode matrix.
     *
     * @var array<string, string>
     */
    public const PRECEDENCE = [
        'antora' => 'DocUp writes the playbook into `/workspace/composition` and points Antora at it '
            .'with no `--fetch`. A repository\'s own `antora-playbook.yml` stays on disk and is '
            .'**never read**, so it can neither add a source nor redirect one. Each source\'s own '
            .'`antora.yml` is still authoritative for its component name, version and nav — that is '
            .'the source\'s own content, not the site\'s shape.',

        'mkdocs' => 'Not supported. `mkdocs-monorepo-plugin` composes through `!include`, which reads '
            .'a path out of the included file — so a contributing repository would be able to name a '
            .'fourth source from inside its own `mkdocs.yml`, which §8.7.12 forbids. Composing MkDocs '
            .'safely means DocUp generating a file per source and discarding each repository\'s own, '
            .'and that is a different feature from including theirs.',

        'sphinx' => 'Not supported. §8.7.12 names `sphinx-multiproject`, but that extension selects '
            .'**one** docset per build through a `PROJECT` environment variable — it is a '
            .'one-repository-many-docsets tool, not a many-repositories-one-site one. Sphinx\'s actual '
            .'answer to this shape is intersphinx, which is `mount` mode plus §8.7.16. Recorded as a '
            .'proposed amendment to §8.7.12.',

        'mdbook' => 'Not supported. mdBook has one `SUMMARY.md` and one source root by design.',
        'docusaurus' => 'Not supported. Multi-instance plugins compose docsets inside one repository, '
            .'not across checkouts, and the configuration that would do it is the repository\'s own JavaScript.',
        'vitepress' => 'Not supported, for the same reason as Docusaurus: the configuration is executable '
            .'and is the repository\'s.',
        'starlight' => 'Not supported, for the same reason as Docusaurus.',
    ];

    public function __construct(private AntoraPlaybook $antora = new AntoraPlaybook) {}

    /**
     * Generate the composition for one preset, or refuse.
     *
     * @param  list<SourceSlot>  $slots  every contributing source, primary first
     * @param  DocupConfig  $primary  the primary component's configuration
     *
     * @throws CompositionRefused when the preset cannot be composed, or the
     *                            composition it would need is incomplete
     */
    public function compose(ToolchainPreset $preset, array $slots, DocupConfig $primary, string $uiBundle): GeneratedComposition
    {
        if ($preset->key !== 'antora') {
            throw CompositionRefused::of(
                CompositionRejection::SinglePassUnsupportedToolchain,
                $preset->name.' cannot be composed in a single pass: '
                    .(self::PRECEDENCE[$preset->key] ?? 'no precedence is documented for this preset'),
            );
        }

        return $this->antora->generate($slots, $primary, $uiBundle);
    }

    /** Whether a preset can be composed at all, for a check before a build row exists. */
    public function supports(ToolchainPreset $preset): bool
    {
        return $preset->key === 'antora';
    }

    /**
     * The precedence table as the Markdown the operator documentation
     * carries, generated for the reason {@see ModeBehaviour}
     * gives: one statement with two readers rather than two that drift.
     */
    public static function precedenceMarkdown(): string
    {
        $lines = [
            '| Preset | `single_pass` | What happens to the repository\'s own configuration |',
            '|---|---|---|',
        ];

        foreach (self::PRECEDENCE as $preset => $rule) {
            $supported = str_starts_with($rule, 'Not supported') ? 'refused' : '**supported**';
            $lines[] = '| `'.$preset.'` | '.$supported.' | '.str_replace('|', '\\|', $rule).' |';
        }

        return implode("\n", $lines)."\n";
    }
}
