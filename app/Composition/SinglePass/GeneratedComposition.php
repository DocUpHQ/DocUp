<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\SinglePass;

use App\Builds\Toolchain\ToolchainPlan;

/**
 * 🛑 The file §8.7.12 requires DocUp to write, and the shell that puts it
 * in the sandbox.
 *
 * > "with **DocUp generating the playbook or include file from the resolved
 * > plan** so a contributing repository cannot redirect sources or add a
 * > fourth repository."
 *
 * Two properties make that sentence true rather than hopeful, and both are
 * here rather than in the generator:
 *
 * 1. **The file lives outside every checkout.** `/workspace/composition` is
 *    a sibling of `/workspace/source`, so no repository can contain it,
 *    overwrite it before the generator reads it, or be mistaken for it. A
 *    generated playbook written *into* a source tree would be a file a
 *    contributing repository could ship at the same path.
 * 2. **The bytes travel base64-encoded.** The materialising command is
 *    `printf | base64 -d > …`, so the playbook's own content — which
 *    contains paths, quotes and newlines — never reaches the shell as
 *    syntax. The alphabet is closed: there is no sequence of base64
 *    characters that ends the argument.
 *
 * The generator is then pointed at this file and at nothing else, which is
 * what makes the 🛑 exit criterion hold: a contributing repository's own
 * `antora-playbook.yml` is still on disk and is simply never read.
 */
final readonly class GeneratedComposition
{
    /** A sibling of the checkouts, never inside one. */
    public const DIRECTORY = '/workspace/composition';

    /**
     * @param  string  $filename  a single segment; the generator's own name for it
     * @param  string  $contents  the generated file, as bytes
     * @param  list<string>  $prepare  per-slot commands the preset declared
     */
    public function __construct(
        public string $filename,
        public string $contents,
        public array $prepare = [],
    ) {}

    /** Where the generator is told to look. */
    public function path(): string
    {
        return self::DIRECTORY.'/'.$this->filename;
    }

    /**
     * The shell that materialises it, as §8.4.10's script sees it.
     *
     * 🛑 Emitted as the **first** section of the environment stage, before
     * `post_checkout` — §8.5.7 puts the repository's own hooks in that
     * stage, and a hook that ran before the composition existed could watch
     * for the file and race it. Writing first means the only state a hook
     * can observe is the finished one.
     *
     * @return list<string>
     */
    public function commands(): array
    {
        $lines = [
            'mkdir -p '.ToolchainPlan::quote(self::DIRECTORY),
            'printf \'%s\' '.ToolchainPlan::quote(base64_encode($this->contents))
                .' | base64 -d > '.ToolchainPlan::quote($this->path()),
        ];

        return array_merge($lines, $this->prepare);
    }
}
