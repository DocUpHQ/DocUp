<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * 🛑 The `/_/x/…` references one build's documents make (§8.7.16).
 *
 * > "Unresolved references MUST be recorded as publish-time link issues
 * > that **never fail a build and never block a publish** — one
 * > repository's typo must not break another repository's build."
 *
 * To record them, something has to know which references a build makes.
 * Collected **here**, during the ingest pass that already holds every
 * HTML document in memory for §8.15.1's injection, because the alternative
 * is a second full read of the artifact at publish time — tens of thousands
 * of files, read to answer a question the first pass could have answered
 * for free.
 *
 * 🛑 It is also the only place the question *can* be asked cheaply. §8.9.8
 * forbids application code from reading documentation bytes on the serving
 * path, and §8.4.18 forbids a per-request existence probe; a publish-time
 * scan would be neither of those, but it would be the one place in the
 * product that re-reads an artifact, and that is a cost nobody would find
 * until a monorepo published.
 *
 * Capped, deduplicated, and never an error: a build with ten thousand
 * distinct cross-references records the first {@see self::MAX} and says how
 * many it dropped. §8.7.16 is explicit that none of this fails anything.
 */
final class CrossReferences
{
    /**
     * Distinct references kept.
     *
     * Two hundred is generous for a real manual — a component referring to
     * more than two hundred *distinct* pages in other components is not a
     * component — and bounds the JSON this ends up as on the build row.
     */
    public const MAX = 200;

    /**
     * 🛑 §8.7.16's URL shape, matched as **bytes**, not parsed.
     *
     * The same argument §8.15.3 makes for injection: parsing and
     * re-serialising attacker-supplied markup changes what a browser
     * renders in ways nobody reviewed. A reference here is only ever read
     * — never written back — so a byte-level search is both sufficient and
     * the conservative choice.
     *
     * The component key matches §10.2's column shape and the path stops at
     * the first character that cannot appear in one: a quote, a space, an
     * angle bracket, a `#` or a `?`.
     */
    private const PATTERN = '#/_/x/([a-z0-9][a-z0-9._-]{0,99})/([^"\'\s<>\#?]{0,512})#i';

    /** @var array<string, array{component: string, path: string, source: string}> */
    private array $references = [];

    private int $dropped = 0;

    /** Scan one document's bytes for references it makes. */
    public function scan(string $path, string $html): void
    {
        if (preg_match_all(self::PATTERN, $html, $matches, PREG_SET_ORDER) === false) {
            return;
        }

        foreach ($matches as $match) {
            $key = strtolower($match[1]);
            $target = $match[2];
            $id = $key.'/'.$target;

            if (isset($this->references[$id])) {
                continue;
            }

            if (count($this->references) >= self::MAX) {
                $this->dropped++;

                continue;
            }

            $this->references[$id] = [
                'component' => $key,
                'path' => $target,

                // The first document that referred to it. One is enough for
                // an operator to find the typo, and keeping every referring
                // page would make the common case — a reference in a shared
                // template, so on every page — the largest value in the row.
                'source' => $this->relative($path),
            ];
        }
    }

    public function isEmpty(): bool
    {
        return $this->references === [];
    }

    public function dropped(): int
    {
        return $this->dropped;
    }

    /**
     * The stored shape, for `builds.cross_references`.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'schema' => 'docup.cross-references/1',
            'dropped' => $this->dropped,
            'references' => array_values($this->references),
        ];
    }

    /** Strip the `html/` format directory, so the path reads as a reader's. */
    private function relative(string $path): string
    {
        return str_starts_with($path, 'html/') ? substr($path, 5) : $path;
    }
}
