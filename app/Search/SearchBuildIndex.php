<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * `search_build_index`: which generation of which build is live, and who wrote
 * it.
 *
 * 🛑 **Driver-independent on purpose**, and the migration's own note says why.
 * This is the bookkeeping that makes §8.16.5's "indexed once" a decidable
 * question without a round trip to a search engine, and §8.16.7's "no window"
 * a property of a `state` column rather than of timing.
 *
 * The three states are a small state machine and the order matters:
 *
 *     writing ──(finish)──> live ──(a newer generation finishes)──> superseded
 *
 * Nothing outside this class reads `writing`, which is the whole point: a
 * generation being written in batches exists half-finished for as long as the
 * write takes, and a scope row pointing at it during that window would serve
 * half a build.
 */
final readonly class SearchBuildIndex
{
    /**
     * The live generation for a build, or null.
     *
     * @param  string  $buildIdText  canonical UUID text
     * @param  int|null  $extractorVersion  when given, a generation written by
     *                                      a **different** extractor does not
     *                                      count as live for the caller's
     *                                      purposes — which is how
     *                                      {@see SectionExtractor::VERSION}
     *                                      forces a re-extraction without an
     *                                      operator having to know it happened.
     *                                      Omitted when the caller only needs
     *                                      to know which generation answers.
     */
    public function liveGenerationFor(string $buildIdText, ?int $extractorVersion = null): ?int
    {
        $query = DB::table('search_build_index')
            ->where('build_id', self::bytes($buildIdText))
            ->where('state', 'live');

        if ($extractorVersion !== null) {
            $query->where('extractor_version', $extractorVersion);
        }

        $generation = $query->orderByDesc('generation')->value('generation');

        return is_numeric($generation) ? (int) $generation : null;
    }

    /**
     * The next generation number for a build.
     *
     * One above the highest ever used, including superseded ones — never
     * `live + 1`. Reusing a number a superseded generation held would make the
     * sweep's "delete the old generation" delete the new one, and the symptom
     * would be a build that is searchable until retention runs.
     */
    public function nextGenerationFor(string $buildIdText): int
    {
        $highest = DB::table('search_build_index')
            ->where('build_id', self::bytes($buildIdText))
            ->max('generation');

        return is_numeric($highest) ? ((int) $highest) + 1 : 1;
    }

    /** Open a generation. Nothing points at it until {@see self::finish()}. */
    public function begin(string $buildIdText, int $generation, int $extractorVersion): void
    {
        DB::table('search_build_index')->updateOrInsert(
            [
                'build_id' => self::bytes($buildIdText),
                'generation' => $generation,
            ],
            [
                'id' => Uuid::v7(),
                'extractor_version' => $extractorVersion,
                /*
                 * A placeholder until `finish()` knows which route produced the
                 * documents. The column is not nullable because a row with no
                 * route is a row nobody can interpret; `html` is the route a
                 * build takes when nothing else applies, so it is the honest
                 * default for an unfinished row.
                 */
                'extracted_from' => ExtractedFrom::Html->value,
                'state' => 'writing',
                'section_count' => 0,
                'document_count' => 0,
                'skipped_count' => 0,
                'created_at' => now(),
                'updated_at' => now(),
            ],
        );
    }

    /**
     * 🛑 Close a generation and supersede its predecessors, in one transaction.
     *
     * Both halves or neither. Two statements outside a transaction would leave
     * a moment with two `live` generations for one build — which is precisely
     * §8.16.7's "no window in which both generations answer", at the build
     * level rather than the project level, and the `MATCH` would return every
     * section twice.
     *
     * A generation with **no** sections is marked `superseded` rather than
     * `live`: an empty live generation would make the build look indexed while
     * answering nothing, and the previous generation — which may hold real
     * documents — would have been retired for it.
     */
    public function finish(
        string $buildIdText,
        int $generation,
        ExtractedFrom $extractedFrom,
        int $sections,
        int $documents,
        int $skipped,
    ): void {
        $bytes = self::bytes($buildIdText);
        $state = $sections > 0 ? 'live' : 'superseded';

        DB::transaction(function () use ($bytes, $generation, $extractedFrom, $sections, $documents, $skipped, $state): void {
            if ($state === 'live') {
                DB::table('search_build_index')
                    ->where('build_id', $bytes)
                    ->where('state', 'live')
                    ->where('generation', '!=', $generation)
                    ->update(['state' => 'superseded', 'updated_at' => now()]);
            }

            DB::table('search_build_index')
                ->where('build_id', $bytes)
                ->where('generation', $generation)
                ->update([
                    'extracted_from' => $extractedFrom->value,
                    'state' => $state,
                    'section_count' => $sections,
                    'document_count' => $documents,
                    'skipped_count' => $skipped,
                    'indexed_at' => now(),
                    'updated_at' => now(),
                ]);
        });
    }

    /**
     * Total sections in the live generations of these builds.
     *
     * 🛑 Over **distinct builds**, which is what makes the number comparable to
     * §8.16.1's threshold: a reused build's sections exist once, so counting
     * them once per mounting project would report a corpus several times its
     * real size and recommend Meilisearch to an installation that does not need
     * it.
     *
     * @param  list<string>  $buildIdTexts
     */
    public function liveSectionCount(array $buildIdTexts): int
    {
        if ($buildIdTexts === []) {
            return 0;
        }

        $total = DB::table('search_build_index')
            ->whereIn('build_id', array_map(self::bytes(...), $buildIdTexts))
            ->where('state', 'live')
            ->sum('section_count');

        return (int) $total;
    }

    /**
     * The report for one build's live generation, for the operator UI.
     *
     * @return array{generation: int, extracted_from: string, sections: int, documents: int, skipped: int, indexed_at: string|null}|null
     */
    public function describe(string $buildIdText): ?array
    {
        $row = DB::table('search_build_index')
            ->where('build_id', self::bytes($buildIdText))
            ->where('state', 'live')
            ->orderByDesc('generation')
            ->first(['generation', 'extracted_from', 'section_count', 'document_count', 'skipped_count', 'indexed_at']);

        if ($row === null) {
            return null;
        }

        return [
            'generation' => (int) $row->generation,
            'extracted_from' => is_string($row->extracted_from) ? $row->extracted_from : 'html',
            'sections' => (int) $row->section_count,
            'documents' => (int) $row->document_count,
            'skipped' => (int) $row->skipped_count,
            'indexed_at' => is_string($row->indexed_at) ? $row->indexed_at : null,
        ];
    }

    /**
     * Raw key bytes for a canonical build id.
     *
     * 🛑 An unparseable id becomes an id that matches nothing, not an
     * exception. The value arrives from a manifest, which is JSON DocUp wrote
     * but which a restore can truncate — and a malformed one must make the
     * build unindexed rather than fail a whole pass over a project.
     * `0xff…` is chosen because UUIDv7's timestamp prefix can never reach it.
     */
    private static function bytes(string $buildIdText): string
    {
        return Uuid::tryToBytes($buildIdText) ?? str_repeat("\xff", 16);
    }
}
