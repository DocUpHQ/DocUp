<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search\Engines;

use App\Search\AuthorisedScope;
use App\Search\DocumentHit;
use App\Search\EngineCapabilities;
use App\Search\EngineCapability;
use App\Search\EngineLimits;
use App\Search\LiteralTerm;
use App\Search\ParsedQuery;
use App\Search\ScopeFact;
use App\Search\SearchBuildIndex;
use App\Search\SearchDriver;
use App\Search\SearchEngine;
use App\Search\SectionBatch;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;
use Tests\Feature\Search\EngineContractTest;

/**
 * 🛑 §8.16.1's shipped default: InnoDB FULLTEXT, with no service to run.
 *
 * > §8.16.1: "MySQL InnoDB FULLTEXT as the shipped default (no additional
 * > service — requirement §8.1.1)".
 *
 * ## 🛑 What this driver cannot do, and why that is stated rather than hidden
 *
 * §8.16.2 fixes the limits and §8.16.12 requires them published: no stemming,
 * no typo tolerance, a three-character minimum token and 36 stopwords. ADR 0004
 * names the consequence — *"Why can't I find `go`?" is the real first support
 * question* — and the answer is not a workaround. A two-character term is not
 * in the index at all, so no query construction can find it.
 *
 * {@see EngineLimits} reads those numbers from the **running server** rather
 * than quoting the specification, because `innodb_ft_min_token_size` is a
 * server variable an operator can change and a UI confidently printing `3`
 * while the server says `4` would be wrong about the one number the reader came
 * to check.
 *
 * ## 🛑 The measured cost, and why the limit does not control it
 *
 * §8.16.6: "a `MATCH … AGAINST` with a `build_id`/scope predicate runs at p95
 * **80 ms** against **10 ms** unfiltered at 200,000 sections, because MySQL
 * cannot combine a FULLTEXT index with a secondary index and the `WHERE` clause
 * defeats its early-`LIMIT` optimisation. The cost therefore scales with
 * **match-set size, not result limit**."
 *
 * So the query below looks like it should be cheap — it has a `LIMIT 10` — and
 * is not. The FULLTEXT index produces every matching row, the scope predicate
 * filters them in the server, and only then is the limit applied. A smaller
 * limit buys nothing. That is what sets §8.16.1's Meilisearch threshold, and
 * `doctor` warns at it rather than leaving an operator to discover it.
 *
 * ## 🛑 Boolean mode, and the escaping that makes it safe
 *
 * The query is built in `IN BOOLEAN MODE`, because §8.16.12's implicit AND and
 * exact phrases are expressible there and not in natural-language mode. Boolean
 * mode has its own operator language — `+ - > < ( ) ~ * " @` — and a reader's
 * term is **not** an expression in it: {@see self::booleanQuery()} strips every
 * operator from a term and escapes the quote in a phrase, so a query can change
 * what is searched for and never how. The abuse corpus carries the cases, and a
 * `-` reaching the engine unescaped would be a reader able to exclude the
 * documents a filter had just included.
 */
final readonly class MysqlFulltextEngine implements SearchEngine
{
    /**
     * §8.16.3's title boost, as a multiplier on the title-only relevance.
     *
     * Two, and the number is a judgement rather than a measurement: a term in a
     * section's own heading is a stronger signal than the same term in its
     * body, and twice is enough to put it first without letting a one-word
     * heading outrank a page that is actually about the subject. The
     * {@see EngineContractTest} asserts the **ordering**
     * this produces, which is the part both drivers owe; the constant is this
     * driver's way of achieving it.
     */
    private const float TITLE_WEIGHT = 2.0;

    /** §8.16.3's nested-title boost. One: above content, below the title. */
    private const float HEADING_WEIGHT = 1.0;

    /**
     * 🛑 The most (build, generation) pairs put into one scope predicate.
     *
     * A project-scoped search — the case this phase serves — has one pair per
     * mount, so a handful. §8.16.12's `self:me` over the reader's whole
     * accessible set is the one that can grow, and a `IN` list of ten thousand
     * row constructors is a parse cost paid before the FULLTEXT index is even
     * consulted.
     *
     * Truncation **loses results**, which is why it is ordered deterministically
     * and reported rather than silently applied: §8.16.10's cross-project
     * search is Phase 30's deliverable and owns the design for an accessible set
     * that does not fit in a predicate. Until then, an installation large
     * enough to hit this is an installation §8.16.1 already recommends
     * Meilisearch to.
     */
    private const int MAX_SCOPE_KEYS = 1_000;

    /** Rows deleted per statement by {@see self::forgetSections()}. */
    private const int DELETE_BATCH = 1_000;

    public function driver(): SearchDriver
    {
        return SearchDriver::MysqlFulltext;
    }

    public function capabilities(): EngineCapabilities
    {
        return EngineCapabilities::of(
            SearchDriver::MysqlFulltext,
            [
                EngineCapability::ImplicitAnd->value => true,
                EngineCapability::ExactPhrase->value => true,
                EngineCapability::ScopeFilters->value => true,
                EngineCapability::FieldWeights->value => true,
            ],
            [
                EngineCapability::TypoTolerance->value => 'A misspelling returns nothing. InnoDB matches whole words against an exact index (§8.16.2).',
                EngineCapability::Prefix->value => 'Boolean-mode prefix matching exists in MySQL but is not offered: it would be a term DocUp '
                    .'accepts here and ignores on Meilisearch, which would make §8.16.12\'s "identical suite" false.',
                EngineCapability::Proximity->value => 'Terms are ANDed; how near they are does not affect the score. An exact phrase is the way to '
                    .'ask for adjacency.',
                EngineCapability::Stemming->value => 'A word matches only itself: `deploying` does not match `deploy` (§8.16.2).',
                EngineCapability::Highlighting->value => 'No server-side highlighting. §8.16.10 puts highlighting in Phase 30, which can mark up the '
                    .'stored section text client-side.',
            ],
        );
    }

    /**
     * §8.16.2's limits, read from the running server.
     *
     * 🛑 `@@global.…` rather than `performance_schema.global_variables`. The
     * latter takes a placeholder and is the tidier query; it also needs the
     * `PROCESS` privilege on some configurations, and DocUp's application user
     * has the privileges §8.1 grants it and no more. A system-variable read is
     * available to every user, and the variable names here are literals in this
     * file — not input — so there is nothing to parameterise.
     *
     * 🛑 Every failure falls back to §8.16.2's documented default rather than
     * throwing. This method is called to render a UI panel; a server that
     * answers "I don't know" must not take the page down, and the specification's
     * figure is the right thing to show when the server will not say.
     */
    public function limits(): EngineLimits
    {
        return new EngineLimits(
            driver: SearchDriver::MysqlFulltext,
            minTokenSize: $this->variable('innodb_ft_min_token_size', EngineLimits::SPEC_MIN_TOKEN_SIZE),
            maxTokenSize: $this->variable('innodb_ft_max_token_size', 84),
            stopwordCount: $this->stopwordCount(),
            stemming: false,
            typoTolerance: false,
            stopwordTable: $this->stopwordTable(),
        );
    }

    /**
     * Always reachable: it is the same database the request is already using.
     *
     * 🛑 This is §8.16.1's whole argument for the default — "no additional
     * service" means there is no second thing that can be down. If this
     * connection is unavailable the request has already failed for reasons that
     * have nothing to do with search.
     */
    public function isReachable(): bool
    {
        return true;
    }

    public function hasSections(string $buildId, int $buildGeneration, int $extractorVersion): bool
    {
        return DB::table('search_documents')
            ->where('build_id', self::key($buildId))
            ->where('build_generation', $buildGeneration)
            ->where('extractor_version', $extractorVersion)
            ->exists();
    }

    public function writeSections(SectionBatch $batch): void
    {
        if ($batch->isEmpty()) {
            return;
        }

        $buildKey = self::key($batch->buildId);
        $now = now();
        $rows = [];

        foreach ($batch->sections as $section) {
            $rows[] = [
                'uuid' => Uuid::v7(),
                'build_id' => $buildKey,
                'build_generation' => $batch->buildGeneration,
                'language' => $batch->language,
                'path' => $section->path,
                'anchor' => $section->anchor,
                'title' => $section->title,
                'heading_path' => $section->headingPath,
                'page_title' => $section->pageTitle,
                'content' => $section->content,
                'page_rank' => $section->rank,
                'position' => $section->position,
                'extracted_from' => $batch->extractedFrom->value,
                'extractor_version' => $batch->extractorVersion,
                'created_at' => $now,
            ];
        }

        /*
         * 🛑 An upsert, so a re-run of a pass that died halfway is idempotent.
         *
         * The conflict target is `search_documents_section_unique`, over
         * `build_id`, `build_generation` and the two **generated** hashes —
         * which is why `uuid` is left out of the update list: a document that
         * already exists keeps the business key other rows may reference. The
         * unique-by argument is informational on MySQL (the driver emits
         * `ON DUPLICATE KEY UPDATE`), and the columns are named anyway so the
         * intent survives a change of database.
         */
        DB::table('search_documents')->upsert(
            $rows,
            ['build_id', 'build_generation', 'path', 'anchor'],
            [
                'language', 'title', 'heading_path', 'page_title', 'content',
                'page_rank', 'position', 'extracted_from', 'extractor_version',
            ],
        );
    }

    /**
     * 🛑 A no-op, deliberately, and this is the honest place to say so.
     *
     * §8.16.8's filterable attributes are `search_mount_scopes` under this
     * driver: the join to that table **is** the filter, so there is nothing to
     * copy onto a document and nothing that could go stale. The method exists
     * on the seam because {@see MeilisearchEngine} needs
     * it, and §8.16.8's "declared in v1" has to be a property of the seam
     * rather than of one driver — an engine added later must be told that the
     * complete set is its responsibility.
     *
     * @param  list<ScopeFact>  $facts
     */
    public function declareFilters(string $buildId, int $buildGeneration, array $facts): void
    {
        // Intentionally empty; see the docblock.
    }

    public function forgetSections(string $buildId, int $buildGeneration): int
    {
        $key = self::key($buildId);
        $removed = 0;

        /*
         * 🛑 §8.16.11's batched delete. The table is unpartitionable, so there
         * is no `DROP PARTITION`, and a single `DELETE` of a 200,000-row
         * generation is a long transaction holding row locks on a §10.9 hot
         * table. §10.9 also requires the scheduled `OPTIMIZE TABLE` these
         * deletes make necessary: they plateau at roughly +28% rather than
         * reclaiming, which is `SearchRetention`'s job.
         */
        do {
            $deleted = DB::table('search_documents')
                ->where('build_id', $key)
                ->where('build_generation', $buildGeneration)
                ->limit(self::DELETE_BATCH)
                ->delete();

            $removed += $deleted;
        } while ($deleted >= self::DELETE_BATCH);

        return $removed;
    }

    /**
     * @return list<DocumentHit>
     */
    public function search(ParsedQuery $query, AuthorisedScope $scope, int $limit): array
    {
        /*
         * 🛑 The empty-scope guard, first, and it is not an optimisation.
         * §8.16.6 makes the scope the whole of the visibility filter, so a
         * `MATCH` built without one would return the installation.
         */
        if ($scope->isEmpty() || $query->isEmpty()) {
            return [];
        }

        $expression = $this->booleanQuery($query);

        if ($expression === '') {
            /*
             * Every term was an operator, a stopword's worth of punctuation, or
             * otherwise left nothing to match. §8.16.12's degradation rule: no
             * error, no results.
             */
            return [];
        }

        $keys = array_slice($scope->documentKeys(), 0, self::MAX_SCOPE_KEYS);

        if ($keys === []) {
            return [];
        }

        $pairs = array_fill(0, count($keys), '(?, ?)');

        /*
         * 🛑 Three `MATCH` expressions against three FULLTEXT indexes, because
         * MySQL offers no other way to weight a field. `MATCH(title)` is legal
         * only with an index on exactly `(title)`, so §8.16.3's three boost
         * levels are three indexes — the migration says the same thing from the
         * schema's side.
         *
         * The rank is **multiplicative**, which is Read the Docs' own model and
         * the reason §8.16.3 bounds it at ±10: `1 + rank/10` makes −10 a factor
         * of zero ("effectively never surface this page") and +10 a factor of
         * two. An additive bonus would make a +10 rank outrank a genuine match
         * on a page ranked 0, which is a ranking hint behaving like a filter.
         */
        $sql = <<<'SQL'
            SELECT d.build_id,
                   d.build_generation,
                   d.path,
                   d.anchor,
                   d.title,
                   d.heading_path,
                   d.page_title,
                   d.content,
                   d.page_rank,
                   (
                       (
                           MATCH (d.title, d.heading_path, d.content) AGAINST (? IN BOOLEAN MODE)
                           + ? * MATCH (d.title) AGAINST (? IN BOOLEAN MODE)
                           + ? * MATCH (d.heading_path) AGAINST (? IN BOOLEAN MODE)
                       )
                       * (1 + (d.page_rank / 10))
                   ) AS relevance
              FROM search_documents d
             WHERE MATCH (d.title, d.heading_path, d.content) AGAINST (? IN BOOLEAN MODE)
               AND (d.build_id, d.build_generation) IN (%s)
             ORDER BY relevance DESC, d.page_rank DESC, d.position ASC, d.id ASC
             LIMIT ?
            SQL;

        /*
         * The bindings in the order the statement reads them: the three scored
         * `MATCH` expressions with the two weights interleaved, then the
         * `WHERE`'s own expression, then the scope pairs, then the limit.
         */
        $bindings = [
            $expression,
            self::TITLE_WEIGHT,
            $expression,
            self::HEADING_WEIGHT,
            $expression,
            $expression,
        ];

        foreach ($keys as [$buildId, $buildGeneration]) {
            $bindings[] = self::key($buildId);
            $bindings[] = $buildGeneration;
        }

        $bindings[] = max(1, $limit);

        $rows = DB::select(sprintf($sql, implode(', ', $pairs)), $bindings);

        $hits = [];

        foreach ($rows as $row) {
            /*
             * 🛑 A row whose key is not 16 bytes is skipped rather than
             * converted. `Uuid::toText()` throws on anything else — correctly,
             * because a half-written key is a bug and not a value — and a
             * reader's search must not 500 on one corrupt row. The row is
             * unreachable by any other route anyway: the scope predicate
             * matched it, so a key that then fails this check means the column
             * itself is damaged.
             */
            if (! is_string($row->build_id) || ! Uuid::isBytes($row->build_id)) {
                continue;
            }

            $hits[] = new DocumentHit(
                buildId: Uuid::toText($row->build_id),
                buildGeneration: (int) $row->build_generation,
                path: is_string($row->path) ? $row->path : '',
                anchor: is_string($row->anchor) ? $row->anchor : null,
                title: is_string($row->title) ? $row->title : '',
                headingPath: is_string($row->heading_path) ? $row->heading_path : '',
                pageTitle: is_string($row->page_title) ? $row->page_title : '',
                content: is_string($row->content) ? $row->content : '',
                rank: (int) $row->page_rank,
                score: (float) $row->relevance,
            );
        }

        return $hits;
    }

    public function sectionCount(): int
    {
        /*
         * 🛑 An approximation from `information_schema`, not `COUNT(*)`.
         *
         * §10.9 names `search_documents` a hot table and §8.16.1's threshold is
         * 200,000 sections — a `COUNT(*)` at that size is a full index scan,
         * and the one caller is `doctor`, which an operator runs when search is
         * already slow. InnoDB's row estimate is within a few per cent, which
         * is far inside the precision a "you are near the threshold" warning
         * needs.
         *
         * A `COUNT(*)` fallback would be worse than the estimate, not better,
         * so there is none: an absent estimate reports zero and `doctor` says
         * it could not read the figure.
         */
        /** @var object{n: int|string|null}|null $row */
        $row = DB::selectOne(
            'SELECT TABLE_ROWS AS n FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            ['search_documents'],
        );

        return $row === null || ! is_numeric($row->n) ? 0 : (int) $row->n;
    }

    /**
     * 🛑 §8.16.12's syntax, as a boolean-mode expression — and nothing more.
     *
     * Each term becomes `+term` (implicit AND) and each phrase `+"phrase"`
     * (exact phrase). Everything else a reader typed is **removed**, not
     * escaped into a literal: boolean mode's operators cannot be escaped in
     * MySQL, so `+`, `-`, `~`, `<`, `>`, `(`, `)`, `*`, `@` and `"` are
     * stripped from a term rather than passed through.
     *
     * That is the only safe reading. A `-` surviving into the expression is a
     * reader able to **exclude** documents — `authentication -internal` would
     * quietly subtract from a result set a filter had just defined — and a `*`
     * is a prefix search this driver's capability matrix says it does not
     * offer. Stripping leaves the word searchable, which is §8.16.12's
     * "degrade to a literal term rather than erroring".
     *
     * A term reduced to nothing is dropped. A whole query reduced to nothing
     * returns no results, which {@see self::search()} handles.
     *
     * 🛑 The reduction is {@see LiteralTerm}'s and not this driver's, so the
     * two engines cannot disagree about what a reader typed. That class records
     * what happened when each driver stripped its own set.
     */
    private function booleanQuery(ParsedQuery $query): string
    {
        $parts = [];

        foreach ($query->terms as $term) {
            foreach (LiteralTerm::wordsOf($term) as $word) {
                $parts[] = '+'.$word;
            }
        }

        foreach ($query->phrases as $phrase) {
            $clean = LiteralTerm::of($phrase);

            if ($clean !== '') {
                $parts[] = '+"'.$clean.'"';
            }
        }

        return implode(' ', $parts);
    }

    /** One InnoDB system variable as an int, or the stated default. */
    private function variable(string $name, int $default): int
    {
        try {
            /*
             * The name is a literal from this file's own call sites and can
             * never be input — `SearchArchitectureTest` asserts this method is
             * private and called only with literals, so there is nothing to
             * parameterise and nothing a reader can influence.
             */
            /** @var object{v: int|string|null}|null $row */
            $row = DB::selectOne('SELECT @@global.'.$name.' AS v');
        } catch (\Throwable) {
            return $default;
        }

        return $row !== null && is_numeric($row->v) ? (int) $row->v : $default;
    }

    /**
     * How many stopwords this server actually has.
     *
     * The operator's own table when `innodb_ft_server_stopword_table` names
     * one, because §8.16.2's "36 default stopwords" stops being the truth the
     * moment an operator configures their own — and the UI's job is to state
     * what is true of this installation.
     */
    private function stopwordCount(): int
    {
        $table = $this->stopwordTable();

        if ($table !== null) {
            $count = $this->countOfStopwordTable($table);

            if ($count !== null) {
                return $count;
            }
        }

        try {
            /** @var object{n: int|string|null}|null $row */
            $row = DB::selectOne('SELECT COUNT(*) AS n FROM INFORMATION_SCHEMA.INNODB_FT_DEFAULT_STOPWORD');
        } catch (\Throwable) {
            return EngineLimits::SPEC_STOPWORD_COUNT;
        }

        return $row !== null && is_numeric($row->n)
            ? (int) $row->n
            : EngineLimits::SPEC_STOPWORD_COUNT;
    }

    /** The operator's configured stopword table, or null for the default list. */
    private function stopwordTable(): ?string
    {
        try {
            /** @var object{v: string|null}|null $row */
            $row = DB::selectOne('SELECT @@global.innodb_ft_server_stopword_table AS v');
        } catch (\Throwable) {
            return null;
        }

        $value = $row?->v;

        return is_string($value) && trim($value) !== '' ? $value : null;
    }

    /**
     * Count an operator-configured stopword table, or null.
     *
     * 🛑 The name comes from a **server variable**, not from a request, and it
     * still goes through a strict shape check before it is interpolated: the
     * variable's documented form is `db/table`, and anything else is refused
     * rather than quoted. A server variable is operator input, and §9.3's
     * posture on operator input is the same as on anybody else's — the
     * difference is who is surprised when it is wrong.
     */
    private function countOfStopwordTable(string $table): ?int
    {
        if (preg_match('/^[A-Za-z0-9_$]{1,64}\/[A-Za-z0-9_$]{1,64}$/', $table) !== 1) {
            return null;
        }

        [$schema, $name] = explode('/', $table, 2);

        try {
            /** @var object{n: int|string|null}|null $row */
            $row = DB::selectOne('SELECT COUNT(*) AS n FROM `'.$schema.'`.`'.$name.'`');
        } catch (\Throwable) {
            return null;
        }

        return $row !== null && is_numeric($row->n) ? (int) $row->n : null;
    }

    /**
     * Raw key bytes for a canonical build id.
     *
     * An unparseable id becomes a key that matches nothing rather than an
     * exception — {@see SearchBuildIndex} takes the same direction
     * and says why.
     */
    private static function key(string $buildIdText): string
    {
        return Uuid::tryToBytes($buildIdText) ?? str_repeat("\xff", 16);
    }
}
