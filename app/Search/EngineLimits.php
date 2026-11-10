<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 §8.16.2's limits, in the shape the **product UI** states them.
 *
 * > §8.16.2: "The documented limits of the default engine MUST be stated **in
 * > the product UI**, not only the documentation: no stemming, no typo
 * > tolerance, a three-character minimum token, 36 default stopwords. 🛑 The
 * > illustration must use a **two**-character term … 'Why can't I find `go`?'
 * > is the real first support question (ADR 0004)."
 *
 * ## 🛑 Why the numbers are read from the server and not written here
 *
 * `innodb_ft_min_token_size` is a **server variable**. An operator who raises
 * it to 4 — or lowers it to 2 to make `go` findable — changes the answer to the
 * support question this requirement exists to pre-empt, and a UI printing the
 * specification's `3` would then be confidently wrong about the one number the
 * reader came to check.
 *
 * So the minimum token length, the maximum, and the stopword count come from
 * `SHOW VARIABLES` and `INFORMATION_SCHEMA.INNODB_FT_DEFAULT_STOPWORD` at render
 * time. §8.16.2's own figures are asserted against a real server by
 * `EngineLimitsTest`, which is the only honest way to claim them — and if a
 * MySQL release changes the default, the test says so rather than the UI
 * quietly lying.
 *
 * The **illustrations** are different in kind: `api` returning 100,000 hits at
 * 200,000 sections is a measurement from ADR 0004 that no UI render can repeat.
 * Those are cited as measured, with the section count they were measured at, so
 * a reader can see they are a report rather than a live reading.
 */
final readonly class EngineLimits
{
    /** §8.16.2's stated default, asserted against a real server, not trusted. */
    public const int SPEC_MIN_TOKEN_SIZE = 3;

    /** §8.16.2's stated default stopword count. */
    public const int SPEC_STOPWORD_COUNT = 36;

    /** The section count ADR 0004's illustrations were measured at. */
    public const int MEASURED_AT_SECTIONS = 200_000;

    /**
     * @param  int  $minTokenSize  the live `innodb_ft_min_token_size`, or the
     *                             engine's own floor
     * @param  int  $maxTokenSize  the live `innodb_ft_max_token_size`
     * @param  int  $stopwordCount  how many stopwords the engine actually has
     * @param  bool  $stemming  §8.16.2: the default engine has none
     * @param  bool  $typoTolerance  §8.16.2: the default engine has none
     * @param  string|null  $stopwordTable  the operator's own stopword table,
     *                                      when `innodb_ft_server_stopword_table`
     *                                      names one — stated because an
     *                                      operator who has set one needs the UI
     *                                      to stop quoting the default list
     */
    public function __construct(
        public SearchDriver $driver,
        public int $minTokenSize,
        public int $maxTokenSize,
        public int $stopwordCount,
        public bool $stemming,
        public bool $typoTolerance,
        public ?string $stopwordTable = null,
    ) {}

    /**
     * 🛑 §8.16.2's five illustrations, with the two-character term first.
     *
     * The order is the requirement's, and the first entry is the one it marks
     * 🛑: a **two**-character term returning nothing is the surprise, because
     * three characters clears the default minimum and so every example a
     * well-meaning author reaches for (`api`, `ssl`, `jwt`) works.
     *
     * `$live` is true for the illustrations this object can derive from the
     * server it just read, and false for ADR 0004's measurements — so the UI
     * can label a measurement as one instead of implying it re-ran it.
     *
     * @return list<array{term: string, outcome: string, why: string, live: bool}>
     */
    public function illustrations(): array
    {
        $min = $this->minTokenSize;

        return [
            [
                'term' => 'go',
                'outcome' => $min > 2 ? 'no results' : 'results',
                'why' => $min > 2
                    ? "two characters, and this server's minimum indexed token is {$min}"
                    : "this server's minimum indexed token has been lowered to {$min}, so two-character terms do match",
                'live' => true,
            ],
            [
                'term' => 'the',
                'outcome' => 'no results',
                'why' => $this->stopwordTable === null
                    ? "a stopword; this server has {$this->stopwordCount} of them"
                    : "a stopword in {$this->stopwordTable}, this server's configured list of {$this->stopwordCount}",
                'live' => true,
            ],
            [
                'term' => 'authentcation',
                'outcome' => 'no results',
                'why' => $this->typoTolerance
                    ? 'this engine tolerates typos, so a misspelling still matches'
                    : 'a misspelling, and this engine has no typo tolerance',
                'live' => true,
            ],
            [
                'term' => 'deploying',
                'outcome' => $this->stemming ? 'matches deploy' : 'does not match deploy',
                'why' => $this->stemming
                    ? 'this engine stems, so the two share a root'
                    : 'this engine does not stem: a word matches only itself',
                'live' => true,
            ],
            [
                'term' => 'api',
                'outcome' => 'about 100,000 results',
                'why' => 'three characters clears the minimum, so a common term matches half the corpus '
                    .'(measured at '.number_format(self::MEASURED_AT_SECTIONS).' sections, ADR 0004)',
                'live' => false,
            ],
        ];
    }

    /**
     * The limits as the UI and the API render them.
     *
     * @return array{driver: string, driver_label: string, min_token_size: int, max_token_size: int, stopword_count: int, stopword_table: string|null, stemming: bool, typo_tolerance: bool, illustrations: list<array{term: string, outcome: string, why: string, live: bool}>}
     */
    public function toPayload(): array
    {
        return [
            'driver' => $this->driver->value,
            'driver_label' => $this->driver->label(),
            'min_token_size' => $this->minTokenSize,
            'max_token_size' => $this->maxTokenSize,
            'stopword_count' => $this->stopwordCount,
            'stopword_table' => $this->stopwordTable,
            'stemming' => $this->stemming,
            'typo_tolerance' => $this->typoTolerance,
            'illustrations' => $this->illustrations(),
        ];
    }
}
