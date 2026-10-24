<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Log;

/**
 * One answer to §8.5.22's `GET /api/v3/builds/{id}/log?from=<seq>`.
 *
 * 🛑 **`next` is the contract, not `from + count(lines)`.** A client that
 * computed its own cursor would be wrong the moment §8.5.21's cap removed
 * lines out of the middle, and wrong again if a line were ever filtered.
 * Handing the next cursor back is what lets the server change how the log
 * is stored without breaking every poller.
 */
final readonly class LogPage implements \JsonSerializable
{
    /** @param list<LogLine> $lines */
    public function __construct(
        public array $lines,

        /** The `from` a client should send next. Always safe to re-send. */
        public int $next,

        /** True when the page was cut by the limit, not by the end of the log. */
        public bool $more,

        /**
         * Lines §8.5.21's cap removed before this page, or null.
         *
         * Null and zero are the same fact and only one of them is said, so
         * a client can test for presence rather than for a value.
         */
        public ?int $omitted = null,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return [
            'lines' => $this->lines,
            'next' => $this->next,
            'more' => $this->more,
            'omitted' => $this->omitted,
        ];
    }

    /** §8.5.21's "NDJSON log streaming", as the bytes of one page. */
    public function toNdjson(): string
    {
        $body = '';

        foreach ($this->lines as $line) {
            $body .= $line->encode();
        }

        return $body;
    }
}
