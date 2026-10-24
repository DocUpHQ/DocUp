<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Log;

/**
 * One line of a build log (§8.5.21, §8.5.22).
 *
 * 🛑 **The sequence number is the address**, and it is assigned once, by the
 * writer, and never reassigned. §8.5.22 makes the contract
 * `?from=<seq>`, so a client's cursor has to survive everything that can
 * happen to the log afterwards — including §8.5.21's cap, which deletes
 * lines out of the middle. If the cap renumbered what remained, every
 * client holding a cursor would silently re-read lines it had already shown.
 * Keeping the numbers and letting the gap be visible is what makes
 * "omitted" an honest answer rather than a replay.
 */
final readonly class LogLine implements \JsonSerializable
{
    public function __construct(
        /** 1-based, monotonic within one build, never reused. */
        public int $seq,

        /** Milliseconds since the epoch, so a client can show elapsed time. */
        public int $at,

        /** `out`, `err`, or `docup` for the pipeline's own narration. */
        public string $stream,
        public string $text,
    ) {}

    /** The pipeline speaking for itself: stage boundaries, refusals, markers. */
    public static function system(int $seq, string $text): self
    {
        return new self($seq, (int) (microtime(true) * 1000), 'docup', $text);
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return ['seq' => $this->seq, 'at' => $this->at, 'stream' => $this->stream, 'text' => $this->text];
    }

    /** One NDJSON record, newline included. */
    public function encode(): string
    {
        return json_encode($this, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE)."\n";
    }

    /**
     * Parse one NDJSON record, or null when it is not one.
     *
     * 🛑 Null rather than an exception. A truncated final line is the normal
     * state of a file being appended to while it is read — the reader must
     * skip it and come back, not fail the request a browser is polling.
     */
    public static function decode(string $json): ?self
    {
        try {
            /** @var array<string, mixed> $data */
            $data = json_decode(trim($json), true, 8, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        if (! is_int($data['seq'] ?? null) || ! is_string($data['text'] ?? null)) {
            return null;
        }

        return new self(
            seq: $data['seq'],
            at: is_int($data['at'] ?? null) ? $data['at'] : 0,
            stream: is_string($data['stream'] ?? null) ? $data['stream'] : 'out',
            text: $data['text'],
        );
    }
}
