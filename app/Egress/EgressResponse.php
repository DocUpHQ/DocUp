<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

/**
 * What came back, bounded.
 *
 * 🛑 §8.3.7: every provider response is untrusted input. Nothing here is
 * decoded, escaped or interpreted — `json()` parses and that is all. Names,
 * descriptions and URLs from a provider are escaped on render and validated
 * against §8.3.4 before use, by the caller, which is the layer that knows what
 * the value is supposed to be.
 */
final readonly class EgressResponse
{
    /** @param  array<string, list<string>>  $headers  lower-cased names */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
        public string $pinnedAddress,
    ) {}

    public function successful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)][0] ?? null;
    }

    /**
     * The body as JSON.
     *
     * Depth is capped at the same 32 §8.4.9 applies to configuration parsing:
     * a provider is no more trusted than a repository, and a deeply nested
     * document is a cheap way to exhaust the parser.
     *
     * @return array<array-key, mixed>|null null when the body is not a JSON object or array
     */
    public function json(): ?array
    {
        try {
            $decoded = json_decode($this->body, true, 32, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            return null;
        }

        return is_array($decoded) ? $decoded : null;
    }
}
