<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

/**
 * §8.12.19's automated half: what a probe found.
 *
 * 🛑 A probe answers "could this provider work", never "is this reader
 * allowed". The distinction matters because a probe runs on a schedule with no
 * reader present, and a driver that conflated the two would be a driver whose
 * scheduled job could admit somebody.
 *
 * 🛑 **`detail` is for an operator and never for a reader.** It names hosts,
 * configuration keys and provider error strings, which is exactly what
 * §8.12.19's health page needs and exactly what §8.12.23 keeps out of a
 * response. It is stored in `auth_provider_bindings.probe` and rendered on the
 * dashboard; the reader's 503 names the binding and nothing else.
 */
final readonly class ProbeResult
{
    /**
     * @param  array<string, string>  $detail  fixed-vocabulary keys, operator-
     *                                         facing values. 🛑 Never a secret:
     *                                         a probe that reported the client
     *                                         secret it tried would put it in a
     *                                         JSON column an API returns.
     */
    public function __construct(
        public bool $passed,
        public string $summary,
        public array $detail = [],
    ) {}

    /** @param  array<string, string>  $detail */
    public static function pass(string $summary, array $detail = []): self
    {
        return new self(passed: true, summary: $summary, detail: $detail);
    }

    /** @param  array<string, string>  $detail */
    public static function fail(string $summary, array $detail = []): self
    {
        return new self(passed: false, summary: $summary, detail: $detail);
    }

    /**
     * The shape stored in `auth_provider_bindings.probe`.
     *
     * @return array{passed: bool, summary: string, detail: array<string, string>, at: string}
     */
    public function toArray(): array
    {
        return [
            'passed' => $this->passed,
            'summary' => $this->summary,
            'detail' => $this->detail,
            'at' => now()->toIso8601String(),
        ];
    }
}
