<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/** One row of the §8.14.5 contrast report: a pair, a scheme and a verdict. */
final readonly class ContrastFinding
{
    public function __construct(
        public string $foreground,
        public string $background,
        public ColourScheme $scheme,
        public ContrastRole $role,
        /** What chrome renders with this pair, for the operator. */
        public string $surface,
        /** The ratio, rounded to two places — the precision a report should claim. */
        public float $ratio,
        public ContrastVerdict $verdict,
    ) {}

    /** One line an operator can act on. */
    public function describe(): string
    {
        return sprintf(
            '%s on %s (%s scheme, %s): %.2f:1 — %s, %s',
            $this->foreground,
            $this->background,
            $this->scheme->value,
            $this->surface,
            $this->ratio,
            $this->verdict->value,
            $this->role->criterion(),
        );
    }

    /** @return array<string, string|float> */
    public function toArray(): array
    {
        return [
            'foreground' => $this->foreground,
            'background' => $this->background,
            'scheme' => $this->scheme->value,
            'role' => $this->role->value,
            'surface' => $this->surface,
            'ratio' => round($this->ratio, 2),
            'verdict' => $this->verdict->value,
        ];
    }
}
