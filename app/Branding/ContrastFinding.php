<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Audit\CanonicalJson;

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
        /** The ratio, full precision. {@see self::toArray()} rounds it. */
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

    /**
     * 🛑 The ratio is a **string** of two decimals, not a float.
     *
     * Two reasons, and the second one is a hard requirement rather than a
     * preference. A report claiming more precision than two places claims more
     * than the measurement supports — a colour is eight bits per channel.
     * And {@see CanonicalJson} **refuses** a float outright, because
     * `json_encode` renders one per `serialize_precision`, so a `php.ini`
     * change would invalidate every audit hash written before it. The override
     * audit event carries these findings, so a float here would make
     * §8.14.5's "operator override audited" unwritable. Found by the test for
     * that override.
     *
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'foreground' => $this->foreground,
            'background' => $this->background,
            'scheme' => $this->scheme->value,
            'role' => $this->role->value,
            'surface' => $this->surface,
            'ratio' => number_format($this->ratio, 2, '.', ''),
            'verdict' => $this->verdict->value,
        ];
    }
}
