<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * What a redirect evaluation produced.
 *
 * 🛑 `rule` is the **identifier the operator sees**, not a database id. It
 * reaches `X-DocUp-Resolver` on the response and an operator's log, and the
 * question it has to answer is "which rule sent me here?" — `exact#3` does,
 * a UUID does not.
 */
final readonly class RedirectMatch
{
    private function __construct(
        public string $to,
        public int $status,
        public string $rule,
        public int $hops,
    ) {}

    public static function to(string $target, int $status, string $rule, int $hops = 1): self
    {
        return new self($target, $status, $rule, $hops);
    }

    /** Whether the target leaves this origin, and so cannot be followed again. */
    public function leavesOrigin(): bool
    {
        return RedirectTarget::isAbsolute($this->to);
    }
}
