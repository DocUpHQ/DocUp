<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

/**
 * What §8.5.12's self-test found, check by check.
 *
 * 🛑 **Three outcomes, not two.** A self-test that could only pass or fail
 * would have to call "there is no sandbox configured here" a failure, and
 * that is the state of every developer machine and of CI before the images
 * exist. `unavailable` is reported honestly and is **not** a pass: the
 * runner refuses to start on it in production exactly as it does on a
 * failure, and `docup:doctor` says which of the two it is.
 */
final readonly class SelfTestResult
{
    /** @param array<string, array{0: bool, 1: string}> $checks */
    private function __construct(
        public bool $passed,
        public bool $available,
        public array $checks,
        public string $summary,
    ) {}

    /** @param array<string, array{0: bool, 1: string}> $checks */
    public static function failed(array $checks): self
    {
        return new self(false, true, $checks, self::describe($checks));
    }

    public static function unavailable(string $why): self
    {
        return new self(false, false, [], $why);
    }

    /**
     * Parse the self-test container's own output.
     *
     * 🛑 **A check that printed nothing is a failure, not a pass.** The
     * parser builds its verdict from lines it saw, and `$passed` is false
     * when there were none — a container killed halfway through would
     * otherwise report a clean sandbox because it never got as far as
     * saying otherwise.
     */
    public static function fromOutput(string $output, string $marker): self
    {
        $checks = [];

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);

            if (! str_starts_with($line, $marker.' ')) {
                continue;
            }

            $parts = preg_split('/\s+/', $line, 4) ?: [];
            $name = $parts[1] ?? '';
            $verdict = $parts[2] ?? '';

            if ($name === '' || $verdict === '') {
                continue;
            }

            $checks[$name] = [$verdict === 'OK', $parts[3] ?? ''];
        }

        if ($checks === []) {
            return self::failed(['output' => [false, 'the self-test container produced no verdicts']]);
        }

        $passed = true;

        foreach ($checks as [$ok]) {
            $passed = $passed && $ok;
        }

        return new self($passed, true, $checks, self::describe($checks));
    }

    /** @param array<string, array{0: bool, 1: string}> $checks */
    private static function describe(array $checks): string
    {
        $parts = [];

        foreach ($checks as $name => [$ok, $detail]) {
            $parts[] = $name.': '.($ok ? 'ok' : 'FAILED').($detail === '' ? '' : ' ('.$detail.')');
        }

        return implode('; ', $parts);
    }

    /** @return list<string> the names of the checks that did not pass */
    public function failures(): array
    {
        $failed = [];

        foreach ($this->checks as $name => [$ok]) {
            if (! $ok) {
                $failed[] = $name;
            }
        }

        return $failed;
    }
}
