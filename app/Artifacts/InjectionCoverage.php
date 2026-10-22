<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Per-build injection coverage (§8.15.3), and the §8.15.4 fallback decision.
 *
 * §8.15.3: "Per-build injection coverage MUST be recorded and reported as a
 * build warning with samples." §8.15.4: "An artifact that cannot be injected
 * MUST fall back to `chrome_mode: api_only` for that build, surfaced as a
 * per-project warning naming the affected files."
 *
 * 🛑 The record and the warning are **different sets**, which is the whole
 * reason this class exists rather than a counter. Navigational stubs are
 * recorded and must not warn (§8.15.3, ADR 0002) — "or every Antora site warns
 * on every build forever and operators learn to ignore injection warnings". A
 * warning an operator has learned to ignore is worse than no warning, so the
 * exclusion is part of the control rather than a softening of it.
 */
final class InjectionCoverage
{
    /** How many sample filenames the warning carries. */
    private const MAX_SAMPLES = 10;

    private int $documents = 0;

    private int $injected = 0;

    /** @var array<string, int> outcome value => count */
    private array $byOutcome = [];

    /** @var list<string> paths that raise a warning */
    private array $warningSamples = [];

    /** @var list<string> paths recorded but deliberately not warned about */
    private array $stubSamples = [];

    public function record(string $path, InjectionOutcome $outcome): void
    {
        $this->documents++;
        $this->byOutcome[$outcome->value] = ($this->byOutcome[$outcome->value] ?? 0) + 1;

        if ($outcome === InjectionOutcome::Injected) {
            $this->injected++;

            return;
        }

        /*
         * Samples are capped. §8.15.3 asks for "samples", not a list — a build
         * whose generator emits ten thousand uninjectable files must produce a
         * warning somebody can read, and the count already carries the scale.
         */
        if ($outcome === InjectionOutcome::SkippedStub) {
            if (count($this->stubSamples) < self::MAX_SAMPLES) {
                $this->stubSamples[] = $path;
            }

            return;
        }

        if (count($this->warningSamples) < self::MAX_SAMPLES) {
            $this->warningSamples[] = $path;
        }
    }

    public function documents(): int
    {
        return $this->documents;
    }

    public function injected(): int
    {
        return $this->injected;
    }

    /**
     * Coverage as a percentage of documents, stubs included in the denominator.
     *
     * Stubs count as documents that were not injected, because they were not —
     * the number should not flatter itself. They simply do not *warn*. ADR 0002
     * reported "51 of 52 HTML files across all seven generators injected
     * (98.1%); **100% of content pages**", and both figures are worth being able
     * to state.
     */
    public function percentage(): float
    {
        return $this->documents === 0 ? 100.0 : ($this->injected / $this->documents) * 100.0;
    }

    /**
     * 🛑 §8.15.4: does this build fall back to `api_only`?
     *
     * One uninjectable document is enough. The fallback is per build, not per
     * file, because chrome is either present across a version or it is not —
     * a reader moving between pages must not find the version switcher
     * appearing and disappearing.
     */
    public function forcesApiOnly(): bool
    {
        return $this->warningSamples !== [] || ($this->byOutcome[InjectionOutcome::RefusedNoHead->value] ?? 0) > 0;
    }

    /** The `chrome_mode` this build actually serves under (§8.15.4, §8.15.7). */
    public function appliedChromeMode(string $projectMode): string
    {
        if ($projectMode !== 'injected') {
            // §8.15.7's `api_only` and `off` are the project's choice, and a
            // build does not override a choice somebody made deliberately.
            return $projectMode;
        }

        return $this->forcesApiOnly() ? 'api_only' : 'injected';
    }

    /**
     * The warning payload, or null when there is nothing to warn about.
     *
     * @return array{files: list<string>, injected: int, documents: int, outcomes: array<string, int>}|null
     */
    public function warning(): ?array
    {
        if ($this->warningSamples === []) {
            return null;
        }

        return [
            'files' => $this->warningSamples,
            'injected' => $this->injected,
            'documents' => $this->documents,
            'outcomes' => $this->byOutcome,
        ];
    }

    /**
     * The full record, including the stubs that do not warn.
     *
     * §8.15.3: stubs "stay in the audit record but must not raise a warning".
     * So they are here and absent from {@see self::warning()}.
     *
     * @return array{
     *     injector_version: int,
     *     documents: int,
     *     injected: int,
     *     percentage: float,
     *     outcomes: array<string, int>,
     *     warning_samples: list<string>,
     *     stub_samples: list<string>
     * }
     */
    public function toArray(): array
    {
        return [
            'injector_version' => ChromeInjector::VERSION,
            'documents' => $this->documents,
            'injected' => $this->injected,
            'percentage' => round($this->percentage(), 2),
            'outcomes' => $this->byOutcome,
            'warning_samples' => $this->warningSamples,
            'stub_samples' => $this->stubSamples,
        ];
    }
}
