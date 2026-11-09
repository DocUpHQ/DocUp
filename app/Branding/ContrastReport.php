<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * The §8.14.5 verdict on one theme revision, in both schemes.
 *
 * 🛑 **Stored on the revision, not recomputed at publish time only.** §8.14.6
 * makes a revision previewable before it goes live, which means an operator
 * looks at the contrast report while the revision is still a draft — and
 * §8.14.5's override is "operator override audited", which needs a record of
 * what was overridden. A report that existed only inside the publish call
 * could be neither.
 */
final readonly class ContrastReport
{
    /**
     * @param  list<ContrastFinding>  $findings  every pair, in matrix order
     */
    public function __construct(public array $findings) {}

    /** 🛑 Whether §8.14.5 refuses publication: any pair below 3:1. */
    public function refuses(): bool
    {
        return $this->worst() === ContrastVerdict::Refuse;
    }

    /** Whether any pair is below its warning threshold. */
    public function warns(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->verdict === ContrastVerdict::Warn) {
                return true;
            }
        }

        return false;
    }

    /** The worst verdict across every pair. */
    public function worst(): ContrastVerdict
    {
        $worst = ContrastVerdict::Pass;

        foreach ($this->findings as $finding) {
            if ($finding->verdict === ContrastVerdict::Refuse) {
                return ContrastVerdict::Refuse;
            }

            if ($finding->verdict === ContrastVerdict::Warn) {
                $worst = ContrastVerdict::Warn;
            }
        }

        return $worst;
    }

    /** @return list<ContrastFinding> */
    public function refusals(): array
    {
        return $this->of(ContrastVerdict::Refuse);
    }

    /** @return list<ContrastFinding> */
    public function warnings(): array
    {
        return $this->of(ContrastVerdict::Warn);
    }

    /**
     * The report as JSON-storable data.
     *
     * The limits travel with the findings, because §8.14.5 requires the
     * honesty to be *stated* and a report an operator reads in the dashboard
     * is where they will read it.
     *
     * @return array{verdict: string, limits: list<string>, findings: list<array<string, string>>}
     */
    public function toArray(): array
    {
        return [
            'verdict' => $this->worst()->value,
            'limits' => ContrastMatrix::LIMITS,
            'findings' => array_map(
                static fn (ContrastFinding $finding): array => $finding->toArray(),
                $this->findings,
            ),
        ];
    }

    /**
     * @return list<ContrastFinding>
     */
    private function of(ContrastVerdict $verdict): array
    {
        return array_values(array_filter(
            $this->findings,
            static fn (ContrastFinding $finding): bool => $finding->verdict === $verdict,
        ));
    }
}
