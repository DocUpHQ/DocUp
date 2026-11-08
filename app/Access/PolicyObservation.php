<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * What §8.12.22's linter saw of one rule on one night.
 *
 * 🛑 `findings` and `changes` are kept apart, and {@see PolicyFinding} says
 * why: the first is a property of the policy as it stands and the second is a
 * property of the difference from last night. Only the second alerts. Merging
 * them would mean a deliberately-shadowed rule generating mail every night for
 * ever, which is how an operator learns to filter the linter.
 */
final readonly class PolicyObservation
{
    /**
     * @param  string  $ruleId  UUID text
     * @param  int  $position  §8.12.6's position, which under first-match-wins
     *                         is semantics rather than presentation
     * @param  string  $label  the operator's own words for the rule, carried so
     *                         an alert can name it as they wrote it. Empty on
     *                         an observation reconstructed from storage, which
     *                         is only ever compared and never reported.
     * @param  bool  $reachable  whether any URL and any instant could make this
     *                           rule decide a request
     * @param  int|null  $shadowedBy  the position of the earliest rule that
     *                                covers this one — 🛑 the *cause*, because
     *                                an operator told only "unreachable" has to
     *                                go and find which of their own edits did it
     * @param  list<PolicyFinding>  $findings  static, stored, fingerprinted
     * @param  array<string, mixed>  $breadth  what the rule admits, as facts
     *                                         comparable in a direction
     * @param  string  $fingerprint  raw 32 bytes; the change detector
     * @param  list<PolicyFinding>  $changes  since the last run, never stored
     */
    public function __construct(
        public string $ruleId,
        public int $position,
        public string $label,
        public bool $reachable,
        public ?int $shadowedBy,
        public array $findings,
        public array $breadth,
        public string $fingerprint,
        public array $changes,
    ) {}

    /** @param  list<PolicyFinding>  $changes */
    public function withChanges(array $changes): self
    {
        return new self(
            ruleId: $this->ruleId,
            position: $this->position,
            label: $this->label,
            reachable: $this->reachable,
            shadowedBy: $this->shadowedBy,
            findings: $this->findings,
            breadth: $this->breadth,
            fingerprint: $this->fingerprint,
            changes: $changes,
        );
    }

    /** Whether anything about this rule should reach an operator tonight. */
    public function alerts(): bool
    {
        foreach ($this->changes as $change) {
            if ($change->alerts()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether this rule is **broken** rather than merely changed — the
     * command's exit code, so monitoring notices without reading mail.
     */
    public function isFaulty(): bool
    {
        foreach ($this->findings as $finding) {
            if ($finding->isFault()) {
                return true;
            }
        }

        return false;
    }

    /** Whether access got wider, which is the direction §8.12.22 is really about. */
    public function widened(): bool
    {
        return in_array(PolicyFinding::Widened, $this->changes, true);
    }

    /**
     * One line for an operator, naming the rule as they wrote it.
     */
    public function summary(): string
    {
        $codes = array_map(
            static fn (PolicyFinding $finding): string => $finding->value,
            [...$this->changes, ...$this->findings],
        );

        $line = 'rule '.$this->position.' ('.($this->label === '' ? $this->ruleId : $this->label).'): '
            .($codes === [] ? 'unchanged' : implode(', ', array_unique($codes)));

        if ($this->shadowedBy !== null) {
            $line .= ' — covered by rule '.$this->shadowedBy;
        }

        return $line;
    }
}
