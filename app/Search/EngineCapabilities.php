<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * §8.16.12's capability matrix for one driver.
 *
 * 🛑 Absence is **documented**, not implied. A capability this driver lacks is
 * present here with `false` and a note saying what happens instead, because
 * §8.16.12's requirement is that the degradation be stated: a reader whose typo
 * returns nothing needs the product to have told them it would.
 */
final readonly class EngineCapabilities
{
    /**
     * @param  array<string, bool>  $supported  keyed by {@see EngineCapability}
     *                                          value
     * @param  array<string, string>  $notes  what happens when it is absent,
     *                                        keyed the same way
     */
    private function __construct(
        public SearchDriver $driver,
        private array $supported,
        private array $notes,
    ) {}

    /**
     * Build a matrix, defaulting every unlisted capability to **unsupported**.
     *
     * 🛑 The default direction matters. A new capability added to the enum must
     * appear as absent in every existing driver until somebody implements it —
     * the alternative is a matrix that claims a feature nobody wrote, which is
     * worse than one that under-claims, because a team chooses an engine from
     * this table.
     *
     * @param  array<string, bool>  $supported
     * @param  array<string, string>  $notes
     */
    public static function of(SearchDriver $driver, array $supported, array $notes = []): self
    {
        return new self($driver, $supported, $notes);
    }

    public function supports(EngineCapability $capability): bool
    {
        return $this->supported[$capability->value] ?? false;
    }

    /** What happens instead, when it is absent. */
    public function note(EngineCapability $capability): string
    {
        return $this->notes[$capability->value] ?? '';
    }

    /**
     * The whole matrix, every capability, in enum order.
     *
     * @return list<array{capability: string, label: string, supported: bool, required: bool, note: string}>
     */
    public function rows(): array
    {
        $rows = [];

        foreach (EngineCapability::cases() as $capability) {
            $rows[] = [
                'capability' => $capability->value,
                'label' => $capability->label(),
                'supported' => $this->supports($capability),
                'required' => $capability->isRequiredOfEveryDriver(),
                'note' => $this->note($capability),
            ];
        }

        return $rows;
    }
}
