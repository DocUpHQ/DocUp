<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

/**
 * 🛑 One URL claimed by two mounts (§8.7.14).
 *
 * > "Output path collisions MUST fail the build by default, naming **both**
 * > contributing sources and the exact path."
 *
 * All three are fields here, because a failure message that named only the
 * path would send an operator looking through every mounted repository for
 * the one that also emits it — and a message that named only the components
 * would not say what to delete.
 */
final readonly class PathCollision
{
    /**
     * @param  string  $url  relative to the version root, e.g. `guide/index.html`
     */
    public function __construct(
        public string $url,
        public ResolvedMount $shallower,
        public ResolvedMount $deeper,
    ) {}

    /**
     * The §8.7.14 message, with both sources and the exact path.
     *
     * Component **keys** rather than ids: the operator typed the keys and
     * will type them again to fix this, and a pair of UUIDs would make them
     * look both up to learn what they already know.
     */
    public function describe(): string
    {
        return $this->url
            .' is emitted by both '.$this->shallower->describe()
            .' and '.$this->deeper->describe();
    }

    /**
     * Whether a policy lets this collision through, and which mount wins.
     *
     * 🛑 §8.7.14 refuses a **tie** under `priority_wins`, and the refusal is
     * not pedantry: equal priorities mean the author believed they had
     * expressed an order and had not, so the composition they get would be
     * decided by row order. `first_wins` has no tie to refuse — it is
     * defined as "the lower `component_sources.priority` wins", and where
     * those are equal the deeper mount wins by §8.7.12's longest-prefix
     * match, which is the behaviour with or without this class.
     */
    public function winner(CollisionPolicy $policy): ?ResolvedMount
    {
        return match ($policy) {
            CollisionPolicy::Fail => null,
            CollisionPolicy::FirstWins => $this->shallower->priority <= $this->deeper->priority
                ? $this->shallower
                : $this->deeper,
            CollisionPolicy::PriorityWins => $this->shallower->priority === $this->deeper->priority
                ? null
                : ($this->shallower->priority < $this->deeper->priority ? $this->shallower : $this->deeper),
        };
    }
}
