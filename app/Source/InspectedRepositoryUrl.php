<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * A repository URL that has passed both halves of §8.3.4: its shape, and where
 * its host actually points.
 *
 * The pinned address travels with it so that Phase 06's fetcher connects to
 * the address this inspection validated rather than resolving the name a
 * second time.
 */
final readonly class InspectedRepositoryUrl
{
    /** @param  list<string>  $addresses */
    public function __construct(
        public RepositoryUrl $url,
        public string $pinnedAddress,
        public array $addresses,
        public Provider $provider,
    ) {}
}
