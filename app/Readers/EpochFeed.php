<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Auth\OrganisationContext;
use App\Readers\Grants\Grant;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §20.2's `/.well-known/docup-epochs` — §8.12.13's Tier C condition, as the
 * document rather than the endpoint.
 *
 * > "**Tier C (optional):** edge-local token verification. 🛑 **Mandatory
 * > condition:** the edge MUST consume a revocation epoch feed at ≤5-second
 * > intervals and refuse any grant below the current epoch. `docup:doctor` MUST
 * > refuse Tier C without it. Without that feed, a project flipped
 * > public→private keeps serving to anonymous readers for the grant lifetime —
 * > the largest exposure window any design in this area produces."
 *
 * 🛑 **Not in the controller**, and the architecture preset is what moved it
 * here: `docup:doctor` has to know the interval to refuse Tier C without it, and
 * a console command depending on an HTTP controller is a transport concern
 * leaking into an operational one. The interval is now a fact about the feed,
 * stated once, read by the endpoint that publishes it and the check that
 * enforces it.
 */
final readonly class EpochFeed
{
    /**
     * 🛑 §8.12.13's "≤5-second intervals", published so the edge does not have
     * to be configured with it separately.
     *
     * A number the consumer reads rather than one two configurations have to
     * agree on. `docup:doctor` checks that the operator's declared poll is at
     * or below it, because the interval **is** the exposure window after a
     * visibility change.
     */
    public const int INTERVAL_SECONDS = 5;

    public function __construct(private OrganisationContext $context) {}

    /**
     * Every project's combined epoch, as the edge reads it.
     *
     * @return array{claim: string, interval: int, generated_at: int, projects: array<string, int>}
     */
    public function document(?int $now = null): array
    {
        /*
         * 🛑 Across every organisation, because the edge serves all of them and
         * has no tenant. This is the one read in the product where spanning
         * tenancy is the requirement rather than a compromise — and it is safe
         * precisely because {@see \App\Http\Controllers\Readers\EpochFeedController}
         * is loopback-only.
         */
        $rows = $this->context->acrossAllOrganisations(
            static fn (): array => DB::table('projects')
                ->whereNull('deleted_at')
                ->get(['id', 'authz_epoch', 'identity_epoch'])
                ->all(),
        );

        $projects = [];

        foreach ($rows as $row) {
            if (! is_string($row->id ?? null)) {
                continue;
            }

            $projects[Uuid::toText($row->id)] = Grant::combinedEpoch(
                // 🛑 `is_numeric` then cast, never `is_int` — Phase 20's finding.
                is_numeric($row->authz_epoch ?? null) ? (int) $row->authz_epoch : 0,
                is_numeric($row->identity_epoch ?? null) ? (int) $row->identity_epoch : 0,
            );
        }

        return [
            /*
             * 🛑 The claim name matches the grant's, so an edge comparing the
             * two is comparing like with like. {@see Grant::combinedEpoch()}
             * explains why one scalar is correct and orderable.
             */
            'claim' => 'ep',
            'interval' => self::INTERVAL_SECONDS,
            'generated_at' => $now ?? time(),
            'projects' => $projects,
        ];
    }
}
