<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Models\IncomingWebhookDelivery;
use App\Webhooks\DeliveryLedger;
use Illuminate\Console\Command;

/**
 * `docup:webhooks:prune` — §20's 30-day retention on incoming deliveries.
 *
 * 🛑 This command is what bounds §8.19.3's weaker replay guarantee, and the
 * direction of the trade-off is worth stating where somebody tuning the
 * number will see it:
 *
 *   - A **longer** retention makes replay protection stronger and the table
 *     larger. §20 caps it at 90 days.
 *   - A **shorter** one makes the table smaller and the window in which a
 *     captured delivery can be replayed shorter to wait out. §20 floors it
 *     at 7 days, and the floor is the point: below it, "delivery-id
 *     uniqueness" stops being a replay defence and becomes a de-duplicator.
 *
 * See {@see DeliveryLedger} for what a successful replay
 * actually achieves, which is less than it sounds.
 */
final class PruneWebhookDeliveriesCommand extends Command
{
    protected $signature = 'docup:webhooks:prune
        {--dry-run : Report what would be removed without removing it}
        {--json : Machine-readable output}';

    protected $description = 'Remove incoming webhook deliveries past the SPEC 20 retention window';

    public function handle(OrganisationContext $context): int
    {
        $days = config('webhooks.delivery_retention_days');
        $days = is_int($days) ? $days : 30;

        /*
         * 🛑 Clamped to §20's stated range rather than trusted. An operator
         * who sets 1 has not disabled a cache, they have disabled a
         * security control — and the floor is in the specification
         * precisely so that it is not a matter of taste.
         */
        $days = max(7, min(90, $days));

        $cutoff = now()->subDays($days);

        // Installation-wide by declaration; retention spans every tenant and
        // §8.2.1's context throws rather than defaulting.
        $context->spanAllOrganisations();

        $query = IncomingWebhookDelivery::query()->where('received_at', '<', $cutoff);

        if ($this->option('dry-run') === true) {
            $count = $query->count();

            $this->line($this->option('json') === true
                ? (string) json_encode(['would_remove' => $count, 'retention_days' => $days], JSON_THROW_ON_ERROR)
                : sprintf('%d deliveries older than %d days', $count, $days));

            return self::SUCCESS;
        }

        /*
         * Chunked rather than one `DELETE`, because a busy installation's
         * thirty-first day can be hundreds of thousands of rows and a
         * single statement would hold a lock long enough for the webhook
         * endpoint — which INSERTs into this table on every delivery — to
         * start timing out. A retention sweep that makes the product
         * unavailable is worse than one that takes a minute.
         */
        $removed = 0;

        do {
            $batch = $query->limit(1000)->delete();
            $removed += $batch;
        } while ($batch > 0);

        $this->line($this->option('json') === true
            ? (string) json_encode(['removed' => $removed, 'retention_days' => $days], JSON_THROW_ON_ERROR)
            : sprintf('%d deliveries removed (retention %d days)', $removed, $days));

        return self::SUCCESS;
    }
}
