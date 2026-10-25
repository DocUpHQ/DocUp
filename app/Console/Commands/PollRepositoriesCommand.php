<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Auth\OrganisationContext;
use App\Builds\RepositoryFanout;
use App\Models\Repository;
use Illuminate\Console\Command;

/**
 * `docup:repositories:poll` — §8.5.3's `ls-remote` poll.
 *
 * The fallback for a repository whose webhook could not be provisioned
 * (§8.3.6's `manual_required`), and the only trigger an installation behind
 * a firewall the provider cannot reach ever gets.
 *
 * 🛑 **Provisioned repositories are not polled.** A poll beside a working
 * webhook doubles the ref advertisements against the provider for no new
 * information, and providers rate-limit — which would eventually cost the
 * repositories that have no other trigger the one trigger they do have.
 */
final class PollRepositoriesCommand extends Command
{
    protected $signature = 'docup:repositories:poll
        {--repository= : Poll one repository by id (hex), whatever its webhook state}
        {--json : Machine-readable output}';

    protected $description = 'Advertise refs for repositories with no working webhook (SPEC 8.5.3)';

    public function handle(OrganisationContext $context, RepositoryFanout $fanout): int
    {
        $context->spanAllOrganisations();

        $repositories = $this->candidates();

        $polled = 0;
        $triggered = 0;
        $failed = 0;

        foreach ($repositories as $repository) {
            /*
             * Scoped to the repository's own tenant for the duration of its
             * sync, because everything below — versions, rules, requests —
             * is organisation-scoped and a span-all context would write
             * rows with no tenant resolved.
             */
            $context->for($repository->organisation_id);

            try {
                $outcome = $fanout->poll($repository);
                $triggered += count($outcome->enqueued);
            } catch (\RuntimeException $failure) {
                /*
                 * 🛑 One unreachable provider must not stop the batch.
                 * §8.3.1 has five providers and an installation may have
                 * repositories on all of them; a loop that threw on the
                 * first timeout would never reach the rest, and the
                 * repositories it never reached are precisely the ones with
                 * no webhook.
                 */
                $this->warn('poll failed for '.bin2hex($repository->id).': '.$failure->getMessage());
                $failed++;
            }

            $repository->forceFill(['webhook_checked_at' => now()])->save();
            $polled++;

            $context->spanAllOrganisations();
        }

        if ($this->option('json') === true) {
            $this->line((string) json_encode([
                'polled' => $polled,
                'triggered' => $triggered,
                'failed' => $failed,
            ], JSON_THROW_ON_ERROR));

            return self::SUCCESS;
        }

        $this->info(sprintf('%d polled, %d triggered, %d failed', $polled, $triggered, $failed));

        return self::SUCCESS;
    }

    /**
     * Repositories worth polling this tick.
     *
     * 🛑 Oldest check first, and never-checked before that, so a batch
     * smaller than the number of eligible repositories still reaches every
     * one of them in rotation. Ordering by id instead would poll the same
     * fifty for ever and never touch the fifty-first.
     *
     * @return list<Repository>
     */
    private function candidates(): array
    {
        $one = $this->option('repository');

        if (is_string($one) && $one !== '') {
            $bytes = @hex2bin($one);
            $repository = $bytes === false ? null : Repository::query()->find($bytes);

            return $repository instanceof Repository ? [$repository] : [];
        }

        $batch = config('webhooks.polling.batch_size');

        /** @var list<Repository> $repositories */
        $repositories = array_values(
            Repository::query()
                ->where('state', 'active')
                ->whereIn('webhook_state', ['unprovisioned', 'manual_required', 'failed'])
                ->orderByRaw('webhook_checked_at IS NULL DESC')
                ->orderBy('webhook_checked_at')
                ->limit(is_int($batch) ? $batch : 50)
                ->get()
                ->all(),
        );

        return $repositories;
    }
}
