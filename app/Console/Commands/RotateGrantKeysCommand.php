<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Models\GrantSigningKey;
use App\Readers\Grants\GrantKeys;
use Illuminate\Console\Command;

/**
 * `docup:readers:rotate` — advance §8.12.11's grant keypair by one state.
 *
 * 🛑 **One step per invocation, deliberately**, and §15's backup set is the
 * reason it is not a single "rotate now": "the Ed25519 grant keypair" is on the
 * list of things an operator must have backed up, and a command that published,
 * promoted and retired in one go would move the installation through three
 * states between two backups.
 *
 * So an operator runs it twice, with whatever interval their edge's JWKS cache
 * needs between the two:
 *
 *   1. the first call publishes a `pending` key — in the JWKS, signing nothing;
 *   2. the second promotes it and stands the previous key down to `retiring`.
 *
 * Retirement is the scheduler's, not this command's — see
 * {@see GrantKeys::retireExpired()} for why the time-based half is safe to
 * automate and the promotion is not.
 */
final class RotateGrantKeysCommand extends Command
{
    protected $signature = 'docup:readers:rotate
        {--status : Print the current key states and change nothing}';

    protected $description = 'Advance the Ed25519 grant signing key rotation by one state (SPEC 8.12.11)';

    public function handle(GrantKeys $keys): int
    {
        if ($this->option('status')) {
            return $this->status();
        }

        $moved = $keys->rotate();

        foreach ($moved as $change) {
            $this->line($change);
        }

        $this->newLine();
        $this->status();

        if (in_array('key_published', $moved, true)) {
            $this->newLine();
            $this->line(
                '  A pending key is now published. 🛑 Wait at least '
                .GrantKeys::JWKS_CACHE_SECONDS.'s — one JWKS cache window — before running this'
            );
            $this->line('  again, so every verifier holds the key before the first grant under it.');
        }

        return self::SUCCESS;
    }

    private function status(): int
    {
        $rows = GrantSigningKey::query()->orderBy('created_at')->get();

        if ($rows->isEmpty()) {
            $this->line('no grant signing keys yet; the first reader request creates one');

            return self::SUCCESS;
        }

        $this->table(
            ['kid', 'state', 'activated', 'retiring since', 'retired'],
            $rows->map(static fn (GrantSigningKey $key): array => [
                $key->kid,
                $key->state->value,
                $key->activated_at?->toDateTimeString() ?? '—',
                $key->retiring_at?->toDateTimeString() ?? '—',
                $key->retired_at?->toDateTimeString() ?? '—',
            ])->all(),
        );

        return self::SUCCESS;
    }
}
