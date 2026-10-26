<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Audit\CanonicalJson;
use App\Models\DomainEvent;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * Writes §10.5's hash-chained `domain_events`.
 *
 * 🛑 **One call site, so the chain cannot be written around.** A chain whose
 * rows some code paths append and others insert directly is a chain with
 * gaps, and a gap is indistinguishable from a deletion — which is the single
 * thing the chain exists to detect.
 *
 * The digest covers the previous digest, the organisation, the hostname, the
 * event and its payload, canonically encoded. It deliberately does **not**
 * cover the row's id: the id is UUIDv7 and therefore time-ordered, so
 * including it would make the chain re-derivable only in insertion order,
 * which is already how it is read.
 */
final readonly class DomainLedger
{
    /**
     * Append one event.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  string|null  $domainId  raw 16 bytes, or null for a released host
     * @param  array<string, mixed>  $payload
     */
    public function record(
        string $organisationId,
        ?string $domainId,
        string $host,
        string $event,
        array $payload = [],
    ): DomainEvent {
        return DB::transaction(function () use ($organisationId, $domainId, $host, $event, $payload): DomainEvent {
            /*
             * 🛑 Locked, because two concurrent writes reading the same tail
             * would both chain onto it and the second would orphan the first.
             * The lock is per organisation, which is the chain's own scope.
             */
            $previous = DomainEvent::query()
                ->where('organisation_id', $organisationId)
                ->orderByDesc('occurred_at')
                ->orderByDesc('id')
                ->lockForUpdate()
                ->first();

            $previousDigest = $previous?->digest;

            /*
             * 🛑 Formatted ONCE, to the column's own precision, and the same
             * string is both digested and stored. Digesting a Carbon and
             * letting MySQL coerce it into `datetime(3)` does not round-trip:
             * the column rounds to the millisecond where PHP truncates, so a
             * timestamp ending `.0005` would be stored one millisecond away
             * from the value the digest covered — and the chain would verify
             * until the first row that happened to land there.
             */
            $now = now();
            $occurredAt = $now->format('Y-m-d H:i:s.v');

            $digest = hash(
                'sha256',
                ($previousDigest === null ? '' : bin2hex($previousDigest))
                    .CanonicalJson::encode([
                        'organisation' => Uuid::toText($organisationId),
                        'host' => $host,
                        'event' => $event,
                        'payload' => $payload,
                        /*
                         * 🛑 The column's own format, to the millisecond.
                         * `datetime(3)` is what the row will hold, so a
                         * digest taken over a richer representation would
                         * never reproduce on read — the chain would verify
                         * only until the first restart.
                         */
                        'occurred_at' => $occurredAt,
                    ]),
                true,
            );

            $row = new DomainEvent;

            $row->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisationId,
                'domain_id' => $domainId,
                'host' => $host,
                'event' => $event,
                'payload' => $payload === [] ? null : $payload,
                'digest' => $digest,
                'previous_digest' => $previousDigest,
                'occurred_at' => $occurredAt,
            ])->save();

            return $row;
        });
    }

    /**
     * Whether an organisation's chain is intact.
     *
     * 🛑 Recomputed rather than compared pairwise. Checking only that each
     * row's `previous_digest` equals the one before it would pass on a chain
     * whose payloads had all been rewritten consistently — the digests have
     * to be re-derived from the content for the check to mean anything.
     *
     * @param  string  $organisationId  raw 16 bytes
     */
    public function verify(string $organisationId): bool
    {
        $previousDigest = null;

        foreach (
            DomainEvent::query()
                ->where('organisation_id', $organisationId)
                ->orderBy('occurred_at')
                ->orderBy('id')
                ->cursor() as $row
        ) {
            $expected = hash(
                'sha256',
                ($previousDigest === null ? '' : bin2hex($previousDigest))
                    .CanonicalJson::encode([
                        'organisation' => Uuid::toText($organisationId),
                        'host' => $row->host,
                        'event' => $row->event,
                        'payload' => $row->payload ?? [],
                        'occurred_at' => $row->occurred_at?->format('Y-m-d H:i:s.v'),
                    ]),
                true,
            );

            if ($row->digest !== $expected || $row->previous_digest !== $previousDigest) {
                return false;
            }

            $previousDigest = $row->digest;
        }

        return true;
    }
}
