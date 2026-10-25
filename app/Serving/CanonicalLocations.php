<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Auth\OrganisationContext;
use App\Support\Uuid;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

/**
 * Loads a project's canonical mount (§8.10.3), cached per routing epoch.
 *
 * 🛑 **Not part of the routing snapshot, and deliberately.** A snapshot is one
 * host's (§8.9.1), and the canonical mount of a project served here may be on
 * a different host entirely — that is the case §8.11.9 exists for. Folding it
 * into the snapshot would make every host's snapshot carry rows about hosts it
 * does not serve, and would grow with the installation rather than with the
 * host.
 *
 * 🛑 **Keyed on `routing_epoch`.** §8.9.10 makes the epoch part of the
 * resolution cache key precisely so a mount change invalidates by bumping a
 * number rather than by hunting cache entries, and the canonical mount is a
 * `domain_mounts` row like any other. An entry for an epoch that has moved is
 * never read again, so nothing has to delete it.
 */
final class CanonicalLocations
{
    public function __construct(private readonly OrganisationContext $context) {}

    /**
     * The canonical location of a project, or null when it has no canonical
     * mount or that mount's domain cannot serve.
     *
     * Null is a real answer and the callers treat it as one: §8.11.6's
     * alternates and §8.11.9's canonical link are both **omitted** rather
     * than guessed at. A project whose canonical mount was deleted has no
     * canonical URL, and inventing one from the serving host would publish
     * the alias as the original.
     *
     * @param  string  $projectId  raw 16 bytes
     */
    public function for(string $projectId, int $routingEpoch): ?CanonicalLocation
    {
        /** @var array{origin: string, path_prefix: string}|null $location */
        $location = Cache::remember(
            'serving:canonical:'.Uuid::toText($projectId).':'.$routingEpoch,
            now()->addHour(),
            fn (): ?array => $this->load($projectId),
        );

        return $location === null
            ? null
            : new CanonicalLocation($location['origin'], $location['path_prefix']);
    }

    /**
     * @return array{origin: string, path_prefix: string}|null
     */
    private function load(string $projectId): ?array
    {
        return $this->context->acrossAllOrganisations(function () use ($projectId): ?array {
            /** @var object{path_prefix: string, host: string, kind: string, state: string, verified_at: string|null}|null $row */
            $row = DB::table('domain_mounts')
                ->join('domains', 'domains.id', '=', 'domain_mounts.domain_id')
                ->where('domain_mounts.project_id', $projectId)
                ->where('domain_mounts.mode', 'canonical')
                ->select([
                    'domain_mounts.path_prefix',
                    'domains.host',
                    'domains.kind',
                    'domains.state',
                    'domains.verified_at',
                ])
                ->first();

            if ($row === null) {
                return null;
            }

            /*
             * 🛑 §8.10.6: "Suspended and unverified hosts MUST be neither
             * served nor certified." An alternate or a canonical link
             * pointing at a host that serves nothing is a dead annotation
             * published to a crawler — the rule is the loader's as much as
             * the resolver's, so the same predicate answers for both.
             */
            if (! RoutingSnapshotLoader::canServe($row->kind, $row->state, $row->verified_at)) {
                return null;
            }

            return [
                // Always https. §8.10.5 makes TLS automatic and mandatory for
                // every serving host, so there is no http canonical URL to
                // emit and a scheme read from the request would let a
                // misconfigured proxy publish one.
                'origin' => 'https://'.$row->host,
                'path_prefix' => (string) $row->path_prefix,
            ];
        });
    }
}
