<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Auth\OrganisationContext;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * The one place the serving path queries the database (§8.9.1).
 *
 * §8.9.1 requires the resolver to be pure and to take "a pre-loaded routing
 * snapshot". This is what pre-loads it — so every query the serving path makes
 * before authorisation is in this file, and the resolver's purity is a property
 * somebody can verify by reading one constructor.
 *
 * 🛑 The host is the **only** input. §8.9.4: "The project MUST be resolved
 * **solely** from the TLS server name or `Host` header plus the path. No request
 * header MUST act as a project, version or tenant selector, in any environment.
 * This is the GHSA-mp38-vprc-7hf5 class." A loader that accepted anything else
 * would make that requirement a convention rather than a shape.
 *
 * 🛑 **Queried across organisations, deliberately.** Hostname resolution is
 * where tenancy comes *from*, exactly as a bearer token is for the API, so it
 * cannot itself be tenant-scoped. The reader has supplied only a hostname and
 * learns only whether it serves documentation — which is observable from DNS
 * anyway.
 */
final class RoutingSnapshotLoader
{
    public function __construct(private readonly OrganisationContext $context) {}

    /**
     * Load the snapshot for a hostname, following §8.9.3's order.
     *
     * Returns a snapshot whose `servable` flag is false when the host is known
     * but may not serve, and an empty one when it is unknown — because §8.9.3
     * wants a hard 404 for the second case and §8.10.6 wants nothing served for
     * the first, and the two are different answers to different questions.
     */
    public function load(string $host): RoutingSnapshot
    {
        $normalised = HostMatcher::normalise($host);

        if ($normalised === null) {
            return RoutingSnapshot::empty($host, HostKind::Custom);
        }

        $candidates = HostMatcher::candidates(
            $normalised,
            self::apex(config('docup.origins.docs')),
            self::apex(config('docup.origins.preview')),
        );

        return $this->context->acrossAllOrganisations(function () use ($normalised, $candidates): RoutingSnapshot {
            /** @var list<object{id: string, kind: string, state: string, verified_at: string|null}> $rows */
            $rows = DB::table('domains')
                ->select('id', 'kind', 'state', 'verified_at')
                ->where('host', $normalised)
                ->get()
                ->all();

            if ($rows === []) {
                // §8.9.3's hard 404. Nothing on this installation answers here.
                return RoutingSnapshot::empty($normalised, HostKind::Custom);
            }

            foreach ($candidates as $candidate) {
                foreach ($rows as $row) {
                    if ($row->kind !== $candidate->kind->value) {
                        continue;
                    }

                    if (! self::isServable($row)) {
                        continue;
                    }

                    return new RoutingSnapshot(
                        host: $normalised,
                        kind: $candidate->kind,
                        servable: true,
                        mounts: $this->mountsFor($row->id),
                    );
                }
            }

            /*
             * A row exists and none of it may serve: unverified, or suspended.
             * §8.10.6 — "Suspended and unverified hosts MUST be neither served
             * nor certified" — so the host is known and answers nothing, which
             * is a different fact from "unknown" and is reported as one.
             */
            return new RoutingSnapshot(
                host: $normalised,
                kind: HostKind::tryFrom($rows[0]->kind) ?? HostKind::Custom,
                servable: false,
                mounts: [],
            );
        });
    }

    /**
     * Whether a `domains` row may serve a byte.
     *
     * 🛑 §8.10.4: "Proof of domain control MUST precede any certificate issuance
     * or **any byte served for a custom hostname**." A default subdomain and a
     * preview host sit under an apex the installation itself controls, so there
     * is nothing to prove and nothing to wait for — but a custom or apex domain
     * serves nothing until `verified_at` is set, whatever its state column says.
     *
     * Both conditions, not either: a verified row that was later suspended must
     * also stop serving, which is the second half of §8.10.6's state machine.
     *
     * @param  object{kind: string, state: string, verified_at: string|null}  $row
     */
    private static function isServable(object $row): bool
    {
        return self::canServe($row->kind, $row->state, $row->verified_at);
    }

    /**
     * The same question, for a caller holding columns rather than a row.
     *
     * 🛑 Public so {@see CanonicalLocations} can ask it. §8.11.6's `hreflang`
     * alternates and §8.11.9's canonical link both name a host this loader
     * may never be asked about — they are the one case where the canonical
     * mount is somewhere else — and a second copy of §8.10.6's predicate is
     * how one of them starts publishing a host the other refuses to serve.
     */
    public static function canServe(string $kind, string $state, ?string $verifiedAt): bool
    {
        if ($state === 'suspended') {
            return false;
        }

        $needsProof = in_array($kind, ['custom', 'apex'], true);

        if ($needsProof && $verifiedAt === null) {
            return false;
        }

        // `pending` is pre-proof. An installation-owned host may serve while
        // pending, because its proof is ownership of the apex.
        return ! ($needsProof && $state === 'pending');
    }

    /**
     * Every mount on a domain, with its project and that project's versions.
     *
     * Three queries rather than one join, and deliberately: a join across
     * mounts, projects and versions multiplies rows by the version count, so a
     * project with four hundred versions would return four hundred copies of
     * its own row for every mount. Three indexed queries are both less data and
     * easier to read.
     *
     * @param  string  $domainId  raw 16 bytes
     * @return list<SnapshotMount>
     */
    private function mountsFor(string $domainId): array
    {
        /*
         * Columns named explicitly rather than `select *`, so the shape
         * annotation below is a claim about what this query returns rather than
         * about what the table happens to contain. A column added to
         * `domain_mounts` by a later phase then does not silently widen what
         * the serving path reads.
         *
         * @var list<object{
         *     id: string,
         *     project_id: string,
         *     path_prefix: string,
         *     mode: string,
         *     mount_exposure: string,
         *     is_indexable: int,
         *     versioning_scheme_override: string|null,
         *     version_scope: string|null
         * }> $mountRows
         */
        $mountRows = DB::table('domain_mounts')
            ->select([
                'id',
                'project_id',
                'path_prefix',
                'mode',
                'mount_exposure',
                'is_indexable',
                'versioning_scheme_override',
                'version_scope',
            ])
            ->where('domain_id', $domainId)
            ->orderBy('position')
            ->get()
            ->all();

        if ($mountRows === []) {
            return [];
        }

        $projectIds = array_values(array_unique(array_map(
            static fn (object $row): string => (string) $row->project_id,
            $mountRows,
        )));

        /**
         * @var array<string, object{
         *     id: string,
         *     slug: string,
         *     url_prefix: string|null,
         *     versioning_scheme: string,
         *     routing_epoch: int,
         *     visibility: string,
         *     chrome_mode: string,
         *     default_version_id: string|null
         * }> $projects
         */
        $projects = DB::table('projects')
            ->select([
                'id',
                'slug',
                'url_prefix',
                'versioning_scheme',
                'routing_epoch',
                'visibility',
                'chrome_mode',
                'default_version_id',
            ])
            ->whereIn('id', $projectIds)
            ->whereNull('deleted_at')
            ->get()
            ->keyBy(static fn (object $row): string => (string) $row->id)
            ->all();

        /** @var array<string, list<SnapshotVersion>> $versions */
        $versions = [];

        /**
         * @var list<object{
         *     id: string,
         *     project_id: string,
         *     slug: string,
         *     language: string,
         *     active: int,
         *     listed: int,
         *     published: int,
         *     visibility: string,
         *     published_manifest_id: string|null,
         *     previous_manifest_id: string|null,
         *     soft_landing_until: string|null,
         *     translation_group_id: string|null
         * }> $versionRows
         */
        $versionRows = DB::table('project_versions')
            ->select([
                'id',
                'project_id',
                'slug',
                'language',
                'active',
                'listed',
                'published',
                'visibility',
                'published_manifest_id',
                'previous_manifest_id',
                'soft_landing_until',
                // §8.6.12's group, loaded with the version rather than
                // queried when a switcher asks: §8.9.1 wants resolution with
                // no database queries, and the language switcher is rendered
                // from the same snapshot the document was resolved against.
                'translation_group_id',
            ])
            ->whereIn('project_id', $projectIds)
            ->whereNull('deleted_at')
            ->get()
            ->all();

        /*
         * §8.6.6's 301 table, loaded with the versions rather than looked
         * up on a miss. §8.9.1 requires resolution with no queries, and a
         * history lookup only on a 404 would put a query behind every probe
         * for a path that does not exist — which §8.11.8 says attackers send
         * in volume.
         *
         * @var array<string, array<string, string>> $formerSlugs
         */
        $formerSlugs = [];

        foreach (
            DB::table('project_version_slug_history')
                ->select(['project_id', 'language', 'slug', 'project_version_id'])
                ->whereIn('project_id', $projectIds)
                ->get() as $historyRow
        ) {
            $formerSlugs[(string) $historyRow->project_id][
                (string) $historyRow->language.':'.(string) $historyRow->slug
            ] = (string) $historyRow->project_version_id;
        }

        foreach ($versionRows as $row) {
            $versions[(string) $row->project_id][] = new SnapshotVersion(
                id: (string) $row->id,
                slug: (string) $row->slug,
                language: (string) $row->language,
                active: (bool) $row->active,
                listed: (bool) $row->listed,
                published: (bool) $row->published,
                visibility: (string) $row->visibility,
                publishedManifestId: $row->published_manifest_id === null
                    ? null
                    : (string) $row->published_manifest_id,
                previousManifestId: $row->previous_manifest_id === null
                    ? null
                    : (string) $row->previous_manifest_id,
                softLandingExpiresAt: $row->soft_landing_until === null
                    ? null
                    : (strtotime((string) $row->soft_landing_until) ?: null),
                translationGroupId: $row->translation_group_id === null
                    ? null
                    : (string) $row->translation_group_id,
            );
        }

        $mounts = [];

        foreach ($mountRows as $row) {
            $projectId = (string) $row->project_id;
            $project = $projects[$projectId] ?? null;

            if ($project === null) {
                // A soft-deleted project. Its mounts serve nothing rather than
                // 500ing, which is the right answer during the §8.22.6 recovery
                // window: the rows are still there and the content is not.
                continue;
            }

            $mounts[] = new SnapshotMount(
                id: (string) $row->id,
                pathPrefix: (string) $row->path_prefix,
                mode: (string) $row->mode,
                mountExposure: (string) $row->mount_exposure,
                isIndexable: (bool) $row->is_indexable,
                project: new SnapshotProject(
                    id: $projectId,
                    slug: (string) $project->slug,
                    urlPrefix: $project->url_prefix === null ? null : (string) $project->url_prefix,
                    versioningScheme: (string) $project->versioning_scheme,
                    routingEpoch: (int) $project->routing_epoch,
                    visibility: (string) $project->visibility,
                    chromeMode: (string) $project->chrome_mode,
                    defaultVersionId: $project->default_version_id === null
                        ? null
                        : (string) $project->default_version_id,
                    versions: $versions[$projectId] ?? [],
                    formerSlugs: $formerSlugs[$projectId] ?? [],
                ),
                versioningSchemeOverride: $row->versioning_scheme_override === null
                    ? null
                    : (string) $row->versioning_scheme_override,
                versionScope: self::decodeScope($row->version_scope),
            );
        }

        return $mounts;
    }

    /**
     * §10.5's `version_scope`, as a list of slugs or null for every version.
     *
     * Malformed JSON resolves to null — "every version" — rather than to an
     * empty allowlist. The alternative fails closed and would be defensible,
     * but it would take a project offline because of a bad write to a
     * presentation column, and §10.5 makes null the documented "no restriction"
     * value. A scope that must restrict is Phase 18's to validate at write time.
     *
     * @return list<string>|null
     */
    private static function decodeScope(mixed $raw): ?array
    {
        if (! is_string($raw) || $raw === '') {
            return null;
        }

        $decoded = json_decode($raw, true);

        if (! is_array($decoded)) {
            return null;
        }

        $slugs = array_values(array_filter($decoded, 'is_string'));

        return $slugs === [] ? null : $slugs;
    }

    /**
     * The apex, from an origin that may carry a scheme.
     *
     * `DOCUP_DOCS_APEX` is documented as a bare hostname, but §8.1.4's boot
     * assertion accepts a URL too, and a loader that silently failed to match
     * because the configured value had `https://` on it would be a
     * misconfiguration with no symptom other than every host 404ing.
     */
    private static function apex(mixed $origin): ?string
    {
        if (! is_string($origin) || $origin === '') {
            return null;
        }

        $host = parse_url($origin, PHP_URL_HOST);

        return is_string($host) ? $host : $origin;
    }

    /**
     * The cache key for a host's snapshot.
     *
     * Not used by {@see self::load()} itself: caching is the caller's decision,
     * because §8.9.10 keys the **resolution** cache on the project's
     * `routing_epoch` and the epoch is inside the snapshot being loaded. A
     * snapshot cached under a key derived from its own contents could never be
     * invalidated, so the snapshot cache is short-lived and the resolution
     * cache is the epoch-keyed one.
     */
    public static function cacheKey(string $host): string
    {
        return 'routing:host:'.hash('sha256', $host);
    }

    /** Raw key bytes as canonical text, for a log line or a header. */
    public static function identify(string $rawId): string
    {
        return Uuid::toText($rawId);
    }
}
