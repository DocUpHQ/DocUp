<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Auth\OrganisationContext;
use App\Models\Domain;
use App\Models\DomainClaim;
use App\Models\DomainMount;
use App\Models\DomainTombstone;
use App\Models\Project;
use App\Support\Invalidation;
use App\Support\Uuid;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Support\Facades\DB;

/**
 * The write side of §8.10's domains: claim, prove, serve, release, reclaim.
 *
 * 🛑 **Every refusal here is about one organisation serving another's
 * hostname**, which is why none of them is a warning. §8.10.4 puts proof
 * before "any byte served for a custom hostname"; §8.10.5 keeps a squatter's
 * pending row from blocking the owner; §8.10.9's tombstone keeps a dangling
 * CNAME from becoming a takeover. Those are three faces of one threat and
 * they are enforced in one place.
 *
 * 🛑 **The unique indexes are the arbiter and the checks are the message.**
 * Two organisations proving one hostname in the same second both pass the
 * read and one loses on the write; the violation is re-reported as the same
 * identifier, so a caller sees one answer whichever way it was caught.
 */
final readonly class Domains
{
    public function __construct(
        private DomainLedger $ledger = new DomainLedger,
        private ?OrganisationContext $context = null,
    ) {}

    /**
     * Add a hostname to an organisation, unproven.
     *
     * 🛑 Unproven on purpose. §8.10.4 forbids serving a byte before proof,
     * and a flow that verified during creation would have to either block on
     * DNS propagation or fail — so the row exists first, the operator
     * publishes the record, and {@see self::verify()} is a separate act.
     *
     * @param  string  $organisationId  raw 16 bytes
     *
     * @throws DomainRefused
     */
    public function add(string $organisationId, string $host, string $kind = 'custom'): Domain
    {
        $normalised = Hostname::normalise($host);

        $this->assertNotReserved($normalised);
        $this->assertClaimable($organisationId, $normalised);

        $domain = new Domain;

        $domain->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $organisationId,
            'host' => $normalised,
            'kind' => $kind === 'custom' && Hostname::looksLikeApex($normalised) ? 'apex' : $kind,
            'state' => 'pending',
            'verification_token' => Challenge::token(),
        ])->save();

        $this->ledger->record($organisationId, $domain->id, $normalised, 'claimed', ['kind' => $domain->kind]);

        return $domain;
    }

    /**
     * Run §8.10.4's proofs and, on success, make the host servable.
     *
     * @throws DomainRefused when the proof is absent or the resolvers disagreed
     */
    public function verify(Domain $domain, DomainVerifier $verifier): Domain
    {
        $result = $verifier->check($domain);

        if (! $result->passed) {
            throw DomainRefused::of(match ($result->outcome) {
                Outcome::Disagreed => DomainRejection::ResolversDisagreed,
                default => DomainRejection::ProofMissing,
            }, $result->detail);
        }

        // Re-checked at the moment of proof, not only at creation: a
        // competing organisation may have proven the same host in between,
        // and the index below is what actually decides it.
        $this->assertClaimable($domain->organisation_id, $domain->host, $domain->id);

        try {
            $domain->forceFill([
                'state' => 'active',
                'verification_method' => $result->method->value,
                'verified_at' => now(),
                'last_checked_at' => now(),
                'check_failures' => 0,
                'failing_since' => null,
                'suspended_at' => null,
                'next_check_at' => now()->addDay(),
            ])->save();
        } catch (UniqueConstraintViolationException) {
            // 🛑 §8.10.5's index got there first: another organisation proved
            // this hostname between the check above and this write.
            throw DomainRefused::of(DomainRejection::HostClaimed, $domain->host);
        }

        $this->ledger->record($domain->organisation_id, $domain->id, $domain->host, 'verified', [
            'method' => $result->method->value,
        ]);

        $this->ledger->record($domain->organisation_id, $domain->id, $domain->host, 'activated');

        $this->bumpRouting($domain);

        return $domain;
    }

    /**
     * 🛑 §8.10.9: release a hostname into a 90-day tombstone.
     *
     * The domain row goes; the tombstone stays, naming the organisation that
     * may reclaim. Deleting the domain without the tombstone is the
     * cross-tenant takeover the requirement describes — the CNAME outlives
     * the row, and without a tombstone anybody may claim what it points at.
     */
    public function release(Domain $domain): DomainTombstone
    {
        return DB::transaction(function () use ($domain): DomainTombstone {
            $organisationId = $domain->organisation_id;
            $host = $domain->host;

            /*
             * A lapsed tombstone for the same host is deleted first. The
             * unique index is on `host` alone — see the migration for why —
             * so a host released, left to lapse and released again would
             * otherwise collide with its own expired row.
             */
            $this->acrossTenants(function () use ($host): void {
                DomainTombstone::query()
                    ->where('host', $host)
                    ->where('expires_at', '<=', now())
                    ->delete();
            });

            $tombstone = new DomainTombstone;

            $tombstone->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisationId,
                'host' => $host,
                'released_at' => now(),
                'expires_at' => now()->addDays(DomainTombstone::DAYS),
            ])->save();

            $this->ledger->record($organisationId, null, $host, 'released', [
                'expires_at' => $tombstone->expires_at?->toIso8601String(),
            ]);

            $this->bumpRouting($domain);

            $domain->delete();

            return $tombstone;
        });
    }

    /**
     * 🛑 §8.10.9: reclaim a tombstoned hostname — the previous owner only,
     * and "always with a freshly issued token".
     *
     * The fresh token is not ceremony. The old token was published in public
     * DNS for as long as the domain existed, so anybody who looked it up
     * once could still produce it; reusing it would let a passer-by prove
     * control of a hostname they merely watched.
     *
     * @param  string  $organisationId  raw 16 bytes
     *
     * @throws DomainRefused
     */
    public function reclaim(string $organisationId, string $host): Domain
    {
        $normalised = Hostname::normalise($host);

        $tombstone = $this->liveTombstone($normalised);

        if ($tombstone instanceof DomainTombstone && $tombstone->organisation_id !== $organisationId) {
            throw DomainRefused::of(DomainRejection::Tombstoned, $normalised);
        }

        $domain = $this->add($organisationId, $normalised);

        if ($tombstone instanceof DomainTombstone) {
            $this->acrossTenants(static fn () => $tombstone->delete());

            $this->ledger->record($organisationId, $domain->id, $normalised, 'reclaimed');
        }

        return $domain;
    }

    /**
     * Prove an organisation-level parent claim (§8.10.4).
     *
     * @param  string  $organisationId  raw 16 bytes
     *
     * @throws DomainRefused
     */
    public function claimParent(string $organisationId, string $apex): DomainClaim
    {
        $normalised = Hostname::normalise($apex);

        $this->assertNotReserved($normalised);

        $claim = new DomainClaim;

        $claim->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $organisationId,
            'apex' => $normalised,
            'token' => Challenge::token(),
            'state' => 'pending',
        ])->save();

        return $claim;
    }

    /**
     * @throws DomainRefused when the apex's TXT record is absent, or another
     *                       organisation proved it first
     */
    public function verifyParent(DomainClaim $claim, DomainVerifier $verifier): DomainClaim
    {
        if (! $verifier->checkClaim($claim)) {
            throw DomainRefused::of(DomainRejection::ProofMissing, Challenge::txtName($claim->apex));
        }

        try {
            $claim->forceFill([
                'state' => 'verified',
                'verified_at' => now(),
                'last_checked_at' => now(),
            ])->save();
        } catch (UniqueConstraintViolationException) {
            throw DomainRefused::of(DomainRejection::ParentClaimed, $claim->apex);
        }

        return $claim;
    }

    /**
     * 🛑 §8.10.2: the first mount of a project is canonical, every later one
     * serves.
     *
     * > "For every subsequent verified domain, `mode` MUST default to
     * > **`serve`**: every verified domain answers 200, with an automatic
     * > `rel=canonical` to the project's canonical mount. Read the Docs'
     * > canonical-plus-301 behaviour is rejected as the default because it
     * > makes mandatory requirement G6 decorative."
     *
     * @throws DomainRefused
     */
    public function mount(Domain $domain, Project $project, string $pathPrefix = '', string $exposure = 'inherit'): DomainMount
    {
        $hasCanonical = DomainMount::query()
            ->where('project_id', $project->id)
            ->where('mode', 'canonical')
            ->exists();

        $mount = new DomainMount;

        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $domain->organisation_id,
            'domain_id' => $domain->id,
            'project_id' => $project->id,
            'path_prefix' => $pathPrefix,
            'mode' => $hasCanonical ? 'serve' : 'canonical',
            'mount_exposure' => $exposure,
            'position' => 0,
        ]);

        try {
            $mount->save();
        } catch (UniqueConstraintViolationException $collision) {
            throw DomainRefused::of(
                str_contains($collision->getMessage(), 'canonical')
                    ? DomainRejection::CanonicalMountExists
                    : DomainRejection::SharedOriginCrossTenant,
                'refused by the database index',
            );
        }

        // 🛑 §8.10.20's derived flag and its restrictions, every time the
        // mount set of a hostname changes.
        SharedOrigin::reconcile($domain);

        $this->bumpRouting($domain);

        return $mount;
    }

    /**
     * 🛑 §8.10.4 and §8.10.5, before a row is written.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  string|null  $exceptDomainId  raw 16 bytes; the row being verified
     *
     * @throws DomainRefused
     */
    private function assertClaimable(string $organisationId, string $host, ?string $exceptDomainId = null): void
    {
        $this->acrossTenants(function () use ($organisationId, $host, $exceptDomainId): void {
            /*
             * 🛑 Only PROVEN rows block, which is §8.10.5's whole point: "An
             * unconditional unique index lets a squatter's pending row block
             * the legitimate owner." A pending row belonging to anybody is
             * invisible here, and the generated column makes that structural
             * rather than a matter of this query being written correctly.
             */
            $proven = Domain::query()
                ->whereNotNull('claimed_host')
                ->where('host', $host)
                ->when($exceptDomainId !== null, static fn ($query) => $query->whereKeyNot($exceptDomainId))
                ->first();

            if ($proven instanceof Domain && $proven->organisation_id !== $organisationId) {
                throw DomainRefused::of(DomainRejection::HostClaimed, $host);
            }

            $apexes = Hostname::parentApexes($host);

            if ($apexes !== []) {
                $parent = DomainClaim::query()
                    ->whereNotNull('active_apex')
                    ->whereIn('apex', $apexes)
                    ->where('organisation_id', '!=', $organisationId)
                    ->first();

                if ($parent instanceof DomainClaim) {
                    throw DomainRefused::of(DomainRejection::ParentClaimed, $parent->apex);
                }
            }

            $tombstone = $this->liveTombstone($host);

            if ($tombstone instanceof DomainTombstone && $tombstone->organisation_id !== $organisationId) {
                throw DomainRefused::of(DomainRejection::Tombstoned, $host);
            }
        });
    }

    /** The unexpired tombstone on a host, if any. */
    private function liveTombstone(string $host): ?DomainTombstone
    {
        return $this->acrossTenants(static fn (): ?DomainTombstone => DomainTombstone::query()
            ->where('host', $host)
            ->where('expires_at', '>', now())
            ->first());
    }

    /**
     * The installation's own apexes are not claimable by a tenant.
     *
     * @throws DomainRefused
     */
    private function assertNotReserved(string $host): void
    {
        foreach (['docs', 'preview', 'app', 'assets'] as $key) {
            $origin = config('docup.origins.'.$key);

            if (! is_string($origin) || $origin === '') {
                continue;
            }

            $apex = parse_url($origin, PHP_URL_HOST);
            $apex = is_string($apex) ? $apex : $origin;

            if ($host === $apex) {
                throw DomainRefused::of(DomainRejection::HostReserved, $host);
            }
        }
    }

    /**
     * §8.9.10's epoch, bumped so the resolution cache addresses new keys.
     *
     * §8.10.16: "Adding, verifying, activating, suspending or removing a
     * domain MUST take effect with **no proxy restart, config render or
     * reload**." The epoch is how — nothing is rendered and nothing is
     * purged, the next request simply computes a different cache key.
     */
    private function bumpRouting(Domain $domain): void
    {
        foreach (DomainMount::query()->where('domain_id', $domain->id)->pluck('project_id') as $projectId) {
            if (is_string($projectId)) {
                // 🛑 Through §10.8's one registry, never by incrementing the
                // column here: an architecture test asserts that
                // `Invalidation` is the only thing that moves an epoch.
                Invalidation::bumpRouting($projectId, 'domain', $domain->organisation_id);
            }
        }
    }

    /**
     * Run a closure across organisations.
     *
     * 🛑 Required rather than convenient: the questions above are "has
     * **somebody else** proven this host?" and "is there a tombstone from
     * **another** organisation?", and a tenancy scope answers both with
     * "no" by hiding the row. That is the one place a scope would be a
     * security bug rather than a safeguard.
     */
    /**
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     */
    private function acrossTenants(\Closure $callback): mixed
    {
        $context = $this->context ?? app(OrganisationContext::class);

        return $context->acrossAllOrganisations($callback);
    }
}
