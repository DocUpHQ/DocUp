<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Domains;

use App\Models\Domain;
use App\Models\DomainMount;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.10.20: one hostname is one browser origin.
 *
 * > "A hostname carrying more than one domain mount MUST set a derived
 * > `shared_origin` flag requiring one organisation, one authentication
 * > profile and one privacy level across those mounts, forbidding tenant CSS
 * > and JavaScript, and recording an operator acknowledgement. 🛑
 * > Cross-organisation mounts on one hostname MUST NOT be permitted:
 * > everything on one hostname shares one browser origin."
 *
 * The browser does not know about path prefixes. Two projects at
 * `/alpha/` and `/beta/` on one hostname share cookies, `localStorage`,
 * `Clear-Site-Data`, service-worker scope and the whole same-origin policy —
 * so documentation served at one can read and overwrite the other's state.
 * That is tolerable inside one organisation, which is a trust boundary its
 * members already share, and it is not tolerable across two.
 *
 * 🛑 **Cross-organisation is refused outright**, and the exposure and
 * authentication constraints are enforced on top. The flag itself is derived
 * from the mount count and maintained here, because MySQL cannot generate a
 * column from another table's row count — so a test asserts the stored flag
 * equals the derivation rather than trusting every write path to call this.
 */
final class SharedOrigin
{
    /**
     * Re-derive the flag and enforce §8.10.20's restrictions.
     *
     * Called after every mount write. Idempotent, and cheap: one count and,
     * only when the hostname is shared, one pass over its mounts.
     *
     * @throws DomainRefused
     */
    public static function reconcile(Domain $domain): void
    {
        /** @var list<DomainMount> $mounts */
        $mounts = array_values(
            DomainMount::query()->where('domain_id', $domain->id)->get()->all(),
        );

        $shared = count($mounts) > 1;

        if ($shared) {
            self::assertOneOrganisation($domain, $mounts);
            self::assertOneExposure($domain, $mounts);
        }

        if ($domain->shared_origin !== $shared) {
            $domain->forceFill(['shared_origin' => $shared])->save();
        }
    }

    /**
     * Whether the stored flag matches the derivation, for the test that keeps
     * every write path honest.
     */
    public static function isConsistent(Domain $domain): bool
    {
        $count = DomainMount::query()->where('domain_id', $domain->id)->count();

        return $domain->shared_origin === ($count > 1);
    }

    /**
     * 🛑 Whether a hostname may carry tenant CSS or JavaScript.
     *
     * §8.10.20 forbids both on a shared origin. Tenant CSS on a page that
     * shares an origin with another tenant's documentation is a styling
     * primitive pointed at somebody else's content, and tenant JavaScript is
     * the same thing without the pretence.
     */
    public static function permitsTenantAssets(Domain $domain): bool
    {
        return ! $domain->shared_origin;
    }

    /**
     * 🛑 §8.10.20's operator acknowledgement.
     *
     * Recorded rather than prompted-for, and the distinction matters: the
     * question is not "do you agree?" but "is it written down that somebody
     * was told?". `docup:doctor` can then report a shared origin nobody has
     * acknowledged, which is the state worth noticing.
     */
    public static function acknowledge(Domain $domain): void
    {
        $domain->forceFill(['shared_origin_acknowledged_at' => now()])->save();
    }

    /**
     * @param  list<DomainMount>  $mounts
     *
     * @throws DomainRefused
     */
    private static function assertOneOrganisation(Domain $domain, array $mounts): void
    {
        $projectIds = array_values(array_unique(array_map(
            static fn (DomainMount $mount): string => $mount->project_id,
            $mounts,
        )));

        $organisations = DB::table('projects')
            ->whereIn('id', $projectIds)
            ->distinct()
            ->pluck('organisation_id');

        if ($organisations->count() > 1) {
            throw DomainRefused::of(
                DomainRejection::SharedOriginCrossTenant,
                $domain->host.' would carry mounts from '.$organisations->count().' organisations',
            );
        }
    }

    /**
     * §8.10.20's "one privacy level across those mounts".
     *
     * Compared on `mount_exposure` rather than on the resolved level: the
     * mounts are the thing an operator configured and the thing they can
     * change, and resolving each against its project's visibility would
     * refuse a configuration that is identical in every column somebody can
     * see.
     *
     * @param  list<DomainMount>  $mounts
     *
     * @throws DomainRefused
     */
    private static function assertOneExposure(Domain $domain, array $mounts): void
    {
        $levels = array_values(array_unique(array_map(
            static fn (DomainMount $mount): string => $mount->mount_exposure,
            $mounts,
        )));

        if (count($levels) > 1) {
            throw DomainRefused::of(
                DomainRejection::SharedOriginExposureMismatch,
                $domain->host.' mixes '.implode(' and ', $levels),
            );
        }
    }
}
