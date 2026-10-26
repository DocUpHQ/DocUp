<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Tls;

use App\Auth\AccessLevel;
use App\Models\Domain;
use App\Models\DomainMount;
use App\Models\Project;

/**
 * 🛑 §8.10.21's `passthrough` mode, and the one case it must refuse.
 *
 * > "`passthrough` TLS mode MUST be supported for corporate load balancers,
 * > and MUST be **refused on any non-public project** — a caching CDN
 * > outside the installation bypasses authorisation entirely. The
 * > supported/unsupported boundary MUST be documented."
 *
 * **What passthrough means here**, since the word is used loosely elsewhere:
 * the TLS session terminates at something that is not this installation. A
 * corporate load balancer or a CDN decrypts, and DocUp sees whatever that
 * device chooses to forward. It is a legitimate and common enterprise
 * topology, and it is supported.
 *
 * **Why a non-public project cannot use it.** Every control §8.12 builds —
 * the grant, the session, the per-request decision, the cache directives
 * that keep private bytes out of shared caches — assumes DocUp is the thing
 * that sees the request. Terminate TLS at a caching CDN and the first
 * authorised reader's response is cached by a device that has never heard of
 * a reader policy, and the second reader gets it without one. There is no
 * header, no `Cache-Control` and no configuration that fixes that from
 * inside, because the device deciding is outside.
 *
 * So the boundary, documented as the requirement asks:
 *
 * | Project visibility | `passthrough` | Why |
 * |---|---|---|
 * | `public` | supported | Nothing to leak; every reader may see every byte. |
 * | `authenticated` | refused | A cache cannot tell one reader from another. |
 * | `members` | refused | Same, and the audience is narrower. |
 * | `restricted` | refused | Same, and §8.2.10 makes this the kill switch. |
 *
 * 🛑 The check is over **every project mounted on the hostname**, not the
 * first. One public project and one private project on one host is §8.10.20's
 * shared origin, and the private one's bytes travel through the same
 * terminating device.
 */
final class PassthroughPolicy
{
    /**
     * @throws CertificateRefused when any project on this host is not public
     */
    public static function assertUsable(Domain $domain): void
    {
        $offenders = self::nonPublicProjects($domain);

        if ($offenders !== []) {
            throw CertificateRefused::of(
                CertificateRejection::PassthroughNotPublic,
                $domain->host.' serves '.implode(', ', $offenders).', which '.
                    (count($offenders) === 1 ? 'is' : 'are').' not public',
            );
        }
    }

    public static function usable(Domain $domain): bool
    {
        return self::nonPublicProjects($domain) === [];
    }

    /**
     * The slugs of every project on this host that is not public.
     *
     * @return list<string>
     */
    private static function nonPublicProjects(Domain $domain): array
    {
        $projectIds = DomainMount::query()
            ->where('domain_id', $domain->id)
            ->pluck('project_id')
            ->all();

        if ($projectIds === []) {
            return [];
        }

        $offenders = [];

        foreach (Project::query()->whereIn('id', $projectIds)->get(['id', 'slug', 'visibility']) as $project) {
            if ($project->visibility !== AccessLevel::Public) {
                $offenders[] = (string) $project->slug;
            }
        }

        return $offenders;
    }
}
