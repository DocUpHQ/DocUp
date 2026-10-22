<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;
use App\Models\BuildOutput;
use App\Models\ProjectVersion;

/**
 * §8.8.10 quota enforcement, at ingest, from the authoritative manifest.
 *
 * 🛑 §8.8.10 is unusually specific about *how*: "Storage and count quotas MUST
 * be enforced **at ingest from the authoritative manifest** — free, exact,
 * failing the build with `contract.quota_exceeded` — not by a `du` poll or a
 * nightly job."
 *
 * Each of those three words is a rejected alternative:
 *
 * - **At ingest**, because a quota discovered later is a quota already
 *   exceeded. The only remedy then is deleting something somebody published,
 *   which is a conversation rather than a control.
 * - **From the manifest**, because the manifest already holds every file's
 *   exact size — so the check costs an addition, not a storage walk. A `du`
 *   poll over an object store is a bill as well as a delay.
 * - **Exact**, because an approximate quota has to be set generously to avoid
 *   false refusals, which makes it a quota in name.
 *
 * A null limit means unlimited, which is the right default for a self-hosted
 * installation whose operator owns the disk: §8.8.10 requires the quota to
 * exist and be enforced, not to be restrictive out of the box.
 */
final class Quotas
{
    /**
     * Refuse an ingest that would take an organisation over its byte quota.
     *
     * Called with the manifest's total, after the tree has been validated and
     * measured but before its build is published. The already-stored bytes of
     * the tree being measured are not counted twice: `build_outputs` holds rows
     * only for builds that completed, and this build has none yet.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  int  $incomingBytes  the manifest's exact total
     *
     * @throws IngestRejected when the quota would be breached
     */
    public function assertArtifactBytesAvailable(string $organisationId, int $incomingBytes): void
    {
        $limit = $this->artifactByteLimit();

        if ($limit === null) {
            return;
        }

        $used = $this->artifactBytesUsed($organisationId);

        if ($used + $incomingBytes > $limit) {
            throw IngestRejected::because(
                RejectionCode::QuotaExceeded,
                detail: sprintf(
                    'organisation artifact bytes: %d used + %d incoming exceeds %d',
                    $used,
                    $incomingBytes,
                    $limit,
                ),
            );
        }
    }

    /**
     * Refuse a new version beyond the per-project ceiling.
     *
     * Separate from the byte quota because they fail for different reasons and
     * an author can act on only one of them: too many bytes means delete or buy
     * room, too many versions means retire some.
     *
     * @param  string  $projectId  raw 16 bytes
     *
     * @throws IngestRejected
     */
    public function assertVersionSlotAvailable(string $projectId): void
    {
        $limit = $this->versionLimit();

        if ($limit === null) {
            return;
        }

        $used = ProjectVersion::query()->where('project_id', $projectId)->count();

        if ($used >= $limit) {
            throw IngestRejected::because(
                RejectionCode::QuotaExceeded,
                detail: sprintf('versions per project: %d of %d used', $used, $limit),
            );
        }
    }

    /**
     * Bytes an organisation currently occupies, summed from `build_outputs`.
     *
     * 🛑 Summed from the rows the ingestor wrote, which is what §8.8.10 means by
     * "the authoritative manifest": each row's `total_bytes` came from counting
     * the real bytes as they streamed, not from an archive header and not from a
     * filesystem stat. The number is therefore exact without touching storage.
     *
     * Every build is counted, not only published ones. That is deliberate: an
     * unpublished build's objects are on the disk and the operator is paying for
     * them, and §8.8.9 gives them at least 24 hours plus a 14-day quarantine
     * before they go. A quota that ignored them would be a quota an author could
     * walk straight past by uploading and never publishing.
     *
     * @param  string  $organisationId  raw 16 bytes
     */
    public function artifactBytesUsed(string $organisationId): int
    {
        return (int) BuildOutput::query()
            ->withoutGlobalScopes()
            ->where('organisation_id', $organisationId)
            ->sum('total_bytes');
    }

    /** The configured byte ceiling, or null for unlimited. */
    public function artifactByteLimit(): ?int
    {
        $limit = config('artifacts.quotas.organisation_artifact_bytes');

        return is_numeric($limit) ? (int) $limit : null;
    }

    /** The configured versions-per-project ceiling, or null for unlimited. */
    public function versionLimit(): ?int
    {
        $limit = config('artifacts.quotas.versions_per_project');

        return is_numeric($limit) ? (int) $limit : null;
    }
}
