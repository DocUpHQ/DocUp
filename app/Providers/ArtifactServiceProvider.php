<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Providers;

use App\Artifacts\ArtifactStore;
use App\Artifacts\IngestCaps;
use App\Artifacts\LocalArtifactStore;
use App\Artifacts\S3ArtifactStore;
use Illuminate\Support\ServiceProvider;

/**
 * Binds the artifact store and the ingest ceilings (§8.8.1, §8.8.2, §11).
 *
 * 🛑 This is the **only** place outside `App\Artifacts` permitted to name the
 * store classes, and the architecture test that enforces §8.8.2's containment
 * allowlists `app/Providers/` by path for exactly this reason: binding a class
 * is not calling {@see ArtifactStore::put()}. The allowlist is a path rather
 * than a comment marker so the exemption cannot be claimed by writing the right
 * words in a file somewhere else.
 *
 * §17 asks for "local driver, S3 driver behind the same interface", and §11's
 * deployment profiles are what choose between them: single-node installations
 * keep artifacts on disk, clustered ones cannot. That is a deployment shape, not
 * a feature tier — §4.4 forbids an open core, so neither driver is the paid one.
 */
final class ArtifactServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        /*
         * A singleton, so one ingest cannot see the caps change underneath it.
         * §8.8.2's ceilings are checked across two passes over an archive, and a
         * cache flush between them would mean the first half was validated
         * against one ceiling and the second against another — an acceptance
         * nobody could reproduce.
         */
        $this->app->singleton(IngestCaps::class, static fn (): IngestCaps => IngestCaps::fromConfig());

        $this->app->singleton(ArtifactStore::class, function (): ArtifactStore {
            $driver = config('artifacts.driver');
            $disks = config('artifacts.disks');

            if (! is_string($driver) || ! is_array($disks) || ! isset($disks[$driver])) {
                /*
                 * 🛑 Thrown, not defaulted. A typo in DOCUP_ARTIFACT_DRIVER that
                 * silently fell back to `local` on a clustered installation
                 * would write every build to one node's disk and serve 404s
                 * from the others — a misconfiguration that looks like an
                 * intermittent bug for as long as it takes somebody to check
                 * which node answered.
                 */
                throw new \RuntimeException(
                    'Unknown artifact driver ['.(is_string($driver) ? $driver : gettype($driver))
                    .']. Set DOCUP_ARTIFACT_DRIVER to one of: '
                    .(is_array($disks) ? implode(', ', array_keys($disks)) : 'local, s3').'.'
                );
            }

            $disk = $disks[$driver];

            if (! is_string($disk)) {
                throw new \RuntimeException("The artifact driver [{$driver}] names no filesystem disk.");
            }

            return match ($driver) {
                's3' => new S3ArtifactStore($disk),
                default => new LocalArtifactStore($disk),
            };
        });
    }
}
