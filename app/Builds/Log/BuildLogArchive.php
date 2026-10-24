<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Log;

use App\Artifacts\ArtifactStore;
use App\Models\Build;

/**
 * Where a finished build's log goes, and how it comes back.
 *
 * §10.3's storage layout names it exactly:
 * `logs/<project_uuid>/<build_uuid>/log.ndjson.gz`.
 *
 * 🛑 **Two homes, one contract.** A running build's log is an append-only
 * file the worker owns; a finished build's is a gzip object in the
 * artifact store, which may be S3. Neither shape leaks into §8.5.22's
 * contract — {@see BuildLog::pageFrom()} pages both, so a client polling
 * across the moment a build finishes sees its cursor keep working.
 *
 * 🛑 **Why not keep the live log in the artifact store too.**
 * {@see ArtifactStore} is write-once by design (§8.8.1), because a
 * published artifact that can be replaced is not an artifact. A log is the
 * opposite: it is appended to thousands of times and deleted at 90 days
 * (§20.3). Forcing one into the other's interface would have meant either
 * weakening write-once or re-uploading a growing object on every line.
 */
final readonly class BuildLogArchive
{
    public function __construct(private ArtifactStore $store) {}

    /**
     * 🛑 The ONE place that writes the `logs/` prefix.
     *
     * `ArtifactStore::prefixFor()` exists for the same reason about
     * `builds/`, and the architecture test that counts its call sites now
     * counts this one too. A second place that assembles this path is how
     * a project slug reaches a storage key: not by anyone deciding to put
     * one there, but by a convenience growing on a duplicate.
     */
    public static function keyFor(string $projectId, string $buildId): string
    {
        return 'logs/'.bin2hex($projectId).'/'.bin2hex($buildId).'/log.ndjson.gz';
    }

    /**
     * The project a build belongs to, through its version.
     *
     * 🛑 `builds` carries `organisation_id` and `project_version_id` but no
     * `project_id`, and adding one would be denormalising a column two
     * joins deep for the sake of a storage path. The organisation is the
     * fallback rather than an error, because §10.3's layout wants a stable
     * prefix more than it wants a particular one — a log under the
     * organisation is still addressable, still swept by the same retention
     * and still impossible to collide.
     */
    private static function prefixOwner(Build $build): string
    {
        $version = $build->projectVersion;

        return is_string($version?->project_id) ? $version->project_id : $build->organisation_id;
    }

    /**
     * Compress the live log into the store and remove the live file.
     *
     * Returns the key, or null when there was nothing to archive — a build
     * refused before any container started has no log, and inventing an
     * empty object for it would mean every log reader had to distinguish
     * "empty" from "absent" anyway.
     */
    public function archive(Build $build, BuildLog $log): ?string
    {
        if (! $log->exists()) {
            return null;
        }

        $log->close();

        $source = @fopen($log->path(), 'rb');

        if ($source === false) {
            return null;
        }

        $temporary = $log->path().'.gz';
        $target = @gzopen($temporary, 'wb9');

        if ($target === false) {
            fclose($source);

            return null;
        }

        /*
         * Streamed, not slurped. A capped log is 10 MiB of text and a
         * worker handling several builds should not hold that in memory
         * to compress it — especially not while another build is running
         * in the same process.
         */
        while (! feof($source)) {
            $chunk = fread($source, 262144);

            if ($chunk === false || $chunk === '') {
                break;
            }

            gzwrite($target, $chunk);
        }

        fclose($source);
        gzclose($target);

        $key = self::keyFor(self::prefixOwner($build), $build->id);
        $contents = @fopen($temporary, 'rb');

        if ($contents === false) {
            return null;
        }

        try {
            $this->store->put($key, $contents);
        } catch (\Throwable $refused) {
            /*
             * A log that cannot be archived must not fail the build it
             * describes. §8.8.1's write-once refusal is the likely cause —
             * a re-run of `finalise` after a crash — and in that case the
             * object already there is the one we were about to write.
             */
            logger()->warning('build log archive refused', [
                'build' => bin2hex($build->id),
                'reason' => $refused->getMessage(),
            ]);

            return $this->store->exists($key) ? $key : null;
        } finally {
            if (is_resource($contents)) {
                fclose($contents);
            }

            @unlink($temporary);
        }

        $log->delete();

        return $key;
    }

    /** Page an archived log, with the same contract as the live one. */
    public function read(Build $build, int $from = 1, int $limit = 2000): LogPage
    {
        return BuildLog::pageFrom($this->rawLines(self::keyFor(self::prefixOwner($build), $build->id)), $from, $limit);
    }

    public function exists(Build $build): bool
    {
        return $this->store->exists(self::keyFor(self::prefixOwner($build), $build->id));
    }

    /**
     * @return \Generator<int, string>
     */
    private function rawLines(string $key): \Generator
    {
        $body = $this->store->get($key);

        if ($body === null) {
            return;
        }

        /*
         * Decompressed whole rather than through `gzopen`, because the
         * store is an interface over Flysystem and an S3 object is a
         * string by the time it arrives. Bounded by §8.5.21's cap, so the
         * worst case is the 10 MiB this method exists to serve.
         */
        $plain = @gzdecode($body);

        if ($plain === false) {
            return;
        }

        foreach (explode("\n", $plain) as $raw) {
            if ($raw !== '') {
                yield $raw;
            }
        }
    }
}
