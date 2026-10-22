<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use App\Artifacts\Exceptions\ArtifactWriteRefused;
use App\Support\Uuid;
use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Storage;

/**
 * The path handling and write-once check both drivers share.
 *
 * Abstract rather than a single concrete class, because §17 asks for a local
 * driver and an S3 driver "behind the same interface" and the two genuinely
 * differ — see {@see LocalArtifactStore::enforceImmutability()} and
 * {@see S3ArtifactStore::enforceImmutability()}. What they do *not* differ in
 * is key construction, and duplicating that would be how the two drivers come
 * to disagree about where a build's bytes live.
 */
abstract class FilesystemArtifactStore implements ArtifactStore
{
    public function __construct(protected readonly string $disk) {}

    /**
     * 🛑 §8.8.1: `builds/{build_id}/{media_type}/…` and nothing else.
     *
     * The build id is rendered as canonical UUID text, which is the one place
     * raw key bytes become a string (ADR 0006's presentation boundary). No
     * slug, no version, no language, no user-supplied name — so a project
     * renamed an hour after publishing still serves the same bytes from the
     * same key.
     */
    public function keyFor(string $buildId, string $mediaType): string
    {
        return 'builds/'.Uuid::toText($buildId).'/'.$mediaType;
    }

    public function put(string $key, mixed $contents): void
    {
        /*
         * 🛑 Checked before writing, not after. An artifact that can be
         * replaced is one whose published bytes are not the bytes that were
         * reviewed, and §8.8.5 needs the previous build intact for rollback to
         * mean anything.
         *
         * This is a check-then-act, so it is not atomic against a concurrent
         * writer. It does not need to be: keys are derived from a build id, and
         * a build id is minted once. Two writers racing on one key would mean
         * the same build ingesting twice, which §10.3's UNIQUE content_key and
         * the in-flight build constraint already prevent. Said out loud because
         * "check-then-act" should always prompt the question.
         */
        if ($this->filesystem()->exists($key)) {
            throw ArtifactWriteRefused::keyExists($key);
        }

        $this->filesystem()->put($key, $contents);
        $this->enforceImmutability($key);
    }

    public function exists(string $key): bool
    {
        return $this->filesystem()->exists($key);
    }

    public function get(string $key): ?string
    {
        if (! $this->filesystem()->exists($key)) {
            return null;
        }

        $contents = $this->filesystem()->get($key);

        return is_string($contents) ? $contents : null;
    }

    /** @return list<string> */
    public function list(string $prefix): array
    {
        $files = $this->filesystem()->allFiles($prefix);

        // sort() reindexes in place, so the result is already a list.
        sort($files, SORT_STRING);

        return $files;
    }

    public function deletePrefix(string $prefix): void
    {
        $this->filesystem()->deleteDirectory($prefix);
    }

    public function sizeOfPrefix(string $prefix): int
    {
        $total = 0;

        foreach ($this->list($prefix) as $file) {
            $total += $this->filesystem()->size($file);
        }

        return $total;
    }

    protected function filesystem(): Filesystem
    {
        return Storage::disk($this->disk);
    }

    /**
     * Make a written object as hard to change as the backing store allows.
     *
     * Separate from {@see self::put()} because this is the one thing the two
     * drivers cannot share: a POSIX filesystem and an object store have
     * genuinely different mechanisms, and pretending otherwise would mean one
     * of them silently doing nothing.
     */
    abstract protected function enforceImmutability(string $key): void;
}
