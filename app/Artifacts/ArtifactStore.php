<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * Write-once storage for artifact trees (§8.8.1, §10.3).
 *
 * 🛑 **Every key is derived from the build id alone.** §8.8.1: "No project
 * slug, version slug, language or user-supplied name MUST appear in any storage
 * key, so renaming can never strand or invalidate stored artifacts." That is
 * why {@see self::keyFor()} takes a build id and a media type and nothing else,
 * and why an architecture test asserts the shape — a slug in a key is the kind
 * of convenience that only hurts the first time somebody renames a project,
 * by which point every stored artifact is unreachable.
 *
 * 🛑 **Write-once.** An artifact that can be overwritten is an artifact whose
 * published bytes are not the bytes that were reviewed, and §8.8.5 depends on
 * the previous build remaining "intact and immediately re-selectable" for
 * rollback. Implementations refuse to write a key that already exists rather
 * than silently replacing it.
 *
 * The two drivers §17 asks for sit behind this: {@see LocalArtifactStore} and
 * {@see S3ArtifactStore}. They share their path handling through
 * {@see FilesystemArtifactStore} because both are Flysystem adapters
 * underneath; they differ in how write-once is actually enforced, which is the
 * part that cannot be shared.
 */
interface ArtifactStore
{
    /**
     * Everything one build owns, as a prefix.
     *
     * 🛑 Exists so that §8.8.1's key grammar has exactly **one** construction
     * site, which an architecture test asserts by counting the places that
     * write the literal `'builds/'`. The Publisher needs this prefix to sweep a
     * refused build's objects, and it built the string itself until that test
     * caught it — which is precisely how a slug reaches a storage key: not by
     * anyone deciding to put one there, but by a second place that assembles
     * the path and later grows a convenience.
     *
     * @param  string  $buildId  raw 16 bytes, as every key in this schema is
     */
    public function prefixFor(string $buildId): string;

    /**
     * The storage key for one media type of one build.
     *
     * @param  string  $buildId  raw 16 bytes, as every key in this schema is
     * @param  string  $mediaType  one of §10.3's formats
     */
    public function keyFor(string $buildId, string $mediaType): string;

    /**
     * Write a file, refusing to replace an existing key.
     *
     * @param  resource|string  $contents
     *
     * @throws Exceptions\ArtifactWriteRefused when the key already exists
     */
    public function put(string $key, mixed $contents): void;

    /** Whether a key exists. */
    public function exists(string $key): bool;

    /** Read a file back, or null when the key does not exist. */
    public function get(string $key): ?string;

    /**
     * Every key under a prefix, sorted.
     *
     * @return list<string>
     */
    public function list(string $prefix): array;

    /**
     * Delete everything under a prefix.
     *
     * 🛑 Only for §8.8.9 garbage collection and for a build that failed before
     * publication. Never for a published build: §8.8.5 requires the previous
     * build to stay re-selectable, and §8.8.9 routes sweeps through a
     * quarantine prefix with a 14-day grace rather than deleting outright.
     */
    public function deletePrefix(string $prefix): void;

    /** Total bytes under a prefix, for quota reporting. */
    public function sizeOfPrefix(string $prefix): int;

    /** The driver's name, for `doctor` and for build provenance. */
    public function driver(): string;
}
