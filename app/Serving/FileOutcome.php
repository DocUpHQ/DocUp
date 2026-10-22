<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * What the second half of the grammar decided (§7.3's last two steps).
 *
 * 🛑 Every answer here comes from the published manifest, never from storage.
 * §8.4.18: the manifest "MUST drive the 404 chain, strong ETags, 404
 * suggestions, cross-version page existence and link validation **without a
 * storage existence probe per request**". A `HEAD` to an object store per 404 is
 * the latency and the bill this design exists to avoid, and the 404 path is the
 * one an attacker can generate without limit.
 */
final class FileOutcome
{
    /**
     * @param  string|null  $key  the manifest path, which is also the storage
     *                            key relative to `builds/{build_id}/`
     * @param  array{sha256: string, bytes: int, content_type: string}|null  $entry
     * @param  string|null  $directoryRedirect  the slash form to 302 to (§8.9.7)
     */
    private function __construct(
        public readonly FileKind $kind,
        public readonly ?string $key = null,
        public readonly ?array $entry = null,
        public readonly ?string $directoryRedirect = null,
        public readonly ?RejectionReason $reason = null,
    ) {}

    /**
     * @param  array{sha256: string, bytes: int, content_type: string}  $entry
     */
    public static function file(string $key, array $entry): self
    {
        return new self(FileKind::File, key: $key, entry: $entry);
    }

    /** §8.9.7: a directory without its trailing slash. */
    public static function directory(string $slashForm): self
    {
        return new self(FileKind::Directory, directoryRedirect: $slashForm);
    }

    public static function rejected(RejectionReason $reason): self
    {
        return new self(FileKind::Rejected, reason: $reason);
    }

    /**
     * The strong ETag for this file (§8.9.12).
     *
     * 🛑 From the manifest's sha256, not from a rehydrated file mtime. §8.9.12
     * requires "an `ETag` derived from the manifest digest and `Last-Modified`
     * from **build time**, not from a rehydrated file mtime" — because an
     * artifact restored from backup, or copied to a second node, has a new
     * mtime and identical bytes. An mtime-derived validator would invalidate
     * every reader's cache on a restore, for content that did not change.
     *
     * Quoted and not weak: the digest is of the exact bytes, so byte-for-byte
     * equality is what it asserts.
     */
    public function etag(): ?string
    {
        if ($this->entry === null) {
            return null;
        }

        return '"'.$this->entry['sha256'].'"';
    }
}
