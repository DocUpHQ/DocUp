<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Storage;

/**
 * Where §8.14.11's content-addressed branding bytes live.
 *
 * 🛑 **Content-addressed and write-once.** The path is derived from the hash of
 * the bytes, so writing the same asset twice writes the same path with the same
 * contents and there is no update operation at all. That is what makes
 * §8.14.4's year-long `immutable` cache safe on these URLs: the bytes behind a
 * path cannot change, so a cached copy cannot be stale.
 *
 * 🛑 **Fanned out two levels.** `ab/cd/abcd…` rather than a flat directory: ext4
 * copes with a large directory and `ls` does not, and an operator debugging a
 * missing logo should be able to list the directory it is in. The same shape the
 * artifact store uses, for the same reason.
 */
final readonly class AssetStore
{
    public function __construct(private Filesystem $disk) {}

    public static function make(): self
    {
        return new self(Storage::disk('theme-assets'));
    }

    /**
     * Store bytes under their own hash, and return the hash.
     *
     * Idempotent: a second write of identical bytes is a no-op, which is what
     * lets two tenants upload the same stock logo without two copies.
     */
    public function put(string $hash, string $extension, string $bytes): string
    {
        $path = self::path($hash, $extension);

        if (! $this->disk->exists($path)) {
            $this->disk->put($path, $bytes);
        }

        return $hash;
    }

    public function get(string $hash, string $extension): ?string
    {
        $path = self::path($hash, $extension);

        if (! $this->disk->exists($path)) {
            return null;
        }

        $bytes = $this->disk->get($path);

        return is_string($bytes) ? $bytes : null;
    }

    public function exists(string $hash, string $extension): bool
    {
        return $this->disk->exists(self::path($hash, $extension));
    }

    /**
     * The path for one hash.
     *
     * 🛑 The hash is validated here rather than trusted, even though every
     * caller computes it: this is the one function that turns an identifier
     * into a filesystem path, and a path built from an unchecked identifier is
     * a traversal waiting for a caller who takes it from a URL. The asset
     * controller does exactly that.
     */
    public static function path(string $hash, string $extension): string
    {
        if (preg_match('/^[0-9a-f]{64}$/', $hash) !== 1) {
            throw new \InvalidArgumentException('a branding asset path is addressed by a SHA-256 hex digest');
        }

        if (preg_match('/^[a-z0-9]{2,5}$/', $extension) !== 1) {
            throw new \InvalidArgumentException('a branding asset extension is short and alphanumeric');
        }

        return substr($hash, 0, 2).'/'.substr($hash, 2, 2).'/'.$hash.'.'.$extension;
    }
}
