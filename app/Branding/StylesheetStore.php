<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use Illuminate\Contracts\Filesystem\Filesystem;
use Illuminate\Support\Facades\Storage;

/**
 * 🛑 §8.14.4's "500 small files", and why they are files.
 *
 * > "Each theme revision MUST publish as an immutable content-addressed
 * > stylesheet […] so 500 projects cost one bundle plus 500 small files and a
 * > token edit mints a new URL with nothing to purge."
 *
 * **Files**, not cache entries. The distinction is load-bearing: a page served
 * with a year-long `immutable` cache directive carries a `<link>` to a
 * stylesheet URL for a year, and a reader whose browser evicted its copy will
 * come back for it. A cache entry can be evicted; a content-addressed file
 * cannot go stale, because the hash is the content.
 *
 * ## 🛑 Written when the URL is minted, not when it is requested
 *
 * {@see ThemeDelivery} compiles and stores the stylesheet in the same call
 * that produces the `<link href>`, so a URL has never been emitted without the
 * bytes behind it existing. The alternative — generating on request — needs a
 * reverse lookup from hash to theme, and there is none: a hash identifies a
 * *resolved cascade*, which may be the cascade of any number of projects and of
 * none once a token is edited.
 *
 * A 404 from the stylesheet route therefore means exactly one thing: a URL from
 * a page cached longer than the file was kept. That is a real and correct
 * answer, and it degrades to an unstyled page rather than a wrong one.
 */
final readonly class StylesheetStore
{
    /** Under its own prefix, so a listing separates generated CSS from uploads. */
    private const PREFIX = 'css';

    public function __construct(private Filesystem $disk) {}

    public static function make(): self
    {
        return new self(Storage::disk('theme-assets'));
    }

    /**
     * Store the stylesheet for one content hash, if it is not there already.
     *
     * Idempotent, and the idempotence is free: the path is the hash, so a
     * second write of the same theme writes the same bytes to the same place.
     */
    public function ensure(string $contentHash, string $css): void
    {
        $path = self::path($contentHash);

        if (! $this->disk->exists($path)) {
            $this->disk->put($path, $css);
        }
    }

    public function get(string $contentHash): ?string
    {
        $path = self::path($contentHash);

        if (! $this->disk->exists($path)) {
            return null;
        }

        $css = $this->disk->get($path);

        return is_string($css) ? $css : null;
    }

    /**
     * 🛑 Validated here, because the controller passes a path segment.
     *
     * The route pattern constrains the hash too. Two checks for one rule, and
     * the duplication is deliberate: the route pattern is where a reader's URL
     * is refused and this is where a traversal cannot be constructed, and
     * neither should depend on the other staying right.
     */
    private static function path(string $contentHash): string
    {
        if (preg_match('/^[0-9a-f]{64}$/', $contentHash) !== 1) {
            throw new \InvalidArgumentException('a theme stylesheet is addressed by a SHA-256 hex digest');
        }

        return self::PREFIX.'/'.substr($contentHash, 0, 2).'/'.$contentHash.'.css';
    }
}
