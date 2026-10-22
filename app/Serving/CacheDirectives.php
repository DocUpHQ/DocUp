<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * The cache headers one response carries, on both axes (§9.3.2, §9.3.3).
 *
 * 🛑 **Both axes, always.** §9.3.2: "Private responses MUST always carry
 * `private, no-store` on **both** the browser and CDN axes plus `Vary: Cookie`,
 * and **never** a cache tag."
 *
 * Two axes because they are read by different things and a CDN does not
 * necessarily honour `Cache-Control: private`. `CDN-Cache-Control` is the one
 * the edge reads and `Cache-Control` is the one the browser reads, and a
 * response that is private on one axis and public on the other is a private
 * document in a shared cache — which is the single failure §9.3 exists to
 * prevent.
 *
 * A value object rather than headers set in a controller, so that the three-way
 * public check in {@see CachePolicy} is the only thing that can construct a
 * public one. §9.3.2 requires an architecture test forbidding "any code path
 * setting a public CDN cache directive outside the single three-way public
 * check", and a private constructor is how that test has something to assert.
 */
final class CacheDirectives
{
    /**
     * @param  list<string>  $vary
     * @param  list<string>  $cacheTags  always empty for a private response
     */
    private function __construct(
        public readonly bool $public,
        public readonly string $cacheControl,
        public readonly string $cdnCacheControl,
        public readonly array $vary,
        public readonly array $cacheTags,
    ) {}

    /**
     * 🛑 Private: `private, no-store` on both axes, `Vary: Cookie`, no tag.
     *
     * `no-store` and not merely `no-cache`: `no-cache` permits storage and
     * requires revalidation, so the bytes still sit in a shared cache waiting
     * for a revalidation that a CDN may skip. `no-store` is the one that means
     * "do not keep this".
     *
     * `Vary: Cookie` is what stops a cache that ignores `private` from serving
     * one reader's authorised response to another — a second line behind the
     * directive, because §9.3.2's failure mode is a cache that does not do as
     * it is told.
     *
     * No cache tag, ever. A tag is a purge handle, and a private response that
     * carries one has told the CDN it is cacheable content worth tracking.
     */
    public static function private(): self
    {
        return new self(
            public: false,
            cacheControl: 'private, no-store',
            cdnCacheControl: 'private, no-store',
            vary: ['Cookie', 'Accept-Encoding'],
            cacheTags: [],
        );
    }

    /**
     * Public, with §9.3.3's tags.
     *
     * 🛑 Constructible only from {@see CachePolicy}, which is where the
     * three-way check lives. Marked `@internal` so the architecture test has a
     * documented contract to point at, and so a reader who finds a second call
     * site knows it is a defect rather than a pattern.
     *
     * @param  list<string>  $cacheTags  §9.3.3: mount, project, version, build, theme
     *
     * @internal only {@see CachePolicy} may call this
     */
    public static function publiclyCacheable(int $maxAge, int $cdnMaxAge, array $cacheTags): self
    {
        return new self(
            public: true,
            cacheControl: 'public, max-age='.$maxAge,
            // A longer ceiling at the edge than in the browser, because the edge
            // can be purged and a browser cannot. §8.9.10's epoch-in-the-key
            // means a failed purge degrades to stale public HTML for this long
            // and never to wrong routing.
            cdnCacheControl: 'public, max-age='.$cdnMaxAge,
            vary: ['Accept-Encoding'],
            cacheTags: $cacheTags,
        );
    }

    /**
     * The headers, ready to apply to a response.
     *
     * `Vary` is returned as one comma-joined value. §8.9.8 permits "multiple
     * `Vary` headers with **distinct** values, which are a semantic union and
     * which Caddy legitimately produces by adding `Vary: Accept-Encoding`" — so
     * joining here and letting the edge add its own is correct, and is why the
     * permanent header test asserts distinctness rather than a single
     * occurrence.
     *
     * @return array<string, string>
     */
    public function headers(): array
    {
        $headers = [
            'Cache-Control' => $this->cacheControl,
            'CDN-Cache-Control' => $this->cdnCacheControl,
            'Vary' => implode(', ', $this->vary),
        ];

        if ($this->cacheTags !== []) {
            $headers['Cache-Tag'] = implode(',', $this->cacheTags);
        }

        return $headers;
    }
}
