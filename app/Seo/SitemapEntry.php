<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

use Illuminate\Support\Carbon;

/**
 * One URL in a sitemap, with the `hreflang` alternates §8.11.6 asks for
 * "across versions, mounts **and** domains".
 */
final readonly class SitemapEntry
{
    /**
     * @param  array<string, string>  $alternates  language → absolute URL
     */
    public function __construct(
        public string $location,
        public ?Carbon $lastModified = null,
        public array $alternates = [],
    ) {}
}
