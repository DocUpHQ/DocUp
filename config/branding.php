<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    /*
    |---------------------------------------------------------------------------
    | The font catalogue (SPEC 8.14.2)
    |---------------------------------------------------------------------------
    | 🛑 "Fonts are catalogue names or self-hosted WOFF2 asset references; **no
    | remote font URL ever** (an injection surface and a third-country
    | transfer)."
    |
    | These are the families the INSTALLATION self-hosts. A tenant may name one
    | of them or upload a WOFF2 of their own; neither path can name a host.
    |
    | Empty by default, and deliberately: a catalogue entry is a promise that
    | the bytes are in the image, and shipping a name whose font is absent gives
    | every reader a silent fallback that nobody can diagnose. An operator who
    | self-hosts a family adds it here and drops the WOFF2 beside it.
    |
    | CSS's own generic families are always available and are NOT listed here —
    | App\Branding\Values\FontStackValue::GENERIC holds them, because CSS's list
    | is closed and an operator cannot extend it.
    */
    'font_catalogue' => [],

    /*
    |---------------------------------------------------------------------------
    | Asset limits (SPEC 8.14.11)
    |---------------------------------------------------------------------------
    | 🛑 "Uploaded rasters MUST be content-sniffed and re-encoded server-side to
    | strip metadata and defeat polyglots, pixel- and byte-capped,
    | content-addressed with the uploaded filename discarded."
    |
    | Both caps, because they fail in different directions. The byte cap stops
    | an upload that is simply too big; the PIXEL cap stops a decompression
    | bomb, which is small on disk and enormous in memory — a 10 KB PNG can
    | declare 50,000 × 50,000 pixels, and GD will try to allocate 10 GB for it
    | before anything has a chance to object.
    |
    | The pixel cap is checked from the header, before any decode.
    */
    'assets' => [

        /* Bytes accepted from the client, per kind. */
        'max_bytes' => [
            'logo' => 512 * 1024,
            'favicon' => 256 * 1024,
            'social_card' => 2 * 1024 * 1024,
            'font' => 1024 * 1024,
        ],

        /*
         * 🛑 The total pixel count, read from the image header before decoding.
         * Four megapixels is a 2048 × 2048 logo, which is already far larger
         * than any chrome renders — and is two orders of magnitude below where
         * GD's allocation becomes a problem.
         */
        'max_pixels' => 4_000_000,

        /*
         * The longest edge DocUp will emit, per kind. Re-encoding downscales to
         * fit, which is part of §8.14.11's "re-encoded server-side": a 4 MP
         * logo served to every reader would be a performance defect the tenant
         * could inflict on the operator.
         */
        'max_edge' => [
            'logo' => 512,
            'favicon' => 180,
            'social_card' => 1200,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Chrome content limits (SPEC 8.14.3)
    |---------------------------------------------------------------------------
    | 🛑 "Chrome content MUST be structured data — navigation links, footer
    | links, an announcement with a tiny inline-tag allowlist, and homepage
    | blocks from a registry — never free HTML."
    |
    | Every collection is bounded. An unbounded navigation list is a payload a
    | tenant can grow until the addons response is the slowest thing on the
    | page, and §9.2's budgets are the operator's problem rather than the
    | tenant's.
    */
    'chrome' => [
        'max_navigation_links' => 12,
        'max_footer_groups' => 4,
        'max_footer_links_per_group' => 8,
        'max_homepage_blocks' => 8,
        'max_announcement_characters' => 400,
    ],

    /*
    |---------------------------------------------------------------------------
    | Stylesheet and asset caching (SPEC 8.14.4)
    |---------------------------------------------------------------------------
    | 🛑 "Each theme revision MUST publish as an immutable content-addressed
    | stylesheet with `max-age=31536000, immutable`, so 500 projects cost one
    | bundle plus 500 small files and a token edit mints a new URL with nothing
    | to purge."
    |
    | A year, which is the longest `max-age` any cache honours. Safe only
    | because the URL is the content hash: a token edit produces a different
    | URL, so nothing stale is ever requested and there is nothing to purge.
    | Lowering this would not make anything safer; it would only make every
    | reader re-request bytes that cannot have changed.
    */
    'immutable_max_age' => 31_536_000,

];
