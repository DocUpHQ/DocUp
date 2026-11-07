<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Http\Middleware\OnlyFromLoopback;
use App\Readers\EpochFeed;
use Illuminate\Http\JsonResponse;

/**
 * §20.2's `/.well-known/docup-epochs` — §8.12.13's Tier C condition.
 *
 * ## 🛑 Internal only, and this is a proposed clarification to §20.2
 *
 * §20.2 lists this path beside the JWKS document and says both are
 * "short-cached by design", which reads as though both were public. The JWKS
 * **is** public — it holds public keys and the same document serves every reader
 * on the installation. This feed is not, and shipping it publicly would undo
 * work the rest of the product does carefully:
 *
 * - it is a **list of every project identifier** on the installation, which
 *   §8.2.7's visibility-filtered index exists to avoid publishing;
 * - and a counter per project that moves on "policy, rule, binding, visibility
 *   change" (§10.8), so watching it tells an anonymous observer *when* a private
 *   project's access policy changed, to the second.
 *
 * §8.6.2 keeps a hidden version out of a sitemap for a weaker reason than that.
 * So the route carries {@see OnlyFromLoopback}, exactly as
 * §8.10.11's "internal, session-free" edge endpoints do, and §20.2's placement
 * under `/.well-known/` is read as what it is — a statement about the path
 * grammar (reserved, unmountable, short-cacheable) rather than about who may
 * read it. Recorded as an amendment (§1.1) rather than a quiet divergence.
 *
 * 🛑 The document and the interval live in {@see EpochFeed}, not here. The
 * architecture preset put them there and it was right to: `docup:doctor` has to
 * know the interval to refuse Tier C without it, and a console command
 * depending on an HTTP controller is a transport concern leaking into an
 * operational one.
 */
final readonly class EpochFeedController
{
    public function __construct(private EpochFeed $feed) {}

    public function __invoke(): JsonResponse
    {
        return new JsonResponse($this->feed->document(), 200, [
            /*
             * 🛑 `no-store`, not the "short-cached" §20.2 permits for the JWKS.
             * The feed's entire value is freshness: §8.12.13 makes the polling
             * interval the exposure window, and a cache in front of it would add
             * its own `max-age` to that window invisibly. The JWKS can be cached
             * because a key that has not been rotated is the same key; an epoch
             * that has not moved is indistinguishable from one whose movement a
             * cache is hiding.
             */
            'Cache-Control' => 'no-store',
            'Content-Type' => 'application/json',
        ]);
    }
}
