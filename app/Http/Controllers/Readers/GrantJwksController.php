<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Readers;

use App\Readers\Grants\GrantKeys;
use App\Serving\CachePolicy;
use Illuminate\Http\JsonResponse;

/**
 * §20.2's `/.well-known/docup-grant-jwks.json` — §8.12.11's "public keys at a
 * JWKS endpoint".
 *
 * 🛑 **Public, and that is correct rather than a concession.** These are public
 * keys; publishing them is the mechanism by which §8.12.12's rule holds:
 *
 * > "No symmetric key capable of minting a grant MUST reach any edge component."
 *
 * An edge that can verify without being able to mint is only possible if the
 * verification material is public. §8.12.11 names the alternative it rejects:
 * "an edge-held HMAC key makes **every edge node a minter**, so compromising one
 * proxy forges access to every private project."
 *
 * 🛑 **Publicly cacheable, which is the one exception §20.2 carves out.** §7.3
 * makes `/.well-known/` reserved and unmountable and says nothing under it is
 * publicly cacheable — and then names this document and the epoch feed as the
 * exceptions: "the JWKS document and the epoch feed are short-cached by design".
 * The reason is §9.3.2's own: nothing here is private, so a shared cache holding
 * it crosses no tenant boundary. It is the same document for every reader of
 * every project on the installation.
 *
 * 🛑 **No tenant information, asserted by its own shape.** `grant_signing_keys`
 * has no `organisation_id` column at all, so there is nothing here to leak —
 * see the migration's note on why the keypair is the installation's.
 */
final readonly class GrantJwksController
{
    public function __construct(private GrantKeys $keys) {}

    public function __invoke(): JsonResponse
    {
        /*
         * 🛑 The directives come from {@see CachePolicy}, not from here, and the
         * architecture test is what put them there: §9.3.2's invariant is that
         * one place decides public cacheability, and a controller writing the
         * literal would be a second place that has to stay correct forever.
         *
         * The lifetime is {@see GrantKeys::JWKS_CACHE_SECONDS}, which is also
         * what the four-state rotation's retiring window is derived from —
         * see {@see GrantKeys::RETIRING_SECONDS}.
         */
        $directives = CachePolicy::forGrantKeys(GrantKeys::JWKS_CACHE_SECONDS);

        return new JsonResponse($this->keys->jwks(), 200, $directives->headers() + [
            'Content-Type' => 'application/jwk-set+json',
            'X-Robots-Tag' => 'noindex',
        ]);
    }
}
