<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Branding;

use App\Branding\Assets\AssetStore;
use App\Branding\Assets\RasterReencoder;
use App\Serving\CachePolicy;
use Illuminate\Http\Response;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;

/**
 * 🛑 §8.14.11's dedicated asset host.
 *
 * > "SVG MUST be DOM-sanitised against an element and attribute allowlist,
 * > re-serialised, and rendered **only via `<img src>`** from a dedicated asset
 * > host carrying `default-src 'none'; sandbox`, `nosniff` and no cookies."
 *
 * Every clause of that is a header or a route property here, and each is worth
 * reading separately:
 *
 * - **`default-src 'none'`** — the response may fetch nothing. An SVG that
 *   survived sanitisation with a reference the allowlist missed still cannot
 *   load it.
 * - **`sandbox`** — with no allow-list tokens, which puts the response in an
 *   **opaque origin** with scripting disabled. §8.14.15 refuses `sandbox` on
 *   *documentation* for exactly that reason ("it creates an opaque origin that
 *   kills the reader session cookie and client-side search"); here the opaque
 *   origin is the point, because an image needs no identity and no cookie.
 * - **`nosniff`** — so a browser honours the declared type instead of guessing
 *   from the bytes, which is the other half of the polyglot defence that
 *   {@see RasterReencoder} begins.
 * - **no cookies** — the route is in no middleware group, so nothing in the
 *   session or cookie stack runs. A test asserts no `Set-Cookie` is ever
 *   emitted here.
 *
 * ## 🛑 Content-addressed, so there is nothing to authorise
 *
 * The path is the SHA-256 of the bytes, which is why this route can have no
 * reader dimension and no tenant resolution. A logo is on public display in
 * every page it appears on; what the hash protects is not secrecy but
 * **integrity** — a URL names exactly one sequence of bytes, for ever, which
 * is what lets §8.14.4's `immutable` be truthful.
 *
 * `Cross-Origin-Resource-Policy: cross-origin` is required rather than
 * incidental: the asset host is by design a different origin from every page
 * that loads from it, so the default `same-origin` would block every logo.
 */
final readonly class BrandingAssetController
{
    /**
     * The `Content-Security-Policy` §8.14.11 names, verbatim.
     *
     * 🛑 A constant, so the containment test can assert the header a response
     * actually carries against the requirement's own words rather than against
     * a paraphrase a future edit might loosen.
     */
    public const string POLICY = "default-src 'none'; sandbox";

    /** The three media types this host will serve, by extension. */
    private const TYPES = [
        'png' => 'image/png',
        'svg' => 'image/svg+xml',
    ];

    public function __construct(private AssetStore $store) {}

    public function __invoke(string $hash, string $extension): SymfonyResponse
    {
        $type = self::TYPES[$extension] ?? null;

        if ($type === null) {
            return $this->refuse();
        }

        $bytes = $this->store->get($hash, $extension);

        if ($bytes === null) {
            return $this->refuse();
        }

        return new Response($bytes, 200, [
            'Content-Type' => $type,
            'Content-Security-Policy' => self::POLICY,
            'X-Content-Type-Options' => 'nosniff',
            /*
             * 🛑 Required, not hardening. The asset host is a different origin
             * from every page that loads from it — that is the whole design —
             * so the `same-origin` default would block every logo on every
             * page. Stating it means a browser that tightens its default does
             * not silently break branding.
             */
            'Cross-Origin-Resource-Policy' => 'cross-origin',
            /*
             * 🛑 §8.14.10 kills CSS exfiltration "by headers, not by parser
             * cleverness". A referrer sent from an image request on a private
             * documentation page would name the page's URL to this host — which
             * is DocUp's own, so nothing leaves the installation, but the
             * access log would then hold a list of private paths.
             */
            'Referrer-Policy' => 'no-referrer',
            'X-Robots-Tag' => 'noindex, nofollow',
            ...CachePolicy::forImmutableBrandingAsset()->headers(),
        ]);
    }

    /**
     * 🛑 404 with the same headers as a hit, and `private, no-store`.
     *
     * The headers because a 404 body is a body, and an installation that sent
     * `default-src 'none'; sandbox` on success and nothing on failure would
     * have one unprotected response shape. `private, no-store` because an
     * absence here is not content-addressed — the bytes may appear a second
     * later, when a theme that names them is first delivered.
     */
    private function refuse(): SymfonyResponse
    {
        return new Response('', 404, [
            'Content-Security-Policy' => self::POLICY,
            'X-Content-Type-Options' => 'nosniff',
            'Cache-Control' => 'private, no-store',
        ]);
    }
}
