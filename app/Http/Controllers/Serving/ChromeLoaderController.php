<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Serving;

use App\Artifacts\ChromeInjector;
use App\Serving\CachePolicy;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.15.1's chrome loader, at the one path every artifact already points at.
 *
 * > "exactly two **project- and version-agnostic** tags before the first
 * > `</head>`: a deferred script at a **stable, non-content-hashed** path […]
 * > Hashing the loader path would orphan chrome on every historical artifact at
 * > each upgrade."
 *
 * {@see ChromeInjector::LOADER_PATH} has been `/_/addons/docup.js` since Phase
 * 04 and nothing served it until now. Every HTML document ingested since then
 * carries a `<script defer src="/_/addons/docup.js">`, which is the point of the
 * stable path: this phase makes those tags work without touching a single
 * stored byte.
 *
 * ## 🛑 Why the script is a hand-written file and not a bundler's output
 *
 * The runtime is served **as authored**, from `resources/js/chrome/docup.js`,
 * with no build step between the source and the reader. Three reasons, in order
 * of weight:
 *
 * 1. **It is one request.** Chrome loads on every documentation page of every
 *    project; native ES-module imports would be one request per module, each
 *    needing a route under §7.3's reserved namespace, and a bundler is the only
 *    other way to avoid that. Keeping the runtime in one file avoids needing
 *    either.
 * 2. **It is auditable.** §8.14.8 forbids tenant JavaScript in chrome at every
 *    scope below installation, on the argument that "a chrome slot puts it in
 *    the same DOM". The script DocUp itself puts in that DOM should be readable
 *    by whoever is checking that claim, and a minified bundle is not.
 * 3. **Nothing on the serving path depends on a manifest.** A Vite-built entry
 *    would make this route fail whenever `public/build` was stale — in a test
 *    run, in a container someone forgot to build in, on a first boot — and the
 *    symptom would be chrome silently absent rather than an error anyone saw.
 *
 * The cost is no minification. §18.4's "browsers released within roughly two
 * years" means no transpilation is needed either, and the edge compresses the
 * response, so what is lost is the few kilobytes minification would have saved.
 *
 * ## The ETag is the revalidation
 *
 * {@see CachePolicy::forChromeLoader()} gives a reader's own browser an hour,
 * after which it asks again. That ask is answered by a strong ETag over the
 * script's digest, so the common answer is a 304 with no body — which is what
 * makes a one-hour private cache affordable on a path §7.3 keeps out of shared
 * caches.
 */
final readonly class ChromeLoaderController
{
    /** The runtime, relative to the repository root. */
    public const string SOURCE = 'resources/js/chrome/docup.js';

    public function __invoke(Request $request): Response
    {
        $script = $this->script();

        if ($script === null) {
            /*
             * 🛑 503 and not 404, and not an empty 200. A missing runtime is an
             * installation defect, not a reader's wrong URL — and an empty 200
             * would be cached by every reader's browser for an hour, turning a
             * deployment mistake into an hour of chrome-less documentation that
             * nothing in the logs explains.
             */
            return new Response('', 503, [
                'Cache-Control' => 'no-store',
                DocumentController::NOTICE_HEADER => 'addons.loader_missing',
            ]);
        }

        [$bytes, $etag] = $script;

        $headers = [
            ...CachePolicy::forChromeLoader()->headers(),

            /*
             * 🛑 `text/javascript`, and `nosniff` beside it. The bytes are
             * DocUp's own, so sniffing is not the risk here — the risk is an
             * operator's proxy deciding otherwise, and §8.9.11 makes `nosniff`
             * unconditional for exactly that reason: "the risk is the browser
             * disagreeing with a type that IS known".
             */
            'Content-Type' => 'text/javascript; charset=utf-8',
            'X-Content-Type-Options' => 'nosniff',
            'ETag' => $etag,
            DocumentController::NOTICE_HEADER => 'addons.loader',
        ];

        if ($this->matches($request, $etag)) {
            return new Response('', 304, $headers);
        }

        return new Response($bytes, 200, $headers);
    }

    /**
     * The runtime's bytes and its strong ETag, or null when it is missing.
     *
     * Cached against the file's own size and modification time, so a warm
     * process answers without a read and an edit during development is picked
     * up on the next request. 🛑 Not cached forever against a constant: the
     * path is stable by requirement, so a key that ignored the file's identity
     * would serve the previous release's chrome until somebody flushed a cache
     * nobody knew was involved.
     *
     * @return array{string, string}|null
     */
    private function script(): ?array
    {
        $path = base_path(self::SOURCE);

        if (! is_file($path)) {
            return null;
        }

        $stamp = (string) filesize($path).':'.(string) filemtime($path);

        /** @var array{string, string}|null */
        return Cache::rememberForever(
            'addons:loader:'.ChromeInjector::VERSION.':'.$stamp,
            static function () use ($path): ?array {
                $bytes = file_get_contents($path);

                if ($bytes === false) {
                    return null;
                }

                return [$bytes, '"'.hash('sha256', $bytes).'"'];
            },
        );
    }

    /**
     * Whether the client already holds these bytes.
     *
     * Strong comparison, and `*` honoured — the same reading
     * {@see DocumentController} applies, because getting it wrong in the
     * permissive direction serves a 304 for a script the browser does not have,
     * which is chrome that never loads and a reader who cannot refresh it away.
     */
    private function matches(Request $request, string $etag): bool
    {
        $header = $request->headers->get('If-None-Match');

        if (! is_string($header) || $header === '') {
            return false;
        }

        if (trim($header) === '*') {
            return true;
        }

        foreach (explode(',', $header) as $candidate) {
            if (trim($candidate) === $etag) {
                return true;
            }
        }

        return false;
    }
}
