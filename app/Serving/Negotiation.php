<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §8.9.13 — serve a pre-compressed sidecar where one exists.
 *
 * §8.9.13: "The system MUST serve pre-compressed sidecars where present, or
 * compress on the fly, with correct `Vary: Accept-Encoding`. The ingest-time
 * disposition of a pre-compressed HTML artifact is §8.15.10's, not this
 * requirement's."
 *
 * The division of labour matters. **This** class picks which stored object to
 * hand the edge; §8.15.10 decided at ingest whether a compressed HTML artifact
 * was injectable at all. On-the-fly compression is the edge's job — `encode
 * zstd gzip` in the Caddyfile, `gzip on` in nginx.conf — because compressing in
 * PHP would mean reading the bytes, which §8.9.8 forbids outright.
 *
 * 🛑 **A sidecar carries its own ETag**, and that falls out of the design rather
 * than needing care: §8.9.12 derives the validator from the manifest digest, and
 * the sidecar is its own manifest entry with its own digest. Had the ETag been
 * shared, a cache holding the gzip bytes under the plain file's validator could
 * answer a client that never asked for gzip — which is `Vary` being right and
 * the validator being wrong, and the validator is the one caches trust.
 */
final class Negotiation
{
    /**
     * Encodings DocUp will serve from a sidecar, best ratio first.
     *
     * Brotli before gzip because it compresses text materially better and every
     * browser that sends `br` also sends `gzip` — so preferring it costs
     * nothing and the fallback is automatic.
     *
     * Zstandard is deliberately absent. Caddy can compress `zstd` on the fly,
     * but a `.zst` sidecar is not a convention any documentation generator
     * emits, and inventing one would mean DocUp looking for files nothing
     * produces.
     *
     * @var array<string, string> token => sidecar extension
     */
    private const SIDECARS = [
        'br' => '.br',
        'gzip' => '.gz',
    ];

    /**
     * Pick the object to serve for one request.
     *
     * @param  array<string, array{sha256: string, bytes: int, content_type: string}>  $files
     *                                                                                         the matched build's manifest
     * @param  string  $key  the manifest path the resolver chose
     * @param  string|null  $acceptEncoding  the request header, or null
     * @return array{0: string,1: string|null} the key to serve, and the
     *                                         `Content-Encoding` to declare
     */
    public static function choose(array $files, string $key, ?string $acceptEncoding): array
    {
        if ($acceptEncoding === null || $acceptEncoding === '') {
            return [$key, null];
        }

        $accepted = self::parse($acceptEncoding);

        foreach (self::SIDECARS as $token => $extension) {
            if (! in_array($token, $accepted, true)) {
                continue;
            }

            $sidecar = $key.$extension;

            if (isset($files[$sidecar])) {
                return [$sidecar, $token];
            }
        }

        return [$key, null];
    }

    /**
     * Whether a manifest path is itself a sidecar.
     *
     * 🛑 Used to keep a sidecar from being served **directly**. A reader
     * requesting `/en/latest/guide.html.gz` must get a 404, not gzip bytes
     * labelled `application/gzip`: the sidecar exists to answer a request for
     * `guide.html` under negotiation, and serving it on its own URL gives one
     * document two URLs — the cache-key surface §8.9.6 spends its strictness
     * collapsing.
     */
    public static function isSidecar(string $path): bool
    {
        foreach (self::SIDECARS as $extension) {
            if (str_ends_with(strtolower($path), $extension)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The acceptable encodings, in no particular order.
     *
     * 🛑 An encoding with `q=0` is explicitly **refused** by the client, and is
     * dropped. Treating `gzip;q=0` as acceptance is the kind of header-parsing
     * slip that sends compressed bytes to something that said it could not read
     * them, and the symptom is a blank page with no error.
     *
     * Quality values are otherwise ignored: the server's preference is what
     * §8.9.13's "where present" means, and DocUp has at most two candidates.
     *
     * @return list<string>
     */
    private static function parse(string $header): array
    {
        $accepted = [];

        foreach (explode(',', strtolower($header)) as $part) {
            $segments = explode(';', trim($part));
            $token = trim($segments[0]);

            if ($token === '') {
                continue;
            }

            $refused = false;

            foreach (array_slice($segments, 1) as $parameter) {
                $parameter = str_replace(' ', '', $parameter);

                if (str_starts_with($parameter, 'q=') && (float) substr($parameter, 2) === 0.0) {
                    $refused = true;
                }
            }

            if (! $refused) {
                $accepted[] = $token;
            }
        }

        return $accepted;
    }
}
