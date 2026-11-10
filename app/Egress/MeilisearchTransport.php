<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Egress;

use App\Search\SearchRefused;
use App\Search\SearchRejection;
use App\Search\SearchTransport;

/**
 * The wire to Meilisearch — §8.16.1's optional engine.
 *
 * ## 🛑 Why this is in `App\Egress` and why it is not `HardenedEgressClient`
 *
 * It is **in this namespace** because the architecture test for §8.3.9 forbids
 * any HTTP mechanism anywhere else, and that rule is worth keeping absolute:
 * the reason it exists is that a second outbound path "gets written in a hurry
 * … by somebody who did not know this class existed". Putting the curl here
 * means a reviewer looking for everything that speaks HTTP finds this too.
 *
 * It is **not** `HardenedEgressClient` because that client implements an
 * address policy for URLs derived from *tenant* configuration: HTTPS only,
 * public addresses only, DNS rebind detection, redirect refusal. Meilisearch
 * runs at an address the operator put in the installation's environment,
 * normally inside the deployment's own network and over plain HTTP, and §8.3.9
 * scopes itself to "every outbound request derived from **user-supplied
 * configuration**". `config/egress.php` makes the same distinction in its own
 * words for ACME directories: "an ACME directory an operator put in that file
 * is installation configuration, in the same class as `DB_HOST` — not something
 * a tenant can set."
 *
 * 🛑 So the control here is not an address policy but **reachability**: the
 * destination comes from one configuration key, the public method takes a
 * **path** and not a URL, and a path that is not origin-relative is refused. No
 * tenant input, no project input and no reader input can influence where this
 * connects. `SearchArchitectureTest` asserts all three.
 *
 * ## 🛑 The key
 *
 * §8.12.21: "search-engine tenant tokens MUST NEVER reach a browser
 * (Meilisearch tenant tokens are plain HS256 — readable by the browser and
 * unrevocable before expiry)." DocUp mints none: §8.16.6 requires search to be
 * "proxied server-side" and that is what it does, so there is never a reason to
 * hand a browser a token. The admin key is read from the environment, used in
 * an `Authorization` header, and has no accessor — and it is deliberately
 * absent from every exception message and every log line here, because a key in
 * an exception is a key in the error tracker.
 */
final readonly class MeilisearchTransport implements SearchTransport
{
    /** The response cap, in bytes. */
    private const int MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

    /** The methods this transport will speak. */
    private const array METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];

    public function isConfigured(): bool
    {
        return $this->origin() !== null;
    }

    /**
     * @param  array<array-key, mixed>|null  $payload
     * @return array{status: int, body: array<array-key, mixed>}
     */
    public function send(string $method, string $path, ?array $payload = null): array
    {
        $origin = $this->origin();

        if ($origin === null) {
            throw new SearchRefused(SearchRejection::EngineUnreachable, ['reason' => 'no engine address configured']);
        }

        $method = strtoupper($method);

        if (! in_array($method, self::METHODS, true)) {
            throw new SearchRefused(SearchRejection::EngineRefused, ['method' => $method]);
        }

        /*
         * 🛑 Origin-relative or nothing. A `//evil.example` or an
         * `http://evil.example/…` arriving here would otherwise be a URL, and
         * the whole point of this class taking a path is that it cannot be
         * handed one. Checked rather than normalised, for §8.9.6's reason: a
         * normalisation produces a plausible path and the question is whether
         * the caller was allowed to write that one.
         */
        if (! str_starts_with($path, '/') || str_starts_with($path, '//') || str_contains($path, '..')) {
            throw new SearchRefused(SearchRejection::EngineRefused, ['reason' => 'path is not origin-relative']);
        }

        $body = $payload === null ? null : json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($payload !== null && ! is_string($body)) {
            throw new SearchRefused(SearchRejection::EngineRefused, ['reason' => 'payload could not be encoded']);
        }

        $headers = ['Accept: application/json', 'Content-Type: application/json'];
        $key = $this->key();

        if ($key !== null) {
            $headers[] = 'Authorization: Bearer '.$key;
        }

        $handle = curl_init();
        $captured = '';
        $exceeded = false;

        curl_setopt_array($handle, [
            CURLOPT_URL => $origin.$path,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,

            /*
             * No redirects, for the reason `PinnedCurlTransport` gives: a
             * redirect is a second destination nobody reviewed, and Meilisearch
             * never issues one.
             */
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,

            CURLOPT_TIMEOUT => $this->timeout(),
            CURLOPT_CONNECTTIMEOUT => $this->timeout(),
            CURLOPT_NOSIGNAL => true,

            /*
             * 🛑 The byte cap is enforced **mid-transfer** rather than after,
             * which is `PinnedCurlTransport`'s finding: a `CURLOPT_MAXFILESIZE`
             * trusts `Content-Length`, and a response without one is not capped
             * at all.
             */
            CURLOPT_WRITEFUNCTION => function (\CurlHandle $_, string $chunk) use (&$captured, &$exceeded): int {
                if (strlen($captured) + strlen($chunk) > self::MAX_RESPONSE_BYTES) {
                    $exceeded = true;

                    return 0;
                }

                $captured .= $chunk;

                return strlen($chunk);
            },
        ]);

        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_errno($handle);
        curl_close($handle);

        if ($exceeded) {
            throw new SearchRefused(SearchRejection::EngineRefused, ['reason' => 'response exceeded the byte cap']);
        }

        if ($error !== 0 || $status === 0) {
            /*
             * 🛑 The curl error *number*, never its message and never the URL.
             * A message can carry the host and a resolved address, and this
             * exception reaches the log.
             */
            throw new SearchRefused(SearchRejection::EngineUnreachable, ['curl' => $error]);
        }

        $decoded = $captured === '' ? [] : json_decode($captured, true, 64);

        return ['status' => $status, 'body' => is_array($decoded) ? $decoded : []];
    }

    /**
     * The configured origin — scheme, host and port, with no trailing slash.
     *
     * 🛑 Parsed and **re-serialised** from its parts rather than trimmed, which
     * is §8.14.2's rule applied one namespace over: "every emitted value MUST
     * be re-serialised from the parsed representation, never echoed from
     * storage". A configuration value carrying a path, a query or userinfo —
     * `http://meili:7700/indexes?x=1`, or a copy-pasted URL with a key in it —
     * contributes its host and port here and nothing else. Userinfo in
     * particular is dropped rather than forwarded, because a credential in a
     * URL is a credential in every proxy log between here and the engine
     * (§8.3.3).
     */
    private function origin(): ?string
    {
        $configured = config('docup.search.meilisearch.url');

        if (! is_string($configured) || trim($configured) === '') {
            return null;
        }

        $parts = parse_url(trim($configured));

        if (! is_array($parts)) {
            return null;
        }

        $scheme = strtolower(is_string($parts['scheme'] ?? null) ? $parts['scheme'] : '');
        $host = is_string($parts['host'] ?? null) ? $parts['host'] : '';

        if (($scheme !== 'http' && $scheme !== 'https') || $host === '') {
            return null;
        }

        $port = is_int($parts['port'] ?? null) ? ':'.$parts['port'] : '';

        return $scheme.'://'.$host.$port;
    }

    /** The admin key, or null when the engine needs none. */
    private function key(): ?string
    {
        $key = config('docup.search.meilisearch.key');

        return is_string($key) && trim($key) !== '' ? trim($key) : null;
    }

    /** The per-request timeout, clamped to something a reader can wait for. */
    private function timeout(): int
    {
        $configured = config('docup.search.meilisearch.timeout_seconds');

        $seconds = is_numeric($configured) ? (int) $configured : 5;

        return max(1, min(30, $seconds));
    }
}
