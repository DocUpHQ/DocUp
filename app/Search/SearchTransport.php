<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 The wire to an external search engine — and it takes a **path**, never a
 * URL.
 *
 * That signature is the structural defence, not a convenience. §8.3.9 requires
 * every outbound request derived from user-supplied configuration to go through
 * one hardened client, and an architecture test forbids any HTTP mechanism
 * outside `App\Egress`. A search engine's address is **installation**
 * configuration — the same class as `DB_HOST`, and `config/egress.php` says so
 * about the equivalent case — so it does not need the address policy; what it
 * does need is to be impossible to point somewhere else.
 *
 * Hence: the caller names `/indexes/docup/search`, the implementation prepends
 * the configured origin, and there is no parameter through which a host, a
 * scheme or a port can arrive. `SearchArchitectureTest` asserts the only
 * implementation lives in `App\Egress` and refuses a path that is not
 * origin-relative.
 *
 * 🛑 And the key never comes back out. §8.12.21: "search-engine tenant tokens
 * MUST NEVER reach a browser (Meilisearch tenant tokens are plain HS256 —
 * readable by the browser and unrevocable before expiry)." DocUp mints no
 * tenant tokens at all, and the admin key is held by the implementation and
 * exposed by no method here. There is nothing to leak because there is no
 * getter.
 */
interface SearchTransport
{
    /** Whether an engine address is configured at all. */
    public function isConfigured(): bool;

    /**
     * One JSON request to the configured engine.
     *
     * @param  string  $method  `GET`, `POST`, `PUT`, `PATCH` or `DELETE`
     * @param  string  $path  origin-relative, beginning with `/`
     * @param  array<array-key, mixed>|null  $payload  encoded as JSON, or null
     *                                                 for a request with no body
     * @return array{status: int, body: array<array-key, mixed>}
     *
     * @throws SearchRefused when the engine cannot be reached or the path is
     *                       not origin-relative
     */
    public function send(string $method, string $path, ?array $payload = null): array;
}
