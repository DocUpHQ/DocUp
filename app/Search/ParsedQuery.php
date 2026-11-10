<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

/**
 * 🛑 §8.16.12's minimum query syntax, parsed — and the **only** thing a client
 * may influence about a search.
 *
 * > §8.16.12: "Filter expressions MUST NOT be accepted from the client in any
 * > form; scope filters are parsed from the query string and re-derived
 * > server-side against the authorised view (§8.12.21)."
 *
 * So this object holds *what the reader typed*, reduced to three kinds of
 * thing: bare terms (implicit AND), quoted phrases, and scope **requests**. A
 * scope request is a request and not a filter: {@see ScopeRequest} names a
 * project slug or a collection slug, and `App\Search\AuthorisedScope` is what
 * turns it into something the engine will act on, after `EffectiveAccess` has
 * agreed. Nothing on this object reaches an engine's filter expression.
 *
 * 🛑 That asymmetry is the whole defence, and it is why there is no
 * `filter(string $raw)` anywhere in this namespace. Meilisearch's filter syntax
 * is expressive enough to ask "every document whose scope is `restricted`", so
 * a driver that forwarded a client string would be an authorisation bypass with
 * a nice API. An architecture test asserts no request input reaches a driver.
 */
final readonly class ParsedQuery
{
    /**
     * @param  list<string>  $terms  bare terms, implicitly ANDed (§8.16.12)
     * @param  list<string>  $phrases  double-quoted exact phrases (§8.16.12)
     * @param  list<ScopeRequest>  $scopes  `project:`, `collection:` and
     *                                      `self:me`, as requests
     * @param  string  $raw  what the reader typed, kept for §8.16.10's
     *                       round-trip assertion and for nothing else — no
     *                       driver reads it
     */
    public function __construct(
        public array $terms,
        public array $phrases,
        public array $scopes,
        public string $raw,
    ) {}

    /** Nothing to match on: no terms and no phrases. */
    public function isEmpty(): bool
    {
        return $this->terms === [] && $this->phrases === [];
    }

    /**
     * Every searchable token, terms then phrases.
     *
     * Used by the drivers to build their own syntax. Phrases stay whole:
     * a phrase is one unit of meaning and splitting it here would turn
     * `"access token"` into two ANDed terms, which is a different query.
     *
     * @return list<string>
     */
    public function tokens(): array
    {
        return [...$this->terms, ...$this->phrases];
    }
}
