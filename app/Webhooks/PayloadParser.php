<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

/**
 * One provider's push payload, read into {@see PushEvent}.
 *
 * Separate from {@see SignatureScheme} because the two axes genuinely do not
 * line up: GitHub and Bitbucket share a signature scheme and share nothing
 * about their payloads, while Gitea and Forgejo share a payload and spell
 * their headers differently. Folding them into one "provider adapter" would
 * mean five copies of two algorithms instead of four schemes and five
 * parsers.
 */
interface PayloadParser
{
    /**
     * Read a decoded payload into zero or more pushes.
     *
     * 🛑 An **empty** list is the normal case, not an error path: `ping`,
     * `issue_comment`, `pull_request` and two dozen other events arrive at
     * the same URL, and a provider that got a 4xx for one of them would
     * eventually disable the hook. The caller answers 202 with
     * {@see WebhookRejection::UnsupportedEvent}.
     *
     * 🛑 **More than one** is equally normal, and is the case that gets
     * forgotten: `git push --all` reaches Bitbucket as one delivery with one
     * entry per ref. A signature returning a single event would silently
     * drop every ref but the first, and the symptom — "only one of my four
     * tags built" — looks like a scheduling problem rather than a parsing
     * one.
     *
     * Everything in `$payload` is untrusted. The implementation reads what
     * it needs with explicit type checks and ignores the rest; it never
     * trusts a string to be a SHA, a ref to be well-formed, or an array to
     * be a list.
     *
     * @param  array<array-key, mixed>  $payload  the decoded JSON body
     * @param  string|null  $event  the provider's own event name, from its header
     */
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array;
}
