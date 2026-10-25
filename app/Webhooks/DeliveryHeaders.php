<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

/**
 * The request headers a delivery arrived with, as a case-insensitive bag.
 *
 * A value object rather than a `Request`, for the reason §8.9.1 gives the
 * resolver: the verification path should be testable, and reasonable about,
 * without a framework. A test that has to build an HTTP request to check that
 * `X-Hub-Signature-256` beats `x-hub-signature-256` is a test nobody writes.
 *
 * 🛑 Lookup is case-insensitive because HTTP header names are
 * (RFC 9110 §5.1) and because the five providers do not agree on spelling:
 * GitHub sends `X-Hub-Signature-256`, GitLab's Standard Webhooks headers are
 * lowercase by specification, and an HTTP/2 client lowercases everything on
 * the wire regardless. A case-sensitive lookup would make verification depend
 * on which protocol version the provider happened to negotiate.
 */
final readonly class DeliveryHeaders
{
    /** @var array<string, string> lowercased name => first value */
    private array $headers;

    /**
     * `Symfony\HttpFoundation\HeaderBag::all()` hands over
     * `array<string, list<string|null>>`, and a hand-built bag in a test
     * hands over plain strings. Both are accepted; neither is trusted.
     *
     * @param  array<string, string|array<int, string|null>|null>  $headers
     */
    public function __construct(array $headers)
    {
        $normalised = [];

        foreach ($headers as $name => $value) {
            if ($value === null) {
                continue;
            }

            $normalised[strtolower($name)] = is_array($value) ? (string) ($value[0] ?? '') : $value;
        }

        $this->headers = $normalised;
    }

    public function get(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** Whether a header is present and non-empty. */
    public function has(string $name): bool
    {
        $value = $this->get($name);

        return $value !== null && $value !== '';
    }

    /**
     * The first of several names that is present.
     *
     * Gitea and Forgejo send the same payload under different header names,
     * and a Forgejo instance migrated from Gitea may send either. Trying both
     * is not laxity: the secret still has to verify, and the alternative is
     * an installation that silently stops building after an upgrade.
     */
    public function first(string ...$names): ?string
    {
        foreach ($names as $name) {
            $value = $this->get($name);

            if ($value !== null && $value !== '') {
                return $value;
            }
        }

        return null;
    }
}
