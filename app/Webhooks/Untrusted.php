<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Versions\RefKind;

/**
 * Reading a provider's JSON without believing any of it.
 *
 * 🛑 §8.3.7 already says this about provider responses — "treating every
 * provider response as untrusted input" — and a webhook body is the same
 * thing arriving by a different route. The signature proves the provider
 * sent it. It does not prove the shape: a `ref` may be an array, a commit
 * `id` may be an object, `commits` may be a JSON object with numeric string
 * keys rather than a list, and any of those turns `$payload['ref']` into a
 * `TypeError` five frames deeper.
 *
 * Every accessor here returns the declared type or a stated fallback, so a
 * malformed payload becomes a parser returning null — a 202 with
 * {@see WebhookRejection::UnsupportedEvent} — rather than a 500 that teaches
 * the provider to redeliver.
 */
final readonly class Untrusted
{
    /**
     * A string at a dotted path, or null.
     *
     * @param  array<array-key, mixed>  $payload
     */
    public static function string(array $payload, string $path): ?string
    {
        $value = self::at($payload, $path);

        /*
         * Integers are accepted and stringified because four of the five
         * providers send `repository.id` as a JSON number, and `(string) 42`
         * is the canonical form §18.27's identifier work settled on. Floats
         * and booleans are not: a `repository.id` of `4.2e1` is a payload
         * nobody should be interpreting.
         */
        if (is_int($value)) {
            return (string) $value;
        }

        return is_string($value) ? $value : null;
    }

    /**
     * An integer at a dotted path, or null.
     *
     * @param  array<array-key, mixed>  $payload
     */
    public static function int(array $payload, string $path): ?int
    {
        $value = self::at($payload, $path);

        if (is_int($value)) {
            return $value;
        }

        // GitLab sends `total_commits_count` as a number; some proxies and
        // some provider versions stringify it. Accepted only when the string
        // is unambiguously an integer.
        return is_string($value) && preg_match('/^\d{1,18}$/', $value) === 1 ? (int) $value : null;
    }

    /** @param array<array-key, mixed> $payload */
    public static function bool(array $payload, string $path): bool
    {
        return self::at($payload, $path) === true;
    }

    /**
     * A list of strings at a dotted path; anything else is dropped.
     *
     * 🛑 Entries that are not strings are **skipped, not stringified**. A
     * changed-path array containing an object would otherwise become the
     * literal `Array` in a glob comparison, and a path that matches nothing
     * is indistinguishable from a path that was not sent.
     *
     * @param  array<array-key, mixed>  $payload
     * @return list<string>
     */
    public static function strings(array $payload, string $path): array
    {
        $value = self::at($payload, $path);

        if (! is_array($value)) {
            return [];
        }

        $strings = [];

        foreach ($value as $entry) {
            if (is_string($entry) && $entry !== '') {
                $strings[] = $entry;
            }
        }

        return $strings;
    }

    /**
     * A list of sub-arrays at a dotted path; anything else is dropped.
     *
     * @param  array<array-key, mixed>  $payload
     * @return list<array<array-key, mixed>>
     */
    public static function objects(array $payload, string $path): array
    {
        $value = self::at($payload, $path);

        if (! is_array($value)) {
            return [];
        }

        $objects = [];

        foreach ($value as $entry) {
            if (is_array($entry)) {
                $objects[] = $entry;
            }
        }

        return $objects;
    }

    /**
     * Walk a dotted path without assuming any level exists.
     *
     * @param  array<array-key, mixed>  $payload
     */
    private static function at(array $payload, string $path): mixed
    {
        $cursor = $payload;

        foreach (explode('.', $path) as $segment) {
            if (! is_array($cursor) || ! array_key_exists($segment, $cursor)) {
                return null;
            }

            $cursor = $cursor[$segment];
        }

        return $cursor;
    }

    /**
     * Split `refs/heads/main` into its kind and short name.
     *
     * 🛑 Returns null for anything that is not a branch or a tag.
     * `refs/pull/42/head`, `refs/notes/commits` and `refs/merge-requests/7/head`
     * all arrive at this endpoint, and treating one as a branch would create
     * a reader-visible version for a pull request — which §8.20 says is a
     * preview, built on a different domain with `no-store`, and not this.
     *
     * @return array{0: RefKind, 1: string}|null
     */
    public static function splitRef(?string $ref): ?array
    {
        if ($ref === null) {
            return null;
        }

        if (str_starts_with($ref, 'refs/heads/')) {
            $name = substr($ref, 11);

            return $name === '' ? null : [RefKind::Branch, $name];
        }

        if (str_starts_with($ref, 'refs/tags/')) {
            $name = substr($ref, 10);

            return $name === '' ? null : [RefKind::Tag, $name];
        }

        return null;
    }

    /**
     * Whether a SHA field means "this ref no longer exists".
     *
     * Git's null object id. GitHub, GitLab and Gitea all signal a deleted
     * ref by sending forty zeros in `after`, and GitHub additionally sets
     * `deleted: true` — which is checked separately, because the two have
     * disagreed in the past for tag deletions.
     */
    public static function isNullSha(?string $sha): bool
    {
        return $sha !== null && trim($sha, '0') === '';
    }
}
