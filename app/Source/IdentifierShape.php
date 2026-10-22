<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * The two shapes a provider-stable repository identifier comes in, and the
 * third case where there is none.
 *
 * Separated from {@see Provider} so the canonicalisation rules are stated once
 * and tested once, rather than once per provider that happens to use integers.
 */
enum IdentifierShape: string
{
    /** GitHub, GitLab, Gitea, Forgejo, Bitbucket Server: a positive `int64`. */
    case Integer = 'integer';

    /** Bitbucket Cloud: `{585074de-7b60-4fd1-81ed-e0bc7fafbda5}`. */
    case BracedUuid = 'braced_uuid';

    /** A generic remote. The §8.3.8 normalised-URL path carries it instead. */
    case None = 'none';

    /** The canonical form to store, or null when the value does not fit. */
    public function canonicalise(string $raw): ?string
    {
        $raw = trim($raw);

        return match ($this) {
            /*
             * Leading zeros are stripped because `042` and `42` are one
             * repository and two strings. The 19-digit ceiling is `int64`'s:
             * a longer run of digits is not an identifier any of these
             * providers issued, and silently truncating it would map two
             * repositories onto one row.
             */
            self::Integer => preg_match('/^0*([1-9][0-9]{0,18})$/', $raw, $m) === 1 ? $m[1] : null,

            /*
             * Braces off, lower-cased. Bitbucket returns the braced form from
             * both the API and webhooks, and the UUID itself is
             * case-insensitive, so the stored form has to pick one of each or
             * the uniqueness constraint is decorative.
             */
            self::BracedUuid => preg_match(
                '/^\{?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\}?$/i',
                $raw,
                $m
            ) === 1 ? strtolower($m[1]) : null,

            self::None => null,
        };
    }
}
