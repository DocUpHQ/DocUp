<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

/**
 * 🛑 §12.3's last conjunct: "share/bearer scope covers (project, version, path)
 * if that was the satisfying leaf".
 *
 * §8.12.16 gives both scoped credentials their shape — a share link converted
 * to a cookie on first use, and "`Authorization: Bearer` reader tokens with
 * version and path scope, `max_uses` and revocation". This is that scope, as
 * the decision function sees it.
 *
 * 🛑 **Narrower than the rule that admitted the reader, never wider.** The
 * conjunct is an intersection like every other in §12.3: a bearer token scoped
 * to `/v2/api/` held by a member does not widen the member's access, and a
 * member's role does not widen the token's scope. Which of the two applies is
 * decided by {@see Requirement::satisfyingLeaf()} — the strongest satisfying
 * leaf — so a reader who did not need the token is not held to it.
 */
final class CredentialScope
{
    /**
     * @param  string|null  $projectId  raw 16 bytes, or null for any project
     *                                  this credential's rule admits
     * @param  list<string>  $versionSlugs  permitted version slugs; empty means
     *                                      every version the rule admits
     * @param  list<string>  $pathPrefixes  permitted normalised path prefixes,
     *                                      relative to the version root; empty
     *                                      means every path
     */
    public function __construct(
        public readonly ?string $projectId = null,
        public readonly array $versionSlugs = [],
        public readonly array $pathPrefixes = [],
    ) {}

    /**
     * Whether this scope covers a (project, version, path).
     *
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $path  normalised, leading slash, relative to the
     *                        version root
     */
    public function covers(string $projectId, string $versionSlug, string $path): bool
    {
        if ($this->projectId !== null && ! hash_equals($this->projectId, $projectId)) {
            return false;
        }

        if ($this->versionSlugs !== [] && ! in_array($versionSlug, $this->versionSlugs, true)) {
            return false;
        }

        if ($this->pathPrefixes === []) {
            return true;
        }

        foreach ($this->pathPrefixes as $prefix) {
            if (PathPrefix::covers($prefix, $path)) {
                return true;
            }
        }

        return false;
    }
}
