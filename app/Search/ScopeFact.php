<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Search;

use App\Auth\AccessLevel;

/**
 * One row of `search_mount_scopes`, as the server derived it.
 *
 * This is §8.16.8's "complete filterable attribute set" in object form —
 * project, version, language, visibility scope, build generation — and §8.16.6's
 * "each matched mount's `min_access`" beside it.
 *
 * 🛑 **Every field here came from the database, never from a request.** That is
 * the whole of §8.16.6's "server-side only" and §8.16.12's "re-derived
 * server-side against the authorised view": the reader supplies a query string
 * and an identity, and the set of these objects they may search over is
 * computed from project authorisation, version visibility and mount exposure.
 * A {@see ScopeRequest} can only ever *narrow* a set of these; it can never add
 * one.
 */
final readonly class ScopeFact
{
    /**
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $projectSlug  the live slug, read at query time — never
     *                               stored on a search row, because §8.8.1's
     *                               reasoning applies to a cached URL as much
     *                               as to a storage key: a renamed project must
     *                               not strand its own search results
     * @param  string  $versionId  raw 16 bytes
     * @param  string  $versionSlug  the live slug, read at query time
     * @param  string|null  $manifestId  raw 16 bytes — the version's published
     *                                   manifest, which §8.16.5 makes the
     *                                   authority for the mount path
     * @param  string  $buildId  canonical UUID text, as the manifest spells it
     * @param  int  $buildGeneration  which document generation of that build
     * @param  AccessLevel  $scope  🛑 §8.12.21's visibility scope identifier
     * @param  AccessLevel|null  $minAccess  §8.7.7's published ceiling
     * @param  string  $channel  `default`, `stable` or `latest` (§8.16.9)
     */
    public function __construct(
        public string $projectId,
        public string $projectSlug,
        public string $versionId,
        public string $versionSlug,
        public ?string $manifestId,
        public string $buildId,
        public int $buildGeneration,
        public string $language,
        public AccessLevel $scope,
        public ?AccessLevel $minAccess,
        public string $channel,
    ) {}

    /**
     * The key a hit is matched back to its scope by.
     *
     * A build plus the generation it was read at, because a build mounted by
     * two projects at two generations is two facts over one document set.
     */
    public function documentKey(): string
    {
        return $this->buildId.'@'.$this->buildGeneration;
    }
}
