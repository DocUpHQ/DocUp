<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Access\ReaderPolicies;
use App\Models\DocsSession;

/**
 * One live `docs_sessions` row, as the serving path sees it.
 *
 * 🛑 **Not the Eloquent model, and the reason is Phase 20's note repeated.**
 * The documentation origin has no tenant context — a reader is not a tenant —
 * so a model carrying §8.2.1's global organisation scope would either filter
 * the row away or require the serving path to declare a context it has no
 * business declaring. {@see ReaderPolicies} reads its policy rows
 * the same way and for the same reason.
 *
 * {@see DocsSession} remains, and is what the dashboard's session
 * inventory and revocation use, where a tenant context exists and belongs.
 */
final readonly class SessionRecord
{
    /**
     * @param  string  $id  raw 16 bytes
     * @param  string  $organisationId  raw 16 bytes
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $domainId  raw 16 bytes
     * @param  string|null  $userId  raw 16 bytes; 🛑 exclusive of the next
     * @param  string|null  $readerIdentityId  raw 16 bytes (§8.12.1)
     */
    public function __construct(
        public string $id,
        public string $organisationId,
        public string $projectId,
        public string $domainId,
        public ?string $userId,
        public ?string $readerIdentityId,
    ) {}
}
