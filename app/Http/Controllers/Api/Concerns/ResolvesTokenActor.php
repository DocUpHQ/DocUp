<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers\Api\Concerns;

use App\Http\Middleware\AuthenticateApiToken;
use App\Models\ApiToken;
use Illuminate\Http\Request;

/**
 * The audit actor behind a bearer token.
 *
 * 🛑 The **minting user**, not the token. §8.22.5 keeps the audit chain to
 * opaque identifiers, and a token id would be one — but it would answer the
 * wrong question. "Who published this?" has to survive the token being revoked
 * and rotated, and an incident timeline naming a credential rather than a person
 * is a timeline that stops where the investigation starts.
 *
 * A trait rather than a base controller: the three publish endpoints are
 * single-action classes, and giving them a shared parent to inherit one method
 * from would be a hierarchy built for a four-line helper.
 */
trait ResolvesTokenActor
{
    /** @return string|null raw 16 bytes, or null when the system acted */
    protected function actor(Request $request): ?string
    {
        $token = $request->attributes->get(AuthenticateApiToken::ATTRIBUTE);

        return $token instanceof ApiToken ? $token->user_id : null;
    }
}
