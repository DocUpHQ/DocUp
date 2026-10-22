<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Auth\ApiTokens;
use App\Auth\OrganisationContext;
use App\Models\ApiToken;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Authenticates a request with a scoped bearer token and declares its tenant
 * (§8.21.2, §8.2.1).
 *
 * 🛑 **The token carries the tenant; the URL does not.** A token is minted for
 * one organisation and that is where its request operates. The alternative —
 * reading an organisation slug from the path and checking the token against it —
 * adds a comparison that can be got wrong, and §8.9.4 is emphatic that no
 * request header or path segment may be trusted to resolve a tenant. Taking it
 * from the credential removes the question.
 *
 * 🛑 **Every rejection is 401 with the same body.** "Expired", "revoked" and
 * "never existed" must be indistinguishable, or somebody sorting through stolen
 * tokens learns which are worth more effort. {@see ApiTokens::find()} already
 * returns null for all three for the same reason; this middleware must not
 * undo that by reporting which.
 */
final class AuthenticateApiToken
{
    /** The request attribute the token is published under. */
    public const ATTRIBUTE = 'api_token';

    public function __construct(
        private readonly ApiTokens $tokens,
        private readonly OrganisationContext $context,
    ) {}

    public function handle(Request $request, \Closure $next): Response
    {
        $plaintext = $this->bearer($request);

        if ($plaintext === null) {
            return $this->unauthorised();
        }

        $token = $this->tokens->find($plaintext);

        if (! $token instanceof ApiToken) {
            return $this->unauthorised();
        }

        /*
         * Declared before `$next`, because route-model binding runs downstream
         * and resolves through the §8.2.1 global scope. Without the context
         * declared first, binding throws rather than filtering — which is the
         * safe direction, and the reason bootstrap/app.php prepends
         * ResolveOrganisation before SubstituteBindings for the web group.
         */
        $this->context->for($token->organisation_id);

        $request->attributes->set(self::ATTRIBUTE, $token);

        /*
         * Recorded before handling, not after. A request that times out or
         * crashes still used the token, and "last used" is read by an operator
         * deciding whether a token is dormant enough to revoke — an undercount
         * there argues for revoking a token that is in use.
         *
         * `updated_at` is deliberately left alone: a touch per request would
         * make the column meaningless and would write a row on every read.
         */
        $token->forceFill(['last_used_at' => now()])->saveQuietly();

        return $next($request);
    }

    /**
     * The bearer credential, or null.
     *
     * Only `Authorization: Bearer`, which is what §8.21.2 specifies. A query
     * parameter fallback is not offered on purpose: query strings reach access
     * logs, proxy logs, `Referer` headers and browser history, so a token in
     * one is a token that has been written down in four places nobody audits.
     */
    private function bearer(Request $request): ?string
    {
        $header = $request->header('Authorization');

        if (! is_string($header)) {
            return null;
        }

        if (! str_starts_with($header, 'Bearer ')) {
            return null;
        }

        $value = trim(substr($header, 7));

        return $value === '' ? null : $value;
    }

    private function unauthorised(): Response
    {
        return response()->json([
            'error' => 'unauthenticated',
            'message' => 'A valid bearer token is required.',
        ], 401, ['WWW-Authenticate' => 'Bearer']);
    }
}
