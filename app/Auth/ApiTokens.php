<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\Exceptions\TokenRejected;
use App\Models\ApiToken;
use App\Models\Organisation;
use App\Models\User;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;

/**
 * Mints and verifies dashboard API tokens (§8.13.6).
 *
 * The sole minter, because minting is where §8.13.6's prohibitions are
 * enforced and a second mint path is a second place to forget them.
 */
final class ApiTokens
{
    /** §8.13.6: mandatory expiry, defaulting to 90 days and capped at 365. */
    public const DEFAULT_LIFETIME_DAYS = 90;

    public const MAXIMUM_LIFETIME_DAYS = 365;

    /**
     * Injected because {@see self::find()} has to span organisations: a bearer
     * token is where tenancy comes from, so looking one up cannot itself be a
     * tenant-scoped question. See the note in that method.
     */
    public function __construct(private readonly OrganisationContext $context) {}

    /**
     * Mint a token and return the **plaintext**, once.
     *
     * @param  list<Capability>  $capabilities
     * @return array{0: ApiToken, 1: string}
     *
     * @throws TokenRejected
     */
    public function mint(
        User $user,
        Organisation $organisation,
        string $name,
        array $capabilities,
        ?Carbon $expiresAt = null,
        Scope $scope = Scope::Organisation,
        ?string $scopeId = null,
        ?string $cidrAllowlist = null,
    ): array {
        if ($capabilities === []) {
            throw TokenRejected::noCapabilities();
        }

        /*
         * 🛑 §8.13.6: "No token MUST hold installation-scope administrative
         * capability, validated at mint."
         *
         * At mint, not at use, because such a token is dangerous the moment it
         * exists — it only has to leak once, and a check at every use site is a
         * list somebody forgets to consult. The question is asked of the
         * capability itself, so one added in a later phase is covered when it
         * exists rather than when someone remembers to extend a list here.
         */
        foreach ($capabilities as $capability) {
            if ($capability->isInstallationAdministrative()) {
                throw TokenRejected::installationAdministrative($capability);
            }
        }

        /*
         * 🛑 A token may never exceed the capabilities of the person minting it.
         *
         * Not in §8.13.6 explicitly, and necessary for it to mean anything:
         * without this, `token.mint` is an escalation primitive. Mint a token
         * holding more than you do, then act as the token. The prohibition on
         * installation-administrative capability would be trivially bypassed by
         * anyone who could mint at all.
         */
        /*
         * 🛑 "Anywhere in the organisation", not "at organisation scope".
         *
         * This read `capabilitiesFor($user, null, $organisation->id)` until
         * Phase 03, which resolves installation and organisation scope but not
         * project scope — so a `project_admin` was told they could not mint a
         * token carrying `project.version.publish`, a capability they hold.
         * §8.13.6's rule is that a token may not exceed its minter; it is not
         * that the minter must hold it at organisation level.
         *
         * Breadth here is safe because it is not the only check. The token is
         * re-checked against the specific project on every request
         * ({@see \App\Http\Middleware\RequireTokenCapability}), so a project
         * admin's token can publish to their project and nowhere else.
         */
        $held = app(RoleResolver::class)->capabilitiesAnywhereIn($user, $organisation->id);

        foreach ($capabilities as $capability) {
            if (! in_array($capability, $held, true)) {
                throw TokenRejected::exceedsMinter($capability);
            }
        }

        $expiresAt ??= now()->addDays(self::DEFAULT_LIFETIME_DAYS);

        if ($expiresAt->isPast()) {
            throw TokenRejected::expiryInThePast();
        }

        if ($expiresAt->greaterThan(now()->addDays(self::MAXIMUM_LIFETIME_DAYS))) {
            throw TokenRejected::expiryTooFar();
        }

        $scopeId = $scope === Scope::Installation ? null : ($scopeId ?? $organisation->id);
        $plaintext = SecretToken::generate('docup_pat');

        $values = array_map(static fn (Capability $c): string => $c->value, $capabilities);

        return DB::transaction(function () use (
            $user, $organisation, $name, $values, $expiresAt, $scope, $scopeId, $cidrAllowlist, $plaintext
        ): array {
            $token = new ApiToken;

            $token->forceFill([
                'id' => Uuid::v7(),
                'organisation_id' => $organisation->id,
                'user_id' => $user->id,
                'name' => $name,
                'token_hash' => SecretToken::hash($plaintext),
                'token_hash_prefix' => SecretToken::prefix($plaintext),
                'scope_type' => $scope->value,
                'scope_id' => $scopeId,
                'capabilities' => $values,
                'expires_at' => $expiresAt,
                'cidr_allowlist' => $cidrAllowlist,
            ])->save();

            Audit::record(
                action: 'token.minted',
                actorType: ActorType::User,
                organisationId: $organisation->id,
                actorId: $user->id,
                subjectType: 'api_token',
                subjectId: $token->id,
                // 🛑 The capability list is recorded deliberately. Which powers
                // a credential was given is exactly what an incident review
                // needs, and none of it is personal data, so it is safe in a
                // payload that can never be edited (§8.22.5).
                payload: [
                    'capabilities' => $values,
                    'expires_at' => $expiresAt->format('Y-m-d'),
                    'scope' => $scope->value,
                ],
            );

            return [$token, $plaintext];
        });
    }

    /**
     * Find the token a presented plaintext belongs to, or null.
     *
     * The indexed prefix narrows to a candidate without scanning; the
     * comparison then happens on the full hash in constant time.
     *
     * 🛑 Returns null for an unusable token rather than distinguishing why.
     * "Expired", "revoked" and "never existed" must look identical to a bearer,
     * or an attacker sorting through stolen tokens learns which are worth more
     * effort.
     */
    public function find(string $plaintext): ?ApiToken
    {
        /*
         * 🛑 Resolved OUTSIDE the §8.2.1 tenancy scope, deliberately, and for
         * the same reason {@see \App\Http\Middleware\ResolveOrganisation}
         * resolves an organisation outside it: this is where tenancy comes
         * from. A bearer token is a credential, and "which token is this"
         * cannot be a tenant-scoped question — there is no tenant until the
         * answer arrives. Scoped, the query ran before any context was declared
         * and every API request died with TenancyContextMissing.
         *
         * Safe because the credential is the whole authority. Spanning
         * organisations here cannot leak anything: the caller must already hold
         * the secret, and the only row that can match is the one it belongs to.
         * The middleware declares the context from the token immediately
         * afterwards, so everything downstream is scoped again.
         */
        $token = $this->context->acrossAllOrganisations(
            fn (): ?ApiToken => ApiToken::query()
                ->where('token_hash_prefix', SecretToken::prefix($plaintext))
                ->get()
                ->first(fn (ApiToken $candidate): bool => SecretToken::matches($plaintext, $candidate->token_hash)),
        );

        if (! $token instanceof ApiToken || ! $token->isUsable()) {
            return null;
        }

        return $token;
    }

    /** Revoke a token, auditing the revocation. */
    public function revoke(ApiToken $token, User $actor): void
    {
        DB::transaction(function () use ($token, $actor): void {
            $token->forceFill(['revoked_at' => now()])->save();

            Audit::record(
                action: 'token.revoked',
                actorType: ActorType::User,
                organisationId: $token->organisation_id,
                actorId: $actor->id,
                subjectType: 'api_token',
                subjectId: $token->id,
            );
        });
    }
}
