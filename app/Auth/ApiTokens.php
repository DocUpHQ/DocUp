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
     * §8.13.6's optional CIDR binding, capped.
     *
     * 🛑 Every entry is compared on every request this token makes, and the
     * column is a `varchar(255)` — ten IPv4 CIDRs fit with room to spare.
     * A longer list is a network boundary rather than a credential binding and
     * belongs in the proxy.
     */
    public const MAX_CIDR_ENTRIES = 10;

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

        /*
         * 🛑 §8.13.6's "optional CIDR binding", **validated and
         * canonicalised** rather than stored as typed.
         *
         * Phase 26b found the column written at mint and read by nothing, so a
         * token bound to an office range was usable from anywhere. Enforcing it
         * without validating it would have been worse than leaving it unread:
         * an unparseable range matches nothing, {@see self::find()} fails
         * closed, and the operator would get the same 401 a stolen token gets.
         */
        $cidrAllowlist = self::binding($cidrAllowlist);

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
     * effort. §8.13.6's CIDR binding joins that list: "from the wrong
     * network" is reported exactly as "no such token", because the alternative
     * tells somebody holding a stolen token where to go and use it.
     *
     * 🛑 `$remoteAddress` has **no default**, and that is the point. Phase
     * 26b found `cidr_allowlist` written at mint and read by nothing — an
     * optional parameter would have left the next caller free to recreate that
     * state without noticing. A caller with no address passes `null`
     * explicitly, which refuses every bound token.
     *
     * @param  string|null  $remoteAddress  the client's address, from
     *                                      `$request->ip()`. Only the client's
     *                                      once §8.9.4's trusted-proxy list is
     *                                      configured; before Phase 26b it was
     *                                      the edge's.
     */
    public function find(string $plaintext, ?string $remoteAddress): ?ApiToken
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

        /*
         * 🛑 §8.13.6's CIDR binding, enforced here rather than in the
         * middleware, so that it cannot be skipped by a second call site. This
         * class is already "the sole minter, because minting is where
         * §8.13.6's prohibitions are enforced and a second mint path is a
         * second place to forget them" — the same argument makes it the
         * sole resolver.
         */
        if (! $token->allowsAddress($remoteAddress)) {
            return null;
        }

        return $token;
    }

    /**
     * 🛑 §8.13.6's **overlap rotation**, and §17's exit criterion for
     * this phase: "A token rotated with overlap serves both values until the
     * old one's expiry and neither afterwards."
     *
     * The predecessor is deliberately **not revoked**. That is the whole of
     * what overlap means: a deployment holding the old secret in three places
     * keeps working while they are updated one at a time, and the old secret
     * dies on its own expiry rather than on a human remembering to come back.
     * Revoking here would make this a replace rather than a rotate, and would
     * reintroduce the outage rotation exists to avoid.
     *
     * ## 🛑 Why this goes through {@see self::mint()}
     *
     * Rotation mints. Every one of §8.13.6's prohibitions therefore has to
     * apply again — no installation-administrative capability, nothing
     * exceeding the person doing it, mandatory expiry inside the cap — and
     * a rotation path that re-implemented the insert would be the second mint
     * path this class's own docblock refuses to have.
     *
     * 🛑 So a rotation **can fail because the holder has lost a
     * capability** since the token was minted, and that is correct rather than
     * inconvenient: carrying a capability forward onto a new secret for someone
     * who no longer holds it is exactly the escalation
     * {@see TokenRejected::exceedsMinter()} exists to stop, with a delay in
     * front of it.
     *
     * @param  Carbon|null  $expiresAt  the successor's expiry; §8.13.6's
     *                                  default and cap apply
     * @param  Carbon|null  $overlapUntil  an earlier end for the predecessor.
     *                                     🛑 May only SHORTEN: see
     *                                     {@see TokenRejected::overlapExtended()}.
     * @return array{0: ApiToken, 1: string} the successor and its plaintext
     *
     * @throws TokenRejected
     */
    public function rotate(
        ApiToken $token,
        User $actor,
        ?Carbon $expiresAt = null,
        ?Carbon $overlapUntil = null,
    ): array {
        /*
         * 🛑 Rotation returns a plaintext, so rotating another user's token
         * would hand the rotator a credential that acts as them — and the
         * audit chain would show the owner acting. Revocation needs no secret
         * and is the operation an administrator actually wants.
         */
        if (! hash_equals((string) $token->user_id, (string) $actor->id)) {
            throw TokenRejected::notYours();
        }

        if (! $token->isUsable()) {
            throw TokenRejected::notRotatable();
        }

        /*
         * 🛑 Once only, so a family holds at most two live secrets. Without
         * this, rotating repeatedly leaves three or four working credentials and
         * an operator with no idea how many are out there — the state
         * rotation exists to end.
         */
        if ($token->successor()->exists()) {
            throw TokenRejected::alreadyRotated();
        }

        $predecessorExpiry = $token->expires_at;

        if ($overlapUntil !== null
            && $predecessorExpiry !== null
            && $overlapUntil->greaterThan($predecessorExpiry)) {
            throw TokenRejected::overlapExtended();
        }

        $organisation = Organisation::query()->find($token->organisation_id);

        if (! $organisation instanceof Organisation) {
            /*
             * Unreachable while the foreign key holds, and kept because the
             * alternative is `mint()` receiving null and failing on a type
             * error inside a transaction.
             */
            throw TokenRejected::notRotatable();
        }

        $capabilities = [];

        foreach ($token->capabilities as $value) {
            $capability = Capability::tryFrom($value);

            if ($capability === null) {
                /*
                 * 🛑 A capability this build no longer defines. Refused
                 * rather than dropped: silently rotating a token into a
                 * narrower one hands the holder a credential that looks like
                 * their old one and does less, and they will debug the
                 * difference as an outage. The remedy is to mint deliberately.
                 */
                throw TokenRejected::notRotatable();
            }

            $capabilities[] = $capability;
        }

        return DB::transaction(function () use (
            $token, $actor, $organisation, $capabilities, $expiresAt, $overlapUntil
        ): array {
            [$successor, $plaintext] = $this->mint(
                user: $actor,
                organisation: $organisation,
                name: $token->name,
                capabilities: $capabilities,
                expiresAt: $expiresAt,
                scope: $token->scope_type,
                scopeId: $token->scope_id,
                /*
                 * 🛑 The binding is carried forward. A rotation that
                 * dropped it would silently widen where the credential works,
                 * which is the one change a rotation must never make.
                 */
                cidrAllowlist: $token->cidr_allowlist,
            );

            $successor->forceFill(['rotated_from_id' => $token->id])->save();

            if ($overlapUntil !== null) {
                $token->forceFill(['expires_at' => $overlapUntil])->save();
            }

            Audit::record(
                action: 'token.rotated',
                actorType: ActorType::User,
                organisationId: $token->organisation_id,
                actorId: $actor->id,
                subjectType: 'api_token',
                subjectId: $successor->id,
                /*
                 * 🛑 Both ids and the overlap end, because the question an
                 * incident review asks is "how long were two secrets live, and
                 * which were they" — and the chain is append-only
                 * (§8.22.5), so it has to be recorded when it is known.
                 */
                payload: [
                    'rotated_from' => bin2hex($token->id),
                    'overlap_until' => $token->expires_at?->format('Y-m-d H:i:s'),
                ],
            );

            return [$successor, $plaintext];
        });
    }

    /**
     * §8.13.6's CIDR binding, validated and canonicalised.
     *
     * 🛑 Canonicalised so that the stored form and the compared form are
     * the same string — the rule {@see CidrRange::canonicalise()}
     * states and the reason it exists. An operator typing `10.0.0.1/8` means
     * `10.0.0.0/8`, and storing their spelling while comparing against the
     * network would show a binding in the UI that is not the one in force.
     *
     * @throws TokenRejected
     */
    private static function binding(?string $cidrAllowlist): ?string
    {
        if ($cidrAllowlist === null || trim($cidrAllowlist) === '') {
            /* Unbound, which is the default and what most tokens are. */
            return null;
        }

        $entries = array_values(array_filter(
            array_map('trim', explode(',', $cidrAllowlist)),
            static fn (string $entry): bool => $entry !== '',
        ));

        if (count($entries) > self::MAX_CIDR_ENTRIES) {
            throw TokenRejected::cidrTooMany(self::MAX_CIDR_ENTRIES);
        }

        $canonical = [];

        foreach ($entries as $entry) {
            $range = CidrRange::canonicalise($entry);

            if ($range === null) {
                throw TokenRejected::cidrInvalid($entry);
            }

            $canonical[] = $range;
        }

        $joined = implode(',', array_values(array_unique($canonical)));

        if (strlen($joined) > 255) {
            /*
             * 🛑 The column's own width, checked rather than discovered:
             * MySQL in strict mode refuses the insert, which surfaces as a
             * query exception inside a transaction instead of as a message
             * about the field the operator is looking at.
             */
            throw TokenRejected::cidrTooMany(self::MAX_CIDR_ENTRIES);
        }

        return $joined;
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
