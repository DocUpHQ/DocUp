<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Saml;

use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The sole reader and writer of `saml_auth_requests`.
 *
 * `App\Auth\Providers\Oidc\OidcExchange`'s sibling, and the argument for it
 * being a class rather than three queries in a controller is the same one:
 * single use is a single atomic conditional write, and a second place that
 * consumed a row would be a second answer to "has this been used".
 *
 * ## 🛑 `RelayState` is an index, and this class is the index
 *
 * ADR 0013 measured that Keycloak returns `RelayState` unmodified, and then
 * recorded the thing that matters — it is **reader-supplied on the way back**,
 * exactly like OIDC's `state`. So it is never a URL, never a domain name and
 * never anything concatenated into a redirect: it is an opaque CSPRNG token
 * that looks a row up, and the row carries the verified domain §8.12.10
 * requires the return address to be built from.
 *
 * ## 🛑 Two secrets with different jobs
 *
 * `RelayState` is hashed because it is the security token: holding it is what
 * lets a response be bound to a login somebody started. The `<AuthnRequest>`
 * `ID` is stored in the clear because it is not a secret — it travels through
 * the browser both ways, and `InResponseTo` is only checked after both
 * signatures verify, so forging one needs the identity provider's key. The
 * migration's column comment carries the full reasoning.
 *
 * ## 🛑 Why SAML needs this table even though it has no PKCE
 *
 * §8.12.18 requires `InResponseTo` verified, so DocUp must remember a request
 * id it sent. The dashboard session cannot hold it: a reader at a SAML binding
 * is not signed in to the dashboard, and a session holds one value per key — so
 * two guarded projects in two tabs would have the second login overwrite the
 * first's request id, and the first reader's valid assertion would then be
 * refused as `InResponseToUnknown`.
 */
final readonly class SamlExchange
{
    /**
     * 🛑 How long a login may stay in flight.
     *
     * Ten minutes, the figure `OidcExchange::TTL_SECONDS` uses and for the same
     * reason: the reader has to *sign in* inside this window, which may mean a
     * password manager, a second factor and a consent screen. Deliberately the
     * same number across both protocols — two different windows would be two
     * numbers to tune and no requirement distinguishes them.
     */
    public const int TTL_SECONDS = 600;

    /**
     * 🛑 **One**, where `OidcExchange::MAX_ATTEMPTS` is two — and the
     * difference is a real asymmetry between the protocols, not an oversight.
     *
     * OIDC allows a second attempt because its exchange has a leg that can fail
     * *before* anything is spent: the back-channel call to the token endpoint
     * may time out, which is the provider's fault and not the reader's, so
     * `OidcExchange::recordAttempt()` releases the row for one retry.
     *
     * SAML has no such leg. The assertion arrives complete, and by the time
     * anything DocUp-side can fail — minting the handoff code, resolving the
     * domain — `ResponseValidator` has already written the assertion id to the
     * replay cache. A retry would therefore present the same assertion and be
     * refused as `AssertionReplayed`, so releasing the row would be theatre:
     * the reader would get a second attempt that cannot succeed.
     *
     * 🛑 Which is why there is **no** `recordAttempt()` here. A method that
     * released a row for a retry that cannot work is worse than its absence,
     * because the next reader of this class would believe the retry path
     * existed.
     *
     * The guard stays in the latch's `WHERE` even though `consumed_at` already
     * refuses a second claim: it is one condition, it costs nothing, and it
     * holds if a future change ever clears `consumed_at`.
     */
    public const int MAX_ATTEMPTS = 1;

    /**
     * Open an exchange, returning the request id and the `RelayState` for it.
     *
     * 🛑 The `RelayState` is returned in the clear **once** and stored hashed,
     * which is §9.1.4's rule and is why there is no "read it back" method.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  string  $bindingId  raw 16 bytes
     * @param  string  $domainId  raw 16 bytes; where the reader came from
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $requestId  the `<AuthnRequest>` `ID`, from {@see AuthnRequest::build()}
     * @param  string  $handoffChallenge  §8.12.10's S256 challenge, 43 chars
     * @param  string  $returnPath  already normalised by the caller
     * @return string the opaque `RelayState` to send with the request
     */
    public function open(
        string $organisationId,
        string $bindingId,
        string $domainId,
        string $projectId,
        string $requestId,
        string $handoffChallenge,
        string $returnPath,
        ?int $now = null,
    ): string {
        $now ??= time();

        /*
         * 🛑 CSPRNG, and never a UUIDv7 — §9.1.4, because v7 embeds a readable
         * creation timestamp and a `RelayState` is enumerable by anybody who
         * watches a redirect.
         */
        $relayState = SecretToken::generate('docup_saml_relay');

        DB::table('saml_auth_requests')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $organisationId,
            'binding_id' => $bindingId,
            'domain_id' => $domainId,
            'project_id' => $projectId,
            'in_response_to' => $requestId,
            'relay_state_hash' => SecretToken::hash($relayState),
            'relay_state_hash_prefix' => SecretToken::prefix($relayState),
            'handoff_challenge' => $handoffChallenge,
            'return_path' => mb_substr($returnPath, 0, 512),
            'expires_at' => date('Y-m-d H:i:s.v', $now + self::TTL_SECONDS),
            'attempts' => 0,
            'created_at' => date('Y-m-d H:i:s.v', $now),
            'updated_at' => date('Y-m-d H:i:s.v', $now),
        ]);

        return $relayState;
    }

    /**
     * 🛑 Resolve and **consume** a `RelayState`, in one atomic conditional write.
     *
     * The single-use latch, in the shape corpus case `reader-001` argues for:
     * every condition that makes the row usable is in the `UPDATE`'s own
     * `WHERE`, so two concurrent POSTs presenting the same `RelayState` cannot
     * both proceed. A `SELECT` then an `UPDATE` has the race whose outcome is
     * whether one assertion mints two sessions.
     *
     * 🛑 The row is read **after** the latch closes. Reading first would hand
     * the caller a usable row it might then fail to claim.
     *
     * 🛑 **Whoever holds a `RelayState` can burn it**, and that is inherent
     * rather than a flaw to be designed away: the value travels in the reader's
     * own redirect, so somebody who can read it can POST rubbish to the ACS and
     * spend the exchange, costing the reader a restart. OIDC's `state` has the
     * identical property. What matters is what it does *not* buy — the response
     * still has to be signed twice by the binding's certificate, so burning an
     * exchange is a nuisance and never an admission.
     *
     * 🛑 And this runs **before** {@see ResponseValidator::validate()}, which is
     * the opposite order from the assertion-id replay cache — that one writes,
     * so it goes last, after the response has earned the right to burn an id.
     * Here the row is DocUp's own and the response has to be matched against it
     * before any of it can be believed, so the latch is first. The two
     * orderings are not inconsistent: each puts the write where a refusal
     * cannot cost a legitimate reader their next attempt.
     *
     * @return array{
     *     id: string,
     *     organisation_id: string,
     *     binding_id: string,
     *     domain_id: string,
     *     project_id: string,
     *     in_response_to: string,
     *     handoff_challenge: string,
     *     return_path: string,
     * }
     *
     * @throws SamlRefused
     */
    public function consume(string $relayState, ?int $now = null): array
    {
        $now ??= time();

        $row = $this->find($relayState);

        if ($row === null) {
            throw SamlRefused::of(
                SamlRejection::RelayStateUnknown,
                'no authentication request matches this relay state',
            );
        }

        $claimed = DB::table('saml_auth_requests')
            ->where('id', $row['id'])
            ->whereNull('consumed_at')
            ->where('expires_at', '>', date('Y-m-d H:i:s.v', $now))
            ->where('attempts', '<', self::MAX_ATTEMPTS)
            ->update([
                'consumed_at' => date('Y-m-d H:i:s.v', $now),
                'attempts' => DB::raw('`attempts` + 1'),
                'updated_at' => date('Y-m-d H:i:s.v', $now),
            ]);

        if ($claimed !== 1) {
            throw SamlRefused::of(
                SamlRejection::RelayStateExpired,
                'the authentication request is already consumed, expired or out of attempts',
            );
        }

        unset($row['expires_at']);

        return $row;
    }

    /**
     * Delete expired rows.
     *
     * 🛑 Housekeeping, not authorisation: {@see self::consume()} checks the
     * expiry on every use, so an unswept row authorises nothing. One row per
     * login attempt, and a table nobody prunes is a table an operator
     * eventually finds.
     */
    public function sweep(?int $now = null): int
    {
        return DB::table('saml_auth_requests')
            ->where('expires_at', '<=', date('Y-m-d H:i:s.v', ($now ?? time()) - 3600))
            ->delete();
    }

    /**
     * 🛑 Find by indexed prefix, then compare the full digest timing-safely.
     *
     * §9.1.4's pattern, as every other credential lookup in this codebase does
     * it: the prefix makes it an index seek, and `hash_equals` on the full
     * digest is what decides — so a prefix collision costs one comparison and
     * discloses nothing.
     *
     * @return array{
     *     id: string,
     *     organisation_id: string,
     *     binding_id: string,
     *     domain_id: string,
     *     project_id: string,
     *     in_response_to: string,
     *     handoff_challenge: string,
     *     return_path: string,
     *     expires_at: string,
     * }|null
     */
    private function find(string $relayState): ?array
    {
        $candidates = DB::table('saml_auth_requests')
            ->where('relay_state_hash_prefix', SecretToken::prefix($relayState))
            ->get([
                'id', 'organisation_id', 'binding_id', 'domain_id', 'project_id',
                'relay_state_hash', 'in_response_to', 'handoff_challenge', 'return_path',
                'expires_at',
            ]);

        $digest = SecretToken::hash($relayState);

        foreach ($candidates as $candidate) {
            if (! is_string($candidate->relay_state_hash) || ! hash_equals($candidate->relay_state_hash, $digest)) {
                continue;
            }

            return [
                'id' => (string) $candidate->id,
                'organisation_id' => (string) $candidate->organisation_id,
                'binding_id' => (string) $candidate->binding_id,
                'domain_id' => (string) $candidate->domain_id,
                'project_id' => (string) $candidate->project_id,
                'in_response_to' => (string) $candidate->in_response_to,
                'handoff_challenge' => (string) $candidate->handoff_challenge,
                'return_path' => (string) $candidate->return_path,
                'expires_at' => (string) $candidate->expires_at,
            ];
        }

        return null;
    }
}
