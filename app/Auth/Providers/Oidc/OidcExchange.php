<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers\Oidc;

use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 The sole reader and writer of `oidc_authorisation_requests`.
 *
 * §8.12.18's `state` and `nonce` are the two facts that have to survive a round
 * trip through somebody else's login page, and both are only as good as their
 * **single use**. That is why this is a class and not three queries in a
 * controller: single-use is one atomic conditional write, and a second place
 * that consumed a row would be a second answer to "has this been used".
 *
 * The same argument `App\Readers\ReaderHandoff` makes for its own code, and
 * this table is that one's sibling by design — hashed secret, short expiry,
 * bounded attempts, server-side return address.
 *
 * ## 🛑 `state` is bound to the originating domain by being stored beside it
 *
 * §8.12.18: "`state` bound to the originating domain". Not signed with it,
 * **stored** with it: the row holds `domain_id`, and the callback reads the
 * domain from the row rather than from anything the reader presents. §8.12.10
 * makes the same choice for the same reason — "the return URL built from the
 * verified domain row, never from a request parameter" — and a `state` that
 * encoded the domain would be a `state` an attacker could re-encode.
 *
 * ADR 0008 confirmed `state` survives a Keycloak round trip intact and then
 * said the thing that matters: "it is reader-supplied on the way back and must
 * be treated as an index into verified state, never as the URL itself". This
 * class is that index.
 */
final readonly class OidcExchange
{
    /**
     * 🛑 How long an authorisation request may stay open.
     *
     * Longer than §8.12.10's 30-second handoff code, and deliberately: a reader
     * has to *sign in* inside this window, which may mean a password manager, a
     * second factor and a consent screen. Ten minutes is the figure OAuth 2.1
     * §4.1.2 suggests for an authorisation code's own lifetime, and an
     * authorisation request has no reason to outlive the code it is waiting
     * for.
     */
    public const int TTL_SECONDS = 600;

    /**
     * 🛑 Attempts against one row before it is spent.
     *
     * Two, for the reason `ReaderHandoff::MAX_ATTEMPTS` is two: a reader whose
     * browser retried a redirect should not be locked out, and anybody probing
     * should not get a third try at the same row.
     */
    public const int MAX_ATTEMPTS = 2;

    /**
     * Open an exchange, returning the secrets to put in the authorisation URL.
     *
     * 🛑 `state` and `nonce` are returned in the clear **once** and stored
     * hashed, which is §9.1.4's rule and is why there is no "read the nonce
     * back" method: the verifier is given the nonce from
     * {@see self::consume()}'s return, in the same request that resolved the
     * row, and nothing else can recover it.
     *
     * @param  string  $bindingId  raw 16 bytes
     * @param  string  $domainId  raw 16 bytes; where the reader came from
     * @param  string  $projectId  raw 16 bytes
     * @param  string  $handoffChallenge  §8.12.10's S256 challenge, 43 chars
     * @param  string  $returnPath  already normalised by the caller
     * @return array{state: string, nonce: string, verifier: string}
     */
    public function open(
        string $organisationId,
        string $bindingId,
        string $domainId,
        string $projectId,
        string $handoffChallenge,
        string $returnPath,
        ?int $now = null,
    ): array {
        $now ??= time();

        /*
         * 🛑 CSPRNG, and never a UUIDv7 — §9.1.4: "security tokens are CSPRNG,
         * stored hashed, and never UUIDv7", because v7 embeds a readable
         * creation timestamp and these values are enumerable.
         */
        $state = SecretToken::generate('docup_oidc_state');
        $nonce = SecretToken::generate('docup_oidc_nonce');

        /*
         * 🛑 PKCE S256, and the verifier is generated here rather than by a
         * driver, because §8.12.18 makes it mandatory: a driver that could
         * supply its own could supply none. 96 bytes of randomness becomes 128
         * base64url characters, which is RFC 7636 §4.1's maximum — the longest
         * verifier the specification permits, for no cost.
         */
        $verifier = rtrim(strtr(base64_encode(random_bytes(96)), '+/', '-_'), '=');

        DB::table('oidc_authorisation_requests')->insert([
            'id' => Uuid::toBytes(Uuid::v7()),
            'organisation_id' => $organisationId,
            'binding_id' => $bindingId,
            'domain_id' => $domainId,
            'project_id' => $projectId,
            'state_hash' => SecretToken::hash($state),
            'state_hash_prefix' => SecretToken::prefix($state),
            'nonce_hash' => SecretToken::hash($nonce),
            'nonce_hash_prefix' => SecretToken::prefix($nonce),
            'code_verifier' => $verifier,
            'handoff_challenge' => $handoffChallenge,
            'return_path' => mb_substr($returnPath, 0, 512),
            'expires_at' => date('Y-m-d H:i:s.v', $now + self::TTL_SECONDS),
            'attempts' => 0,
            'created_at' => date('Y-m-d H:i:s.v', $now),
            'updated_at' => date('Y-m-d H:i:s.v', $now),
        ]);

        return ['state' => $state, 'nonce' => $nonce, 'verifier' => $verifier];
    }

    /**
     * 🛑 Resolve and **consume** a `state`, in one atomic conditional write.
     *
     * This is the single-use latch §8.12.18 requires, and the shape is the one
     * corpus case `reader-001` argues for: the guard is in the `UPDATE`'s own
     * `WHERE`, so two concurrent callbacks presenting the same `state` cannot
     * both proceed. A `SELECT` then an `UPDATE` has a race whose outcome is
     * whether one authorisation code mints two sessions.
     *
     * 🛑 The row is **read after** the latch closes, not before. Reading first
     * and updating second would hand the caller a usable row it might then
     * fail to consume.
     *
     * @return array{
     *     id: string,
     *     organisation_id: string,
     *     binding_id: string,
     *     domain_id: string,
     *     project_id: string,
     *     nonce_hash: string,
     *     code_verifier: string,
     *     handoff_challenge: string,
     *     return_path: string,
     * }
     *
     * @throws OidcRefused
     */
    public function consume(string $state, ?int $now = null): array
    {
        $now ??= time();

        $row = $this->find($state);

        if ($row === null) {
            throw OidcRefused::of(OidcRejection::StateUnknown, 'no authorisation request matches this state');
        }

        /*
         * 🛑 One UPDATE, and every condition that makes the row usable is in
         * its WHERE. The affected-row count is the answer: 1 means this caller
         * won the latch, 0 means the row was already consumed, had expired, or
         * had run out of attempts — and the caller cannot tell which, which is
         * correct, because all three are "this state is spent".
         */
        $claimed = DB::table('oidc_authorisation_requests')
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
            throw OidcRefused::of(
                OidcRejection::StateExpired,
                'the authorisation request is already consumed, expired or out of attempts',
            );
        }

        unset($row['expires_at']);

        return $row;
    }

    /**
     * 🛑 Whether a presented nonce is the one this exchange asked for.
     *
     * The comparison is against the stored **hash**, because §9.1.4 stores the
     * nonce hashed — so the plaintext is not available to compare, by design.
     * `hash_equals` over the digests, which is the same timing-safe comparison
     * the rest of the credential surface uses.
     *
     * 🛑 Separate from {@see IdTokenVerifier::claimsFor()}'s own nonce check, and
     * both are needed: that one asserts the token answers *a* request whose
     * nonce the caller supplied; this one is how the caller knows which nonce
     * to supply without ever holding the plaintext in storage.
     */
    public function nonceMatches(string $storedHash, string $presented): bool
    {
        return hash_equals($storedHash, SecretToken::hash($presented));
    }

    /**
     * Record a failed attempt without consuming the row.
     *
     * 🛑 Used where the exchange fails for a reason that is **not** the
     * reader's doing — a token endpoint timeout, say. The attempt counter still
     * moves, so a provider that fails forever cannot be retried forever, but
     * the row stays usable for the one retry `MAX_ATTEMPTS` allows. A failure
     * that consumed the row would turn a transient provider error into a
     * reader who has to start again.
     */
    public function recordAttempt(string $id, ?int $now = null): void
    {
        $now ??= time();

        DB::table('oidc_authorisation_requests')
            ->where('id', $id)
            ->update([
                'consumed_at' => null,
                'attempts' => DB::raw('`attempts` + 1'),
                'updated_at' => date('Y-m-d H:i:s.v', $now),
            ]);
    }

    /**
     * Delete expired rows.
     *
     * 🛑 Housekeeping, not authorisation: {@see self::consume()} checks the
     * expiry on every use, so an unswept row authorises nothing. Scheduled for
     * the reason the handoff's sweep is — one row per login attempt, and a
     * table nobody prunes is a table an operator eventually finds.
     */
    public function sweep(?int $now = null): int
    {
        $now ??= time();

        return DB::table('oidc_authorisation_requests')
            ->where('expires_at', '<=', date('Y-m-d H:i:s.v', $now - 3600))
            ->delete();
    }

    /**
     * 🛑 Find by indexed prefix, then compare the full digest timing-safely.
     *
     * The pattern §9.1.4 prescribes and the rest of this codebase uses: the
     * prefix makes the lookup an index seek rather than a table scan, and
     * `hash_equals` on the full digest is what actually decides — so a prefix
     * collision costs one comparison and discloses nothing.
     *
     * @return array{
     *     id: string,
     *     organisation_id: string,
     *     binding_id: string,
     *     domain_id: string,
     *     project_id: string,
     *     nonce_hash: string,
     *     code_verifier: string,
     *     handoff_challenge: string,
     *     return_path: string,
     *     expires_at: string,
     * }|null
     */
    private function find(string $state): ?array
    {
        $candidates = DB::table('oidc_authorisation_requests')
            ->where('state_hash_prefix', SecretToken::prefix($state))
            ->get([
                'id', 'organisation_id', 'binding_id', 'domain_id', 'project_id',
                'state_hash', 'nonce_hash', 'code_verifier', 'handoff_challenge', 'return_path',
                'expires_at',
            ]);

        $digest = SecretToken::hash($state);

        foreach ($candidates as $candidate) {
            if (! is_string($candidate->state_hash) || ! hash_equals($candidate->state_hash, $digest)) {
                continue;
            }

            /*
             * Narrowed to an array of strings here rather than returned as a
             * dynamic row, so every reader of this method gets typed fields
             * instead of `object` with an undefined property.
             */
            return [
                'id' => (string) $candidate->id,
                'organisation_id' => (string) $candidate->organisation_id,
                'binding_id' => (string) $candidate->binding_id,
                'domain_id' => (string) $candidate->domain_id,
                'project_id' => (string) $candidate->project_id,
                'nonce_hash' => (string) $candidate->nonce_hash,
                'code_verifier' => (string) $candidate->code_verifier,
                'handoff_challenge' => (string) $candidate->handoff_challenge,
                'return_path' => (string) $candidate->return_path,
                'expires_at' => (string) $candidate->expires_at,
            ];
        }

        return null;
    }
}
