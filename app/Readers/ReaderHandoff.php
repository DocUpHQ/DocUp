<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Domain;
use App\Models\Project;
use App\Models\User;
use App\Serving\RoutingSnapshotLoader;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * 🛑 §8.12.10's cross-domain handoff: the one mechanism that makes "many
 * domains per project" compatible with session authentication.
 *
 * > "Cookies cannot span registrable domains, so each documentation origin MUST
 * > establish its own session by a first-party PKCE code exchange against the
 * > dashboard: a single-use handoff code expiring within 30 seconds, bound to
 * > the resolved domain and project, with the return URL built **from the
 * > verified domain row, never from a request parameter**. This handoff is the
 * > entire mechanism that makes 'many domains per project' compatible with
 * > session authentication."
 *
 * ## 🛑 The shape, and where each guarantee lives
 *
 * 1. The documentation origin starts it: a PKCE pair, the verifier into a
 *    `__Host-` cookie on **that** origin, and a redirect to the dashboard
 *    carrying the challenge and a domain **identifier**.
 * 2. The dashboard mints a code here — {@see self::mint()} — after checking the
 *    signed-in user may read the project and that the domain row is servable.
 *    The redirect back is built from `domains.host`, so the only hosts this
 *    endpoint can send a reader to are hosts the installation has verified.
 * 3. The documentation origin redeems it — {@see self::redeem()} — against the
 *    verifier in its own cookie, and the code dies in the same statement that
 *    reads it.
 *
 * 🛑 **The domain identifier in step 1 is a lookup key, not a destination**,
 * and that distinction is the whole of §8.12.10's "never from a request
 * parameter". An attacker may name any identifier they like; what they get is
 * the `domains` row with that id, or nothing. They cannot get a host that is
 * not in the table, which is what an open redirect would need.
 */
final readonly class ReaderHandoff
{
    /**
     * 🛑 §8.12.10's ceiling: "a single-use handoff code expiring within 30
     * seconds".
     *
     * A constant rather than configuration. The window is what bounds the value
     * of a leaked URL, and an operator raising it to "fix" a slow network would
     * be trading the one property the code has for a symptom that a retry
     * solves.
     */
    public const int CODE_TTL_SECONDS = 30;

    /**
     * 🛑 How many times a reader may be sent round the handoff before it stops.
     *
     * One attempt, then one retry. See {@see HandoffRejection::LoopDetected}:
     * the failure this bounds is a browser that accepts the redirect and
     * discards the cookie, which produces an infinite 302 loop with no error
     * anywhere. §18.10 is the unverified assumption behind that risk, and this
     * is half of why Phase 22 does not depend on it.
     */
    public const int MAX_ATTEMPTS = 2;

    /**
     * Mint a code on the dashboard origin, for a signed-in user.
     *
     * 🛑 **Returns the absolute URL to send the reader to, built from the
     * domain row.** Returning the code alone and letting a caller assemble the
     * URL would put §8.12.10's one hard rule in the caller.
     *
     * @param  string  $challenge  the `S256` challenge from the docs origin
     * @param  string  $returnPath  where the reader was going; 🛑 stored, and
     *                              normalised to a path by
     *                              {@see self::safeReturnPath()}, so it can
     *                              never become an origin
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return array{url: string, code: string}
     *
     * @throws HandoffRefused when the domain is not servable or the reader may
     *                        not read the project
     */
    public function mint(
        User $user,
        Domain $domain,
        Project $project,
        string $challenge,
        string $returnPath,
        ?int $now = null,
    ): array {
        $now ??= time();

        if (strlen($challenge) !== 43 || preg_match('/^[A-Za-z0-9_-]{43}$/', $challenge) !== 1) {
            /*
             * 🛑 The challenge is stored in a CHAR(43) ascii_bin column and
             * compared with `hash_equals`, so a malformed one would be
             * truncated or padded by the database rather than refused. Checked
             * here, where the reason can be stated.
             */
            throw HandoffRefused::of(HandoffRejection::VerifierMismatch, 'malformed challenge');
        }

        /*
         * 🛑 Re-read through the resolver rather than trusting the model. The
         * caller found this `Domain` by id; whether it may serve is
         * §8.10.6's rule and {@see RoutingSnapshotLoader::canServe()} is where
         * it lives. A second implementation here is how "unverified hosts are
         * neither served nor certified" becomes true in one place and false in
         * another.
         */
        if (! RoutingSnapshotLoader::canServe($domain->kind, $domain->state, $domain->verified_at?->toDateTimeString())) {
            throw HandoffRefused::of(HandoffRejection::DomainNotServable, Uuid::toText($domain->id));
        }

        if (! hash_equals((string) $domain->organisation_id, (string) $project->organisation_id)) {
            /*
             * 🛑 A domain of one organisation cannot mint for a project of
             * another, even if the reader holds a role on both. The mount list
             * is what ties a domain to a project and it is checked by the
             * caller; this is the tenancy boundary beneath it.
             */
            throw HandoffRefused::of(HandoffRejection::WrongAudience, 'cross-organisation handoff');
        }

        $code = SecretToken::generate('docup_hc');
        $id = Uuid::toBytes(Uuid::v7());

        DB::table('reader_handoff_codes')->insert([
            'id' => $id,
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'domain_id' => $domain->id,
            'user_id' => $user->id,
            'code_hash' => SecretToken::hash($code),
            'code_hash_prefix' => SecretToken::prefix($code),
            'challenge' => $challenge,
            'return_path' => self::safeReturnPath($returnPath),
            'created_at' => date('Y-m-d H:i:s.v', $now),
            'expires_at' => date('Y-m-d H:i:s.v', $now + self::CODE_TTL_SECONDS),
        ]);

        Audit::record(
            action: 'reader.handoff.minted',
            actorType: ActorType::User,
            organisationId: (string) $project->organisation_id,
            actorId: $user->id,
            subjectType: 'project',
            subjectId: $project->id,
            payload: ['domain' => Uuid::toText($domain->id)],
        );

        return [
            /*
             * 🛑 **The URL, from the row.** `$domain->host` is the verified
             * hostname; nothing a request supplied contributes an origin here,
             * and the path is a literal.
             */
            'url' => 'https://'.$domain->host.'/_/auth/callback?code='.urlencode($code),
            'code' => $code,
        ];
    }

    /**
     * Redeem a code on the documentation origin.
     *
     * 🛑 **Single-use, as one atomic statement.** `UPDATE … WHERE consumed_at
     * IS NULL` returning one affected row is the latch; a `SELECT` followed by
     * an `UPDATE` has a race between them, and the thing that race decides is
     * whether one code mints two sessions. This is also why the codes are a
     * table rather than a cache entry — a cache `get`-then-`forget` is the same
     * race with a nicer API.
     *
     * @param  string  $projectId  raw 16 bytes, from the resolved snapshot
     * @param  string  $domainId  raw 16 bytes, from the resolved snapshot
     * @param  string  $verifier  from the `__Host-docup_state` cookie
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return array{userId: string, returnPath: string}
     *
     * @throws HandoffRefused for every one of {@see HandoffRejection}'s cases
     */
    public function redeem(
        string $code,
        string $projectId,
        string $domainId,
        string $verifier,
        ?int $now = null,
    ): array {
        $now ??= time();

        $candidates = DB::table('reader_handoff_codes')
            ->where('code_hash_prefix', SecretToken::prefix($code))
            ->limit(8)
            ->get(['id', 'code_hash', 'challenge', 'project_id', 'domain_id', 'user_id', 'return_path', 'expires_at', 'consumed_at']);

        $row = null;

        foreach ($candidates as $candidate) {
            if (is_string($candidate->code_hash) && SecretToken::matches($code, $candidate->code_hash)) {
                $row = $candidate;
                break;
            }
        }

        if ($row === null) {
            throw HandoffRefused::of(HandoffRejection::UnknownCode);
        }

        /*
         * 🛑 The audience first, before anything that consumes the code. A code
         * presented on the wrong domain must not be spent: the legitimate
         * reader's own redemption, arriving a moment later on the right domain,
         * has to still work. Consuming it here would turn a probe into a denial
         * of service against the reader it was stolen from.
         */
        if (! hash_equals((string) $row->domain_id, $domainId) || ! hash_equals((string) $row->project_id, $projectId)) {
            throw HandoffRefused::of(HandoffRejection::WrongAudience);
        }

        if (! is_string($row->challenge) || ! PkceChallenge::satisfies($verifier, $row->challenge)) {
            /* Same argument: a wrong verifier does not spend the code. */
            throw HandoffRefused::of(HandoffRejection::VerifierMismatch);
        }

        /*
         * 🛑 Now consume it, and let the database decide whether this call or
         * another one got there first. Expiry is in the `WHERE` **as well as**
         * checked below, because the one statement that latches the code is the
         * only place both facts can be evaluated together.
         */
        $claimed = DB::table('reader_handoff_codes')
            ->where('id', $row->id)
            ->whereNull('consumed_at')
            ->where('expires_at', '>', date('Y-m-d H:i:s.v', $now))
            ->update(['consumed_at' => date('Y-m-d H:i:s.v', $now)]);

        if ($claimed !== 1) {
            /*
             * Either somebody redeemed it first or it expired. Distinguished
             * for the audit — a replay is an operator signal and an expiry is
             * not — by re-reading the row we already hold.
             */
            $expired = is_string($row->expires_at) && strtotime((string) $row->expires_at) <= $now;

            throw HandoffRefused::of(
                $expired ? HandoffRejection::Expired : HandoffRejection::AlreadyUsed,
            );
        }

        return [
            'userId' => (string) $row->user_id,
            /*
             * 🛑 Re-normalised on the way out. The column cannot hold an origin
             * because {@see self::safeReturnPath()} ran on the way in, and it
             * runs again here because a row written by an older version of this
             * code is not something a redirect should trust.
             */
            'returnPath' => self::safeReturnPath(is_string($row->return_path) ? $row->return_path : '/'),
        ];
    }

    /**
     * Delete codes past their window.
     *
     * The table is write-heavy and short-lived: one row per handoff, dead after
     * thirty seconds. Swept rather than retained because a consumed code
     * carries no fact §8.22's audit chain does not already hold — the mint and
     * the session establishment are both audited.
     */
    public function sweep(?int $now = null): int
    {
        $now ??= time();

        return DB::table('reader_handoff_codes')
            ->where('expires_at', '<=', date('Y-m-d H:i:s.v', $now - 60))
            ->delete();
    }

    /**
     * 🛑 A path, and only ever a path.
     *
     * §8.12.10 puts the origin beyond a request's reach; this keeps the *path*
     * from smuggling one back. The cases that matter, each of which is a real
     * open-redirect technique:
     *
     * - `https://evil.example/` — an absolute URL. Refused by requiring a
     *   leading `/`.
     * - `//evil.example/` — a scheme-relative URL, which a browser reads as
     *   another origin and which *does* begin with `/`. This is the one that
     *   gets missed, and §8.11.2's `RedirectTarget` was written for the same
     *   trap.
     * - `/\evil.example` — backslash, which several browsers normalise to `/`
     *   and then read as scheme-relative.
     * - a newline or a control character, which splits a `Location` header.
     *
     * Anything that is not plainly a single-slash-rooted path becomes `/`,
     * which is a correct destination rather than an error: the reader asked for
     * a page and gets the site root, instead of a refusal they cannot act on.
     */
    public static function safeReturnPath(string $path): string
    {
        if ($path === '' || $path[0] !== '/') {
            return '/';
        }

        if (str_starts_with($path, '//') || str_starts_with($path, '/\\')) {
            return '/';
        }

        if (preg_match('/[\x00-\x1f\x7f]/', $path) === 1) {
            return '/';
        }

        /*
         * Length-capped to the column. A longer path is not an attack, but a
         * silently truncated one is a redirect to a URL nobody asked for.
         */
        return strlen($path) > 2048 ? '/' : $path;
    }

    /**
     * The dashboard URL a documentation origin sends a reader to.
     *
     * Built here so the two origins' halves of §8.12.10 agree on one spelling,
     * and so the documentation origin never has to know the dashboard's route
     * name.
     *
     * @param  string  $domainId  raw 16 bytes
     */
    public function startUrl(string $domainId, string $challenge, string $returnPath): string
    {
        /*
         * 🛑 `docup.origins.app` is a **host**, not a URL — `DOCUP_APP_HOST` —
         * so the scheme is prepended here. Always `https`, for the reason
         * {@see \App\Serving\CanonicalLocations} gives: §8.10.5 makes TLS
         * automatic and mandatory for every serving host, so there is no http
         * dashboard to redirect to, and a scheme read from the request would
         * let a misconfigured proxy send a reader's handoff over plaintext.
         *
         * The first version omitted it, which produced a schemeless
         * `Location` — a relative URL, which the browser resolves against the
         * *documentation* origin and which therefore 404s on a host that has
         * no `/reader/handoff`. Caught by the handoff test walking all three
         * requests rather than asserting the first one's status.
         */
        $dashboard = config('docup.origins.app');

        return 'https://'.rtrim(is_string($dashboard) ? $dashboard : '', '/')
            .'/reader/handoff?'
            .http_build_query([
                'domain' => Uuid::toText($domainId),
                'challenge' => $challenge,
                'return' => self::safeReturnPath($returnPath),
            ]);
    }
}
