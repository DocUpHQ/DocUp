<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use App\Access\CredentialScope;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Project;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

/**
 * §8.12.16's share links and reader tokens: the only class that reads or writes
 * `reader_credentials`.
 *
 * 🛑 **Sole call site, asserted by an architecture test**, for the reason
 * `ReaderSessions` has one: four things can end a credential — revocation,
 * expiry, exhausted uses, and the binding leaving `active` — and a second
 * implementation is the kind that remembers three.
 *
 * ## 🛑 Why `DB::table` and not Eloquent
 *
 * The serving path reads these on a documentation origin, where no tenant
 * context is declared — a reader is not a tenant. `App\Access\ReaderPolicies`
 * and `App\Readers\ReaderSessions` both read their tables the same way and for
 * the same reason.
 */
final readonly class ReaderCredentials
{
    /**
     * 🛑 A cap per project, because every one is a URL that may still be in
     * somebody's bookmarks.
     *
     * Two hundred is generous for the use case §8.12.16 describes — a link per
     * client engagement — and bounded: without a cap, an integration minting a
     * link per page view would fill the table and make the revocation screen
     * unusable, which is the screen that matters.
     */
    public const int MAX_PER_PROJECT = 200;

    /**
     * The share cookie's lifetime when the credential carries no expiry.
     *
     * 🛑 Reachable only for a **reader token**: §8.12.16 makes a share link's
     * expiry mandatory and a database CHECK enforces it, so a `shared_link`
     * row always has one. A token is presented in a header and never converted
     * to a cookie, so this value is a floor that nothing currently uses — kept
     * because `resolve()` serves both kinds and returning null for one of them
     * would push the branch into every caller.
     */
    private const int DEFAULT_COOKIE_SECONDS = 3600;

    public function __construct(private ReaderThrottle $throttle) {}

    /**
     * Issue a credential and return its plaintext secret **once**.
     *
     * @param  'shared_link'|'reader_token'  $kind
     * @param  list<string>  $versionSlugs  empty means every version the rule admits
     * @param  list<string>  $pathPrefixes  empty means every path
     * @param  int|null  $expiresAt  unix seconds; 🛑 required for a share link
     * @return array{id: string, secret: string}
     *
     * @throws BindingRefused
     */
    public function issue(
        Project $project,
        string $bindingId,
        string $kind,
        string $label,
        array $versionSlugs = [],
        array $pathPrefixes = [],
        ?int $expiresAt = null,
        ?int $maxUses = null,
        ?string $password = null,
        ?string $actorId = null,
    ): array {
        /*
         * 🛑 §8.12.16's mandatory expiry, refused here as well as by the
         * database CHECK. Two defences for one rule because they fail
         * differently: the CHECK cannot explain itself and this can, and the
         * CHECK survives a future writer who forgets this one.
         */
        if ($kind === 'shared_link' && $expiresAt === null) {
            throw BindingRefused::of(
                BindingRejection::ShareLinkNeedsExpiry,
                'a share link must expire (§8.12.16)',
            );
        }

        $binding = DB::table('auth_provider_bindings')
            ->where('id', $bindingId)
            ->first(['id', 'shareable', 'type', 'state']);

        if ($binding === null) {
            throw BindingRefused::of(BindingRejection::UnknownDriver, 'no such binding');
        }

        /*
         * 🛑 The `shareable` flag, default false. §8.12.16 gives a share link
         * mandatory expiry and a rate limiter; a binding nobody has considered
         * in those terms must not acquire a credential class by default.
         */
        if ($kind === 'shared_link' && $binding->shareable !== 1 && $binding->shareable !== true) {
            throw BindingRefused::of(
                BindingRejection::BindingNotShareable,
                'this binding is not marked shareable',
            );
        }

        $live = DB::table('reader_credentials')
            ->where('project_id', $project->id)
            ->whereNull('revoked_at')
            ->count();

        if ($live >= self::MAX_PER_PROJECT) {
            throw BindingRefused::of(
                BindingRejection::ConfigInvalid,
                'a project may hold at most '.self::MAX_PER_PROJECT.' live reader credentials',
            );
        }

        $secret = SecretToken::generate($kind === 'shared_link' ? 'docup_link' : 'docup_rtok');
        $id = Uuid::toBytes(Uuid::v7());

        DB::table('reader_credentials')->insert([
            'id' => $id,
            'organisation_id' => $project->organisation_id,
            'project_id' => $project->id,
            'binding_id' => $bindingId,
            'kind' => $kind,
            'label' => mb_substr($label, 0, 120),
            'secret_hash' => SecretToken::hash($secret),
            'secret_hash_prefix' => SecretToken::prefix($secret),
            /*
             * 🛑 Argon2id for the link's password too, at the same floor.
             * `Hash::make` reads `config/hashing.php`, which §8.12.16 requires
             * to be overridden above Laravel's default — so there is one
             * parameter set and `docup:doctor` checks it once.
             */
            'password_hash' => $password === null || $password === '' ? null : Hash::make($password),
            /* Already lists by the signature's own type, so no `array_values`. */
            'version_selector' => (string) json_encode($versionSlugs),
            'path_patterns' => (string) json_encode($pathPrefixes),
            'expires_at' => $expiresAt === null ? null : date('Y-m-d H:i:s.v', $expiresAt),
            'max_uses' => $maxUses,
            'uses' => 0,
            'created_by' => $actorId,
            'created_at' => now()->format('Y-m-d H:i:s.v'),
            'updated_at' => now()->format('Y-m-d H:i:s.v'),
        ]);

        Audit::record(
            action: 'reader.credential.issued',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: (string) $project->organisation_id,
            actorId: $actorId,
            subjectType: 'reader_credential',
            subjectId: $id,
            /*
             * 🛑 §8.22.5: identifiers and fixed vocabulary only. The secret is
             * not here, the password is not here, and the label is not here —
             * a label is operator-authored text and §8.22.5 keeps free text out
             * of the chain.
             */
            payload: [
                'kind' => $kind,
                'project' => Uuid::toText($project->id),
                'expires' => $expiresAt === null ? 'never' : 'set',
                'passworded' => $password === null ? 'no' : 'yes',
            ],
        );

        return ['id' => $id, 'secret' => $secret];
    }

    /**
     * Resolve a presented secret to a usable credential, or null.
     *
     * 🛑 **Four conditions, all of them here**, which is why this class is the
     * sole reader: revoked, expired, out of uses, and the binding not `active`.
     * A caller that checked three would be a caller that serves a revoked link
     * until it expires, or an expired one until it is revoked.
     *
     * @param  'shared_link'|'reader_token'  $kind
     * @param  string  $projectId  raw 16 bytes, from the resolved snapshot
     * @return array{id: string, bindingId: string, scope: CredentialScope, passworded: bool, expiresIn: int}|null
     */
    public function resolve(
        string $secret,
        string $kind,
        string $projectId,
        ?int $now = null,
    ): ?array {
        $now ??= time();

        $candidates = DB::table('reader_credentials')
            ->join(
                'auth_provider_bindings',
                'auth_provider_bindings.id',
                '=',
                'reader_credentials.binding_id',
            )
            ->where('reader_credentials.secret_hash_prefix', SecretToken::prefix($secret))
            ->where('reader_credentials.project_id', $projectId)
            ->where('reader_credentials.kind', $kind)
            ->whereNull('reader_credentials.revoked_at')
            ->limit(8)
            ->get([
                'reader_credentials.id',
                'reader_credentials.binding_id',
                'reader_credentials.secret_hash',
                'reader_credentials.password_hash',
                'reader_credentials.version_selector',
                'reader_credentials.path_patterns',
                'reader_credentials.expires_at',
                'reader_credentials.max_uses',
                'reader_credentials.uses',
                'auth_provider_bindings.state as binding_state',
            ]);

        foreach ($candidates as $row) {
            if (! is_string($row->secret_hash) || ! SecretToken::matches($secret, $row->secret_hash)) {
                continue;
            }

            /*
             * 🛑 The binding's state, checked on the credential's own path.
             * §8.12.19's `degraded` must deny, and a share link against a
             * degraded binding is not a way around that — a credential cannot
             * outlive the provider that authorises it.
             */
            if ($row->binding_state !== BindingState::Active->value) {
                return null;
            }

            if (is_string($row->expires_at) && strtotime((string) $row->expires_at) <= $now) {
                /* 🛑 §17's exit criterion: "An expired link 404s." */
                return null;
            }

            if ($row->max_uses !== null && (int) $row->uses >= (int) $row->max_uses) {
                return null;
            }

            return [
                'id' => (string) $row->id,
                'bindingId' => (string) $row->binding_id,
                'scope' => self::scopeOf($projectId, $row),
                'passworded' => is_string($row->password_hash) && $row->password_hash !== '',
                /*
                 * 🛑 Seconds remaining, for §8.12.16's cookie. The expiry has
                 * already been checked above, so this is positive — but it is
                 * clamped anyway, because a clock moving between the check and
                 * here would otherwise produce a negative `Max-Age`, which a
                 * browser reads as "delete this cookie" and turns a working
                 * link into one that silently never converts.
                 */
                'expiresIn' => is_string($row->expires_at)
                    ? max((int) strtotime((string) $row->expires_at) - $now, 1)
                    : self::DEFAULT_COOKIE_SECONDS,
            ];
        }

        return null;
    }

    /**
     * Check a share link's own password.
     *
     * 🛑 §8.12.16: "Share-link password attempts MUST be rate-limited with
     * lockout and timing-safe comparison." The lockout is checked **before**
     * the comparison, so a locked-out client's guess is never compared — doing
     * it afterwards would leak through timing the thing the lockout protects.
     *
     * @param  string  $credentialId  raw 16 bytes
     */
    public function passwordMatches(
        string $credentialId,
        string $submitted,
        ?string $address,
    ): bool {
        $key = 'credential:'.bin2hex($credentialId);

        if (! $this->throttle->permits($key, $address)) {
            return false;
        }

        $hash = DB::table('reader_credentials')
            ->where('id', $credentialId)
            ->value('password_hash');

        if (! is_string($hash) || $hash === '') {
            return false;
        }

        if (! Hash::check($submitted, $hash)) {
            $this->throttle->fail($key, $address);

            return false;
        }

        $this->throttle->succeed($key, $address);

        return true;
    }

    /**
     * Count a use, atomically.
     *
     * 🛑 One `UPDATE` with the guard in the `WHERE`, so `max_uses` is a limit
     * rather than a suggestion. A read-then-write would let two concurrent
     * requests both see `uses = 9` against a `max_uses` of 10 and both
     * proceed — which for a single-use link is the whole of its value lost.
     *
     * @param  string  $credentialId  raw 16 bytes
     * @return bool whether the use was counted; false means it was exhausted
     *              between {@see self::resolve()} and here
     */
    public function countUse(string $credentialId, ?int $now = null): bool
    {
        $now ??= time();

        return DB::table('reader_credentials')
            ->where('id', $credentialId)
            ->whereNull('revoked_at')
            ->where(function ($query): void {
                $query->whereNull('max_uses')->orWhereColumn('uses', '<', 'max_uses');
            })
            ->update([
                'uses' => DB::raw('`uses` + 1'),
                'last_used_at' => date('Y-m-d H:i:s.v', $now),
            ]) === 1;
    }

    /**
     * Revoke a credential.
     *
     * 🛑 No epoch bump. A credential is checked against the database on the
     * request that presents it — there is no grant minted from it that could
     * outlive the revocation, because `ReaderResolver` mints a grant from the
     * *session*, and a share link establishes one of those only after this
     * check passes. The next presentation of a revoked secret resolves to
     * nothing.
     */
    public function revoke(string $credentialId, string $reason, ?string $actorId = null): bool
    {
        $row = DB::table('reader_credentials')
            ->where('id', $credentialId)
            ->first(['organisation_id', 'kind']);

        if ($row === null) {
            return false;
        }

        $affected = DB::table('reader_credentials')
            ->where('id', $credentialId)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now()->format('Y-m-d H:i:s.v'),
                'revoked_reason' => $reason,
                'updated_at' => now()->format('Y-m-d H:i:s.v'),
            ]);

        if ($affected === 0) {
            return false;
        }

        Audit::record(
            action: 'reader.credential.revoked',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: is_string($row->organisation_id) ? $row->organisation_id : null,
            actorId: $actorId,
            subjectType: 'reader_credential',
            subjectId: $credentialId,
            payload: ['kind' => (string) $row->kind, 'reason' => $reason],
        );

        return true;
    }

    /**
     * Delete credentials whose expiry passed long enough ago to be evidence of
     * nothing.
     *
     * 🛑 A grace period rather than an immediate delete, because an operator
     * asking "why did this link stop working" is asking about a link that has
     * just expired. Thirty days after expiry the row answers no question the
     * audit chain does not already answer.
     *
     * @return int rows removed
     */
    public function sweep(?int $now = null): int
    {
        $now ??= time();

        return DB::table('reader_credentials')
            ->whereNotNull('expires_at')
            ->where('expires_at', '<=', date('Y-m-d H:i:s.v', $now - 30 * 86400))
            ->delete();
    }

    /**
     * §8.12.16's "version and path scope", as §12.3's conjunct reads it.
     *
     * 🛑 Scoped to the **project** as well, always. A credential is issued
     * against one project, and §12.3's scope check compares the project id —
     * so a credential whose scope omitted it would be satisfied by a request
     * for another project that happened to share a version slug.
     */
    private static function scopeOf(string $projectId, object $row): CredentialScope
    {
        return new CredentialScope(
            projectId: $projectId,
            versionSlugs: self::stringList($row->version_selector ?? null),
            pathPrefixes: self::stringList($row->path_patterns ?? null),
        );
    }

    /**
     * 🛑 Fails to the **empty** list on anything uninterpretable, and the
     * direction is deliberate — but it is the *wider* one, so it needs saying.
     *
     * An empty scope means "every version" and "every path", which is wider
     * than a malformed row probably intended. The alternative — failing to a
     * scope that matches nothing — would make a credential silently stop
     * working while still resolving, which presents to the reader as a 404 on
     * a link that the dashboard shows as live.
     *
     * What makes the wide direction safe is that the scope is a **narrowing**
     * conjunct, not a granting one: §12.3 has already decided the reader is
     * admitted by a rule before the scope is applied. An empty scope therefore
     * means "as wide as the rule", never "wider than the rule".
     *
     * @return list<string>
     */
    private static function stringList(mixed $json): array
    {
        if (! is_string($json)) {
            return [];
        }

        $decoded = json_decode($json, true, 4);

        if (! is_array($decoded)) {
            return [];
        }

        $out = [];

        foreach ($decoded as $entry) {
            if (is_string($entry) && $entry !== '') {
                $out[] = $entry;
            }
        }

        return $out;
    }
}
