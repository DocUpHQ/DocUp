<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Readers;

use App\Access\ReaderContext;
use App\Audit\ActorType;
use App\Audit\Audit;
use App\Auth\OrganisationContext;
use App\Auth\Providers\Federation\ReaderProvisioning;
use App\Auth\RoleResolver;
use App\Models\DocsSession;
use App\Models\Project;
use App\Models\ReaderIdentity;
use App\Models\User;
use App\Support\Invalidation;
use App\Support\SecretToken;
use App\Support\Uuid;
use Illuminate\Support\Facades\DB;

/**
 * §12.4's server-side reader sessions: the only class that reads or writes
 * `docs_sessions`.
 *
 * 🛑 **Sole call site, asserted by an architecture test**, for the reason §19
 * decision 17 gives this table its existence:
 *
 * > "Reader sessions are **server-side and revocable**, behind an opaque
 * > refresh cookie, with a short-lived grant as the per-request bearer.
 * > Stateless-only cannot satisfy SCIM offboarding or session inventory;
 * > grant-only cannot be revoked. Both are needed."
 *
 * A second reader of this table would be a second answer to "is this session
 * still live", and the three ways a session ends ({@see
 * \App\Models\DocsSession::isLive()}) are exactly the kind of thing a second
 * implementation remembers two of.
 *
 * ## 🛑 Where the level comes from, and why not from the row
 *
 * §12.3 puts a reader at `members` when their identity maps "to a role
 * assignment or group on this organisation". That is re-derived on every grant
 * mint — {@see self::contextFor()} — and deliberately **not** stored on the
 * session row. A stored level would be a copy of `role_assignments` with no
 * epoch behind it, so somebody removed from a project would keep reading until
 * their session expired rather than until their grant did. Re-deriving makes
 * the staleness exactly one grant TTL, which is §8.12.11's ≤10 minutes.
 *
 * 🛑 §10.8 assigns role-assignment changes to `permission_epoch`, which is not
 * yet implemented, so a role change is **not** bounded at one request the way a
 * policy edit or a session revoke is. That is recorded here rather than papered
 * over by bumping `identity_epoch` instead: §10.8's registry exists so that
 * each epoch's trigger list is true, and widening one to cover another's job is
 * how the registry stops being evidence.
 */
final readonly class ReaderSessions
{
    /**
     * §12.4's "8–24 h", as the idle and absolute halves.
     *
     * 🛑 Two numbers, because §12.4's range is a range for a reason: a reader
     * who closes the tab should not hold a credential overnight, and a reader
     * who keeps reading should not be thrown out mid-afternoon. Eight hours of
     * idle and twenty-four absolute are the two ends of §12.4's own interval.
     */
    public const int IDLE_SECONDS = 8 * 3600;

    public const int ABSOLUTE_SECONDS = 24 * 3600;

    public function __construct(
        private RoleResolver $roles,
        private OrganisationContext $context,
    ) {}

    /**
     * Establish a session for a dashboard member who completed §8.12.10's
     * handoff.
     *
     * 🛑 **One session per (project, domain, subject), replaced rather than
     * added to.** A reader who re-runs the handoff — a new tab, an expired
     * grant, a second sign-in — must not accumulate rows, because
     * §8.12.15's session inventory is a security surface and an inventory
     * showing forty sessions for one person is one nobody reads. The previous
     * row is revoked, not deleted, so the audit trail survives.
     *
     * @param  int|null  $now  unix seconds; null reads the clock
     * @return array{session: SessionRecord, handle: string, cacheKey: string}
     *                                                                         the two plaintext secrets, returned
     *                                                                         once and never retrievable again
     */
    public function establish(
        Project $project,
        string $domainId,
        User|ReaderIdentity $subject,
        int $combinedEpoch,
        ?int $now = null,
    ): array {
        $now ??= time();

        $isMember = $subject instanceof User;

        $handle = SecretToken::generate('docup_rsess');
        $cacheKey = SecretToken::generate('docup_ck');

        $id = Uuid::toBytes(Uuid::v7());

        $record = DB::transaction(function () use (
            $project, $domainId, $subject, $isMember, $handle, $cacheKey, $id, $combinedEpoch, $now
        ): SessionRecord {
            $column = $isMember ? 'user_id' : 'reader_identity_id';

            DB::table('docs_sessions')
                ->where('project_id', $project->id)
                ->where('domain_id', $domainId)
                ->where($column, $subject->id)
                ->whereNull('revoked_at')
                ->update([
                    'revoked_at' => date('Y-m-d H:i:s.v', $now),
                    'revoked_reason' => 'superseded',
                    'updated_at' => date('Y-m-d H:i:s.v', $now),
                ]);

            DB::table('docs_sessions')->insert([
                'id' => $id,
                'organisation_id' => $project->organisation_id,
                'project_id' => $project->id,
                'domain_id' => $domainId,
                'user_id' => $isMember ? $subject->id : null,
                'reader_identity_id' => $isMember ? null : $subject->id,
                'handle_hash' => SecretToken::hash($handle),
                'handle_hash_prefix' => SecretToken::prefix($handle),
                'cache_key_hash' => SecretToken::hash($cacheKey),
                'cache_key_hash_prefix' => SecretToken::prefix($cacheKey),
                'created_at' => date('Y-m-d H:i:s.v', $now),
                'updated_at' => date('Y-m-d H:i:s.v', $now),
                'last_seen_at' => date('Y-m-d H:i:s.v', $now),
                'idle_expires_at' => date('Y-m-d H:i:s.v', $now + self::IDLE_SECONDS),
                'absolute_expires_at' => date('Y-m-d H:i:s.v', $now + self::ABSOLUTE_SECONDS),
                'established_epoch' => $combinedEpoch,
            ]);

            return new SessionRecord(
                id: $id,
                organisationId: (string) $project->organisation_id,
                projectId: $project->id,
                domainId: $domainId,
                userId: $isMember ? $subject->id : null,
                readerIdentityId: $isMember ? null : $subject->id,
            );
        });

        Audit::record(
            action: 'reader.session.established',
            actorType: $isMember ? ActorType::User : ActorType::System,
            organisationId: (string) $project->organisation_id,
            actorId: $isMember ? $subject->id : null,
            subjectType: 'docs_session',
            subjectId: $id,
            payload: [
                'project' => Uuid::toText($project->id),
                'domain' => Uuid::toText($domainId),
                'population' => $isMember ? 'user' : 'reader_identity',
            ],
        );

        return ['session' => $record, 'handle' => $handle, 'cacheKey' => $cacheKey];
    }

    /**
     * The live session a handle names, for this project and this origin.
     *
     * 🛑 **Both the project and the domain are checked**, and that is §17's
     * exit criterion rather than defence in depth. A `__Host-` cookie is
     * already confined to one origin by the browser, so a handle arriving on
     * domain B would have to have been placed there — by a sibling-subdomain
     * cookie toss, which is the fixture §17 requires to fail. Checking the row
     * means a tossed handle names a session that does not match and is refused,
     * with no reliance on the browser having behaved.
     *
     * @param  string  $projectId  raw 16 bytes, from the resolved snapshot
     * @param  string  $domainId  raw 16 bytes, from the resolved snapshot
     * @param  int|null  $now  unix seconds; null reads the clock
     */
    public function resolve(
        string $handle,
        string $projectId,
        string $domainId,
        ?int $now = null,
    ): ?SessionRecord {
        return $this->lookup('handle_hash', $handle, $projectId, $domainId, $now);
    }

    /**
     * The same, by §8.12.13's Tier B cache-key cookie.
     *
     * 🛑 A separate secret and therefore a separate lookup. The cache key's
     * value lands in an nginx cache filename; it must not be usable as a
     * session handle anywhere, and it is not, because this is the only query
     * that accepts it and it grants nothing the handle does not.
     */
    public function resolveByCacheKey(
        string $cacheKey,
        string $projectId,
        string $domainId,
        ?int $now = null,
    ): ?SessionRecord {
        return $this->lookup('cache_key_hash', $cacheKey, $projectId, $domainId, $now);
    }

    /**
     * 🛑 §12.3's "reader's established context", re-derived on every mint.
     *
     * A dashboard user holding any role that bears on this project is a
     * `members` reader; one holding none is `authenticated`. That is §12.3's
     * own definition — "an identity mapping to a role assignment or group on
     * this organisation" — and it is why a project's own members can read its
     * private documentation with no provider configured at all, which is §17's
     * Phase 21 note that "readers are members or anonymous only".
     *
     * 🛑 A reader identity never reaches {@see RoleResolver}. §8.12.1: "a reader
     * identity MUST NEVER hold a role assignment", and the way that is kept
     * true is that this method does not ask. The resolver would raise if it
     * were asked ({@see RoleResolver::rolesFor()} is typed on `User`), which is
     * the backstop; not asking is the design.
     */
    /**
     * 🛑 Which binding vouched for this session's reader, or null.
     *
     * Null for a dashboard member's session, because no binding vouched for
     * them — §8.12.5 is explicit that a portal-session reader "already holds
     * whatever roles they hold; the binding grants nothing".
     *
     * Added in Phase 24 so `{binding}` can mean a *particular* binding. §12.3
     * lets a rule name one, and before this every session satisfied every
     * session-backed rule: a project with a portal and an OIDC provider could
     * not tell its own members from the provider's readers, which is the whole
     * reason §8.12.17 names the two drivers separately.
     *
     * 🛑 One indexed read, on the session's own reader identity, and only
     * when there is one. A member's session costs nothing extra.
     *
     * @return string|null raw 16 bytes
     */
    public function bindingFor(SessionRecord $session): ?string
    {
        $identity = $this->identityFor($session);

        return is_string($identity['binding_id'] ?? null) ? $identity['binding_id'] : null;
    }

    /**
     * The session's reader identity, as the two facts the serving path needs.
     *
     * 🛑 **One query for both**, where Phase 24 and Phase 26b each wanted their
     * own. `bindingFor()` needed the binding and the group elevation below
     * needs the groups, and they are two columns of the same row on the hottest
     * path in the product — so this is the read and both callers share it.
     *
     * 🛑 **Deliberately NOT memoised**, and the first version of this method
     * was. A field on this class would be a field on whatever lifetime the
     * container gives it: under FrankenPHP worker mode or in the queue worker a
     * shared instance would hold one reader's groups across requests, and
     * §8.12.14 names that failure by hand — "a stale read in the unsafe
     * direction serves private bytes with no decision at all, which is a worse
     * class of bug than a stale allow for an already-authorised reader".
     *
     * Two indexed primary-key lookups on one row is the cost, and it is the
     * right trade: §8.12.14's own argument is that the fast path and the slow
     * path should be the same path.
     *
     * @return array{binding_id?: string, reader_groups?: string}
     */
    private function identityFor(SessionRecord $session): array
    {
        if ($session->readerIdentityId === null) {
            return [];
        }

        $key = $session->readerIdentityId;

        /*
         * 🛑 Spanning every organisation, as `contextFor()` does and for the
         * reason stated there: a reader is not a tenant, the documentation
         * origin declares no organisation context, and this is a primary-key
         * lookup whose key came from the session row — so it cannot return
         * another tenant's anything.
         */
        $row = $this->context->acrossAllOrganisations(
            static fn (): ?object => DB::table('reader_identities')
                ->where('id', $key)
                ->first(['binding_id', 'reader_groups']),
        );

        $identity = [];

        if ($row !== null) {
            if (is_string($row->binding_id)) {
                $identity['binding_id'] = $row->binding_id;
            }

            if (is_string($row->reader_groups)) {
                $identity['reader_groups'] = $row->reader_groups;
            }
        }

        return $identity;
    }

    /**
     * 🛑 §12.3's `members` rung, by **group** — the half of its own definition
     * that nothing implemented until Phase 26b.
     *
     * §12.3 defines `members` as "a reader whose identity maps to a role
     * assignment **or group** on this organisation". Phase 24 built the group
     * half's write side — §8.13.7 reconciles `reader_groups` on every login,
     * added **and** removed — and Phase 26a found that no decision path ever
     * read the column. So an operator could map an IdP group to a reader group,
     * watch it land on the identity, and find their `members` rule still
     * refusing every reader it was written for.
     *
     * 🛑 Phase 26b needs it for its own first exit criterion: "an LDAP group
     * removal drops access on the next decision" is a statement about groups
     * deciding access, which they could not do.
     *
     * **Any** mapped group is enough, and that is the faithful reading rather
     * than a lenient one: a `provider_group_mappings` row is organisation-scoped
     * and an operator wrote it deliberately, so a group on the identity *is*
     * "a group on this organisation". §12.3's stronger rung is untouched —
     * `restricted` still requires a rule naming the resource explicitly — so
     * this admits a mapped reader to `members` content and no further.
     *
     * @param  array{binding_id?: string, reader_groups?: string}  $identity
     */
    private static function hasGroups(array $identity): bool
    {
        $stored = $identity['reader_groups'] ?? null;

        if (! is_string($stored) || $stored === '') {
            return false;
        }

        $decoded = json_decode($stored, true);

        if (! is_array($decoded)) {
            return false;
        }

        foreach ($decoded as $group) {
            if (is_string($group) && $group !== '') {
                return true;
            }
        }

        return false;
    }

    public function contextFor(SessionRecord $session, ?Project $project = null): ReaderContext
    {
        if ($session->userId === null) {
            /*
             * A provider-authenticated reader (P23).
             *
             * 🛑 **AMENDED (Phase 26b).** P23's note here read: "`authenticated`
             * and never more: §12.3's `members` rung is about this
             * installation's own role assignments, and a reader vouched for by
             * somebody else's directory holds none of them." Half of that is
             * right and the half that was wrong made §12.3 smaller than it is.
             *
             * §12.3 defines `members` as "a reader whose identity maps to a
             * role assignment **or group** on this organisation". The role half
             * is indeed unreachable for a reader — §8.12.1 forbids a reader
             * identity holding a role assignment at all — but the **group**
             * half is exactly for this population, and it is what §8.13.7's
             * reconciliation exists to feed. See {@see self::hasGroups()}.
             */
            return self::hasGroups($this->identityFor($session))
                ? ReaderContext::member($session->id)
                : ReaderContext::authenticated($session->id);
        }

        /*
         * 🛑 **Inside `acrossAllOrganisations`, and this is the serving path's
         * one legitimate tenancy span.** A reader is not a tenant: the
         * documentation origin declares no organisation context, by design
         * (§8.9.4 resolves a project from the host and path alone), so
         * `Project`'s §8.2.1 global scope would raise here — which it did, and
         * the handoff test caught it.
         *
         * Spanning is safe because both reads are **primary-key lookups whose
         * keys came from the session row**, so neither can return another
         * tenant's anything. The alternative — declaring the context for
         * `$session->organisationId` — would mutate ambient state for the rest
         * of the request on the hottest path in the product, which is how a
         * later query silently inherits a tenant nobody asked for.
         *
         * 🛑 And {@see RoleResolver} is still the only thing that reads
         * `role_assignments`. It uses `DB::select` internally precisely
         * because installation-scope rows carry a NULL `organisation_id` and
         * the global scope would filter exactly those away — so the span here
         * is for the two model loads, not for the authorisation query.
         */
        [$user, $project] = $this->context->acrossAllOrganisations(
            static fn (): array => [
                User::query()->find($session->userId),
                $project ?? Project::query()->find($session->projectId),
            ],
        );

        if (! $user instanceof User) {
            /*
             * The row's foreign key says this cannot happen, so reaching here
             * means the user was deleted between the lookup and now. Fail
             * closed to anonymous rather than to authenticated: a deleted
             * principal is not a principal.
             */
            return ReaderContext::anonymous();
        }

        $roles = $this->roles->rolesFor($user, $project instanceof Project ? $project : null);

        return $roles === []
            ? ReaderContext::authenticated($session->id)
            : ReaderContext::member($session->id);
    }

    /**
     * A fresh Tier B cache key for a live session, returned in plaintext once.
     *
     * 🛑 **Rotated with every grant, which is what §12.4's "TTL = grant" means
     * in practice.** The stored value is a digest, so the plaintext cannot be
     * recovered to re-issue the cookie — and that turns out to be the right
     * behaviour rather than an obstacle: §8.12.13 has nginx cache an
     * authorisation subrequest keyed on this cookie, so a key that outlived a
     * grant would keep a cached 2xx addressable after the grant behind it had
     * expired. Rotating with the grant makes the cache entry's lifetime the
     * grant's lifetime, with no cache invalidation at the edge at all.
     *
     * 🛑 And the old key stops working in the same statement, because the
     * column holds one digest. There is no window with two valid cache keys.
     */
    public function rotateCacheKey(SessionRecord $session): ?string
    {
        $cacheKey = SecretToken::generate('docup_ck');

        $affected = DB::table('docs_sessions')
            ->where('id', $session->id)
            ->whereNull('revoked_at')
            ->update([
                'cache_key_hash' => SecretToken::hash($cacheKey),
                'cache_key_hash_prefix' => SecretToken::prefix($cacheKey),
                'updated_at' => now()->format('Y-m-d H:i:s.v'),
            ]);

        return $affected === 1 ? $cacheKey : null;
    }

    /**
     * Revoke one session, by handle, on its own origin.
     *
     * 🛑 Bumps `identity_epoch`, which is what gives §8.12.15 its bound:
     *
     * > "at Tier A and Tier B, revoking a session or editing a policy takes
     * > effect on the **next request**, because the decision is made in the
     * > application against the current epoch."
     *
     * The grant in the reader's cookie carries the combined epoch it was minted
     * under, so the bump alone invalidates it — with no purge, no cache sweep
     * and nothing to go wrong at the edge. §17's exit criterion "revoking a
     * session … stops service within one subsequent request" is this line.
     *
     * 🛑 **And only this project's epoch.** §17's "logging out of project A
     * leaves project B signed in" is the same fact from the reader's side: the
     * session row is per project, the bump is per project, and neither reaches
     * across.
     */
    public function revoke(SessionRecord $session, string $reason = 'reader_logout', ?string $actorId = null): void
    {
        $affected = DB::table('docs_sessions')
            ->where('id', $session->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now()->format('Y-m-d H:i:s.v'),
                'revoked_reason' => $reason,
                'updated_at' => now()->format('Y-m-d H:i:s.v'),
            ]);

        if ($affected === 0) {
            /* Already revoked. Nothing changed, so nothing is invalidated. */
            return;
        }

        Invalidation::bumpIdentity(
            projectId: $session->projectId,
            cause: 'session revoke',
            organisationId: $session->organisationId,
            actorId: $actorId,
        );

        Audit::record(
            action: 'reader.session.revoked',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $session->organisationId,
            actorId: $actorId,
            subjectType: 'docs_session',
            subjectId: $session->id,
            payload: ['reason' => $reason],
        );
    }

    /**
     * Revoke every live session for a project — §8.12.26's deprovisioning
     * primitive and the dashboard's "sign everyone out".
     *
     * One epoch bump for the whole set rather than one per row: the epoch is
     * per project and a second increment invalidates nothing a first one did
     * not.
     *
     * @return int how many sessions were ended
     */
    public function revokeProject(Project $project, string $reason, ?string $actorId = null): int
    {
        $affected = DB::table('docs_sessions')
            ->where('project_id', $project->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => now()->format('Y-m-d H:i:s.v'),
                'revoked_reason' => $reason,
                'updated_at' => now()->format('Y-m-d H:i:s.v'),
            ]);

        if ($affected === 0) {
            return 0;
        }

        Invalidation::bumpIdentity(
            projectId: $project->id,
            cause: 'session revoke',
            organisationId: (string) $project->organisation_id,
            actorId: $actorId,
        );

        Audit::record(
            action: 'reader.session.revoked_all',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: (string) $project->organisation_id,
            actorId: $actorId,
            subjectType: 'project',
            subjectId: $project->id,
            payload: ['reason' => $reason, 'sessions' => (string) $affected],
        );

        return $affected;
    }

    /**
     * 🛑 End every session one reader identity holds, anywhere.

     *
     * §8.12.15: "Session inventory and per-session revocation are required
     * because **SCIM offboarding** needs them" — and this is the method that
     * sentence was asking for. Until Phase 26b nothing offboarded, so nothing
     * called it.
     *
     * 🛑 Here rather than in `App\Auth\Providers\Federation`, and an
     * architecture test is what insisted: "only the readers namespace reads the
     * session tables". The first version of {@see ReaderProvisioning}'s
     * deprovisioning ran its own `UPDATE docs_sessions`, which worked and was
     * wrong — a second writer of this table is a second place to forget the
     * epoch bump, and an identity revoked without one keeps reading until its
     * grant expires at Tier A and B where it should have stopped on the next
     * request.
     *
     * One epoch bump **per project the reader had a session on**, because
     * {@see Invalidation::bumpIdentity()} is per project and a reader may hold
     * sessions on several.
     *
     * @return int how many sessions were ended
     */
    public function revokeIdentity(ReaderIdentity $identity, string $reason, ?int $now = null): int
    {
        $now ??= time();
        $stamp = date('Y-m-d H:i:s.v', $now);

        /*
         * The projects first, because the UPDATE is what makes them
         * unreadable afterwards and the epoch bump needs to know which.
         */
        $rows = DB::table('docs_sessions')
            ->select('project_id', 'organisation_id')
            ->where('reader_identity_id', $identity->id)
            ->whereNull('revoked_at')
            ->get();

        $affected = DB::table('docs_sessions')
            ->where('reader_identity_id', $identity->id)
            ->whereNull('revoked_at')
            ->update([
                'revoked_at' => $stamp,
                'revoked_reason' => $reason,
                'updated_at' => $stamp,
            ]);

        if ($affected === 0) {
            return 0;
        }

        $seen = [];

        foreach ($rows as $row) {
            $projectId = $row->project_id ?? null;

            if (! is_string($projectId) || isset($seen[$projectId])) {
                continue;
            }

            $seen[$projectId] = true;

            Invalidation::bumpIdentity(
                projectId: $projectId,
                cause: 'identity '.$reason,
                organisationId: is_string($row->organisation_id ?? null) ? $row->organisation_id : null,
            );
        }

        Audit::record(
            action: 'reader.session.revoked_identity',
            actorType: ActorType::System,
            /*
             * No `is_string()` guard: `ReaderIdentity::$organisation_id` is
             * declared non-nullable and level 8 proves the narrowing always
             * true. An installation-scoped binding's identity does carry the
             * binding's null organisation — but that is typed where it is read
             * from the binding, not here.
             */
            organisationId: $identity->organisation_id,
            subjectType: 'reader_identity',
            subjectId: $identity->id,
            payload: ['reason' => $reason, 'sessions' => (string) $affected],
        );

        return $affected;
    }

    /**
     * Delete sessions past their absolute ceiling.
     *
     * 🛑 **Deleted, not revoked.** A revoked row is evidence and §20.3 keeps the
     * decision log beside it; a row whose absolute expiry passed cannot
     * authorise anything and carries no fact an audit needs, and
     * `docs_sessions` is a table with one row per reader per project per
     * domain. The sweep is what keeps the session inventory readable.
     *
     * No epoch bump: an expired session was already refused by
     * {@see DocsSession::isLive()} on every request since it
     * expired, so nothing becomes true here that was not already true.
     *
     * @return int rows removed
     */
    public function sweep(?int $now = null): int
    {
        $now ??= time();

        return DB::table('docs_sessions')
            ->where('absolute_expires_at', '<=', date('Y-m-d H:i:s.v', $now))
            ->delete();
    }

    /**
     * The one query shape, for both secrets.
     *
     * 🛑 The prefix narrows and `hash_equals` decides — {@see SecretToken} says
     * why: "comparing a credential is where timing analysis belongs even when
     * the attacker is assumed not to be measuring, because the habit is what
     * survives into the code where they are."
     *
     * 🛑 Liveness is checked **in PHP** against {@see DocsSession}'s
     * own predicate rather than in the `WHERE`. Two reasons: the three
     * conditions stay in one place for both this class and the dashboard, and a
     * SQL clause comparing three datetimes against `NOW()` would read the
     * database's clock where every other expiry decision in the serving path
     * reads the application's.
     */
    private function lookup(
        string $column,
        string $presented,
        string $projectId,
        string $domainId,
        ?int $now,
    ): ?SessionRecord {
        $now ??= time();

        $candidates = DB::table('docs_sessions')
            ->where($column.'_prefix', SecretToken::prefix($presented))
            ->where('project_id', $projectId)
            ->where('domain_id', $domainId)
            ->whereNull('revoked_at')
            ->limit(8)
            ->get([
                'id', 'organisation_id', 'project_id', 'domain_id',
                'user_id', 'reader_identity_id', $column,
                'idle_expires_at', 'absolute_expires_at',
            ]);

        foreach ($candidates as $row) {
            if (! is_string($row->{$column}) || ! SecretToken::matches($presented, $row->{$column})) {
                continue;
            }

            if (! self::rowIsLive($row, $now)) {
                return null;
            }

            $this->touch((string) $row->id, $now);

            return new SessionRecord(
                id: (string) $row->id,
                organisationId: (string) $row->organisation_id,
                projectId: (string) $row->project_id,
                domainId: (string) $row->domain_id,
                userId: is_string($row->user_id) ? $row->user_id : null,
                readerIdentityId: is_string($row->reader_identity_id) ? $row->reader_identity_id : null,
            );
        }

        return null;
    }

    /** §12.4's two expiries, over a raw row. */
    private static function rowIsLive(object $row, int $now): bool
    {
        $idle = is_string($row->idle_expires_at ?? null) ? strtotime((string) $row->idle_expires_at) : false;
        $absolute = is_string($row->absolute_expires_at ?? null) ? strtotime((string) $row->absolute_expires_at) : false;

        if ($idle === false || $absolute === false) {
            return false;
        }

        return $idle > $now && $absolute > $now;
    }

    /**
     * Push the idle deadline out, on use.
     *
     * 🛑 Only the **idle** deadline. `absolute_expires_at` is never touched,
     * which is what makes it absolute — the correction §12.4 makes to Laravel's
     * single renewable `lifetime`, applied to the reader's session as well as
     * the dashboard's.
     *
     * Not transactional and its failure is not raised: a session that was used
     * and whose `last_seen_at` did not move is a cosmetic loss, and a reader
     * request must not fail because an `UPDATE` did.
     */
    private function touch(string $id, int $now): void
    {
        DB::table('docs_sessions')->where('id', $id)->update([
            'last_seen_at' => date('Y-m-d H:i:s.v', $now),
            'idle_expires_at' => date('Y-m-d H:i:s.v', $now + self::IDLE_SECONDS),
            'updated_at' => date('Y-m-d H:i:s.v', $now),
        ]);
    }
}
