<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Readers\ReaderSessions;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * §12.4's `docs_sessions`: "opaque handle to a server-side revocable
 * `docs_sessions` row".
 *
 * 🛑 **Per origin and per project, which is the entire reason §8.12.10's
 * handoff exists.** §12.4 scopes the cookie to "each docs origin", and a
 * cookie cannot span registrable domains — so a session is not a thing a
 * reader has, it is a thing a reader has *here*. §17's exit criterion "logging
 * out of project A leaves project B signed in" is that scoping, observed.
 *
 * 🛑 §19 decision 17 on why this row exists at all beside a signed grant:
 *
 * > "Stateless-only cannot satisfy SCIM offboarding or session inventory;
 * > grant-only cannot be revoked. Both are needed."
 *
 * So the division is: this row is the *revocable* fact, re-read on every grant
 * mint, and the grant is the *cheap* fact, verified without touching the
 * database. Revoking here stops the next mint, which §8.12.15 bounds at "the
 * next request" for Tiers A and B.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_id
 * @property string $domain_id
 * @property string|null $user_id 🛑 exclusive of reader_identity_id (§8.12.1)
 * @property string|null $reader_identity_id 🛑 exclusive of user_id (§8.12.1)
 * @property string $handle_hash
 * @property string $handle_hash_prefix
 * @property string $cache_key_hash
 * @property string $cache_key_hash_prefix
 * @property Carbon|null $last_seen_at
 * @property Carbon $idle_expires_at
 * @property Carbon $absolute_expires_at
 * @property Carbon|null $revoked_at
 * @property string|null $revoked_reason
 * @property int $established_epoch
 */
#[Tenancy(TenancyPosture::OrganisationScoped, because: 'a reader session is established on one project of one organisation; the serving path reads it by handle on the documentation origin, where the organisation comes from the resolved project')]
final class DocsSession extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * 🛑 Everything, for the reason {@see ReaderIdentity} gives: one writer
     * ({@see ReaderSessions}), explicit fills, and no path by
     * which a request payload reaches a column that decides who may read.
     *
     * @var list<string>
     */
    protected $guarded = ['*'];

    /**
     * The two bearer digests never leave the server, not even to a dashboard
     * session-inventory view that legitimately lists this row.
     *
     * @var list<string>
     */
    protected $hidden = [
        'handle_hash', 'handle_hash_prefix',
        'cache_key_hash', 'cache_key_hash_prefix',
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'established_epoch' => 'integer',
            'last_seen_at' => 'datetime:Y-m-d H:i:s.v',
            'idle_expires_at' => 'datetime:Y-m-d H:i:s.v',
            'absolute_expires_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * 🛑 **Live, as one predicate rather than three scattered checks.**
     *
     * Three things can end a session and all three are checked here: an
     * explicit revoke, §12.4's idle timeout and §12.4's absolute ceiling. A
     * caller that tested only `revoked_at` would honour a revoke and serve an
     * expired session forever, which is the half of §12.4 that has no audit
     * trail to catch it.
     *
     * @param  int|null  $now  unix seconds; null reads the clock
     */
    public function isLive(?int $now = null): bool
    {
        $now ??= time();

        if ($this->revoked_at !== null) {
            return false;
        }

        return $this->idle_expires_at->getTimestamp() > $now
            && $this->absolute_expires_at->getTimestamp() > $now;
    }

    /** Which population this session's subject belongs to (§8.12.1). */
    public function isMemberSession(): bool
    {
        return $this->user_id !== null;
    }

    /**
     * 🛑 There is a `user()` and there is **no** `readerIdentity()`.
     *
     * The dashboard's session inventory lists a member's sessions and names the
     * person; a reader identity is somebody else's directory subject and
     * §8.12.1 keeps it out of anything that looks like a principal here. P23
     * adds a *display* accessor for one, which is a different thing from a
     * relation an eager load could reach through.
     *
     * @return BelongsTo<User, $this>
     */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    /** @return BelongsTo<Project, $this> */
    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }
}
