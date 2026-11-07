<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Access\DecisionLog;
use App\Auth\RoleResolver;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Readers\ReaderSessions;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * 🛑 §8.12.1's second principal population, and the whole point is what this
 * class is **not**.
 *
 * > "The system MUST maintain two **physically disjoint** principal
 * > populations: `users` for the dashboard and `reader_identities` for
 * > published documentation. Reader identities MUST be keyed `(binding_id,
 * > subject_hash)`, **email MUST NEVER be used for linking or lookup**, and a
 * > reader identity MUST NEVER hold a role assignment — the permission resolver
 * > MUST raise rather than return an empty set for a reader subject. A project
 * > admin controls their own IdP; find-or-create-by-email would let any tenant
 * > mint an installation owner."
 *
 * So, deliberately absent and each absence asserted by an architecture test:
 *
 * - **No `Authenticatable`.** A reader is never `auth()->user()`, never passes
 *   through a Laravel guard, and cannot be handed to anything typed on
 *   `User`. The dashboard's authorisation machinery cannot be asked about one
 *   by accident, because there is no type by which one arrives.
 * - **No `email` column and no `byEmail()`.** Not "we do not use it" — it does
 *   not exist. §8.12.1's failure mode is a convenience method written three
 *   phases later by somebody who did not read this comment.
 * - **No roles relation.** `role_assignments.subject_type` is
 *   `ENUM('user', 'group', 'api_token')`, so the database refuses a row naming
 *   a reader identity. {@see RoleResolver} raises rather than
 *   returning an empty set, which is §8.12.1's own remedy: an empty set reads
 *   as "authorised for nothing" and is indistinguishable from a reader who has
 *   simply not been granted anything yet.
 *
 * 🛑 **No rows exist in Phase 22.** A reader identity is produced by an
 * `auth_provider_bindings` driver, and bindings are P23's first deliverable
 * (§17). P22's sessions are all `user_id` sessions — dashboard members who
 * completed §8.12.10's handoff. The table and the model ship now because
 * `docs_sessions` references them and because the disjointness is a schema
 * property that has to be true before the first provider arrives, not after.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $binding_id
 * @property string $subject_hash a keyed digest, never a readable subject
 * @property string|null $display_label
 * @property Carbon|null $last_seen_at
 * @property Carbon|null $deprovisioned_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped, because: 'a reader identity belongs to the organisation whose binding vouched for it; §8.12.3 scopes bindings at installation, organisation or project level and the identity inherits that organisation')]
final class ReaderIdentity extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * 🛑 Everything. A reader identity is written by exactly one class
     * ({@see ReaderSessions}) through explicit `forceFill`, so
     * there is no mass-assignment path at all — which is the shape §8.12.1
     * wants for a population an external directory supplies the keys for.
     *
     * @var list<string>
     */
    protected $guarded = ['*'];

    /** @var list<string> */
    protected $hidden = ['subject_hash'];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'last_seen_at' => 'datetime:Y-m-d H:i:s.v',
            'deprovisioned_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /**
     * 🛑 §8.12.1's key, as the one function that computes it.
     *
     * Keyed with `APP_KEY` rather than a bare digest, so the stored value is
     * useless to anybody who obtains the table without the key — the same
     * construction {@see DecisionLog::subjectHash()} uses, and for
     * the same reason: a plain SHA-256 of an email address or a short numeric
     * subject is a dictionary away from being the identifier itself.
     *
     * @param  string  $subject  the provider's own subject identifier
     * @return string raw 32 bytes
     */
    public static function hashSubject(string $subject): string
    {
        $key = config('app.key');

        return hash_hmac('sha256', $subject, is_string($key) ? $key : '', binary: true);
    }

    /** Whether this identity may still establish a session (§10.8). */
    public function isUsable(): bool
    {
        return $this->deprovisioned_at === null;
    }
}
