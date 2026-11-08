<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\CidrRange;
use App\Auth\Scope;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Support\Carbon;

/**
 * A dashboard API token (§8.13.6).
 *
 * 🛑 One of the **two separate token families** §8.13.6 insists on keeping
 * apart: these authenticate a human's automation against the dashboard API.
 * Reader credentials are a different table, a different lifetime and a
 * different trust model, and conflating them is how a long-lived automation
 * token ends up granting documentation access.
 *
 * No `$fillable`: {@see ApiTokens} is the only thing that may mint
 * one, because minting is where §8.13.6's prohibition on installation-scope
 * administrative capability is enforced.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $user_id
 * @property string $name
 * @property string $token_hash
 * @property Scope $scope_type
 * @property string|null $scope_id
 * @property list<string> $capabilities
 * @property string $token_hash_prefix
 * @property Carbon|null $expires_at
 * @property Carbon|null $last_used_at
 * @property Carbon|null $revoked_at
 * @property string|null $cidr_allowlist
 * @property string|null $rotated_from_id
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class ApiToken extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'capabilities' => 'array',
            'scope_type' => Scope::class,
            'expires_at' => 'datetime:Y-m-d H:i:s.v',
            'last_used_at' => 'datetime:Y-m-d H:i:s.v',
            'revoked_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    public function isUsable(): bool
    {
        return $this->revoked_at === null
            && $this->expires_at !== null
            && $this->expires_at->isFuture();
    }

    /**
     * §8.13.6's optional CIDR binding.
     *
     * 🛑 **Null or empty means UNBOUND and usable from anywhere**,
     * which is the default and is what most tokens are. An unset binding is not
     * an empty allowlist — conflating the two would make every existing
     * token stop working the moment this was enforced.
     *
     * 🛑 But a bound token presented from an address we do not know
     * fails **closed**. The address comes from `$request->ip()`, which is only
     * the reader's once §8.9.4's trusted-proxy list is configured
     * (the `TrustEdgeProxies` middleware — named in prose rather than with
     * `{@see}`, because Pint turns that into an import and the Laravel
     * architecture preset rightly refuses a model that depends on
     * middleware); before Phase 26b it
     * was the edge's. A binding compared against an address nobody resolved is
     * a binding that admits whoever the proxy happens to be, so "no address"
     * is a refusal rather than a pass.
     */
    public function allowsAddress(?string $address): bool
    {
        $ranges = $this->cidrRanges();

        if ($ranges === []) {
            return true;
        }

        if ($address === null || $address === '') {
            return false;
        }

        return CidrRange::anyCovers($ranges, $address);
    }

    /** Whether this token is bound to a set of addresses at all. */
    public function isAddressBound(): bool
    {
        return $this->cidrRanges() !== [];
    }

    /**
     * The binding, as a list.
     *
     * Stored as one comma-separated string in a `varchar(255)` because
     * §10's schema put it there in Phase 02 and a bounded list of ranges is
     * not a table. Canonicalised at mint, so what is split here is what the
     * operator was shown.
     *
     * @return list<string>
     */
    public function cidrRanges(): array
    {
        $configured = $this->cidr_allowlist;

        if (! is_string($configured) || trim($configured) === '') {
            return [];
        }

        return array_values(array_filter(
            array_map('trim', explode(',', $configured)),
            static fn (string $range): bool => $range !== '',
        ));
    }

    /**
     * 🛑 The successor this token was rotated into, if any.
     *
     * Read by {@see ApiTokens::rotate()} to refuse a second rotation, so a
     * family never holds more than two live secrets.
     *
     * @return HasOne<self, $this>
     */
    public function successor(): HasOne
    {
        return $this->hasOne(self::class, 'rotated_from_id');
    }

    /**
     * The token this one replaced, if it was minted by a rotation.
     *
     * @return BelongsTo<self, $this>
     */
    public function rotatedFrom(): BelongsTo
    {
        return $this->belongsTo(self::class, 'rotated_from_id');
    }

    /** Whether this token carries a capability. */
    public function grants(Capability $capability): bool
    {
        return in_array($capability->value, $this->capabilities, true);
    }

    /** @return BelongsTo<User, $this> */
    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }
}
