<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Concerns;

use App\Support\Uuid;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * UUIDv7 primary keys stored as BINARY(16), held in the model as RAW BYTES.
 *
 * 🛑 ADR 0006 is the reason this trait looks the way it does, and the reason it
 * must not be "tidied" into an attribute cast.
 *
 * The obvious implementation casts the key to the canonical 36-character string
 * so that `$model->id` reads nicely. That was measured and rejected. An Eloquent
 * cast applies to model ATTRIBUTES but not to query bindings, pivot inserts or
 * find(), so with a cast in place:
 *
 *   - find($uuid) returns null for a row that exists        (silent)
 *   - whereIn('id', [...]) matches 0 of 100 existing rows   (silent)
 *   - belongsToMany across a BINARY(16) pivot returns empty (silent)
 *   - assigning a foreign key raises "Data too long"        (loud)
 *
 * Fixing those needs a custom builder, per-model foreign-key declarations and a
 * bespoke pivot attach - and even then belongsToMany stays broken, because the
 * constrained column lives on the pivot table and escapes every override. In
 * DocUp the relation that breaks is project_versions <-> components: the
 * composition model itself (SPEC 8.7.2). A silently empty composition is a
 * documentation site with no content and no error anywhere.
 *
 * Holding raw bytes instead means every query Eloquent builds from an attribute
 * is already binary and matches natively, with nothing to intercept and so
 * nothing to forget. Conversion happens at exactly two boundaries, both of
 * which fail visibly if they are wrong:
 *
 *   - route binding   (resolveRouteBinding + getRouteKey below)
 *   - presentation    (the `uuid` accessor, used by JSON and the UI)
 *
 * tests/Feature/UuidKeyTest.php holds the two assertions that must never be
 * deleted, and tests/Arch/ArchitectureTest.php fails if a cast reappears.
 *
 * @phpstan-require-extends Model
 */
trait HasUuidKey
{
    public static function bootHasUuidKey(): void
    {
        static::creating(static function (Model $model): void {
            $key = $model->getKeyName();

            if ($model->getAttribute($key) === null) {
                $model->setAttribute($key, Uuid::v7());
            }
        });
    }

    public function initializeHasUuidKey(): void
    {
        $this->incrementing = false;
        $this->keyType = 'string';
    }

    /** The canonical form, for JSON, URLs and the UI. */
    public function getUuidAttribute(): ?string
    {
        $key = $this->getAttribute($this->getKeyName());

        return is_string($key) ? Uuid::toText($key) : null;
    }

    /** Route keys are the canonical form; the raw bytes never appear in a URL. */
    public function getRouteKey(): ?string
    {
        return $this->getUuidAttribute();
    }

    public function getRouteKeyName(): string
    {
        return $this->getKeyName();
    }

    /**
     * 🛑 SPEC 18.6 / ADR 0006: an invalid route key MUST render 404, never 500.
     *
     * Returning null makes the framework raise ModelNotFoundException, which the
     * exception handler renders as 404. Converting first and letting
     * InvalidArgumentException escape would produce a 500, which is the exact
     * failure mode the Phase 00 spike was written to catch.
     */
    public function resolveRouteBinding(mixed $value, mixed $field = null): ?Model
    {
        if (! is_string($value) || ! Str::isUuid($value)) {
            return null;
        }

        // Laravel's UrlRoutable declares $field as mixed, so the signature must
        // accept mixed to stay contravariant (PHPStan level 9 catches narrowing
        // it to ?string). Narrow here instead, where a non-string field is a
        // programming error rather than reader input.
        $column = is_string($field) && $field !== '' ? $field : $this->getRouteKeyName();

        $model = $this->newQuery()
            ->where($column, Uuid::toBytes($value))
            ->first();

        return $model instanceof Model ? $model : null;
    }

    /**
     * Hide the raw bytes from array and JSON output; expose `uuid` instead.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        $array = parent::toArray();

        unset($array[$this->getKeyName()]);

        $array['uuid'] = $this->getUuidAttribute();

        return $array;
    }

    /**
     * Binary-safe whereIn over keys, since callers hold canonical strings.
     *
     * The scope exists rather than being a convenience: `whereIn` with
     * canonical strings against a BINARY(16) column matches NOTHING, silently
     * (ADR 0006). Having one obvious correct way to do it is the mitigation.
     *
     * @param  Builder<static>  $query
     * @param  array<int, string>  $uuids
     * @return Builder<static>
     */
    public function scopeWhereUuidIn(Builder $query, array $uuids): Builder
    {
        return $query->whereIn($this->getKeyName(), Uuid::allToBytes($uuids));
    }

    /**
     * Binary-safe single-key lookup for callers holding a canonical string.
     *
     * @param  Builder<static>  $query
     * @return Builder<static>
     */
    public function scopeWhereUuid(Builder $query, string $uuid): Builder
    {
        return $query->where($this->getKeyName(), Uuid::toBytes($uuid));
    }
}
