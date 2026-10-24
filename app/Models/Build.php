<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\RejectionCode;
use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Support\Carbon;

/**
 * One attempt to produce a component's documentation (§8.19, §10.3).
 *
 * 🛑 **`success_unpublished` is not a failure.** §8.8.4 makes publication a
 * compare-and-swap, and zero affected rows means another build won the race.
 * The losing build's artifacts are valid and remain selectable — it simply is
 * not the one being served. Conflating that with failure would have operators
 * chasing phantom build errors every time two builds finish together, which on
 * a busy monorepo is most of the time.
 *
 * 🛑 **`content_key` is UNIQUE and excludes project-scoped input** (§8.7.9).
 * That exclusion is what makes one build shareable between every project that
 * mounts the same component; it is also why §8.7.10 forbids project-scoped
 * input from entering a build container at all. A key that varied per project
 * would make the sharing unexpressible, and the two requirements would quietly
 * contradict each other.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $project_version_id
 * @property string $component_id
 * @property string $content_key
 * @property string|null $commit_sha
 * @property string $state
 * @property string|null $failure_class
 * @property string|null $failure_identifier
 * @property int|null $exit_code
 * @property int $file_count
 * @property int $total_bytes
 * @property int|null $injector_version
 * @property string|null $chrome_mode_applied
 * @property int $chrome_documents
 * @property int $chrome_injected
 * @property array<string, mixed>|null $chrome_coverage
 * @property Carbon|null $started_at
 * @property Carbon|null $finished_at
 * @property Carbon|null $queued_at
 * @property int $log_lines
 * @property int $log_bytes
 * @property bool $log_capped
 * @property Carbon|null $cancel_requested_at
 * @property string|null $cancel_requested_by
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class Build extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * States from which nothing further happens (§8.8.9).
     *
     * Named here because garbage collection depends on the distinction: §8.8.9
     * sweeps only terminal builds older than 24 hours, and a running build's
     * objects must never be collected out from under it.
     */
    public const TERMINAL_STATES = ['published', 'success_unpublished', 'failed', 'cancelled'];

    /** @var list<string> */
    protected $guarded = ['id'];

    /** @var array<string, mixed> */
    protected $attributes = [
        'state' => 'queued',
        'file_count' => 0,
        'total_bytes' => 0,
    ];

    /** @return array<string, string> */
    protected function casts(): array
    {
        return [
            'file_count' => 'integer',
            'total_bytes' => 'integer',
            'exit_code' => 'integer',
            'log_lines' => 'integer',
            'log_bytes' => 'integer',
            'log_capped' => 'boolean',
            'cancel_requested_at' => 'datetime:Y-m-d H:i:s.v',
            'injector_version' => 'integer',
            'chrome_documents' => 'integer',
            'chrome_injected' => 'integer',
            'chrome_coverage' => 'array',
            'queued_at' => 'datetime:Y-m-d H:i:s.v',
            'started_at' => 'datetime:Y-m-d H:i:s.v',
            'finished_at' => 'datetime:Y-m-d H:i:s.v',
            'created_at' => 'datetime:Y-m-d H:i:s.v',
            'updated_at' => 'datetime:Y-m-d H:i:s.v',
        ];
    }

    /** @return BelongsTo<ProjectVersion, $this> */
    public function projectVersion(): BelongsTo
    {
        return $this->belongsTo(ProjectVersion::class);
    }

    /** @return BelongsTo<Component, $this> */
    public function component(): BelongsTo
    {
        return $this->belongsTo(Component::class);
    }

    /**
     * The trigger that produced this build (§8.5.3).
     *
     * Needed by §8.5.10: whether a build came from a fork is a property of
     * the request, and the pipeline has to ask before it decides whether
     * this build may be handed a credential.
     *
     * @return BelongsTo<BuildRequest, $this>
     */
    public function buildRequest(): BelongsTo
    {
        return $this->belongsTo(BuildRequest::class);
    }

    /** @return HasMany<BuildOutput, $this> */
    public function outputs(): HasMany
    {
        return $this->hasMany(BuildOutput::class);
    }

    /**
     * The §8.5.1 pinned sources, "recorded immutably on the build record".
     *
     * @return HasMany<BuildSource, $this>
     */
    public function sources(): HasMany
    {
        return $this->hasMany(BuildSource::class);
    }

    /**
     * §8.5.6's twelve stages, in order.
     *
     * Ordered by `sequence` rather than by `created_at`: the rows are written
     * in one loop and can share a millisecond, so a timestamp sort would
     * present the pipeline in an arbitrary order on a fast machine.
     *
     * @return HasMany<BuildStep, $this>
     */
    public function steps(): HasMany
    {
        return $this->hasMany(BuildStep::class)->orderBy('sequence');
    }

    public function isTerminal(): bool
    {
        return in_array($this->state, self::TERMINAL_STATES, true);
    }

    /**
     * Whether this build's artifacts are exempt from §8.8.9's age floor and
     * quarantine.
     *
     * §8.8.9 and §20.3: a **failed** build's objects can never have been
     * published, so neither the 24-hour floor nor the 14-day quarantine buys
     * anything — both exist to protect bytes somebody might still be serving or
     * might want back. They are deleted at terminal state instead.
     */
    public function isSweepableImmediately(): bool
    {
        return $this->state === 'failed';
    }

    /**
     * Record a terminal failure with its §8.19.15 class and stable identifier.
     *
     * 🛑 The class is derived from the identifier rather than passed alongside
     * it, so the two cannot disagree. A row reading `failure_class = 'rejected'`
     * beside `failure_identifier = 'contract.quota_exceeded'` would be a lie
     * that every alert built on these columns inherits — and §8.19.15 makes
     * them a stable contract precisely because operators build alerts on them.
     *
     * No `$detail` parameter: there is nowhere to put one. The offending entry
     * name belongs in the build log, which arrives with the runner in Phase 06;
     * until then it is carried by the thrown
     * {@see IngestRejected} and returned to the
     * caller in the API response, where the person who uploaded the tree is the
     * one who can act on it.
     */
    public function recordRejection(RejectionCode $code): void
    {
        $this->forceFill([
            'state' => 'failed',
            'failure_class' => $code->failureClass(),
            'failure_identifier' => $code->value,
            'finished_at' => now(),
        ])->save();
    }
}
