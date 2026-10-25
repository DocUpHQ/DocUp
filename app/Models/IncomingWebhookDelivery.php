<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Models;

use App\Auth\Tenancy;
use App\Auth\TenancyPosture;
use App\Concerns\BelongsToOrganisation;
use App\Concerns\HasUuidKey;
use App\Webhooks\DeliveryLedger;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Support\Carbon;

/**
 * A delivery this installation has already seen (§8.19.3).
 *
 * 🛑 The replay defence for the three signature schemes that carry no
 * timestamp. See {@see DeliveryLedger} for why it is weaker
 * than a window and exactly how much weaker.
 *
 * Distinct from `build_requests`, which carries the same pair as §8.5.4's
 * FIRST deduplication layer: that table remembers deliveries that produced a
 * request, and this one remembers every delivery that verified — including
 * those that resolved to nothing. A replay of one of those is still a replay.
 *
 * @property-read string $id
 * @property string $organisation_id
 * @property string $integration_id
 * @property string $delivery_id
 * @property string|null $event
 * @property Carbon $received_at
 */
#[Tenancy(TenancyPosture::OrganisationScoped)]
final class IncomingWebhookDelivery extends Model
{
    use BelongsToOrganisation;
    use HasUuidKey;

    /**
     * 🛑 No `updated_at`. A delivery is written once and never touched
     * again; a second write to one of these rows would mean the uniqueness
     * constraint had been worked around.
     */
    public $timestamps = false;

    /** @return array<string, string> */
    protected function casts(): array
    {
        return ['received_at' => 'datetime:Y-m-d H:i:s.v'];
    }

    /** @return BelongsTo<WebhookIntegration, $this> */
    public function integration(): BelongsTo
    {
        return $this->belongsTo(WebhookIntegration::class, 'integration_id');
    }
}
