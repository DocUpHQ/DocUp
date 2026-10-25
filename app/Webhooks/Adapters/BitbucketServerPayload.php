<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks\Adapters;

use App\Source\Provider;
use App\Versions\RefKind;
use App\Webhooks\DeliveryHeaders;
use App\Webhooks\PayloadParser;
use App\Webhooks\ProviderProfile;
use App\Webhooks\PushEvent;
use App\Webhooks\Untrusted;

/**
 * Bitbucket Data Center / Server's `repo:refs_changed`.
 *
 * A different payload from Cloud's under a different event key, which is
 * ADR 0009's whole point: one `bitbucket` provider would have needed a
 * parser that branched on the shape of the body it received, and a parser
 * that guesses which product sent it is a parser that can be made to guess
 * wrong.
 *
 * 🛑 Like Cloud, it carries **no changed-file arrays** — §8.5.4's case (c) —
 * so every push is "everything changed" and no path rule applies.
 */
final readonly class BitbucketServerPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        /*
         * The header is authoritative, but Server also puts `eventKey` in
         * the body and some reverse proxies drop the header. Accepting
         * either is safe: the body was signed, so a body claiming to be a
         * push IS one as far as authenticity goes.
         */
        $key = $event ?? Untrusted::string($payload, 'eventKey');

        if ($key !== 'repo:refs_changed') {
            return [];
        }

        $profile = ProviderProfile::for(Provider::BitbucketServer);
        $deliveryId = $profile->deliveryId($headers);
        $identifier = Untrusted::string($payload, 'repository.id');

        $events = [];

        foreach (Untrusted::objects($payload, 'changes') as $index => $change) {
            $ref = Untrusted::splitRef(Untrusted::string($change, 'ref.id'));

            if ($ref === null) {
                continue;
            }

            [$kind, $name] = $ref;

            /*
             * Server states the ref type separately from the ref path, and
             * they must agree. A `BRANCH` typed change whose id is under
             * `refs/tags/` is a payload nobody should act on — see the same
             * refusal in {@see GitLabPayload}.
             */
            $declared = Untrusted::string($change, 'ref.type');

            if ($declared === 'BRANCH' && $kind !== RefKind::Branch) {
                continue;
            }

            if ($declared === 'TAG' && $kind !== RefKind::Tag) {
                continue;
            }

            $toHash = Untrusted::string($change, 'toHash') ?? '';

            $events[] = new PushEvent(
                // Suffixed per change for the reason {@see BitbucketCloudPayload}
                // gives: one delivery, several refs, and §8.5.4's first layer
                // is a uniqueness constraint on the delivery id.
                deliveryId: $deliveryId === null ? null : $deliveryId.'#'.$index,
                event: $key,
                repositoryIdentifier: $identifier,
                refName: $name,
                refKind: $kind,
                commitSha: $toHash,
                changedPaths: [],
                commitMessages: [],
                payloadTruncated: true,
                refDeleted: Untrusted::string($change, 'type') === 'DELETE' || Untrusted::isNullSha($toHash),
            );
        }

        return $events;
    }
}
