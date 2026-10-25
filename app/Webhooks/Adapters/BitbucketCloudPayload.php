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
 * Bitbucket Cloud's `repo:push`.
 *
 * 🛑 **Every Bitbucket push is "everything changed"**, and no configuration
 * can make it otherwise. §8.5.4's case (c) is "absence of the changed-file
 * arrays altogether", and Bitbucket's push payload has none: `push.changes[]`
 * carries commits with hashes and messages, and the file lists are only
 * available by a second API call per commit. A skip rule that filtered on
 * paths against a Bitbucket push would be filtering against an empty list,
 * which matches nothing and would skip every build.
 *
 * It also sends a per-change `truncated` flag — §8.5.4's case (a) — which is
 * read and honoured even though case (c) has already decided the outcome,
 * because a payload that says it was truncated should be recorded as
 * truncated whatever else is true of it.
 *
 * 🛑 One push may carry SEVERAL changes: Bitbucket batches `git push --all`
 * into a single delivery with one entry per ref, which is why
 * {@see PayloadParser::parse()} returns a list rather than one event.
 */
final readonly class BitbucketCloudPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        if ($event !== 'repo:push') {
            return [];
        }

        $profile = ProviderProfile::for(Provider::BitbucketCloud);
        $deliveryId = $profile->deliveryId($headers);
        $identifier = Untrusted::string($payload, 'repository.uuid');

        $events = [];

        foreach (Untrusted::objects($payload, 'push.changes') as $index => $change) {
            $target = is_array($change['new'] ?? null) ? $change['new'] : null;
            $closed = Untrusted::bool($change, 'closed');

            // A closed change has no `new`; the ref it names is in `old`.
            $source = $target ?? (is_array($change['old'] ?? null) ? $change['old'] : null);

            if ($source === null) {
                continue;
            }

            $name = Untrusted::string($source, 'name');
            $type = Untrusted::string($source, 'type');

            if ($name === null || ($type !== 'branch' && $type !== 'tag')) {
                continue;
            }

            $messages = [];

            foreach (Untrusted::objects($change, 'commits') as $commit) {
                $message = Untrusted::string($commit, 'message');

                if ($message !== null) {
                    $messages[] = $message;
                }
            }

            $events[] = new PushEvent(
                /*
                 * 🛑 The delivery id is suffixed per change, because
                 * §8.5.4's first layer is `UNIQUE (integration_id,
                 * delivery_id)` and a `git push --all` of four branches is
                 * four build requests from one delivery. Without the suffix
                 * three of them would collide with the first and be silently
                 * returned as redeliveries.
                 *
                 * The REPLAY ledger still keys on the bare delivery id, so
                 * the weaker guarantee §8.19.3 permits here is unaffected:
                 * one delivery, one ledger row, four requests.
                 */
                deliveryId: $deliveryId === null ? null : $deliveryId.'#'.$index,
                event: $event,
                repositoryIdentifier: $identifier,
                refName: $name,
                refKind: $type === 'tag' ? RefKind::Tag : RefKind::Branch,
                commitSha: Untrusted::string($source, 'target.hash') ?? '',
                changedPaths: [],
                commitMessages: $messages,
                payloadTruncated: true,
                refDeleted: $closed || $target === null,
            );
        }

        return $events;
    }
}
