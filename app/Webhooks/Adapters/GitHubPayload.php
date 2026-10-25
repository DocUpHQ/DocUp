<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks\Adapters;

use App\Source\Provider;
use App\Webhooks\DeliveryHeaders;
use App\Webhooks\PayloadParser;
use App\Webhooks\ProviderProfile;
use App\Webhooks\PushEvent;
use App\Webhooks\Untrusted;

/**
 * GitHub's `push` event.
 *
 * 🛑 §8.5.4's truncation detection, all three cases, in the order the
 * requirement gives them:
 *
 *   (a) **No truncation flag exists.** GitHub's push payload has none — it
 *       simply stops at 20 commits and 3,000 files without saying so, which
 *       is the exact failure mode §8.5.4 was written against.
 *   (b) **The ceilings**, from configuration (§8.5.4 forbids hard-coding
 *       them). A push at or above either ceiling is treated as "everything
 *       changed".
 *   (c) **Absent arrays.** A payload with no `commits` at all — which GitHub
 *       sends for a branch deletion — yields no changed paths, and
 *       {@see PushEvent::changedPathsAreTrustworthy()} refuses to apply a
 *       path rule to it.
 */
final readonly class GitHubPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        if ($event !== 'push') {
            return [];
        }

        $ref = Untrusted::splitRef(Untrusted::string($payload, 'ref'));

        if ($ref === null) {
            return [];
        }

        [$kind, $name] = $ref;

        $after = Untrusted::string($payload, 'after') ?? '';
        $deleted = Untrusted::bool($payload, 'deleted') || Untrusted::isNullSha($after);

        $commits = Untrusted::objects($payload, 'commits');

        $paths = [];
        $messages = [];

        foreach ($commits as $commit) {
            foreach (['added', 'removed', 'modified'] as $field) {
                foreach (Untrusted::strings($commit, $field) as $path) {
                    $paths[$path] = true;
                }
            }

            $message = Untrusted::string($commit, 'message');

            if ($message !== null) {
                $messages[] = $message;
            }
        }

        $profile = ProviderProfile::for(Provider::GitHub);
        $commitCeiling = $profile->commitCeiling();
        $fileCeiling = $profile->fileCeiling();

        $truncated = ($commitCeiling !== null && count($commits) >= $commitCeiling)
            || ($fileCeiling !== null && count($paths) >= $fileCeiling);

        return [new PushEvent(
            deliveryId: $profile->deliveryId($headers),
            event: $event,
            repositoryIdentifier: Untrusted::string($payload, 'repository.id'),
            refName: $name,
            refKind: $kind,
            commitSha: $after,
            changedPaths: array_keys($paths),
            commitMessages: $messages,
            payloadTruncated: $truncated,
            refDeleted: $deleted,
        )];
    }
}
