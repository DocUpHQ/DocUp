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
 * Gitea's and Forgejo's `push`, `create` and `delete`.
 *
 * One parser for both because Forgejo is a Gitea fork and its hook structs
 * are literally Gitea's: `PushPayload`, `CreatePayload`, `DeletePayload`,
 * field for field. Writing it twice would mean two places to fix when one of
 * them diverges, and nothing to tell a reader that they had not.
 *
 * 🛑 **Tags arrive as `create`, not as `push`.** Gitea sends `push` for
 * branch updates and a separate `create` event carrying `ref` and `ref_type`
 * for a new tag — so a parser that only handled `push` would never create a
 * version for a release tag, which is the single most important thing
 * §8.6.1 asks for. Found by reading the hook structs rather than by
 * assuming the payloads matched GitHub's.
 */
final readonly class GiteaPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        return match ($event) {
            'push' => $this->parsePush($payload, $headers),
            'create' => $this->parseRefLifecycle($payload, $headers, deleted: false),
            'delete' => $this->parseRefLifecycle($payload, $headers, deleted: true),
            default => [],
        };
    }

    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    private function parsePush(array $payload, DeliveryHeaders $headers): array
    {
        $ref = Untrusted::splitRef(Untrusted::string($payload, 'ref'));

        if ($ref === null) {
            return [];
        }

        [$kind, $name] = $ref;

        $after = Untrusted::string($payload, 'after') ?? '';
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

        $profile = $this->profile($headers);

        /*
         * §8.5.4 case (a) where the instance sends `total_commits`, case (b)
         * otherwise. Gitea's cap is its own `webhook.PAGING_NUM`, which an
         * operator may raise — which is precisely why §8.5.4 insists the
         * ceiling be configuration here too.
         */
        $total = Untrusted::int($payload, 'total_commits');
        $truncated = $total !== null && $total > count($commits);

        if (! $truncated) {
            $ceiling = $profile->commitCeiling();
            $truncated = $ceiling !== null && count($commits) >= $ceiling;
        }

        return [new PushEvent(
            deliveryId: $profile->deliveryId($headers),
            event: 'push',
            repositoryIdentifier: Untrusted::string($payload, 'repository.id'),
            refName: $name,
            refKind: $kind,
            commitSha: $after,
            changedPaths: array_keys($paths),
            commitMessages: $messages,
            payloadTruncated: $truncated,
            refDeleted: Untrusted::isNullSha($after),
        )];
    }

    /**
     * Gitea's `create` and `delete`, which is how tags arrive.
     *
     * 🛑 `ref` here is the SHORT name (`v2.0.0`), not a full ref path, and
     * `ref_type` says which namespace it is in. Running it through
     * {@see Untrusted::splitRef()} would reject every one of them.
     *
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    private function parseRefLifecycle(array $payload, DeliveryHeaders $headers, bool $deleted): array
    {
        $name = Untrusted::string($payload, 'ref');
        $type = Untrusted::string($payload, 'ref_type');

        if ($name === null || $name === '' || ($type !== 'branch' && $type !== 'tag')) {
            return [];
        }

        $profile = $this->profile($headers);

        return [new PushEvent(
            deliveryId: $profile->deliveryId($headers),
            event: $deleted ? 'delete' : 'create',
            repositoryIdentifier: Untrusted::string($payload, 'repository.id'),
            refName: $name,
            refKind: $type === 'tag' ? RefKind::Tag : RefKind::Branch,

            /*
             * `create` carries `sha` on newer Gitea and nothing on older; a
             * missing SHA is fine because §8.5.1 re-pins every ref with
             * `ls-remote` before a build anyway. What matters is that a
             * version gets created for the tag.
             */
            commitSha: Untrusted::string($payload, 'sha') ?? '',
            changedPaths: [],
            commitMessages: [],
            payloadTruncated: true,
            refDeleted: $deleted,
        )];
    }

    /**
     * Which of the two providers sent this, by the headers it used.
     *
     * The payloads are identical so the body cannot say; the header spelling
     * can, and it decides which delivery-id header is read.
     */
    private function profile(DeliveryHeaders $headers): ProviderProfile
    {
        return ProviderProfile::for(
            $headers->has('X-Forgejo-Event') || $headers->has('X-Forgejo-Signature')
                ? Provider::Forgejo
                : Provider::Gitea
        );
    }
}
