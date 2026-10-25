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
 * GitLab's `push` and `tag_push` events.
 *
 * 🛑 GitLab is the one provider that supplies §8.5.4's **case (a)**, a
 * genuine truncation signal: `total_commits_count` carries the real number
 * while `commits` is capped at twenty. Comparing the two is exact where a
 * ceiling comparison is only a heuristic, so it is checked first and the
 * configured ceiling is the fallback — which is the order §8.5.4 states.
 */
final readonly class GitLabPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        $kind = Untrusted::string($payload, 'object_kind');

        if ($kind !== 'push' && $kind !== 'tag_push') {
            return [];
        }

        $ref = Untrusted::splitRef(Untrusted::string($payload, 'ref'));

        if ($ref === null) {
            return [];
        }

        [$refKind, $name] = $ref;

        /*
         * 🛑 A `tag_push` whose ref parses as a branch, or the reverse, is
         * refused rather than reconciled. The two fields disagreeing means
         * either a provider bug or a forged body that passed verification
         * because somebody shared a secret, and guessing which the sender
         * meant is how a tag becomes a branch version with a moving target.
         */
        $expected = $kind === 'tag_push' ? RefKind::Tag : RefKind::Branch;

        if ($refKind !== $expected) {
            return [];
        }

        /*
         * `checkout_sha` is null for a deletion and is the authoritative
         * value otherwise; `after` is the raw ref target. Preferring
         * `checkout_sha` matters for an annotated tag, where `after` is the
         * tag object's own SHA and `checkout_sha` is the commit it points
         * at — and §8.5.1 pins a commit, not a tag object.
         */
        $after = Untrusted::string($payload, 'after') ?? '';
        $checkout = Untrusted::string($payload, 'checkout_sha');
        $deleted = $checkout === null || Untrusted::isNullSha($after);

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

        $profile = ProviderProfile::for(Provider::GitLab);

        // §8.5.4 case (a), the one provider that gives us one.
        $total = Untrusted::int($payload, 'total_commits_count');
        $truncated = $total !== null && $total > count($commits);

        if (! $truncated) {
            $ceiling = $profile->commitCeiling();
            $truncated = $ceiling !== null && count($commits) >= $ceiling;
        }

        /*
         * 🛑 §10.2's identifier is the project id, and GitLab sends it in
         * two places that do not always both appear: `project_id` at the top
         * level of a push, and `project.id` in the nested object. Reading
         * only one is how a payload from a slightly different GitLab version
         * resolves to no repository and silently does nothing.
         */
        $identifier = Untrusted::string($payload, 'project_id')
            ?? Untrusted::string($payload, 'project.id');

        return [new PushEvent(
            deliveryId: $profile->deliveryId($headers),
            event: $kind,
            repositoryIdentifier: $identifier,
            refName: $name,
            refKind: $refKind,
            commitSha: $checkout ?? $after,
            changedPaths: array_keys($paths),
            commitMessages: $messages,
            payloadTruncated: $truncated,
            refDeleted: $deleted,
        )];
    }
}
