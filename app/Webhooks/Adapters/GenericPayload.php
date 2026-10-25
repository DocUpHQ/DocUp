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
 * DocUp's own push shape, for a git host we have no adapter for.
 *
 * 🛑 **Signed.** §8.19.3 forbids an *unsigned* generic endpoint, not a
 * generic one: "Read the Docs ships one and it is a build-trigger oracle."
 * This parser is reached only after `X-DocUp-Signature` has verified against
 * the integration's secret, exactly as GitHub's is, and §8.5.3 lists
 * "generic webhook" among the eight trigger kinds. If you are reading this
 * looking for the unauthenticated path, there isn't one — see
 * `config/webhooks.php`.
 *
 * The contract, which is §8.1.11 public and versioned with the rest:
 *
 * ```json
 * {
 *   "ref":            "refs/heads/main",      // required, full ref path
 *   "commit":         "<40-hex sha>",         // optional; re-pinned anyway
 *   "deleted":        false,                  // optional
 *   "changed_paths":  ["docs/index.md"],      // optional
 *   "commit_message": "Update the guide"      // optional
 * }
 * ```
 *
 * 🛑 `changed_paths` is honoured when present and the payload is **not**
 * marked truncated, which is the one place this differs from Bitbucket: a
 * sender writing against DocUp's own contract can tell us the truth about
 * what changed, and §8.5.4's case (c) only applies when they say nothing.
 * A sender who cannot enumerate reliably sets `"truncated": true` and gets
 * a full rebuild, which is the safe default stated in the contract rather
 * than inferred from an empty array.
 */
final readonly class GenericPayload implements PayloadParser
{
    /**
     * @param  array<array-key, mixed>  $payload
     * @return list<PushEvent>
     */
    public function parse(array $payload, ?string $event, DeliveryHeaders $headers): array
    {
        if ($event !== null && $event !== 'push') {
            return [];
        }

        $ref = Untrusted::splitRef(Untrusted::string($payload, 'ref'));

        if ($ref === null) {
            return [];
        }

        [$kind, $name] = $ref;

        $commit = Untrusted::string($payload, 'commit') ?? '';
        $paths = Untrusted::strings($payload, 'changed_paths');
        $message = Untrusted::string($payload, 'commit_message');

        /*
         * Truncated when the sender says so, or when they sent no paths at
         * all. The second half is §8.5.4's case (c) and is what makes the
         * minimal three-field payload above safe: it rebuilds everything
         * rather than matching a path rule against nothing.
         */
        $truncated = Untrusted::bool($payload, 'truncated') || $paths === [];

        return [new PushEvent(
            deliveryId: ProviderProfile::for(Provider::Generic)->deliveryId($headers),
            event: 'push',

            /*
             * No repository identifier: the integration is already bound to
             * exactly one repository by its own row, and a generic sender
             * has no provider-stable id for us to cross-check against. The
             * binding is the URL plus the secret, which is strictly more
             * than a payload field would add.
             */
            repositoryIdentifier: null,
            refName: $name,
            refKind: $kind === RefKind::Tag ? RefKind::Tag : RefKind::Branch,
            commitSha: $commit,
            changedPaths: $paths,
            commitMessages: $message === null ? [] : [$message],
            payloadTruncated: $truncated,
            refDeleted: Untrusted::bool($payload, 'deleted') || Untrusted::isNullSha($commit),
        )];
    }
}
