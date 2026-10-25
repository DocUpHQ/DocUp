<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Source\Provider;
use App\Webhooks\Adapters\BitbucketCloudPayload;
use App\Webhooks\Adapters\BitbucketServerPayload;
use App\Webhooks\Adapters\GenericPayload;
use App\Webhooks\Adapters\GiteaPayload;
use App\Webhooks\Adapters\GitHubPayload;
use App\Webhooks\Adapters\GitLabPayload;

/**
 * What one provider's HTTP looks like: where the signature is, where the
 * delivery id is, what it calls the event, and who reads its payload.
 *
 * 🛑 The header names are data, not scattered literals, because §8.19.3's
 * guarantee is only as good as reading the right header. A verifier that
 * looked for `X-Hub-Signature-256` on a Gitea delivery would find nothing,
 * and "nothing" is one careless `?? ''` away from "verified against the
 * empty string".
 */
final readonly class ProviderProfile
{
    /**
     * @param  list<string>  $signatureHeaders  tried in order; first present wins
     * @param  list<string>  $deliveryIdHeaders  §8.19.3's replay key where there is no timestamp
     * @param  list<string>  $eventHeaders  the provider's own event name
     */
    private function __construct(
        public Provider $provider,
        public array $signatureHeaders,
        public array $deliveryIdHeaders,
        public array $eventHeaders,
        public SignatureScheme $defaultScheme,
        public PayloadParser $parser,
    ) {}

    public static function for(Provider $provider): self
    {
        return match ($provider) {
            /*
             * 🛑 `X-Hub-Signature-256` only. GitHub still sends the SHA-1
             * `X-Hub-Signature` beside it, and listing both here would make
             * the SHA-256 header optional in practice: an attacker who can
             * forge SHA-1 — which has had practical collisions since 2017 —
             * would simply omit the stronger header.
             */
            Provider::GitHub => new self(
                $provider,
                ['X-Hub-Signature-256'],
                ['X-GitHub-Delivery'],
                ['X-GitHub-Event'],
                SignatureScheme::HmacSha256Prefixed,
                new GitHubPayload,
            ),

            /*
             * GitLab's default is still the legacy shared token; an instance
             * on 19.1 or later that has enabled Standard Webhooks signing
             * sets `scheme` on the integration row and overrides this. The
             * default is the weaker one because choosing the stronger by
             * default would silently stop building for every operator below
             * 19.1, and a build that stops is reported by nobody.
             */
            Provider::GitLab => new self(
                $provider,
                ['X-Gitlab-Token'],
                ['X-Gitlab-Event-UUID', 'webhook-id'],
                ['X-Gitlab-Event'],
                SignatureScheme::SharedToken,
                new GitLabPayload,
            ),

            /*
             * 🛑 §8.3.1 and §11.1: Bitbucket supplies **no timestamp**, so
             * replay protection here is delivery-id uniqueness and nothing
             * else. `X-Request-UUID` is Cloud's; Server sends
             * `X-Request-Id`. Both are listed because a delivery without one
             * is refused outright rather than admitted unprotected.
             */
            Provider::BitbucketCloud => new self(
                $provider,
                ['X-Hub-Signature'],
                ['X-Request-UUID', 'X-Hook-UUID'],
                ['X-Event-Key'],
                SignatureScheme::HmacSha256Prefixed,
                new BitbucketCloudPayload,
            ),

            Provider::BitbucketServer => new self(
                $provider,
                ['X-Hub-Signature'],
                ['X-Request-Id'],
                ['X-Event-Key'],
                SignatureScheme::HmacSha256Prefixed,
                new BitbucketServerPayload,
            ),

            /*
             * Gitea and Forgejo send byte-identical push payloads — Forgejo
             * is a Gitea fork and its hook structs are the same ones — so
             * they share a parser. They do not share header names, and a
             * Forgejo instance migrated from Gitea may still send the Gitea
             * spelling, so both are tried. Trying both is not laxity: the
             * secret still has to verify.
             */
            Provider::Gitea => new self(
                $provider,
                ['X-Gitea-Signature', 'X-Forgejo-Signature'],
                ['X-Gitea-Delivery', 'X-Forgejo-Delivery'],
                ['X-Gitea-Event', 'X-Forgejo-Event'],
                SignatureScheme::HmacSha256Hex,
                new GiteaPayload,
            ),

            Provider::Forgejo => new self(
                $provider,
                ['X-Forgejo-Signature', 'X-Gitea-Signature'],
                ['X-Forgejo-Delivery', 'X-Gitea-Delivery'],
                ['X-Forgejo-Event', 'X-Gitea-Event'],
                SignatureScheme::HmacSha256Hex,
                new GiteaPayload,
            ),

            /*
             * 🛑 The generic provider is SIGNED. §8.5.3 lists "generic
             * webhook" among the eight trigger kinds and §8.19.3 forbids an
             * **unsigned** one; both hold at once because this profile
             * requires `X-DocUp-Signature` and the integration row requires a
             * secret. What makes it generic is that nobody has written a
             * payload adapter for the sender, not that nobody checks who it
             * is.
             */
            Provider::Generic => new self(
                $provider,
                ['X-DocUp-Signature'],
                ['X-DocUp-Delivery'],
                ['X-DocUp-Event'],
                SignatureScheme::HmacSha256Hex,
                new GenericPayload,
            ),
        };
    }

    public function deliveryId(DeliveryHeaders $headers): ?string
    {
        return $headers->first(...$this->deliveryIdHeaders);
    }

    public function event(DeliveryHeaders $headers): ?string
    {
        return $headers->first(...$this->eventHeaders);
    }

    /**
     * §8.5.4's per-provider commit ceiling, from configuration.
     *
     * 🛑 Never a hard-coded fact, by the requirement's own words: "providers
     * change these limits without notice". Null means the provider publishes
     * no ceiling, which is not the same as "no truncation" — see
     * {@see GenericPayload} and the Bitbucket parsers, where the file arrays
     * are absent altogether and §8.5.4's case (c) applies.
     */
    public function commitCeiling(): ?int
    {
        $value = config('webhooks.truncation.'.$this->provider->value.'.commits');

        return is_int($value) ? $value : null;
    }

    /** §8.5.4's per-provider changed-file ceiling, from configuration. */
    public function fileCeiling(): ?int
    {
        $value = config('webhooks.truncation.'.$this->provider->value.'.files');

        return is_int($value) ? $value : null;
    }
}
