<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

/**
 * The providers of §8.3.1, and what each one calls its stable repository
 * identifier.
 *
 * 🛑 This enum is where ADR 0009's verification of §18.27 lives **as code**,
 * rather than only as a table in a document nobody reads twice. Every value
 * below was taken from the provider's current API or webhook definition on
 * 2026-10-22:
 *
 * | Provider | Field | Type | At attach | In webhooks |
 * |---|---|---|---|---|
 * | GitHub | `repository.id` (also `node_id`) | `integer`/`int64` | yes | yes |
 * | GitLab | `project_id` / `project.id` | `integer` | yes | yes |
 * | Bitbucket Cloud | `repository.uuid` | **braced** UUID string | yes | yes |
 * | Bitbucket Server | `repository.id` | integer | yes | yes |
 * | Gitea | `repository.id` | `int64` | yes | yes |
 * | Forgejo | `repository.id` | `int64` | yes | yes |
 *
 * 🛑 **Bitbucket is two providers.** Cloud carries a braced `uuid` and no
 * numeric id; Data Center/Server carries a numeric `id` and a `slug`. One
 * provider value would mean a column whose type depends on a deployment the
 * operator chose, which is how `{ABC…}` and `42` end up in the same `VARCHAR`
 * under a uniqueness constraint that cannot tell them apart.
 *
 * 🛑 **The identifier is unique per instance, not per provider.** Gitea and
 * Forgejo are self-hosted only; GitLab CE commonly is. Repository 42 exists on
 * every Gitea server in the world, so `provider_repo_id` is only a key when
 * the provider **host** is part of it. §10.2's constraint was amended for this
 * in ADR 0009.
 */
enum Provider: string
{
    case GitHub = 'github';
    case GitLab = 'gitlab';
    case BitbucketCloud = 'bitbucket_cloud';
    case BitbucketServer = 'bitbucket_server';
    case Gitea = 'gitea';
    case Forgejo = 'forgejo';

    /**
     * Any other git remote — a bare SSH host, a self-hosted server we have no
     * API for.
     *
     * 🛑 It is in the enum rather than excluded because the fallback path has
     * to be a first-class case. §8.3.8 requires degrading to normalised-URL
     * matching "where none exists", and a schema in which that case is an
     * exception is a schema where the exception is untested.
     */
    case Generic = 'generic';

    /** The JSON field name the provider's API and webhooks use. */
    public function stableIdentifierField(): ?string
    {
        return match ($this) {
            self::BitbucketCloud => 'uuid',
            self::Generic => null,
            default => 'id',
        };
    }

    /** Where the identifier sits in a webhook payload, for Phase 11. */
    public function webhookIdentifierPath(): ?string
    {
        return match ($this) {
            self::GitHub, self::Gitea, self::Forgejo, self::BitbucketServer => 'repository.id',
            self::GitLab => 'project_id',
            self::BitbucketCloud => 'repository.uuid',
            self::Generic => null,
        };
    }

    public function shape(): IdentifierShape
    {
        return match ($this) {
            self::BitbucketCloud => IdentifierShape::BracedUuid,
            self::Generic => IdentifierShape::None,
            default => IdentifierShape::Integer,
        };
    }

    /**
     * The identifier in the one form that is stored and compared.
     *
     * 🛑 Canonicalisation is not tidying. `{A1B2…}` and `a1b2…` are the same
     * Bitbucket repository and `042` and `42` are the same GitHub repository,
     * so a column that stores whichever spelling arrived has a uniqueness
     * constraint that does not constrain — and the §8.3.8 rename path, which
     * looks the repository up **by this value**, misses the row it was built
     * to find. The function returns null rather than guessing when the value
     * does not fit the provider's shape: storing an uninterpretable identifier
     * is worse than storing none, because the schema then claims a guarantee
     * the data does not support.
     */
    public function canonicaliseIdentifier(string $raw): ?string
    {
        return $this->shape()->canonicalise($raw);
    }

    /** The hosted instance, where there is exactly one. */
    public function canonicalHost(): ?string
    {
        return match ($this) {
            self::GitHub => 'github.com',
            self::GitLab => 'gitlab.com',
            self::BitbucketCloud => 'bitbucket.org',
            default => null,   // self-hosted: the host is the operator's
        };
    }

    /** The provider a well-known host implies, for attach-time convenience. */
    public static function forHost(string $host): self
    {
        return match (strtolower($host)) {
            'github.com', 'www.github.com' => self::GitHub,
            'gitlab.com', 'www.gitlab.com' => self::GitLab,
            'bitbucket.org', 'www.bitbucket.org' => self::BitbucketCloud,
            default => self::Generic,
        };
    }
}
