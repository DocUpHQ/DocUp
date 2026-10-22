<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Source;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Models\Component;
use App\Models\ComponentSource;
use App\Models\Repository;
use App\Models\RepositoryCredential;

/**
 * §8.3.2: "A repository MUST be connectable once and attachable to many
 * components and projects."
 *
 * 🛑 "Connectable once" is a property of the *data*, not of the UI. The second
 * attempt to connect the same repository must return the **same row**, so that
 * two projects attaching the same monorepo share one credential, one webhook
 * and one fetch — rather than two rows that both provision a webhook and each
 * clone the same bytes. {@see connect()} is therefore an upsert keyed on
 * {@see Repository::locate()}, not an insert.
 *
 * 🛑 Resolution is by **stable identifier first**. A repository renamed at the
 * provider arrives with a new URL and the same identifier; resolving by URL
 * would miss it, insert a duplicate, and leave every existing component
 * pointing at a repository nobody fetches any more. ADR 0009 verified that
 * every provider in §8.3.1 supplies such an identifier, which is what makes
 * this order available.
 */
final readonly class RepositoryConnector
{
    public function __construct(private GitUrlPolicy $policy) {}

    /**
     * Connect a repository, or return the one already connected.
     *
     * @param  string  $organisationId  raw 16 bytes
     * @param  string|null  $providerRepoId  the provider's own identifier, in
     *                                       whatever spelling it supplied;
     *                                       canonicalised here
     *
     * @throws SourceRefused when §8.3.4 refuses the URL
     */
    public function connect(
        string $organisationId,
        string $url,
        ?Provider $provider = null,
        ?string $providerRepoId = null,
        ?RepositoryCredential $credential = null,
        bool $submodulesEnabled = false,
        bool $enforceAddressPolicy = true,
    ): Repository {
        $inspected = $this->policy->inspect($url, $enforceAddressPolicy);
        $provider ??= $inspected->provider;

        /*
         * 🛑 Canonicalise before storing or comparing. `{A1B2…}` and `a1b2…`
         * are one Bitbucket repository, `042` and `42` are one GitHub
         * repository, and a column that stores whichever spelling arrived has
         * a uniqueness constraint that does not constrain (ADR 0009). A value
         * that does not fit the provider's shape becomes null and the §8.3.8
         * URL fallback carries the row, because storing an uninterpretable
         * identifier is worse than storing none.
         */
        $canonicalId = $providerRepoId === null ? null : $provider->canonicaliseIdentifier($providerRepoId);

        $existing = Repository::locate(
            $provider,
            $inspected->url->host,
            $canonicalId,
            $inspected->url->normalised,
        );

        if ($existing instanceof Repository) {
            return $this->reconcile($existing, $inspected, $canonicalId, $credential);
        }

        $repository = new Repository;
        $repository->organisation_id = $organisationId;
        $repository->provider = $provider;
        $repository->provider_host = $inspected->url->host;
        $repository->provider_repo_id = $canonicalId;
        $repository->normalised_url = $inspected->url->normalised;
        $repository->clone_url = $inspected->url->canonical;
        $repository->submodules_enabled = $submodulesEnabled;
        $repository->credential_id = $credential?->id;
        $repository->save();

        Audit::record(
            action: 'repository.connected',
            actorType: ActorType::User,
            organisationId: $organisationId,
            subjectType: 'repository',
            subjectId: $repository->id,
            payload: [
                'provider' => $provider->value,
                'has_stable_identifier' => $canonicalId !== null,
                'submodules_enabled' => $submodulesEnabled,
            ],
        );

        return $repository;
    }

    /**
     * Attach a connected repository to a component.
     *
     * The second half of §8.3.2. One repository, many sources: a monorepo
     * contributing three components holds three of these rows at three paths,
     * and each component mounts into whichever projects want it.
     */
    public function attach(Repository $repository, Component $component, string $sourcePath = ''): ComponentSource
    {
        $source = new ComponentSource;
        $source->organisation_id = $repository->organisation_id;
        $source->component_id = $component->id;
        $source->repository_id = $repository->id;
        $source->source_path = trim($sourcePath, '/');
        $source->save();

        Audit::record(
            action: 'repository.attached',
            actorType: ActorType::User,
            organisationId: $repository->organisation_id,
            subjectType: 'component_source',
            subjectId: $source->id,
            payload: ['repository_id' => bin2hex($repository->id)],
        );

        return $source;
    }

    /**
     * Bring an existing row up to date with what the provider now says.
     *
     * 🛑 This is where a **rename survives**. The row was found by its stable
     * identifier; its URL no longer matches, so the URL is corrected and the
     * attachment is untouched. The inverse — refusing to update, or creating a
     * second row — is what §8.3.8 exists to prevent: "so a repository rename
     * or transfer does not orphan components".
     *
     * An identifier is also **learned** here: a repository attached before we
     * could recognise its provider carries none, and the first connect that
     * supplies one records it rather than creating a second row.
     */
    private function reconcile(
        Repository $repository,
        InspectedRepositoryUrl $inspected,
        ?string $canonicalId,
        ?RepositoryCredential $credential,
    ): Repository {
        $changes = [];

        if ($canonicalId !== null && $repository->provider_repo_id !== $canonicalId) {
            if ($repository->provider_repo_id === null) {
                $repository->provider_repo_id = $canonicalId;
                $changes[] = 'provider_repo_id';
            } else {
                /*
                 * The URL matched but the identifier did not. That is not a
                 * rename — it is a **different repository at a reused URL**,
                 * which happens when one is deleted and another created with
                 * the same name. Linking them would hand the new repository's
                 * builds to the old one's components.
                 */
                throw new SourceRefused(
                    SourceRejection::Malformed,
                    $inspected->url->host,
                    ['reason' => 'url_reused_by_a_different_repository'],
                );
            }
        }

        if ($repository->normalised_url !== $inspected->url->normalised) {
            $repository->normalised_url = $inspected->url->normalised;
            $repository->clone_url = $inspected->url->canonical;
            $changes[] = 'normalised_url';
        }

        if ($credential !== null && $repository->credential_id !== $credential->id) {
            $repository->credential_id = $credential->id;
            $changes[] = 'credential_id';
        }

        if ($changes === []) {
            return $repository;
        }

        $repository->save();

        Audit::record(
            action: 'repository.reconciled',
            actorType: ActorType::System,
            organisationId: $repository->organisation_id,
            subjectType: 'repository',
            subjectId: $repository->id,
            payload: ['changed' => $changes],
        );

        return $repository;
    }
}
