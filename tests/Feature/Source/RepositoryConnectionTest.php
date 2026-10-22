<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Source;

use App\Auth\OrganisationContext;
use App\Egress\AddressGuard;
use App\Egress\IpAddressClassifier;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Source\GitUrlPolicy;
use App\Source\Provider;
use App\Source\RepositoryConnector;
use App\Source\SourceRefused;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Tests\Support\FakeDnsResolver;
use Tests\TestCase;

/**
 * 🛑 Two of Phase 05's exit criteria, demonstrated:
 *
 * > "One repository connected once and attached to two projects."
 * > "A repository renamed at the provider still resolves by its stable
 * > identifier."
 *
 * The second is the one ADR 0009 was written for. §18.27 was unverified until
 * this phase, and the whole of §8.3.8 — "so a repository rename or transfer
 * does not orphan components" — rests on it. The test asserts the inverse as
 * well as the property: after a rename, a URL-only lookup **misses**, which
 * is the entire reason the stable identifier is in the schema.
 */
final class RepositoryConnectionTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private RepositoryConnector $connector;

    protected function setUp(): void
    {
        parent::setUp();

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Source Co',
            'slug' => 'source-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $resolver = (new FakeDnsResolver)
            ->stable('github.com', ['140.82.121.4'])
            ->stable('git.acme.test', ['93.184.216.34'])
            ->stable('git.other.test', ['93.184.216.35']);

        $this->connector = new RepositoryConnector(
            new GitUrlPolicy(new AddressGuard($resolver, new IpAddressClassifier)),
        );
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /**
     * 🛑 §8.3.2: "A repository MUST be connectable once and attachable to many
     * components and projects."
     *
     * One repository row, two components, two projects. The assertion that
     * matters is the **count**: a second row would mean two webhooks, two
     * credentials and two clones of the same bytes, and the duplicate is the
     * kind of thing nobody notices until the provider rate-limits the
     * installation.
     */
    public function test_one_repository_is_connected_once_and_attached_to_two_projects(): void
    {
        $repository = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://github.com/acme/monorepo.git',
            providerRepoId: '1296269',
        );

        // The same repository offered again, in its SSH spelling and with the
        // provider's identifier. §8.3.2's "once" has to survive this.
        $again = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'git@github.com:acme/monorepo.git',
            providerRepoId: '1296269',
        );

        $this->assertSame($repository->id, $again->id);
        $this->assertSame(1, Repository::query()->count());

        $guides = $this->attachProject('guides', $repository, 'docs/guides');
        $api = $this->attachProject('api', $repository, 'docs/api');

        $this->assertNotSame($guides->id, $api->id);

        $this->assertSame(
            2,
            $repository->sources()->count(),
            'one repository must carry a source per component',
        );

        // The full chain the criterion names: repository → source → component
        // → mount → version → project, twice, from one repository row.
        $projectsReached = ProjectVersion::query()
            ->whereIn('id', ComponentMount::query()
                ->whereIn('component_id', $repository->sources()->pluck('component_id'))
                ->pluck('project_version_id'))
            ->pluck('project_id')
            ->unique();

        $this->assertCount(2, $projectsReached);
    }

    /**
     * 🛑 "A repository renamed at the provider still resolves by its stable
     * identifier."
     *
     * The rename changes the URL and nothing else. Resolution finds the
     * original row by `provider_repo_id`, corrects the stored URL, and leaves
     * every attachment in place.
     */
    public function test_a_renamed_repository_still_resolves_by_its_stable_identifier(): void
    {
        $repository = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://github.com/acme/old-name.git',
            providerRepoId: '1296269',
        );

        $component = $this->attachProject('guides', $repository, 'docs');
        $sourceCount = $repository->sources()->count();

        // The provider renamed it. Same identifier, new URL.
        $afterRename = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://github.com/acme/new-name.git',
            providerRepoId: '1296269',
        );

        $this->assertSame($repository->id, $afterRename->id, 'the rename created a second repository');
        $this->assertSame(1, Repository::query()->count());
        $this->assertSame('github.com/acme/new-name', $afterRename->normalised_url);
        $this->assertSame('https://github.com/acme/new-name', $afterRename->clone_url);

        $this->assertSame($sourceCount, $afterRename->sources()->count(), 'the rename orphaned a component');
        $this->assertSame(
            $component->id,
            (string) $afterRename->sources()->first()?->component_id,
            'the attachment no longer points at the same component',
        );

        /*
         * 🛑 The inverse, which is why the identifier is in the schema at all.
         * A URL-only lookup now misses — so an installation without the
         * stable identifier would have created a second repository here and
         * left the first one attached to a name nobody fetches.
         */
        $this->assertNull(
            Repository::locate(Provider::GitHub, 'github.com', null, 'github.com/acme/old-name'),
        );
    }

    /**
     * A URL reused by a **different** repository is not a rename.
     *
     * Deleting `acme/docs` and creating a new repository with the same name
     * is a real provider workflow. Linking the two would hand the new
     * repository's builds to the old one's components.
     */
    public function test_a_reused_url_with_a_different_identifier_is_refused(): void
    {
        $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://github.com/acme/docs.git',
            providerRepoId: '1296269',
        );

        $this->expectException(SourceRefused::class);

        $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://github.com/acme/docs.git',
            providerRepoId: '9999999',
        );
    }

    /**
     * A repository attached before its provider was recognised carries no
     * identifier. The first connect that supplies one **learns** it rather
     * than creating a second row.
     */
    public function test_a_stable_identifier_is_learned_rather_than_duplicated(): void
    {
        $first = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://git.acme.test/acme/docs.git',
        );

        $this->assertNull($first->provider_repo_id);
        $this->assertSame(Provider::Generic, $first->provider);

        $second = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://git.acme.test/acme/docs.git',
            provider: Provider::Gitea,
            providerRepoId: '42',
        );

        $this->assertSame($first->id, $second->id);
        $this->assertSame('42', $second->provider_repo_id);
        $this->assertSame(1, Repository::query()->count());
    }

    /**
     * 🛑 The identifier is unique **per instance**, which is the first of the
     * three defects ADR 0009 found in §10.2's key as written.
     *
     * Two self-hosted Gitea servers both have a repository 42. Under
     * `UNIQUE (provider, provider_repo_id)` the second would have been
     * unattachable.
     */
    public function test_the_same_identifier_on_two_instances_is_two_repositories(): void
    {
        $acme = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://git.acme.test/team/docs.git',
            provider: Provider::Gitea,
            providerRepoId: '42',
        );

        $other = $this->connector->connect(
            organisationId: $this->organisation->id,
            url: 'https://git.other.test/team/docs.git',
            provider: Provider::Gitea,
            providerRepoId: '42',
        );

        $this->assertNotSame($acme->id, $other->id);
        $this->assertSame(2, Repository::query()->count());
    }

    /** The canonicalisation ADR 0009 requires, per provider shape. */
    public function test_provider_identifiers_are_canonicalised_before_storage(): void
    {
        $this->assertSame('42', Provider::GitHub->canonicaliseIdentifier('0042'));
        $this->assertSame('42', Provider::Gitea->canonicaliseIdentifier(' 42 '));
        $this->assertNull(Provider::GitHub->canonicaliseIdentifier('not-a-number'));
        $this->assertNull(Provider::GitHub->canonicaliseIdentifier('0'));

        $this->assertSame(
            '585074de-7b60-4fd1-81ed-e0bc7fafbda5',
            Provider::BitbucketCloud->canonicaliseIdentifier('{585074DE-7B60-4FD1-81ED-E0BC7FAFBDA5}'),
        );
        $this->assertSame(
            '585074de-7b60-4fd1-81ed-e0bc7fafbda5',
            Provider::BitbucketCloud->canonicaliseIdentifier('585074de-7b60-4fd1-81ed-e0bc7fafbda5'),
        );
        $this->assertNull(Provider::BitbucketCloud->canonicaliseIdentifier('1296269'));

        // A generic remote has none, and §8.3.8's URL path carries it.
        $this->assertNull(Provider::Generic->canonicaliseIdentifier('anything'));
    }

    /** Creates a project, a version, a component, a mount and the source row. */
    private function attachProject(string $slug, Repository $repository, string $sourcePath): Component
    {
        $project = Project::query()->create([
            'slug' => $slug.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($slug),
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $component = Component::query()->create([
            'key' => $slug.'-'.bin2hex(random_bytes(3)),
            'name' => ucfirst($slug),
            'min_access' => 'public',
        ]);

        $mount = new ComponentMount;
        $mount->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $component->id,
            'mount_path' => '',
            'is_primary' => true,
            'min_access_snapshot' => 'public',
        ])->save();

        $this->connector->attach($repository, $component, $sourcePath);

        return $component;
    }
}
