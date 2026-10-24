<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\OrganisationContext;
use App\Builds\ComponentEnvironment;
use App\Builds\Fragments\FragmentCache;
use App\Builds\Fragments\FragmentDigest;
use App\Builds\Stage;
use App\Credentials\EnvelopeCipher;
use App\Models\Build;
use App\Models\Component;
use App\Models\ComponentVariable;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

/**
 * §8.5.19's fragment cache, and §8.5.25's variables that decide whether it
 * may be used at all.
 *
 * > "The system MUST cache per-source build output keyed by
 * > `fragment_digest = H(source_digest, env_digest, config_digest,
 * > public_env)`, 🛑 **looked up only within the originating
 * > `repository_id`** … An architecture test MUST assert that no lookup path
 * > omits the repository scope."
 *
 * 🛑 **The scope test here is the behavioural half; the structural half is
 * in `ArchitectureTest`.** Each catches what the other cannot: this one
 * proves a second repository with the same digest misses, and that one
 * proves there is no second place a lookup could be written. §14.2 names the
 * trap — a shared fragment would make the cache a cross-tenant
 * file-existence oracle — and §19/38 records that the answer is the
 * repository row rather than an installation-level opt-in.
 */
final class FragmentCacheTest extends TestCase
{
    use DatabaseTransactions;

    private FragmentCache $cache;

    private Organisation $organisation;

    private Repository $repository;

    private Component $component;

    protected function setUp(): void
    {
        parent::setUp();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->cache = new FragmentCache;

        $this->organisation = Organisation::query()->create([
            'name' => 'Fragment Co',
            'slug' => 'frag-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->repository = $this->repositoryNamed('one');
        $this->component = $this->componentNamed('docs');
    }

    /** The digest is a pure function of §8.5.19's four inputs. */
    public function test_the_digest_is_stable_across_identical_inputs(): void
    {
        $first = $this->digest(publicEnv: ['THEME' => 'dark']);
        $second = $this->digest(publicEnv: ['THEME' => 'dark']);

        $this->assertSame($first->hex(), $second->hex());

        // ...and insertion order is not an input. Two builds that set the
        // same variables in a different order are the same build.
        $this->assertSame(
            $this->digest(publicEnv: ['A' => '1', 'B' => '2'])->hex(),
            $this->digest(publicEnv: ['B' => '2', 'A' => '1'])->hex(),
        );
    }

    /** Each of the four inputs moves it. */
    public function test_every_input_changes_the_digest(): void
    {
        $base = $this->digest()->hex();

        $this->assertNotSame($base, $this->digest(source: 'other')->hex());
        $this->assertNotSame($base, $this->digest(env: 'other')->hex());
        $this->assertNotSame($base, $this->digest(config: 'other')->hex());
        $this->assertNotSame($base, $this->digest(publicEnv: ['X' => '1'])->hex());
    }

    /**
     * 🛑 The requirement, as behaviour: the same digest in a different
     * repository is a miss.
     */
    public function test_an_identical_digest_in_another_repository_misses(): void
    {
        $digest = $this->digest()->bytes();
        $build = $this->publishedBuild();

        $this->cache->remember($build, $this->repository->id, $digest, cacheable: true);

        $this->assertInstanceOf(Build::class, $this->cache->lookup($this->repository->id, $digest));

        $other = $this->repositoryNamed('two');

        $this->assertNull(
            $this->cache->lookup($other->id, $digest),
            '🛑 §8.5.19: a fragment is looked up only within the originating repository_id',
        );
    }

    /** §8.5.19: a non-cacheable fragment is recorded and never served. */
    public function test_a_non_cacheable_fragment_is_never_served(): void
    {
        $digest = $this->digest()->bytes();
        $build = $this->publishedBuild();

        $this->cache->remember($build, $this->repository->id, $digest, cacheable: false);

        $this->assertDatabaseHas('fragments', ['cacheable' => false]);
        $this->assertNull($this->cache->lookup($this->repository->id, $digest));
    }

    /**
     * 🛑 A fragment pointing at a build that failed, or was deleted, must
     * miss rather than resolve.
     */
    public function test_a_fragment_whose_build_is_not_successful_misses(): void
    {
        $digest = $this->digest()->bytes();
        $build = $this->publishedBuild();

        $this->cache->remember($build, $this->repository->id, $digest, cacheable: true);

        $build->forceFill(['state' => 'failed'])->save();

        $this->assertNull($this->cache->lookup($this->repository->id, $digest));
    }

    /** A rebuilt fragment replaces the row rather than colliding with it. */
    public function test_remembering_the_same_fragment_twice_is_idempotent(): void
    {
        $digest = $this->digest()->bytes();
        $first = $this->publishedBuild();
        $second = $this->publishedBuild();

        $this->cache->remember($first, $this->repository->id, $digest, cacheable: true);
        $this->cache->remember($second, $this->repository->id, $digest, cacheable: true);

        $this->assertSame(1, DB::table('fragments')->where('repository_id', $this->repository->id)->count());
        $this->assertSame(
            bin2hex($second->id),
            bin2hex((string) $this->cache->lookup($this->repository->id, $digest)?->id),
        );
    }

    /** A hit bumps the refcount §8.8's collector reads. */
    public function test_a_hit_is_counted_and_linked(): void
    {
        $digest = $this->digest()->bytes();
        $cached = $this->publishedBuild();
        $reusing = $this->publishedBuild();

        $this->cache->remember($cached, $this->repository->id, $digest, cacheable: true);
        $this->cache->recordHit($reusing, $this->repository->id, $digest);

        $this->assertSame(1, (int) DB::table('fragments')
            ->where('repository_id', $this->repository->id)
            ->value('refcount'));

        $this->assertDatabaseHas('build_fragments', [
            'build_id' => $reusing->id,
            'was_hit' => true,
        ]);
    }

    // ------------------------------------------------------------- §8.5.25

    /**
     * 🛑 "a public variable enters `public_env` and therefore the fragment
     * digest; a secret does not, and marks the fragment non-cacheable".
     *
     * Both halves in one test, because each alone would pass against a
     * wrong implementation: putting the secret in the digest would satisfy
     * "the digest changed", and leaving it out without marking the fragment
     * would satisfy "no secret in the key".
     */
    public function test_a_secret_stays_out_of_the_digest_and_blocks_the_cache(): void
    {
        $this->variable('PUBLIC_INDEX', 'https://packages.example.com', public: true);

        $withPublicOnly = ComponentEnvironment::forComponent($this->component, fromFork: false);

        $this->assertSame(['PUBLIC_INDEX' => 'https://packages.example.com'], $withPublicOnly->public);
        $this->assertFalse($withPublicOnly->makesFragmentUncacheable());

        $this->variable('INDEX_TOKEN', 'super-secret-value', public: false);

        $withSecret = ComponentEnvironment::forComponent($this->component, fromFork: false);

        // The secret opened, and did not enter `public_env`.
        $this->assertArrayHasKey('INDEX_TOKEN', $withSecret->secret);
        $this->assertSame('super-secret-value', $withSecret->secret['INDEX_TOKEN']->reveal());
        $this->assertArrayNotHasKey('INDEX_TOKEN', $withSecret->public);

        // 🛑 So the digest is unchanged by it...
        $this->assertSame(
            $this->digest(publicEnv: $withPublicOnly->public)->hex(),
            $this->digest(publicEnv: $withSecret->public)->hex(),
        );

        // ...and the fragment is not cacheable, which is the other half.
        $this->assertTrue($withSecret->makesFragmentUncacheable());

        // And the value does reach the container, which is the control: a
        // secret nobody can use is not the requirement.
        $this->assertSame(
            'super-secret-value',
            $withSecret->forStage(Stage::Build)['INDEX_TOKEN'],
        );
    }

    /**
     * 🛑 §8.5.25: "withheld entirely from fork and pull-request builds
     * **regardless of the `public` flag**".
     */
    public function test_a_fork_build_receives_no_variables_at_all(): void
    {
        $this->variable('PUBLIC_INDEX', 'https://packages.example.com', public: true);
        $this->variable('INDEX_TOKEN', 'super-secret-value', public: false);

        $fork = ComponentEnvironment::forComponent($this->component, fromFork: true);

        $this->assertSame([], $fork->public);
        $this->assertSame([], $fork->secret);
        $this->assertSame([], $fork->forStage(Stage::Build));
    }

    /** §8.5.25: "never present during `fetch`". */
    public function test_variables_are_refused_for_the_fetch_stage(): void
    {
        $this->variable('INDEX_TOKEN', 'super-secret-value', public: false);

        $this->expectException(\LogicException::class);

        ComponentEnvironment::forComponent($this->component, fromFork: false)
            ->forStage(Stage::Fetch);
    }

    /** 🛑 §8.5.25: "never returned by any API or UI". */
    public function test_a_sealed_variable_never_serialises_its_ciphertext(): void
    {
        $this->variable('INDEX_TOKEN', 'super-secret-value', public: false);

        $row = ComponentVariable::query()->where('name', 'INDEX_TOKEN')->firstOrFail();
        $attributes = $row->toArray();

        foreach (['wrapped_key', 'ciphertext', 'kek_fingerprint', 'envelope_version'] as $column) {
            $this->assertArrayNotHasKey($column, $attributes);
        }

        /*
         * 🛑 Scanned rather than `json_encode`d, and the reason is worth
         * recording: the key columns are raw BINARY(16) (§9.1.1, ADR 0006)
         * and are converted at the presentation boundary, so a model's own
         * `toArray()` is not valid UTF-8 and `json_encode` throws before it
         * can prove anything. Walking the values tests the same claim
         * without depending on a representation nothing in production uses.
         */
        foreach ($attributes as $key => $value) {
            if (is_string($value)) {
                $this->assertStringNotContainsString('super-secret-value', $value, $key.' carries the plaintext');
            }
        }

        // The control: the row is real and the value really is sealed in it.
        $this->assertSame('INDEX_TOKEN', $attributes['name']);
        $this->assertNotNull($row->sealed());
    }

    // ------------------------------------------------------------ fixtures

    /** @param  array<string, string>  $publicEnv */
    private function digest(
        string $source = 'source',
        string $env = 'env',
        string $config = 'config',
        array $publicEnv = [],
    ): FragmentDigest {
        return new FragmentDigest($source, $env, $config, $publicEnv);
    }

    private function repositoryNamed(string $name): Repository
    {
        $repository = new Repository;
        $repository->forceFill([
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/'.$name.'.git',
            'normalised_url' => 'https://github.com/docup/'.$name,
            'default_branch' => 'main',
            'provider_repo_id' => $name,
        ])->save();

        return $repository;
    }

    private function componentNamed(string $key): Component
    {
        return Component::query()->create([
            'key' => $key.'-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'min_access' => 'public',
        ]);
    }

    private function variable(string $name, string $value, bool $public): void
    {
        $id = Uuid::v7();
        $attributes = [
            'id' => $id,
            'organisation_id' => $this->organisation->id,
            'component_id' => $this->component->id,
            'name' => $name,
            'is_public' => $public,
            'public_value' => $public ? $value : null,
        ];

        if (! $public) {
            $sealed = EnvelopeCipher::fromConfig()->seal(
                ['value' => $value],
                EnvelopeCipher::variableAad($id, $this->organisation->id, $this->component->id, $name),
            );

            $attributes += [
                'envelope_version' => $sealed->version,
                'kek_fingerprint' => $sealed->kekFingerprint,
                'wrapped_key' => $sealed->wrappedKey,
                'ciphertext' => $sealed->ciphertext,
            ];
        }

        (new ComponentVariable)->forceFill($attributes)->save();
    }

    private function publishedBuild(): Build
    {
        $project = Project::query()->create([
            'slug' => 'frag-'.bin2hex(random_bytes(4)),
            'name' => 'Fragment',
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

        $build = new Build;
        $build->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $this->component->id,
            'content_key' => hash('sha256', 'frag:'.bin2hex(random_bytes(8))),
            'state' => 'published',
        ])->save();

        return $build;
    }
}
