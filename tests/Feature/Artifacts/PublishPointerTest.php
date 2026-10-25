<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Artifacts;

use App\Artifacts\Exceptions\IngestRejected;
use App\Artifacts\Publisher;
use App\Artifacts\Quotas;
use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Models\ApiToken;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\ProjectVersionManifest;
use App\Models\User;
use App\Models\VersionPointerEvent;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\Response;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Illuminate\Testing\TestResponse;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 **Phase 03's exit criteria.**
 *
 * "`curl` publishes a three-file tree with a scoped token and the manifest lists
 * a per-file sha256. … Re-publishing creates build 2 and the flip is one row.
 * Rollback restores build 1's bytes exactly. 🛑 A version points at a
 * **manifest** from this phase, with a degenerate single-component manifest —
 * not at a build id (§8.8.3)."
 *
 * The §8.8.2 rejections are demonstrated by {@see ArtifactIngestorTest} against
 * the abuse corpus. This file is the pointer half: §8.8.4's compare-and-swap,
 * §8.8.5's rollback and pin, §8.8.6's soft landing, §8.8.8's event log and
 * §8.8.10's quota.
 */
final class PublishPointerTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private User $writer;

    private string $writerToken;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        $this->fixtures = sys_get_temp_dir().'/docup-publish-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Publish Co',
            'slug' => 'publish-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create(['slug' => 'docs', 'name' => 'Docs']);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'publish_mode' => ProjectVersion::defaultPublishModeFor('channel'),
        ])->save();

        $this->context->spanAllOrganisations();

        $this->writer = User::query()->create([
            'name' => 'Writer',
            'email' => 'writer-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        // project_admin rather than project_writer, so one token can exercise
        // both publish and rollback. The capability split itself is asserted in
        // test_a_token_without_the_capability_is_refused() below.
        $this->grant($this->writer, Role::ProjectAdmin);

        $this->writerToken = $this->mint([
            Capability::ProjectVersionPublish,
            Capability::ProjectVersionRollback,
        ]);

        // 🛑 Forgotten before any request runs. The middleware must declare the
        // context; a test that left one set could pass while the middleware did
        // nothing at all.
        $this->context->forget();
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        if (is_dir($this->fixtures)) {
            foreach ((array) glob($this->fixtures.'/*') as $file) {
                if (is_string($file)) {
                    @unlink($file);
                }
            }

            @rmdir($this->fixtures);
        }

        parent::tearDown();
    }

    // ------------------------------------------------------- the exit criteria

    /**
     * 🛑 "`curl` publishes a three-file tree with a scoped token and the
     * manifest lists a per-file sha256."
     *
     * Through the real HTTP endpoint with a real bearer token, because that is
     * what the criterion says. Calling the Publisher directly would prove the
     * publish and skip the thing being claimed — that a scoped token is what
     * authorises it.
     */
    public function test_a_scoped_token_publishes_a_three_file_tree_over_http(): void
    {
        $response = $this->publish($this->tree('one'));

        $response->assertCreated()
            ->assertJsonPath('published', true)
            ->assertJsonPath('build.file_count', 3)
            ->assertJsonPath('manifest.revision', 1)
            ->assertJsonPath('previous_manifest', null);

        $manifestKey = 'builds/'.$response->json('build.id').'/manifest/manifest.json';
        /** @var array{files: array<string, array{sha256: string, bytes: int}>} $manifest */
        $manifest = json_decode((string) Storage::disk('artifacts')->get($manifestKey), true);

        $this->assertCount(3, $manifest['files']);

        foreach ($manifest['files'] as $path => $entry) {
            $stored = (string) Storage::disk('artifacts')->get('builds/'.$response->json('build.id').'/'.$path);

            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $entry['sha256'], $path);
            $this->assertSame(hash('sha256', $stored), $entry['sha256'], $path);
        }
    }

    /**
     * 🛑 "A version points at a **manifest** from this phase, with a degenerate
     * single-component manifest — not at a build id (§8.8.3)."
     *
     * The strongest form of this assertion is the schema one: there is no
     * `current_build_id` column to point at. §8.8.3 calls the later move from a
     * build pointer to a manifest pointer "exactly the un-retrofittable change
     * Phase 00 forbids", so the absence is the requirement.
     */
    public function test_the_version_points_at_a_manifest_and_there_is_no_build_pointer(): void
    {
        $response = $this->publish($this->tree('one'));

        $this->context->for($this->organisation->id);
        $version = $this->version->fresh();

        $this->assertNotNull($version);
        $this->assertNotNull($version->published_manifest_id);
        $this->assertSame($response->json('manifest.id'), Uuid::toText($version->published_manifest_id));

        // 🛑 No build pointer exists to get this wrong with.
        /** @var list<object{Field: string}> $rows */
        $rows = DB::select('SHOW COLUMNS FROM `project_versions`');
        $columns = array_map(static fn (object $c): string => $c->Field, $rows);

        $this->assertNotContains('current_build_id', $columns);
        $this->assertContains('published_manifest_id', $columns);

        // The degenerate single-component manifest: one mount, at the root.
        $manifest = ProjectVersionManifest::query()->whereKey($version->published_manifest_id)->firstOrFail();

        /*
         * 🛑 `/2` since Phase 14. The document gained the provenance
         * §8.7.21 needs answerable from the manifest alone — component key,
         * selector, resolved ref, commit — and §8.7.15's shadow redirects.
         * Versioned in the payload rather than implied, because §8.1.11's
         * stability promise means `/1` manifests written before this phase
         * stay readable, and a reader that cannot tell which shape it has
         * must guess.
         */
        $this->assertSame('docup.version-manifest/2', $manifest->mounts_json['schema']);
        $this->assertCount(1, $manifest->mounts_json['mounts']);
        $this->assertSame('', $manifest->mounts_json['mounts'][0]['mount_path']);
        $this->assertTrue($manifest->mounts_json['mounts'][0]['is_primary']);
        $this->assertSame($response->json('build.id'), $manifest->mounts_json['mounts'][0]['build_id']);
    }

    /** 🛑 "Re-publishing creates build 2 and the flip is one row." */
    public function test_republishing_creates_a_second_build_and_the_flip_is_one_row(): void
    {
        $first = $this->publish($this->tree('one'))->assertCreated();

        $queries = 0;
        DB::listen(function ($query) use (&$queries): void {
            if (str_starts_with(strtolower(trim($query->sql)), 'update `project_versions`')) {
                $queries++;
            }
        });

        $second = $this->publish($this->tree('two'))->assertCreated();

        // 🛑 §8.8.4: "a single compare-and-swap row update". One UPDATE, not a
        // read-modify-write pair and not a cascade of them.
        $this->assertSame(1, $queries, 'the pointer flip must be exactly one UPDATE on project_versions');

        $this->context->for($this->organisation->id);

        $this->assertSame(2, Build::query()->where('project_version_id', $this->version->id)->count());
        $this->assertNotSame($first->json('build.id'), $second->json('build.id'));
        $this->assertSame(2, $second->json('manifest.revision'));
        $this->assertSame($first->json('manifest.id'), $second->json('previous_manifest'));

        // §8.8.6: the previous manifest stays resolvable for a bounded window,
        // so a page loaded a second before the flip can still fetch its assets.
        $version = $this->version->fresh();
        $this->assertNotNull($version);
        $this->assertTrue($version->isWithinSoftLanding());
    }

    /** 🛑 "Rollback restores build 1's bytes exactly." */
    public function test_rollback_restores_the_previous_builds_bytes_exactly(): void
    {
        $first = $this->publish($this->tree('one'))->assertCreated();
        $firstBytes = (string) Storage::disk('artifacts')
            ->get('builds/'.$first->json('build.id').'/html/index.html');

        $this->publish($this->tree('two'))->assertCreated();

        $rolled = $this->withToken($this->writerToken)
            ->postJson($this->url('rollback'), ['reason' => 'Bad release'])
            ->assertOk();

        $this->context->for($this->organisation->id);
        $version = $this->version->fresh();

        $this->assertNotNull($version);
        $this->assertSame($first->json('manifest.id'), Uuid::toText((string) $version->published_manifest_id));
        $this->assertSame($first->json('manifest.id'), $rolled->json('manifest.id'));

        /*
         * 🛑 "Exactly" means byte-identical, and the reason it can be is that
         * rollback moves nothing: §8.8.5 requires the previous build to stay
         * "intact and immediately re-selectable", so the bytes were never
         * touched. A rollback that re-fetched or re-wrote them could not make
         * this claim.
         */
        $afterBytes = (string) Storage::disk('artifacts')
            ->get('builds/'.$first->json('build.id').'/html/index.html');

        $this->assertSame($firstBytes, $afterBytes);
        $this->assertSame('one', $afterBytes);

        // 🛑 §8.8.5: "plus a pin that blocks automatic republication until a
        // human unpins". Without it the next successful build immediately
        // republishes what was just withdrawn.
        $this->assertTrue($version->pinned);
        $this->assertSame('Bad release', $version->pinned_reason);
        $this->assertTrue($version->blocksAutomaticPublish());
    }

    // --------------------------------------------------- the pointer machinery

    /**
     * 🛑 §8.8.4: "Zero affected rows means another build won, and that build
     * MUST terminate as `success_unpublished`."
     *
     * Simulated by moving the pointer between the ingest and the flip, which is
     * exactly what a concurrent build does. Two real parallel requests would
     * make this test a race about a race.
     */
    public function test_a_build_that_loses_the_compare_and_swap_is_success_unpublished(): void
    {
        $this->publish($this->tree('one'))->assertCreated();

        $this->context->for($this->organisation->id);
        $version = $this->version->fresh();
        $this->assertNotNull($version);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);

        /*
         * `$stale` holds the pointer as it was before the publish above, which
         * is precisely the state a build that started earlier would carry. The
         * Publisher reads the expected pointer from the model it is given, so a
         * stale model IS a lost race.
         */
        $stale = new ProjectVersion;
        $stale->forceFill($version->getAttributes());
        $stale->exists = true;
        $stale->published_manifest_id = null;

        $outcome = $publisher->publishUpload($stale, $this->tree('three'), $this->writer->id);

        $this->assertFalse($outcome->published, 'a build racing against a newer pointer must not publish');
        $this->assertNotNull($outcome->build);
        $this->assertSame('success_unpublished', $outcome->build->fresh()?->state);

        // 🛑 Not a failure. Its artifacts are stored, valid and selectable —
        // which is what makes a later rollback to it possible at all.
        $this->assertSame(
            'three',
            Storage::disk('artifacts')->get('builds/'.Uuid::toText($outcome->build->id).'/html/index.html'),
        );
    }

    /** §8.8.8: every flip is an append-only row naming what moved and why. */
    public function test_each_flip_appends_a_pointer_event(): void
    {
        $first = $this->publish($this->tree('one'))->assertCreated();
        $this->publish($this->tree('two'))->assertCreated();
        $this->withToken($this->writerToken)->postJson($this->url('rollback'))->assertOk();

        $this->context->for($this->organisation->id);

        /** @var list<VersionPointerEvent> $events */
        $events = VersionPointerEvent::query()
            ->where('project_version_id', $this->version->id)
            ->orderBy('created_at')
            ->orderBy('id')
            ->get()
            ->all();

        $this->assertCount(3, $events);
        $this->assertSame(['publish', 'publish', 'rollback'], array_map(
            static fn (VersionPointerEvent $e): string => $e->reason,
            $events,
        ));

        // The first publish came from nothing; every later event names both ends.
        $this->assertNull($events[0]->from_manifest_id);
        $this->assertSame($first->json('manifest.id'), Uuid::toText((string) $events[0]->to_manifest_id));
        $this->assertSame($this->writer->id, $events[2]->actor_id);
    }

    public function test_unpinning_clears_the_block_and_is_a_deliberate_act(): void
    {
        $this->publish($this->tree('one'))->assertCreated();
        $this->publish($this->tree('two'))->assertCreated();
        $this->withToken($this->writerToken)->postJson($this->url('rollback'))->assertOk();

        $this->withToken($this->writerToken)
            ->deleteJson($this->url('pin'))
            ->assertOk()
            ->assertJsonPath('pinned', false);

        $this->context->for($this->organisation->id);
        $version = $this->version->fresh();

        $this->assertNotNull($version);
        $this->assertFalse($version->pinned);
        $this->assertNull($version->pinned_reason);
    }

    /** §8.8.5 and §10.4: a published manifest is never edited or removed. */
    public function test_a_stored_manifest_cannot_be_changed_or_deleted(): void
    {
        $response = $this->publish($this->tree('one'))->assertCreated();

        $this->context->for($this->organisation->id);

        $manifest = ProjectVersionManifest::query()
            ->whereKey(Uuid::toBytes((string) $response->json('manifest.id')))
            ->firstOrFail();

        try {
            $manifest->revision = 99;
            $manifest->save();
            $this->fail('A manifest revision was updated.');
        } catch (\LogicException $e) {
            $this->assertStringContainsString('immutable', $e->getMessage());
        }

        try {
            $manifest->delete();
            $this->fail('A manifest was deleted.');
        } catch (\LogicException $e) {
            $this->assertStringContainsString('immutable', $e->getMessage());
        }
    }

    // ------------------------------------------------------------------ quotas

    /** 🛑 §8.8.10: at ingest, from the manifest, failing with the named code. */
    public function test_a_quota_breach_fails_with_contract_quota_exceeded(): void
    {
        config(['artifacts.quotas.organisation_artifact_bytes' => 8]);

        $this->publish($this->tree('one'))
            ->assertStatus(422)
            ->assertJsonPath('error', 'contract.quota_exceeded')
            ->assertJsonPath('failure_class', 'contract');

        /*
         * 🛑 And the bytes are gone. §8.8.10 wants the quota exact, which means
         * counted — so the tree is on the disk when the check runs, and a
         * refusal that left it there would let an author exceed the quota by
         * exceeding the quota.
         */
        $this->assertSame([], Storage::disk('artifacts')->allFiles());

        $this->context->for($this->organisation->id);
        $this->assertSame(0, Build::query()->where('project_version_id', $this->version->id)->count());
    }

    public function test_a_version_quota_refuses_a_new_version(): void
    {
        config(['artifacts.quotas.versions_per_project' => 1]);

        $this->context->for($this->organisation->id);

        /** @var Quotas $quotas */
        $quotas = app(Quotas::class);

        try {
            $quotas->assertVersionSlotAvailable($this->project->id);
            $this->fail('A version beyond the quota was allowed.');
        } catch (IngestRejected $rejection) {
            $this->assertSame('contract.quota_exceeded', $rejection->rejection->value);
        }
    }

    // ------------------------------------------------------------ the API edge

    public function test_an_unauthenticated_request_is_401(): void
    {
        $this->postJson($this->url('uploads'), ['archive' => $this->upload($this->tree('one'))])
            ->assertStatus(401)
            ->assertHeader('WWW-Authenticate', 'Bearer');
    }

    /**
     * 🛑 A token carrying publish but not rollback is refused the rollback.
     *
     * The capability split is the thing being asserted: §8.8.5's rollback
     * withdraws content readers are being served and leaves a pin, so it sits a
     * role higher than publishing.
     */
    public function test_a_token_without_the_capability_is_refused(): void
    {
        $publishOnly = $this->mint([Capability::ProjectVersionPublish]);

        $this->withToken($publishOnly)
            ->postJson($this->url('uploads'), ['archive' => $this->upload($this->tree('one'))])
            ->assertCreated();

        $this->withToken($publishOnly)
            ->postJson($this->url('rollback'))
            ->assertStatus(403)
            ->assertJsonPath('error', 'forbidden');
    }

    /**
     * 🛑 §8.2.2: another tenant's project is 404, never 403, "through the UI,
     * the API **and** direct identifier access".
     */
    public function test_another_tenants_project_is_404(): void
    {
        $this->context->spanAllOrganisations();

        $other = Organisation::query()->create([
            'name' => 'Other',
            'slug' => 'other-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($other->id);
        $theirs = Project::query()->create(['slug' => 'theirs', 'name' => 'Theirs']);
        $this->context->forget();

        // By slug, and by raw identifier — the second is the one people forget,
        // and the one an attacker reaches for after seeing a UUID in a log.
        foreach (['theirs', Uuid::toText($theirs->id)] as $reference) {
            $this->withToken($this->writerToken)
                ->postJson(
                    "/api/v3/projects/{$reference}/versions/latest/uploads",
                    ['archive' => $this->upload($this->tree('one'))],
                )
                ->assertNotFound();
        }
    }

    public function test_a_tree_the_ingestor_refuses_returns_its_stable_identifier(): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', "<!doctype html><p>ok</p>\n")
            ->add('html/.user.ini', "auto_prepend_file=/tmp/x.php\n")
            ->toTarGz($this->fixtures.'/planted.tar.gz');

        $this->publish($archive)
            ->assertStatus(422)
            ->assertJsonPath('error', 'contract.reserved_filename')
            ->assertJsonPath('failure_class', 'contract');
    }

    public function test_rolling_back_a_version_with_one_revision_is_a_conflict(): void
    {
        $this->publish($this->tree('one'))->assertCreated();

        $this->withToken($this->writerToken)
            ->postJson($this->url('rollback'))
            ->assertStatus(409)
            ->assertJsonPath('error', 'conflict');
    }

    public function test_rollback_outside_a_request_refuses_an_unpublished_version(): void
    {
        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);

        $this->expectException(\RuntimeException::class);

        $publisher->rollback($this->version, 'nothing to undo');
    }

    // ----------------------------------------------------------------- helpers

    /** A three-file html tree whose index carries the given marker bytes. */
    private function tree(string $marker): string
    {
        return (new ArchiveWriter)
            ->add('html/index.html', $marker)
            ->add('html/guide.html', "<p>guide</p>\n")
            ->add('html/assets/site.css', "body{color:#222}\n")
            ->toTarGz($this->fixtures.'/tree-'.$marker.'.tar.gz');
    }

    private function upload(string $path): UploadedFile
    {
        return new UploadedFile($path, basename($path), 'application/gzip', test: true);
    }

    /** @return TestResponse<Response> */
    private function publish(string $archive): TestResponse
    {
        return $this->withToken($this->writerToken)
            ->postJson($this->url('uploads'), ['archive' => $this->upload($archive)]);
    }

    private function url(string $action): string
    {
        return "/api/v3/projects/{$this->project->slug}/versions/{$this->version->slug}/{$action}";
    }

    /** @param  list<Capability>  $capabilities */
    private function mint(array $capabilities): string
    {
        $this->context->for($this->organisation->id);

        /** @var ApiTokens $tokens */
        $tokens = app(ApiTokens::class);

        // mint() returns [ApiToken, plaintext]; the plaintext is shown once and
        // never stored, which is why it comes back beside the row rather than on
        // it (§9.1.4 keeps only a hash).
        [, $plaintext] = $tokens->mint(
            user: $this->writer,
            organisation: $this->organisation,
            name: 'publisher-'.bin2hex(random_bytes(3)),
            capabilities: $capabilities,
        );

        $this->context->forget();

        return (string) $plaintext;
    }

    private function grant(User $user, Role $role): void
    {
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'scope_type' => 'project',
            'scope_id' => $this->project->id,
            'role' => $role->value,
            'source' => 'manual',
            'created_at' => now(),
            'updated_at' => now(),
        ]);
    }
}
