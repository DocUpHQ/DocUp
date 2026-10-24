<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Auth\ApiTokens;
use App\Auth\Capability;
use App\Auth\OrganisationContext;
use App\Auth\Role;
use App\Builds\Log\BuildLog;
use App\Credentials\SecretRedactor;
use App\Credentials\SecretRegistry;
use App\Models\Build;
use App\Models\Component;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\User;
use App\Support\Uuid;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\DB;
use Illuminate\Testing\TestResponse;
use Tests\TestCase;

/**
 * §8.5.22's offset-addressed contract, over HTTP.
 *
 * > "Build logs MUST be exposed through one offset-addressed contract
 * > (`GET /api/v3/builds/{id}/log?from=<seq>`) consumable by both
 * > transports … Log access MUST be authorised by the same policy as the
 * > project, and build-log visibility for anonymous readers of public
 * > projects MUST be a per-project setting defaulting to **off**."
 *
 * 🛑 **Two readers with independent cursors is the exit criterion**, not
 * an incidental property: "a nine-minute build's log reaches two
 * browsers by byte-offset poll". A contract that worked for one reader
 * and not two would be one that kept state on the server, which is
 * exactly what offset addressing is for.
 */
final class BuildLogApiTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private Build $build;

    private string $token;

    protected function setUp(): void
    {
        parent::setUp();

        config()->set('builds.log_spool', sys_get_temp_dir().'/docup-logapi-'.bin2hex(random_bytes(6)));
        SecretRegistry::flush();

        $context = app(OrganisationContext::class);
        $context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Watchers',
            'slug' => 'watch-'.bin2hex(random_bytes(4)),
        ]);

        $context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'watch-'.bin2hex(random_bytes(3)),
            'name' => 'Watched',
            'visibility' => 'public',
        ]);

        $version = new ProjectVersion;
        $version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();

        $component = Component::query()->create([
            'key' => 'watch-'.bin2hex(random_bytes(4)),
            'name' => 'Watched',
            'min_access' => 'public',
        ]);

        $this->build = new Build;
        $this->build->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $version->id,
            'component_id' => $component->id,
            'content_key' => bin2hex(random_bytes(32)),
            'state' => 'running',
            'kind' => 'full',
            'started_at' => now(),
        ])->save();

        $user = User::query()->create([
            'name' => 'Watcher',
            'email' => 'watch-'.bin2hex(random_bytes(4)).'@example.test',
            'password' => 'x',
        ]);

        /*
         * 🛑 The role comes first. §8.13.6 refuses to mint a token holding
         * a capability the minter does not hold — "otherwise minting is an
         * escalation primitive" — so a fixture that skipped this would be
         * testing a token nobody could have created.
         */
        DB::table('role_assignments')->insert([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'subject_type' => 'user',
            'subject_id' => $user->id,
            'role' => Role::OrgAdmin->value,
            'scope_type' => 'organisation',
            'scope_id' => $this->organisation->id,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        [, $plaintext] = app(ApiTokens::class)->mint(
            $user,
            $this->organisation,
            'log reader',
            [Capability::ProjectView],
        );

        $this->token = $plaintext;
    }

    protected function tearDown(): void
    {
        BuildLog::open(bin2hex($this->build->id))->delete();
        SecretRegistry::flush();

        parent::tearDown();
    }

    /** 🛑 The exit criterion: two readers, two cursors, no shared state. */
    public function test_two_readers_follow_the_same_log_independently(): void
    {
        $log = $this->log();
        $log->append('starting');
        $log->append('step one');

        // Reader A catches up.
        $a = $this->read();
        $a->assertOk();
        $this->assertSame(['starting', 'step one'], $this->texts($a->json('lines')));
        $cursorA = (int) $a->json('next');

        // Reader B arrives late and gets everything from the beginning.
        $b = $this->read();
        $this->assertSame(['starting', 'step one'], $this->texts($b->json('lines')));

        $log->append('step two');

        // A sees only what is new to A.
        $a2 = $this->read($cursorA);
        $this->assertSame(['step two'], $this->texts($a2->json('lines')));

        // B, still holding its own cursor, sees the same one line.
        $b2 = $this->read((int) $b->json('next'));
        $this->assertSame(['step two'], $this->texts($b2->json('lines')));

        // And re-sending a cursor is safe: no server-side state moved.
        $again = $this->read($cursorA);
        $this->assertSame(['step two'], $this->texts($again->json('lines')));
    }

    /**
     * 🛑 `complete` comes from the build's state, not from an empty page.
     *
     * An empty page means "nothing new yet" while a build runs and "that
     * is all there is" once it ends. A client that could not tell them
     * apart would either stop polling early or poll a finished build for
     * ever.
     */
    public function test_complete_reflects_the_build_state_not_the_page(): void
    {
        $this->log()->append('only line');

        $running = $this->read((int) $this->read()->json('next'));
        $running->assertOk();
        $this->assertSame([], $running->json('lines'));
        $this->assertFalse($running->json('complete'));

        $this->build->forceFill(['state' => 'published', 'finished_at' => now()])->save();

        $finished = $this->read();
        $this->assertTrue($finished->json('complete'));
    }

    /** §8.5.21's NDJSON form, from the same endpoint and the same cursor. */
    public function test_the_same_contract_serves_ndjson(): void
    {
        $log = $this->log();
        $log->append('one');
        $log->append('two');

        $response = $this->withToken($this->token)
            ->get('/api/v3/builds/'.bin2hex($this->build->id).'/log', ['Accept' => 'application/x-ndjson']);

        $response->assertOk();
        $response->assertHeader('Content-Type', 'application/x-ndjson');
        $response->assertHeader('X-DocUp-Log-Next', '3');

        $lines = array_values(array_filter(explode("\n", (string) $response->getContent())));

        $this->assertCount(2, $lines);

        /** @var array<string, mixed> $first */
        $first = json_decode($lines[0], true, 8, JSON_THROW_ON_ERROR);
        $this->assertSame(1, $first['seq']);
        $this->assertSame('one', $first['text']);
    }

    /** 🛑 §8.5.22: anonymous readers get nothing by default. */
    public function test_an_anonymous_reader_is_refused_by_default(): void
    {
        $this->log()->append('secret-ish paths and dependency versions');

        $this->assertFalse($this->project->anonymous_build_logs, 'the setting must default to off');

        $this->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log')->assertNotFound();
    }

    /** ...and get the log once the project's owner turns the setting on. */
    public function test_an_anonymous_reader_is_served_when_the_project_opts_in(): void
    {
        $this->log()->append('public enough');
        $this->project->forceFill(['anonymous_build_logs' => true])->save();

        $response = $this->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log');

        $response->assertOk();
        $this->assertSame(['public enough'], $this->texts($response->json('lines')));
    }

    /**
     * 🛑 The setting widens access to a project people can already read;
     * it does not grant access to one they cannot.
     */
    public function test_the_setting_does_not_expose_a_private_project(): void
    {
        $this->log()->append('private');
        $this->project->forceFill([
            'visibility' => 'members',
            'anonymous_build_logs' => true,
        ])->save();

        $this->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log')->assertNotFound();
    }

    /**
     * 🛑 A WRONG credential is 401, never a silent downgrade to the
     * anonymous view.
     *
     * `api.token:optional` means "no credential is acceptable" and never
     * "a bad credential is ignored" — a caller with a revoked token who
     * was quietly shown the public view would believe they were
     * authenticated.
     */
    public function test_a_revoked_token_is_rejected_rather_than_downgraded(): void
    {
        $this->log()->append('anything');
        $this->project->forceFill(['anonymous_build_logs' => true])->save();

        $this->withToken('docup_pat_'.str_repeat('0', 40))
            ->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log')
            ->assertUnauthorized();
    }

    /** §8.2.2's "404, never 403" for a build in another tenant. */
    public function test_a_build_that_does_not_exist_is_404(): void
    {
        $this->withToken($this->token)
            ->getJson('/api/v3/builds/'.bin2hex(random_bytes(16)).'/log')
            ->assertNotFound();
    }

    /** A malformed identifier is a 404 too, not a 500. */
    public function test_a_malformed_identifier_is_404(): void
    {
        $this->withToken($this->token)
            ->getJson('/api/v3/builds/..%2F..%2Fetc/log')
            ->assertNotFound();
    }

    /** 🛑 A secret planted in the log never reaches a reader. */
    public function test_a_planted_secret_never_reaches_the_api(): void
    {
        $secret = 'ghp_'.str_repeat('a', 36);
        SecretRegistry::remember($secret);

        $log = BuildLog::open(bin2hex($this->build->id), new SecretRedactor);
        $log->append('cloning with '.$secret);
        $log->close();

        $body = (string) $this->withToken($this->token)
            ->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log')
            ->getContent();

        $this->assertStringNotContainsString($secret, $body);
        $this->assertStringContainsString(SecretRedactor::MARKER, $body);
    }

    /** §8.5.23's queue position and estimate, from the build endpoint. */
    public function test_the_build_endpoint_carries_the_queue_position(): void
    {
        $this->build->forceFill(['state' => 'queued', 'queued_at' => now()])->save();

        $response = $this->withToken($this->token)->getJson('/api/v3/builds/'.bin2hex($this->build->id));

        $response->assertOk();
        $response->assertJsonStructure([
            'build', 'state', 'queue_position', 'running_builds',
            'estimated_wait_seconds', 'median_duration_seconds', 'log',
        ]);

        $this->assertSame(1, $response->json('queue_position'));

        /*
         * 🛑 Null, not a guess. This project has never finished a build,
         * so there is nothing to estimate from — and an invented figure
         * is worse than none, because a reader told "about 2 minutes" who
         * waits eleven stops believing the number at all.
         */
        $this->assertNull($response->json('estimated_wait_seconds'));
    }

    private function log(): BuildLog
    {
        return BuildLog::open(bin2hex($this->build->id));
    }

    /** @return TestResponse<JsonResponse> */
    private function read(int $from = 1): TestResponse
    {
        return $this->withToken($this->token)
            ->getJson('/api/v3/builds/'.bin2hex($this->build->id).'/log?from='.$from);
    }

    /**
     * @return list<string>
     */
    private function texts(mixed $lines): array
    {
        $texts = [];

        foreach (is_array($lines) ? $lines : [] as $line) {
            if (is_array($line) && is_string($line['text'] ?? null)) {
                $texts[] = $line['text'];
            }
        }

        return $texts;
    }
}
