<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Webhooks;

use App\Auth\AccessLevel;
use App\Auth\OrganisationContext;
use App\Builds\Jobs\RunBuild;
use App\Models\BuildRequest;
use App\Models\Component;
use App\Models\ComponentMount;
use App\Models\ComponentSource;
use App\Models\IncomingWebhookDelivery;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Models\Repository;
use App\Models\WebhookIntegration;
use App\Support\Uuid;
use App\Webhooks\IntegrationSecrets;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

/**
 * 🛑 Phase 11's exit criteria, over the real route.
 *
 * > "A real push builds within 5 seconds. A forged signature, and a valid
 * > signature replayed outside the window, each return 401 and are audited."
 *
 * The signature mathematics is {@see SignatureVerificationTest}; this file
 * is what the HTTP endpoint does with it — the status, the audit event, the
 * enqueued job and the `build_requests` row.
 */
final class WebhookDeliveryTest extends TestCase
{
    use DatabaseTransactions;

    private Organisation $organisation;

    private Project $project;

    private Repository $repository;

    private ProjectVersion $version;

    private WebhookIntegration $integration;

    private string $secret;

    protected function setUp(): void
    {
        parent::setUp();

        Queue::fake();

        app(OrganisationContext::class)->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Hooks Co',
            'slug' => 'hooks-'.bin2hex(random_bytes(4)),
        ]);

        app(OrganisationContext::class)->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'visibility' => 'public',
        ]);

        $this->repository = new Repository;
        $this->repository->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'provider' => 'github',
            'provider_host' => 'github.com',
            'clone_url' => 'https://github.com/docup/docs.git',
            'normalised_url' => 'https://github.com/docup/docs',
            'default_branch' => 'main',
            'provider_repo_id' => '4242',
            'webhook_state' => 'provisioned',
        ])->save();

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'main',
            'kind' => 'channel',
            'language' => 'en',
            'active' => true,
            'listed' => true,
            'published' => false,
            'visibility' => AccessLevel::Public->value,
            'ref_name' => 'main',
            'ref_kind' => 'branch',
            'ref_commit_sha' => str_repeat('0', 40),
        ])->save();

        $this->project->forceFill(['default_version_id' => $this->version->id])->save();

        $this->attachComponent();

        [$integration, $secret] = IntegrationSecrets::make()->provision($this->repository);

        $this->integration = $integration;
        $this->secret = $secret->reveal();
    }

    protected function tearDown(): void
    {
        app(OrganisationContext::class)->forget();

        parent::tearDown();
    }

    /**
     * 🛑 "A real push builds within 5 seconds."
     *
     * Measured over the whole endpoint — verification, parse, ref sync,
     * automation rules, skip rules, request, enqueue — because that is what
     * stands between a `git push` and a build starting. The job is faked:
     * what the criterion bounds is the latency the provider sees and the
     * enqueue, not how long Sphinx then takes.
     */
    public function test_a_real_push_is_accepted_and_enqueued_within_five_seconds(): void
    {
        $body = $this->pushBody('refs/heads/main', 'cafebabe'.str_repeat('0', 32));

        $started = microtime(true);

        $response = $this->postJson(
            $this->url(),
            $this->decode($body),
            $this->githubHeaders($body, 'delivery-real-push'),
        );

        $elapsed = microtime(true) - $started;

        $response->assertStatus(202);
        $this->assertLessThan(5.0, $elapsed, '§17 Phase 11: a real push builds within 5 seconds');

        Queue::assertPushed(RunBuild::class, 1);

        $request = BuildRequest::query()->where('project_version_id', $this->version->id)->sole();

        $this->assertSame('webhook', $request->trigger);
        $this->assertSame('queued', $request->state);
        $this->assertSame($this->integration->id, $request->integration_id);
    }

    /** 🛑 "A forged signature ... returns 401 and is audited." */
    public function test_a_forged_signature_is_refused_and_audited(): void
    {
        $body = $this->pushBody('refs/heads/main', 'deadbeef'.str_repeat('0', 32));

        $headers = $this->githubHeaders($body, 'delivery-forged');
        $headers['X-Hub-Signature-256'] = 'sha256='.hash_hmac('sha256', $body, 'not-the-secret');

        $this->postJson($this->url(), $this->decode($body), $headers)
            ->assertStatus(401)
            ->assertJson(['error' => 'webhook.signature_invalid']);

        Queue::assertNothingPushed();

        $this->assertAudited('webhook.signature_invalid');
    }

    /**
     * 🛑 "a valid signature replayed outside the window ... returns 401 and
     * is audited."
     *
     * GitHub supplies no timestamp, so §8.19.3's fallback applies: the
     * replay is caught by delivery-id uniqueness, and "outside the window"
     * means "after the first delivery was recorded" rather than "more than
     * five minutes old". The timestamped half is the GitLab test below.
     */
    public function test_a_replayed_delivery_is_refused_and_audited(): void
    {
        $body = $this->pushBody('refs/heads/main', 'f00dface'.str_repeat('0', 32));
        $headers = $this->githubHeaders($body, 'delivery-replayed');
        $payload = $this->decode($body);

        $this->postJson($this->url(), $payload, $headers)->assertStatus(202);

        // The same bytes, the same signature, the same delivery id. Every
        // part of it is genuine; only the fact that we have seen it is new.
        $this->postJson($this->url(), $payload, $headers)
            ->assertStatus(401)
            ->assertJson(['error' => 'webhook.delivery_replayed']);

        $this->assertAudited('webhook.delivery_replayed');

        $this->assertSame(
            1,
            IncomingWebhookDelivery::query()->where('delivery_id', 'delivery-replayed')->count(),
            'the ledger holds exactly one row per delivery, which is what makes the second one a replay',
        );
    }

    /** The timestamped half of the same criterion, over the route. */
    public function test_a_replayed_gitlab_delivery_outside_the_window_is_refused(): void
    {
        $this->repository->forceFill(['provider' => 'gitlab'])->save();
        $this->integration->forceFill(['provider' => 'gitlab', 'scheme' => 'standard_webhooks'])->save();

        $body = (string) json_encode([
            'object_kind' => 'push',
            'ref' => 'refs/heads/main',
            'after' => 'abcdef12'.str_repeat('0', 32),
            'checkout_sha' => 'abcdef12'.str_repeat('0', 32),
            'project_id' => 4242,
            'total_commits_count' => 1,
            'commits' => [['id' => 'abcdef12', 'message' => 'docs: update', 'modified' => ['docs/index.md']]],
        ]);

        // Signed six minutes ago, which is a minute outside §8.19.3's window.
        $signedAt = time() - 360;
        $id = 'msg_stale';

        $this->call(
            'POST',
            $this->url(),
            [],
            [],
            [],
            $this->serverHeaders([
                'webhook-id' => $id,
                'webhook-timestamp' => (string) $signedAt,
                'webhook-signature' => 'v1,'.base64_encode(
                    hash_hmac('sha256', $id.'.'.$signedAt.'.'.$body, $this->secret, true)
                ),
                'X-Gitlab-Event' => 'Push Hook',
                'Content-Type' => 'application/json',
            ]),
            $body,
        )->assertStatus(401);

        $this->assertAudited('webhook.timestamp_outside_window');
        Queue::assertNothingPushed();
    }

    /**
     * 🛑 An unknown integration answers exactly as a bad signature does.
     *
     * A 404 here beside a 401 for a wrong secret would turn the URL into an
     * oracle for which integrations exist, and the id is in the path where
     * anyone can try one.
     */
    public function test_an_unknown_integration_is_indistinguishable_from_a_bad_signature(): void
    {
        $body = $this->pushBody('refs/heads/main', 'aaaaaaaa'.str_repeat('0', 32));

        $this->postJson(
            '/_/webhook/'.Uuid::toText(Uuid::v7()),
            $this->decode($body),
            $this->githubHeaders($body, 'delivery-unknown'),
        )->assertStatus(401);
    }

    /**
     * 🛑 A verified delivery naming another repository is refused.
     *
     * The signature proves the sender holds this integration's secret. It
     * does not prove the payload describes this integration's repository,
     * and a provider misconfigured to point repository A's hook at
     * repository B's URL would otherwise let whoever controls A trigger
     * builds of B.
     */
    public function test_a_payload_naming_another_repository_is_refused(): void
    {
        $body = (string) json_encode([
            'ref' => 'refs/heads/main',
            'after' => 'bbbbbbbb'.str_repeat('0', 32),
            'deleted' => false,
            'repository' => ['id' => 9999],
            'commits' => [['id' => 'bbbbbbbb', 'message' => 'docs', 'modified' => ['docs/index.md']]],
        ]);

        $this->postJson($this->url(), $this->decode($body), $this->githubHeaders($body, 'delivery-wrong-repo'))
            ->assertStatus(401)
            ->assertJson(['error' => 'webhook.repository_mismatch']);

        $this->assertAudited('webhook.repository_mismatch');
        Queue::assertNothingPushed();
    }

    /**
     * A `ping` is accepted and does nothing — 202, not 4xx.
     *
     * A provider that got a 4xx for its own health event eventually
     * disables the hook, which is how a repository stops building for a
     * reason nobody connects to the ping.
     */
    public function test_a_ping_is_accepted_and_builds_nothing(): void
    {
        $body = (string) json_encode(['zen' => 'Non-blocking is better than blocking.']);

        $headers = $this->githubHeaders($body, 'delivery-ping');
        $headers['X-GitHub-Event'] = 'ping';

        $this->postJson($this->url(), $this->decode($body), $headers)
            ->assertStatus(202)
            ->assertJson(['error' => 'webhook.unsupported_event']);

        Queue::assertNothingPushed();

        $this->assertSame(
            0,
            $this->auditCount('webhook.unsupported_event'),
            'a ping is not a security event; auditing it would bury the forgeries',
        );
    }

    /** A disabled integration refuses without looking at the signature. */
    public function test_a_disabled_integration_refuses(): void
    {
        $this->integration->forceFill(['state' => 'disabled'])->save();

        $body = $this->pushBody('refs/heads/main', 'cccccccc'.str_repeat('0', 32));

        $this->postJson($this->url(), $this->decode($body), $this->githubHeaders($body, 'delivery-disabled'))
            ->assertStatus(401)
            ->assertJson(['error' => 'webhook.integration_disabled']);
    }

    /** 🛑 §8.3.6: "MUST re-provision idempotently without creating duplicates." */
    public function test_reprovisioning_rotates_in_place_and_keeps_the_url(): void
    {
        $before = $this->integration->id;

        [$again, $newSecret] = IntegrationSecrets::make()->provision($this->repository);

        $this->assertSame($before, $again->id, 'the integration id is in the URL the provider already has');
        $this->assertNotSame($this->secret, $newSecret->reveal(), 're-provisioning rotates the secret');
        $this->assertSame(1, WebhookIntegration::query()->where('repository_id', $this->repository->id)->count());

        // The old secret no longer verifies, which is what rotation means.
        $body = $this->pushBody('refs/heads/main', 'dddddddd'.str_repeat('0', 32));

        $this->postJson($this->url(), $this->decode($body), $this->githubHeaders($body, 'delivery-old-secret'))
            ->assertStatus(401);
    }

    /** The secret never leaves the model, even through `toArray()`. */
    public function test_the_integration_never_serialises_its_envelope(): void
    {
        $serialised = $this->integration->toArray();

        foreach (['ciphertext', 'wrapped_key', 'kek_fingerprint', 'envelope_version'] as $column) {
            $this->assertArrayNotHasKey($column, $serialised, $column.' must never reach a UI payload');
        }
    }

    // ------------------------------------------------------------- helpers

    private function url(): string
    {
        return '/_/webhook/'.Uuid::toText($this->integration->id);
    }

    private function pushBody(string $ref, string $after): string
    {
        return (string) json_encode([
            'ref' => $ref,
            'before' => str_repeat('0', 40),
            'after' => $after,
            'deleted' => false,
            'repository' => ['id' => 4242, 'full_name' => 'docup/docs'],
            'commits' => [
                ['id' => $after, 'message' => 'docs: update the guide', 'modified' => ['docs/index.md']],
            ],
        ]);
    }

    /**
     * 🛑 The signature is computed over `$body`, and `postJson` re-encodes
     * whatever array it is given — so the array has to round-trip from the
     * same bytes or every test here would be testing the re-encoding rather
     * than the signature.
     *
     * Laravel's `json_encode` of a decoded payload happens to reproduce the
     * original here because the fixtures are built by `json_encode` in the
     * first place. Where it would not — the GitLab test — `$this->call()`
     * sends the raw bytes instead.
     *
     * @return array<array-key, mixed>
     */
    private function decode(string $body): array
    {
        /** @var array<array-key, mixed> $decoded */
        $decoded = json_decode($body, true, 512, JSON_THROW_ON_ERROR);

        return $decoded;
    }

    /** @return array<string, string> */
    private function githubHeaders(string $body, string $deliveryId): array
    {
        return [
            'X-Hub-Signature-256' => 'sha256='.hash_hmac('sha256', $body, $this->secret),
            'X-GitHub-Delivery' => $deliveryId,
            'X-GitHub-Event' => 'push',
        ];
    }

    /**
     * `$this->call()` takes CGI-style server variables, not header names.
     *
     * @param  array<string, string>  $headers
     * @return array<string, string>
     */
    private function serverHeaders(array $headers): array
    {
        $server = [];

        foreach ($headers as $name => $value) {
            $server['HTTP_'.strtoupper(str_replace('-', '_', $name))] = $value;
        }

        return $server;
    }

    private function assertAudited(string $reasonCode): void
    {
        $this->assertSame(
            1,
            $this->auditCount($reasonCode),
            '§8.19.3 requires the refusal to be audited, not merely refused',
        );
    }

    /**
     * 🛑 Read with raw SQL, as every other audit test does.
     *
     * §8.22's chain is append-only at the database level — the triggers
     * refuse an UPDATE or a DELETE from the application principal — and
     * there is deliberately no Eloquent model over it: a model invites a
     * `->save()` the trigger would reject at run time, in production, where
     * nobody is reading.
     */
    private function auditCount(string $reasonCode): int
    {
        return (int) DB::scalar(
            'SELECT COUNT(*) FROM `audit_events` WHERE `action` = ? AND `reason_code` = ?',
            ['webhook.delivery.refused', $reasonCode],
        );
    }

    /**
     * A component sourced from the repository and mounted on the version,
     * which is what makes the project a consumer of pushes to it.
     */
    private function attachComponent(): void
    {
        $component = new Component;
        $component->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'key' => 'docs-'.bin2hex(random_bytes(3)),
            'name' => 'Docs',
            'min_access' => AccessLevel::Public->value,
        ])->save();

        $source = new ComponentSource;
        $source->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'component_id' => $component->id,
            'repository_id' => $this->repository->id,
            'source_path' => '',
            'module' => 'ROOT',
            'priority' => 0,
            'state' => 'active',
        ])->save();

        $mount = new ComponentMount;
        $mount->forceFill([
            'id' => Uuid::v7(),
            'organisation_id' => $this->organisation->id,
            'project_version_id' => $this->version->id,
            'component_id' => $component->id,
            'mount_path' => '/',
            'selector_kind' => 'ref',
            'selector_value' => 'main',
            'is_required' => true,
            'is_primary' => true,
            'min_access_snapshot' => AccessLevel::Public->value,
        ])->save();
    }
}
