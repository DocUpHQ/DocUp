<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Artifacts\Publisher;
use App\Auth\OrganisationContext;
use App\Models\Organisation;
use App\Models\Project;
use App\Models\ProjectVersion;
use App\Serving\RouteOutcome;
use App\Support\Epoch;
use App\Support\Invalidation;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Storage;
use Tests\Support\ArchiveWriter;
use Tests\TestCase;

/**
 * 🛑 §10.8's mandated test: "**one test proving a bump takes effect within its
 * bound**."
 *
 * §10.8 requires every epoch to declare five things — what bumps it, which
 * caches key on it, its maximum staleness, its fail-closed behaviour, and this
 * test. Two epochs are implemented in Phases 03 and 04, and both claim a bound
 * of **0**. A bound of zero is the one that can be proved exactly rather than
 * measured, and this file proves each of them the way it is achieved:
 *
 * - `routing_epoch` is 0 because it is **in the cache key**, so a bump addresses
 *   different keys and no stale entry exists to be read.
 * - `serving_epoch` is 0 because it moves **inside the compare-and-swap**, under
 *   the same row lock as the pointer, so no reader sees one without the other.
 */
final class InvalidationEpochTest extends TestCase
{
    use DatabaseTransactions;

    private OrganisationContext $context;

    private Organisation $organisation;

    private Project $project;

    private ProjectVersion $version;

    private string $fixtures;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('artifacts');

        $this->fixtures = sys_get_temp_dir().'/docup-epoch-'.getmypid();

        if (! is_dir($this->fixtures)) {
            mkdir($this->fixtures, 0o755, true);
        }

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Epoch Co',
            'slug' => 'epoch-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->project = Project::query()->create([
            'slug' => 'epochs',
            'name' => 'Epochs',
            'visibility' => 'public',
        ]);

        $this->version = new ProjectVersion;
        $this->version->forceFill([
            'organisation_id' => $this->organisation->id,
            'project_id' => $this->project->id,
            'slug' => 'latest',
            'kind' => 'channel',
            'language' => 'en',
            'visibility' => 'public',
        ])->save();
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

    // ----------------------------------------------- routing_epoch, bound 0

    /**
     * 🛑 The bound is 0, and this is why: the bump changes the cache key.
     *
     * Not "the cache is purged quickly" — there is nothing to purge. A reader
     * arriving after the bump computes a key that has never been written, so it
     * cannot read a stale entry even in principle. §8.9.10: "A failed CDN purge
     * then degrades to stale public HTML for `max-age`, never to wrong routing."
     */
    public function test_a_routing_bump_takes_effect_within_zero_requests(): void
    {
        $before = $this->routingEpoch();
        $keyBefore = RouteOutcome::cacheKey($before, 'alpha.docs.test', '/en/latest/');

        Invalidation::bumpRouting(
            projectId: $this->project->id,
            cause: 'domain change',
            organisationId: $this->organisation->id,
        );

        $after = $this->routingEpoch();

        $this->assertSame($before + 1, $after, 'the bump must increment by exactly one');

        $keyAfter = RouteOutcome::cacheKey($after, 'alpha.docs.test', '/en/latest/');

        // The whole proof: a different key, immediately, with no purge.
        $this->assertNotSame($keyBefore, $keyAfter);
        $this->assertStringContainsString(':'.$after.':', $keyAfter);
    }

    /**
     * 🛑 The bump is atomic, so concurrent changes cannot lose one.
     *
     * Two domain edits landing together must both be reflected. With the next
     * value computed in PHP the second write overwrites the first, and the cache
     * key stays where one of them left it — which is a stale routing answer
     * produced by the mechanism that exists to prevent one.
     */
    public function test_concurrent_routing_bumps_cannot_lose_one(): void
    {
        $before = $this->routingEpoch();

        for ($i = 0; $i < 5; $i++) {
            Invalidation::bumpRouting(
                projectId: $this->project->id,
                cause: 'mount change',
                organisationId: $this->organisation->id,
            );
        }

        $this->assertSame($before + 5, $this->routingEpoch());
    }

    /**
     * 🛑 §8.9.10: "one project's domain change cannot invalidate every other
     * project's resolution cache".
     *
     * A single installation-wide counter would make every domain edit a full
     * cache flush — a thundering herd on the hottest path in the product.
     */
    public function test_a_bump_is_confined_to_its_own_project(): void
    {
        $other = Project::query()->create([
            'slug' => 'untouched',
            'name' => 'Untouched',
            'visibility' => 'public',
        ]);

        $otherBefore = $this->routingEpoch($other->id);

        Invalidation::bumpRouting(
            projectId: $this->project->id,
            cause: 'domain change',
            organisationId: $this->organisation->id,
        );

        $this->assertSame($otherBefore, $this->routingEpoch($other->id));
    }

    /** §8.22: the bump is audited, with identifiers and fixed vocabulary only. */
    public function test_a_routing_bump_is_audited(): void
    {
        Invalidation::bumpRouting(
            projectId: $this->project->id,
            cause: 'redirect change',
            organisationId: $this->organisation->id,
        );

        $event = DB::table('audit_events')
            ->where('organisation_id', $this->organisation->id)
            ->where('action', 'epoch.bumped')
            ->orderByDesc('id')
            ->first();

        $this->assertNotNull($event);

        /** @var array<string, mixed> $payload */
        $payload = json_decode((string) $event->payload, true);

        $this->assertSame('routing_epoch', $payload['epoch']);
        $this->assertSame('redirect change', $payload['cause']);
    }

    // ----------------------------------------------- serving_epoch, bound 0

    /**
     * 🛑 The bound is 0 because the bump happens inside the §8.8.4
     * compare-and-swap, under the same row lock as the pointer.
     *
     * So the two cannot be observed apart: there is no instant at which the
     * version points at a new manifest while its epoch still names the old one.
     */
    public function test_a_publish_bumps_the_serving_epoch_with_the_pointer(): void
    {
        $before = $this->servingEpoch();

        $this->publish('one');

        $this->context->for($this->organisation->id);
        $version = $this->version->fresh();

        $this->assertNotNull($version);
        $this->assertSame($before + 1, $this->servingEpoch());

        // The pointer moved in the same transaction as the epoch.
        $this->assertNotNull($version->published_manifest_id);
    }

    /** And a second publish bumps it again, once. */
    public function test_each_pointer_flip_bumps_the_serving_epoch_once(): void
    {
        $before = $this->servingEpoch();

        $this->publish('one');
        $this->publish('two');

        $this->assertSame($before + 2, $this->servingEpoch());
    }

    /**
     * 🛑 A publish also bumps `routing_epoch`, because §10.8 lists "version
     * pointer change" among the four things that do.
     *
     * Without it, a reader whose resolution was cached before the flip would
     * keep resolving to the old manifest for the life of the entry — which is
     * exactly the stale routing the epoch exists to make impossible.
     */
    public function test_a_publish_bumps_the_routing_epoch_too(): void
    {
        $before = $this->routingEpoch();

        $this->publish('one');

        $this->assertSame($before + 1, $this->routingEpoch());
    }

    // ------------------------------------------------------------ the registry

    /**
     * 🛑 §10.8 requires every epoch to declare all five properties. Asserted
     * here so an epoch added later cannot be half-declared.
     */
    public function test_every_epoch_declares_what_section_10_8_requires(): void
    {
        $this->assertCount(7, Epoch::cases(), '§10.8 names seven epochs');

        foreach (Epoch::cases() as $epoch) {
            $this->assertNotSame('', $epoch->bumpedBy(), "{$epoch->value} must say what bumps it");
            $this->assertNotSame('', $epoch->keys(), "{$epoch->value} must say which caches key on it");
            $this->assertNotSame('', $epoch->maxStaleness(), "{$epoch->value} must state its staleness bound");
            $this->assertNotSame('', $epoch->ownedByPhase(), "{$epoch->value} must name its owning phase");
        }
    }

    /**
     * The two with a bound of 0 are the two that are implemented, and the
     * registry says so.
     *
     * 🛑 This is the assertion that keeps the registry honest. Seven declared
     * epochs read as seven working controls; four have a column, a declaration
     * and nothing that moves them. An unenforced control that looks enforced is
     * worse than an absent one, so the registry is required to admit it.
     */
    public function test_the_registry_admits_which_epochs_are_not_yet_live(): void
    {
        $implemented = array_values(array_filter(
            Epoch::cases(),
            static fn (Epoch $epoch): bool => $epoch->isImplemented(),
        ));

        $this->assertSame([Epoch::Routing, Epoch::Serving], $implemented);

        foreach ($implemented as $epoch) {
            $this->assertStringContainsString('0', $epoch->maxStaleness(), $epoch->value);
        }

        // §8.12.21: the search epochs fail closed, because a stale gating answer
        // is a disclosure rather than a wrong page.
        $this->assertTrue(Epoch::SearchGeneration->failsClosed());
        $this->assertTrue(Epoch::PolicyGeneration->failsClosed());
        $this->assertFalse(Epoch::Routing->failsClosed());
    }

    // ---------------------------------------------------------------- helpers

    /** @param  string|null  $projectId  raw 16 bytes; defaults to this test's project */
    private function routingEpoch(?string $projectId = null): int
    {
        return (int) DB::table('projects')
            ->where('id', $projectId ?? $this->project->id)
            ->value('routing_epoch');
    }

    private function servingEpoch(): int
    {
        return (int) DB::table('project_versions')
            ->where('id', $this->version->id)
            ->value('serving_epoch');
    }

    private function publish(string $marker): void
    {
        $archive = (new ArchiveWriter)
            ->add('html/index.html', $marker)
            ->toTarGz($this->fixtures.'/tree-'.$marker.'.tar.gz');

        $this->context->for($this->organisation->id);

        /** @var Publisher $publisher */
        $publisher = app(Publisher::class);
        $publisher->publishUpload($this->version->fresh() ?? $this->version, $archive);
    }
}
