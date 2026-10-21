<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature;

use App\Support\Uuid;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use Tests\Fixtures\Models\SpikeChild;
use Tests\Fixtures\Models\SpikeParent;
use Tests\Fixtures\Models\SpikeTag;
use Tests\TestCase;

/**
 * The SPEC 9.1 identifier policy, and the two silent failure modes ADR 0006
 * measured.
 *
 * 🛑 These two are the reason this file exists, and neither may ever be deleted:
 *   - an invalid route key MUST render 404, never 500
 *   - belongsToMany across a BINARY(16) pivot MUST return its rows
 *
 * Both failed under the obvious implementation (a key cast to the canonical
 * string). The second failed SILENTLY, with the pivot row present and correct,
 * and the relation it breaks in production is the composition model itself.
 */
final class UuidKeyTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // Test-only tables: Phase 01 has no domain model (its scope note says
        // so), but the invariant still needs proving. Built with the SPEC 9.1
        // schema macros, so the macros are under test too.
        Schema::create('spike_parents', function (Blueprint $table): void {
            $table->uuidKey();
            $table->string('name');
            $table->timestamps();
        });

        Schema::create('spike_children', function (Blueprint $table): void {
            $table->uuidKey();
            $table->uuidForeign('parent_id');
            $table->string('name');
            $table->timestamps();
        });

        Schema::create('spike_tags', function (Blueprint $table): void {
            $table->uuidKey();
            $table->string('label');
            $table->timestamps();
        });

        Schema::create('spike_parent_tag', function (Blueprint $table): void {
            $table->uuidForeign('parent_id');
            $table->uuidForeign('tag_id');
            $table->string('note')->default('');
            $table->primary(['parent_id', 'tag_id']);
        });
    }

    protected function tearDown(): void
    {
        foreach (['spike_parent_tag', 'spike_tags', 'spike_children', 'spike_parents'] as $table) {
            Schema::dropIfExists($table);
        }

        parent::tearDown();
    }

    /** @return array{parent: SpikeParent, child: SpikeChild, tag: SpikeTag} */
    private function graph(): array
    {
        $parent = SpikeParent::create(['name' => 'handbook']);
        $child = SpikeChild::create(['parent_id' => $parent->getKey(), 'name' => 'latest']);
        $tag = SpikeTag::create(['label' => 'guide']);
        $parent->tags()->attach($tag->getKey(), ['note' => 'mounted at root']);

        return compact('parent', 'child', 'tag');
    }

    public function test_the_macro_produces_binary_16_with_a_legible_id_text(): void
    {
        $parent = SpikeParent::create(['name' => 'acme']);

        $this->assertSame(16, (int) DB::scalar('SELECT LENGTH(id) FROM spike_parents LIMIT 1'));
        $this->assertSame(
            $parent->uuid,
            DB::scalar('SELECT id_text FROM spike_parents LIMIT 1'),
            'the SPEC 9.1.2 id_text virtual column does not match the canonical form',
        );
    }

    public function test_keys_are_uuid_version_7_and_time_ordered(): void
    {
        $uuid = SpikeParent::create(['name' => 'a'])->uuid;
        $this->assertNotNull($uuid);
        $this->assertSame('7', $uuid[14], 'not a v7 UUID');

        $uuids = [];
        for ($i = 0; $i < 6; $i++) {
            $uuids[] = (string) SpikeParent::create(['name' => "o{$i}"])->uuid;
            usleep(2000);
        }

        $sorted = $uuids;
        sort($sorted);

        // The whole justification for BINARY(16) over CHAR(36) is index
        // locality, which depends on the keys being time-ordered.
        $this->assertSame($sorted, $uuids, 'UUIDv7 keys are not lexicographically time-ordered');
    }

    public function test_the_raw_attribute_holds_bytes_not_a_string(): void
    {
        $parent = SpikeParent::create(['name' => 'acme']);

        // 🛑 ADR 0006: this is the design. The attribute is raw bytes so that
        // every query Eloquent builds from it is already binary. If a future
        // edit adds a cast, this assertion fails before anything silently
        // breaks downstream.
        $this->assertSame(16, strlen($parent->getKey()));
        $this->assertTrue(Str::isUuid($parent->uuid));
    }

    public function test_json_exposes_uuid_and_hides_the_raw_key(): void
    {
        $array = SpikeParent::create(['name' => 'acme'])->toArray();

        $this->assertArrayHasKey('uuid', $array);
        $this->assertArrayNotHasKey('id', $array, 'raw bytes must never reach JSON');
        $this->assertTrue(Str::isUuid($array['uuid']));
    }

    /** 🛑 Exit criterion. The silent failure mode here is a 500. */
    public function test_route_binding_with_an_invalid_key_returns_404_not_500(): void
    {
        // Laravel binds implicitly by PARAMETER NAME, not by type hint: the URI
        // segment and the closure variable must match, or the container hands
        // back a fresh empty model and every assertion below passes vacuously.
        Route::middleware('web')->get(
            '/_t/parents/{spikeParent}',
            fn (SpikeParent $spikeParent) => $spikeParent->name,
        );

        $parent = SpikeParent::create(['name' => 'handbook']);

        $this->get('/_t/parents/'.(string) $parent->uuid)->assertOk()->assertSee('handbook');

        foreach ([
            'not-a-uuid',
            str_repeat('z', 36),
            '1',
            'null',
            '../../etc/passwd',
            Str::uuid7()->toString(),   // well-formed but absent
        ] as $bad) {
            $status = $this->get('/_t/parents/'.urlencode($bad))->getStatusCode();

            $this->assertSame(404, $status, "route key [{$bad}] returned {$status}, expected 404");
        }
    }

    /** 🛑 Exit criterion. This is the one that failed SILENTLY under a cast key. */
    public function test_belongs_to_many_across_a_binary16_pivot_returns_its_rows(): void
    {
        $g = $this->graph();

        $fresh = SpikeParent::query()->whereUuid((string) $g['parent']->uuid)->firstOrFail();

        $this->assertCount(1, $fresh->tags, 'belongsToMany across a BINARY(16) pivot returned empty');

        $tag = $fresh->tags->firstOrFail();
        $this->assertSame('guide', $tag->label);
        $this->assertSame('mounted at root', $tag->getRelationValue('pivot')->note);
    }

    public function test_eager_loading_every_relation_kind(): void
    {
        $this->graph();

        $parents = SpikeParent::with(['children', 'tags'])->get();

        $this->assertCount(1, $parents);

        $parent = $parents->firstOrFail();
        $this->assertCount(1, $parent->children, 'hasMany returned empty');
        $this->assertCount(1, $parent->tags, 'belongsToMany returned empty');

        $child = SpikeChild::with('parent')->firstOrFail();
        $this->assertNotNull($child->parent, 'belongsTo returned null');
        $this->assertSame('handbook', $child->parent->name);
    }

    public function test_find_and_where_in_resolve_canonical_strings(): void
    {
        $uuids = [];
        for ($i = 0; $i < 40; $i++) {
            $uuids[] = (string) SpikeParent::create(['name' => "p{$i}"])->uuid;
        }

        // find() takes raw bytes, because the attribute is raw bytes. Callers
        // holding a canonical string use the whereUuid scope - which is why the
        // scope exists rather than being a convenience.
        $this->assertNotNull(SpikeParent::find(Uuid::toBytes($uuids[0])));
        $this->assertSame(40, SpikeParent::query()->whereUuidIn($uuids)->count());
        $this->assertSame(1, SpikeParent::query()->whereUuid($uuids[7])->count());
    }

    public function test_uuid_helper_round_trips_and_rejects_rubbish(): void
    {
        $text = Str::uuid7()->toString();

        $this->assertSame($text, Uuid::toText(Uuid::toBytes($text)));
        $this->assertSame(16, strlen(Uuid::toBytes($text)));

        // Idempotence matters: these helpers are called at boundaries where the
        // caller may legitimately already hold either form.
        $this->assertSame($text, Uuid::toText($text));
        $this->assertSame(Uuid::toBytes($text), Uuid::toBytes(Uuid::toBytes($text)));

        $this->expectException(\InvalidArgumentException::class);
        Uuid::toBytes('not-a-uuid');
    }
}
