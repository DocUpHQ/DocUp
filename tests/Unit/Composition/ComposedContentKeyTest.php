<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Builds\BuildPlan;
use App\Builds\ContentKey;
use App\Composition\SinglePass\ComposedContentKey;
use App\Support\Uuid;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.7.9's key, extended to a build with several components (§8.7.12).
 *
 * The three properties that matter, and each one is a different way for a
 * project to serve somebody else's bytes:
 *
 * 1. a composed key **never** equals a mount-mode key, so a composed site
 *    can never be reused as one component's pages;
 * 2. the key is stable under source reordering, so a monorepo push fanning
 *    out does not build one composition three times;
 * 3. every input changes it.
 */
final class ComposedContentKeyTest extends TestCase
{
    /**
     * 🛑 A composed key and a mount-mode key are never equal, even when
     * every shared input agrees.
     *
     * The artifacts mean different things — one is a component's pages,
     * the other is a whole site — and a collision would publish one where
     * the other was expected.
     */
    public function test_a_composed_key_can_never_equal_a_mount_mode_key(): void
    {
        $organisation = Uuid::v7();
        $component = Uuid::v7();
        $source = Uuid::v7();
        $repository = Uuid::v7();
        $commit = str_repeat('a', 40);

        $plan = $this->plan([[$source, $repository, 'main', $commit, '']]);

        $composed = ComposedContentKey::compute($organisation, $plan);

        $mounted = ContentKey::compute(
            organisationId: $organisation,
            componentId: $component,
            commitSha: $commit,
            configDigest: $plan->configDigest,
            envDigest: $plan->envDigest,
            pipelineVersion: $plan->pipelineVersion,
        );

        $this->assertNotSame($mounted, $composed);
    }

    /**
     * 🛑 Order does not change the key.
     *
     * A monorepo push fans out to several projects at once and nothing
     * guarantees the order their sources were read in. Without this, one
     * composition would compute several keys and be built several times —
     * which is the cost §8.7.9 exists to avoid.
     */
    public function test_the_key_is_stable_under_source_reordering(): void
    {
        $organisation = Uuid::v7();
        $a = [Uuid::v7(), Uuid::v7(), 'main', str_repeat('a', 40), 'docs/a'];
        $b = [Uuid::v7(), Uuid::v7(), 'main', str_repeat('b', 40), 'docs/b'];

        $this->assertSame(
            ComposedContentKey::compute($organisation, $this->plan([$a, $b])),
            ComposedContentKey::compute($organisation, $this->plan([$b, $a])),
        );
    }

    /** A different organisation is a different key, however identical the rest. */
    public function test_two_organisations_never_share_a_key(): void
    {
        $plan = $this->plan([[Uuid::v7(), Uuid::v7(), 'main', str_repeat('a', 40), '']]);

        $this->assertNotSame(
            ComposedContentKey::compute(Uuid::v7(), $plan),
            ComposedContentKey::compute(Uuid::v7(), $plan),
        );
    }

    /** Adding a source changes the key, which is what "composed" means. */
    public function test_adding_a_source_changes_the_key(): void
    {
        $organisation = Uuid::v7();
        $a = [Uuid::v7(), Uuid::v7(), 'main', str_repeat('a', 40), 'docs/a'];
        $b = [Uuid::v7(), Uuid::v7(), 'main', str_repeat('b', 40), 'docs/b'];

        $this->assertNotSame(
            ComposedContentKey::compute($organisation, $this->plan([$a])),
            ComposedContentKey::compute($organisation, $this->plan([$a, $b])),
        );
    }

    /** And so does every other input. */
    public function test_every_input_changes_the_key(): void
    {
        $organisation = Uuid::v7();
        $source = [Uuid::v7(), Uuid::v7(), 'main', str_repeat('a', 40), 'docs'];

        $base = ComposedContentKey::compute($organisation, $this->plan([$source]));

        $moved = $source;
        $moved[3] = str_repeat('b', 40);

        $this->assertNotSame($base, ComposedContentKey::compute($organisation, $this->plan([$moved])));

        $this->assertNotSame(
            $base,
            ComposedContentKey::compute($organisation, $this->plan([$source], configDigest: 'other')),
        );

        $this->assertNotSame(
            $base,
            ComposedContentKey::compute($organisation, $this->plan([$source], envDigest: 'other')),
        );
    }

    /**
     * @param  list<array{0: string, 1: string, 2: string, 3: string, 4: string}>  $sources
     */
    private function plan(array $sources, string $configDigest = 'cfg', string $envDigest = 'env'): BuildPlan
    {
        $rows = [];

        foreach ($sources as [$sourceId, $repositoryId, $ref, $commit, $path]) {
            $rows[] = [
                'source_id' => $sourceId,
                'repository_id' => $repositoryId,
                'ref' => $ref,
                'commit_sha' => $commit,
                'source_path' => $path,
            ];
        }

        return new BuildPlan(
            versionId: Uuid::v7(),
            sources: $rows,
            configDigest: $configDigest,
            envDigest: $envDigest,
        );
    }
}
