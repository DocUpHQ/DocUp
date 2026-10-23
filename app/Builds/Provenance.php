<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Models\Build;
use App\Models\BuildSource;

/**
 * `provenance.json` (§8.5.24).
 *
 * > "The system MUST record `provenance.json` per build — plan digest, image
 * > digest, tool versions, source SHAs, actor — served at
 * > `/_/provenance/{build}`."
 *
 * 🛑 **`origin` is the field that makes the document honest.** A build from
 * the built-in runner can state its image digest and its source SHAs; an
 * archive uploaded by somebody else's CI cannot, and §8.21.6 insists that
 * such an upload is a first-class citizen rather than a degraded one. So the
 * document says which kind it is, and absent facts are **absent** rather than
 * null-filled. A consumer that cannot tell "we do not know the image digest"
 * from "there was no image" will eventually treat the second as the first and
 * claim a provenance it does not have.
 *
 * 🛑 Nothing here is a secret or a credential, and nothing is a free-text
 * field an author controls. The document is served publicly for a public
 * project, so every field is either a digest, an identifier, or a version
 * string from a toolchain DocUp installed itself.
 */
final readonly class Provenance
{
    /** Bumped when the document's shape changes, so consumers can branch. */
    public const SCHEMA = 'docup.provenance/1';

    /**
     * @param  'runner'|'upload'  $origin
     * @param  array<string, mixed>  $facts
     */
    public function __construct(
        public string $origin,
        public string $buildId,
        public array $facts,
    ) {}

    /**
     * The document for a build produced by the built-in runner.
     *
     * @param  iterable<BuildSource>  $sources
     * @param  array<string, mixed>  $toolVersions
     */
    public static function forRunner(
        Build $build,
        iterable $sources,
        string $imageReference,
        ?string $imageDigest,
        array $toolVersions,
        ?string $actorId,
    ): self {
        $pinned = [];

        foreach ($sources as $source) {
            $pinned[] = [
                'repository' => bin2hex((string) $source->repository_id),
                'ref' => $source->ref,
                'commit_sha' => $source->commit_sha,
                'source_path' => $source->source_path,

                // ADR 0010 / §18.14. In the provenance because a consumer
                // auditing a build wants to know whether the clone it was
                // built from was the narrow one DocUp asked for.
                'filter_honoured' => $source->filter_honoured,
            ];
        }

        return new self('runner', bin2hex($build->id), [
            'plan_digest' => is_string($build->plan_digest) ? bin2hex($build->plan_digest) : null,
            'config_digest' => $build->config_digest,
            'env_digest' => $build->env_digest,
            'pipeline_version' => $build->pipeline_version,
            'content_key' => $build->content_key,
            'image' => array_filter([
                'reference' => $imageReference,
                'digest' => $imageDigest,
            ]),
            'tool_versions' => $toolVersions,
            'sources' => $pinned,
            'actor' => $actorId === null ? null : bin2hex($actorId),
        ]);
    }

    /**
     * The document for an archive somebody else's CI uploaded.
     *
     * 🛑 Deliberately sparse. §8.21.6 makes this path first-class, and the
     * honest thing a first-class path can say is "DocUp did not build this,
     * here is who published it and what arrived". Inventing an image digest
     * for a tree that never saw an image would be the opposite of provenance.
     */
    /** @param  array<string, mixed>  $facts */
    public static function forUpload(Build $build, ?string $actorId, array $facts = []): self
    {
        return new self('upload', bin2hex($build->id), array_merge([
            'content_key' => $build->content_key,
            'file_count' => $build->file_count,
            'total_bytes' => $build->total_bytes,
            'actor' => $actorId === null ? null : bin2hex($actorId),
        ], $facts));
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'schema' => self::SCHEMA,
            'origin' => $this->origin,
            'build' => $this->buildId,
            'recorded_at' => now()->toIso8601String(),
        ] + $this->facts;
    }

    public function toJson(): string
    {
        return json_encode(
            $this->toArray(),
            JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES,
        );
    }
}
