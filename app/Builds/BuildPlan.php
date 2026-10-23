<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

use App\Audit\CanonicalJson;

/**
 * The resolved plan, and its digest (§8.5.1, §8.5.2).
 *
 * > "A build MUST be a pure function of a fully resolved plan: every
 * > contributing ref pinned to an immutable commit SHA by `git ls-remote`
 * > **before any repository code executes**, with the resolved plan recorded
 * > immutably on the build record."
 *
 * > "The system MUST compute `plan_digest = H(version, ordered(source:commit_sha),
 * > config_digest, env_digest, pipeline_version)` and MUST short-circuit a
 * > trigger whose digest equals the published build's to a terminal
 * > `unchanged` state in under a second, with no container started."
 *
 * 🛑 **`ordered(...)` is load-bearing and is why the sources are sorted here
 * rather than wherever they came from.** Two triggers that resolved the same
 * sources in a different order must produce the same digest, or the
 * short-circuit never fires for a composed project and every webhook rebuilds
 * everything. Sorting at the point of digesting — not at the point of
 * collection — means no caller can get it wrong.
 *
 * 🛑 **Canonical JSON, not `serialize()` or `implode()`.** The digest decides
 * whether a build runs, so it must be reproducible by a different PHP version
 * on a different machine months later; `App\Audit\CanonicalJson` already
 * exists for exactly that property and rejects the values (floats, objects)
 * whose encoding is environment-dependent. Reusing it also means the two
 * things in this codebase that must hash identically forever share one
 * implementation.
 */
final readonly class BuildPlan
{
    /**
     * 🛑 Bumped whenever a change to the pipeline would produce different
     * output from identical inputs — a new injector version, a changed
     * composition rule, a corrected output contract.
     *
     * Without it the §8.5.2 short-circuit is actively wrong after any such
     * change: every version's inputs are unchanged, so every rebuild is
     * refused, and the fix never reaches anybody's documentation. It is in the
     * digest for the same reason the image digest is in `env_digest`.
     */
    public const PIPELINE_VERSION = 1;

    /**
     * @param  string  $versionId  raw 16 bytes
     * @param  list<array{source_id: string, repository_id: string, ref: string, commit_sha: string, source_path: string}>  $sources
     */
    public function __construct(
        public string $versionId,
        public array $sources,
        public string $configDigest,
        public string $envDigest,
        public int $pipelineVersion = self::PIPELINE_VERSION,
    ) {}

    /**
     * `H(version, ordered(source:commit_sha), config_digest, env_digest,
     * pipeline_version)`, as hex.
     */
    public function digest(): string
    {
        return hash('sha256', CanonicalJson::encode([
            'version' => bin2hex($this->versionId),
            'sources' => $this->orderedSources(),
            'config_digest' => $this->configDigest,
            'env_digest' => $this->envDigest,
            'pipeline_version' => $this->pipelineVersion,
        ]));
    }

    /** The raw 32 bytes, for the `plan_digest BINARY(32)` column. */
    public function digestBytes(): string
    {
        return (string) hex2bin($this->digest());
    }

    /**
     * `source:commit_sha` pairs, sorted.
     *
     * Sorted by the **source identifier**, not by the SHA: the identifier is
     * stable across rebuilds and the SHA is the thing that changes, so sorting
     * by the SHA would reorder the list on every commit and make the ordering
     * meaningless.
     *
     * @return list<string>
     */
    public function orderedSources(): array
    {
        $pairs = [];

        foreach ($this->sources as $source) {
            $pairs[] = bin2hex($source['source_id']).':'.$source['commit_sha'];
        }

        sort($pairs, SORT_STRING);

        return $pairs;
    }

    /**
     * Does this plan produce the same build as one already published?
     *
     * 🛑 Compared on the digest alone. Comparing field by field would invite a
     * caller to skip a field, and the digest exists precisely so the
     * comparison is total.
     */
    public function matches(?string $publishedDigest): bool
    {
        if ($publishedDigest === null || $publishedDigest === '') {
            return false;
        }

        // Accepts either the hex form or the raw 32 bytes the column holds,
        // because callers legitimately have both and converting at every call
        // site is how one of them eventually compares the wrong pair.
        $normalised = strlen($publishedDigest) === 32 ? bin2hex($publishedDigest) : strtolower($publishedDigest);

        return hash_equals($this->digest(), $normalised);
    }

    /** @return array<string, mixed> for `provenance.json` (§8.5.24) */
    public function toArray(): array
    {
        return [
            'version' => bin2hex($this->versionId),
            'sources' => $this->orderedSources(),
            'config_digest' => $this->configDigest,
            'env_digest' => $this->envDigest,
            'pipeline_version' => $this->pipelineVersion,
            'plan_digest' => $this->digest(),
        ];
    }
}
