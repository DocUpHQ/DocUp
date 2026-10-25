<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Builds\ContentKey;
use App\Models\Component;
use App\Models\ComponentMount;

/**
 * One mount, its selector's answer, and the files that answer serves.
 *
 * The unit the rest of the composition works in. Assembling it once per
 * publish means the build's file manifest — which can be fifty thousand
 * entries — is read once rather than once per question asked of it.
 */
final class ResolvedMount
{
    /** @var list<string>|null */
    private ?array $documentPaths = null;

    /** Copied from the mount, because every comparison in this phase reads it. */
    public readonly string $mountPath;

    /**
     * @param  array<string, array{sha256: string, bytes: int, content_type: string}>  $files
     *                                                                                         the build's file manifest, keyed as it is stored:
     *                                                                                         `html/index.html`, `pdf/document.pdf`
     * @param  int  $priority  `component_sources.priority`, for §8.7.14
     */
    public function __construct(
        public readonly ComponentMount $mount,
        public readonly Component $component,
        public readonly SelectorResolution $resolution,
        public readonly array $files = [],
        public readonly int $priority = 100,
    ) {
        $this->mountPath = $mount->mount_path;
    }

    public function componentKey(): string
    {
        return $this->component->key;
    }

    /**
     * The served paths, relative to the mount — i.e. with `html/` removed.
     *
     * 🛑 Only the `html/` tree. §8.7.19 gives offline formats to the primary
     * mount alone and they live at their own URLs, so a `pdf/document.pdf`
     * from two mounts is not a collision in the §8.7.14 sense: the two never
     * share a URL.
     *
     * @return list<string>
     */
    public function documentPaths(): array
    {
        if ($this->documentPaths !== null) {
            return $this->documentPaths;
        }

        $paths = [];

        foreach (array_keys($this->files) as $path) {
            if (str_starts_with($path, 'html/')) {
                $paths[] = substr($path, 5);
            }
        }

        return $this->documentPaths = $paths;
    }

    /** Whether this mount's build serves a path relative to the mount. */
    public function serves(string $relative): bool
    {
        return isset($this->files['html/'.$relative]);
    }

    /**
     * §8.7.11's base path for this mount, or null under `relative`.
     *
     * Read through {@see ContentKey::mountPathFor()} so the value the
     * container saw and the value the key was computed from cannot
     * disagree — the Phase 13 note that made it one decision.
     */
    public function basePath(): ?string
    {
        return ContentKey::mountPathFor($this->mount, $this->component);
    }

    /** `key` at `path`, for a refusal a human reads. */
    public function describe(): string
    {
        return $this->component->key.' (mounted at "'.$this->mountPath.'")';
    }
}
