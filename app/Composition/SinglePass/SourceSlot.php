<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\SinglePass;

use App\Builds\BuildEnvironment;
use App\Models\Component;
use App\Models\ComponentSource;
use App\Models\Repository;
use App\Support\Uuid;

/**
 * One contributing source, and where it sits in the shared sandbox.
 *
 * §8.7.12's `single_pass` checks every source out "side by side in **one**
 * sandbox", so each needs a directory of its own under the workspace. This
 * is that directory, decided by DocUp and by nothing in the repository.
 *
 * 🛑 **The slot name is derived, validated and never the mount path.**
 * §8.7.10 forbids a mount path under `base_url_mode='relative'` from
 * entering a build container, and `single_pass` does not suspend that rule —
 * it suspends only the one-component-per-build assumption. Antora decides a
 * page's URL from the component's own `antora.yml`, not from where DocUp put
 * the checkout, so the mount path is not needed here and is therefore not
 * sent.
 */
final readonly class SourceSlot
{
    /**
     * A slot name is a single path segment, and a narrow one.
     *
     * 🛑 Narrower than `components.key` allows on purpose. The key permits
     * `.`, so `a..b` is a legal key and would be a legal directory name —
     * harmless today, and exactly the kind of value that stops being
     * harmless when somebody later joins it onto a path with a different
     * separator. A name outside this pattern falls back to the component's
     * hex id, which is always safe and never ambiguous.
     */
    private const SAFE_NAME = '/^[a-z0-9][a-z0-9_-]{0,63}$/';

    private function __construct(
        public Component $component,
        public ComponentSource $source,
        public Repository $repository,
        public string $slot,
        public bool $isPrimary,
    ) {}

    public static function for(
        Component $component,
        ComponentSource $source,
        Repository $repository,
        bool $isPrimary,
    ): self {
        return new self($component, $source, $repository, self::slotFor($component), $isPrimary);
    }

    /** The checkout directory inside the sandbox. */
    public function path(): string
    {
        return BuildEnvironment::REPOSITORY_PATH.'/'.$this->slot;
    }

    /**
     * The directory the generator should read, below the checkout.
     *
     * §8.4.1's `source_path` again: a monorepo contributing three components
     * holds three documentation directories, and the composition has to name
     * the right one for each.
     */
    public function contentPath(): string
    {
        $relative = trim($this->source->source_path, '/');

        return $relative === '' ? $this->path() : $this->path().'/'.$relative;
    }

    /** `source_path` on its own, for a generator that takes it separately. */
    public function startPath(): string
    {
        return trim($this->source->source_path, '/');
    }

    private static function slotFor(Component $component): string
    {
        $key = strtolower($component->key);

        return preg_match(self::SAFE_NAME, $key) === 1 ? $key : bin2hex($component->id);
    }

    /** The component id as text, for provenance. */
    public function componentId(): string
    {
        return Uuid::toText($this->component->id);
    }
}
