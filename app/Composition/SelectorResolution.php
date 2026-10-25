<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition;

use App\Models\Build;

/**
 * What one mount's selector answered, and why (§8.8.8).
 *
 * The "why" is {@see self::$outcome} and it is not decoration. §8.7.5's
 * `mirror_label` can produce the same build through three different routes
 * — an exact label match, a `newest_semver_lte` fallback, or `newest` — and
 * an operator looking at a release that served the wrong glossary needs to
 * know which of the three happened. The build id alone cannot tell them.
 */
final readonly class SelectorResolution
{
    /**
     * @param  Build|null  $build  null when the selector matched nothing
     * @param  string|null  $label  the version label of the matched build
     * @param  string|null  $ref  the git ref it was built from
     */
    private function __construct(
        public SelectorKind $kind,
        public ?string $value,
        public ?MirrorFallback $fallback,
        public ?Build $build,
        public ?string $label,
        public ?string $ref,
        public ?string $commitSha,
        public ResolutionOutcome $outcome,
    ) {}

    public static function matched(
        SelectorKind $kind,
        ?string $value,
        ?MirrorFallback $fallback,
        Build $build,
        ?string $label,
        ?string $ref,
        ResolutionOutcome $outcome,
    ): self {
        return new self($kind, $value, $fallback, $build, $label, $ref, $build->commit_sha, $outcome);
    }

    public static function unresolved(
        SelectorKind $kind,
        ?string $value,
        ?MirrorFallback $fallback,
        ResolutionOutcome $outcome = ResolutionOutcome::NoCandidate,
    ): self {
        return new self($kind, $value, $fallback, null, null, null, null, $outcome);
    }

    public function resolved(): bool
    {
        return $this->build instanceof Build;
    }
}
