<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Fragments;

use App\Audit\CanonicalJson;
use App\Builds\BuildPlan;

/**
 * §8.5.19's `fragment_digest = H(source_digest, env_digest, config_digest,
 * public_env)`.
 *
 * 🛑 **`public_env` is in the digest and secret values are not** — §8.5.25:
 * "a public variable enters `public_env` and therefore the fragment digest;
 * a secret does not, and marks the fragment non-cacheable". Both halves of
 * that are load-bearing. A secret in the key would put its value in a column
 * and in every log line that mentions a cache miss; a secret left out of the
 * key *without* marking the fragment non-cacheable would let a build made
 * with one credential be served to a build that no longer has it.
 *
 * 🛑 **The repository is NOT in the digest**, and that is deliberate rather
 * than an omission: it is the **lookup scope**, not an input. Two
 * repositories with byte-identical sources genuinely do produce the same
 * output, and the digest says so honestly; what stops them sharing is that
 * {@see FragmentCache} will not look outside the repository row it was given
 * (§14.2, §19/38). Folding the repository into the digest would hide the
 * scope inside a hash, where no test can see whether a caller remembered it.
 *
 * Canonical JSON for the same reason {@see BuildPlan} uses it:
 * this number decides whether a container starts, so it must be reproducible
 * by another PHP version on another machine months later.
 */
final readonly class FragmentDigest
{
    /**
     * 🛑 Bumped when a change to the pipeline would make the same inputs
     * produce different output — exactly as `BuildPlan::PIPELINE_VERSION` is,
     * and for the sharper reason: a stale fragment is served, not rebuilt,
     * so without this a fix to the script renderer would never reach any
     * repository whose sources had not changed.
     */
    public const FRAGMENT_VERSION = 1;

    /**
     * @param  string  $sourceDigest  the pinned commit and the source path
     * @param  string  $envDigest  the image digest and builder version (§8.5.14)
     * @param  string  $configDigest  the configuration file and how it resolved
     * @param  array<string, string>  $publicEnv  §8.5.25's public variables only
     */
    public function __construct(
        public string $sourceDigest,
        public string $envDigest,
        public string $configDigest,
        public array $publicEnv,
        public int $fragmentVersion = self::FRAGMENT_VERSION,
    ) {}

    /**
     * The digest, as hex.
     *
     * The public environment is sorted by name, because a map's iteration
     * order is its insertion order and two builds that set the same two
     * variables in a different order are the same build.
     */
    public function hex(): string
    {
        $publicEnv = $this->publicEnv;
        ksort($publicEnv);

        return hash('sha256', CanonicalJson::encode([
            'source_digest' => $this->sourceDigest,
            'env_digest' => $this->envDigest,
            'config_digest' => $this->configDigest,
            'public_env' => $publicEnv,
            'fragment_version' => $this->fragmentVersion,
        ]));
    }

    /** The raw 32 bytes, for the `fragment_digest BINARY(32)` column. */
    public function bytes(): string
    {
        return (string) hex2bin($this->hex());
    }

    /**
     * The source half: what was checked out, and from where in the tree.
     *
     * A component rooted at `docs/` and one rooted at `sdk/` in the same
     * commit are different fragments, which is the monorepo case §8.4.1
     * exists for.
     */
    public static function sourceDigestFor(string $commitSha, string $sourcePath): string
    {
        return hash('sha256', CanonicalJson::encode([
            'commit_sha' => $commitSha,
            'source_path' => trim($sourcePath, '/'),
        ]));
    }

    /**
     * The environment half: §8.5.14's digest-pinned image, and the preset.
     *
     * The image digest is in here rather than in the config digest because
     * §8.5.14 says it must be in `env_digest` — "so that a rebuilt image
     * invalidates the §8.5.2 short-circuit", and a security fix to the
     * toolchain reaches every project whose inputs have not changed.
     */
    public static function envDigestFor(string $imageKey, ?string $imageDigest, string $toolchain): string
    {
        return hash('sha256', CanonicalJson::encode([
            'image_key' => $imageKey,
            'image_digest' => $imageDigest ?? 'unpinned',
            'toolchain' => $toolchain,
        ]));
    }

    /**
     * The configuration half: the file, and everything about how it resolved.
     *
     * 🛑 The resolved values are in here as well as the file's own digest,
     * because two of them are not in the file. `shell_semantics` and
     * `build_context_mode` are component settings (§8.4.10, §8.4.12) that
     * change the output, so a fragment keyed on the file alone would serve
     * a build made under the other setting.
     */
    public static function configDigestFor(
        string $fileDigest,
        string $shellSemantics,
        string $buildContextMode,
        ?string $generatorConfiguration,
    ): string {
        return hash('sha256', CanonicalJson::encode([
            'file' => $fileDigest,
            'shell_semantics' => $shellSemantics,
            'build_context_mode' => $buildContextMode,
            'generator_configuration' => $generatorConfiguration ?? '',
        ]));
    }
}
