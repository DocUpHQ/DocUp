<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Assets\AssetStore;
use App\Models\ThemeAsset;
use App\Support\Origins;
use App\Support\Uuid;
use Illuminate\Database\Eloquent\Builder;

/**
 * Which `theme_assets` rows a writer may reference, and where they are served.
 *
 * 🛑 **The scope rule is a widening, which is why it is here and not a global
 * scope.** A project writer may reference their own project's assets, their
 * organisation's, and the installation's — three scopes, of which only the
 * middle one is what a tenancy scope would filter to. {@see ThemeAsset} is
 * declared `Installation` posture for exactly this reason and says so.
 *
 * 🛑 **"Not yours" and "no such asset" are one answer.** {@see self::kindOf()}
 * returns null for both, which is §8.2.2's 404-never-403 rule applied to a
 * token value: a distinguishable response would let a project owner enumerate
 * another organisation's asset ids by watching which ones produced
 * {@see TokenRejection::WrongAssetKind} instead of
 * {@see TokenRejection::UnknownAsset}.
 */
final readonly class ThemeAssets implements AssetLookup
{
    /**
     * @param  string|null  $organisationId  the writer's organisation, if any
     * @param  string|null  $projectId  the writer's project, if any
     */
    public function __construct(
        private ?string $organisationId = null,
        private ?string $projectId = null,
    ) {}

    /** Installation scope only — what a credential page may draw on (§8.14.12). */
    public static function installationOnly(): self
    {
        return new self;
    }

    public function kindOf(string $assetId): ?string
    {
        $asset = $this->visible()->whereKey($this->keyFor($assetId))->first();

        return $asset instanceof ThemeAsset ? $asset->kind : null;
    }

    /** One visible asset, or null. */
    public function find(string $assetId): ?ThemeAsset
    {
        $asset = $this->visible()->whereKey($this->keyFor($assetId))->first();

        return $asset instanceof ThemeAsset ? $asset : null;
    }

    /**
     * 🛑 §8.14.11's asset-host URL, built from the content hash.
     *
     * The URL is **derived**, never stored. Moving the asset host is then a
     * configuration change rather than a migration over every tenant's tokens,
     * and a token value cannot name a host at all — which is the same
     * guarantee §8.14.2 makes about fonts, extended to every asset.
     *
     * The extension comes from the stored media type rather than from the
     * token, so a sanitised SVG serves as `.svg` and a re-encoded raster as
     * `.png` with no caller having to know which.
     */
    public static function urlFor(ThemeAsset $asset): string
    {
        return self::assetOrigin().'/'.$asset->content_hash.'.'.self::extensionFor($asset->media_type);
    }

    /** The extension for one of the four media types DocUp emits. */
    public static function extensionFor(string $mediaType): string
    {
        return match ($mediaType) {
            'image/svg+xml' => 'svg',
            'font/woff2' => 'woff2',
            default => 'png',
        };
    }

    /**
     * The scheme and host branding assets are served from.
     *
     * 🛑 §8.14.11 requires a **dedicated** asset host. When
     * `DOCUP_ASSET_HOST` is unset the assets fall back to the dashboard
     * origin, which is a degradation and not a silent one: `docup:doctor`
     * reports it, and {@see self::hasDedicatedHost()} is what the chrome
     * payload and the CSP builder consult so the `img-src` allowlist describes
     * what is actually happening.
     *
     * The scheme follows `APP_URL`'s, so a development installation on plain
     * HTTP does not emit `https://` URLs that resolve to nothing.
     */
    public static function assetOrigin(): string
    {
        $host = config('docup.origins.assets');

        if (! is_string($host) || $host === '') {
            return rtrim(self::applicationUrl(), '/');
        }

        return self::scheme().'://'.Origins::normalise($host);
    }

    /** Whether §8.14.11's dedicated host is configured. */
    public static function hasDedicatedHost(): bool
    {
        $host = config('docup.origins.assets');

        return is_string($host) && $host !== '';
    }

    /** The store, for the controller that serves the bytes. */
    public static function store(): AssetStore
    {
        return AssetStore::make();
    }

    /**
     * The visible set, as a query.
     *
     * @return Builder<ThemeAsset>
     */
    private function visible(): Builder
    {
        $organisationId = $this->organisationId;
        $projectId = $this->projectId;

        return ThemeAsset::query()->where(static function ($query) use ($organisationId, $projectId): void {
            /* The installation's own assets are visible to every writer. */
            $query->where(static function ($installation): void {
                $installation->where('scope_type', 'installation')->whereNull('scope_id');
            });

            if ($organisationId !== null) {
                $query->orWhere(static function ($organisation) use ($organisationId): void {
                    $organisation->where('scope_type', 'organisation')->where('scope_id', $organisationId);
                });
            }

            if ($projectId !== null) {
                $query->orWhere(static function ($project) use ($projectId): void {
                    $project->where('scope_type', 'project')->where('scope_id', $projectId);
                });
            }
        });
    }

    /**
     * The binary key for a canonical UUID, or a value that matches nothing.
     *
     * 🛑 A malformed id becomes a key that cannot match rather than an
     * exception, because this is reached from a token value an operator typed.
     * The caller's answer is the same either way — null, meaning "no such
     * asset" — and raising here would turn a typo into a 500.
     */
    private function keyFor(string $assetId): string
    {
        return Uuid::tryToBytes($assetId) ?? str_repeat("\xff", 16);
    }

    private static function scheme(): string
    {
        return str_starts_with(self::applicationUrl(), 'http://') ? 'http' : 'https';
    }

    /**
     * `APP_URL`, narrowed.
     *
     * Narrowed in one place rather than cast at each use: `config()` returns
     * mixed, and the level-9 analysis app/Branding is held to refuses a cast
     * from it — which is the right refusal, because a misconfigured APP_URL
     * reaching a URL builder as an array is a URL nobody can read.
     */
    private static function applicationUrl(): string
    {
        $url = config('app.url');

        return is_string($url) ? $url : '';
    }
}
