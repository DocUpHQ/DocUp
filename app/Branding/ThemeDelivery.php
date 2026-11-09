<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Chrome\ChromeContent;
use App\Models\ThemeAsset;
use App\Models\ThemeRevision;
use App\Support\Uuid;

/**
 * 🛑 The whole of §8.14's goal, in one call.
 *
 * > §8.14 goal (§17): "Two projects look different from the **same build
 * > artifact**, with no rebuild."
 *
 * That sentence is this class's contract. Given a {@see ThemeTarget} — which is
 * four optional identifiers and nothing else — it resolves the cascade,
 * compiles the stylesheet, stores it under its own hash and returns everything
 * a page or an addons payload needs. Nothing it touches is part of a build
 * artifact, which is why two projects sharing one build can look different: the
 * artifact carries §8.15.1's two project-agnostic tags and no theme at all.
 *
 * ## 🛑 The store write happens here
 *
 * Compiling and storing in the same call that produces the `<link href>` is
 * what makes {@see StylesheetStore}'s guarantee true — a URL is never emitted
 * before the bytes exist. Splitting them would reintroduce the reverse lookup
 * from hash to theme that cannot exist.
 */
final readonly class ThemeDelivery
{
    public function __construct(
        private Themes $themes,
        private StylesheetStore $stylesheets,
        private ?string $organisationId = null,
        private ?string $projectId = null,
    ) {}

    public static function make(?string $organisationId = null, ?string $projectId = null): self
    {
        return new self(
            Themes::make($organisationId, $projectId),
            StylesheetStore::make(),
            $organisationId,
            $projectId,
        );
    }

    /**
     * Resolve, compile, store, and describe.
     *
     * @throws TokenRefused when a stored revision no longer parses
     */
    public function deliver(ThemeTarget $target): DeliveredTheme
    {
        return $this->finish($this->themes->resolve($target));
    }

    /**
     * 🛑 §8.14.6's preview, delivered the same way.
     *
     * The same compile and the same store, so a preview URL is a real
     * stylesheet URL with real bytes behind it — which is what lets a preview
     * be rendered by the same page code as the live theme rather than by a
     * second path that could diverge.
     *
     * The stylesheet is **content-addressed like any other**, so a draft that
     * resolves to the same values as the live theme shares its URL. That is
     * correct and occasionally surprising: previewing a draft that changes
     * nothing shows the live stylesheet, because it is the same stylesheet.
     */
    public function previewOf(ThemeTarget $target, ThemeRevision $draft): DeliveredTheme
    {
        return $this->finish($this->themes->preview($target, $draft));
    }

    private function finish(ResolvedTheme $theme): DeliveredTheme
    {
        $fonts = $this->fontsOf($theme);
        $css = (new StylesheetCompiler($fonts))->compile($theme);
        $hash = $theme->contentHash();

        $this->stylesheets->ensure($hash, $css);

        return new DeliveredTheme(
            theme: $theme,
            stylesheetUrl: StylesheetUrl::forHash($hash),
            contentHash: $hash,
            assets: $this->assetsOf($theme),
            chrome: $this->chromeOf($theme),
        );
    }

    /**
     * The asset rows the theme's asset tokens name, keyed by token.
     *
     * 🛑 Looked up through {@see ThemeAssets}, so the scope rule applies on
     * read as well as on write. A project theme that somehow carried another
     * organisation's asset id — because the asset was moved, or because the
     * row was written before a scope change — resolves to no URL rather than
     * to someone else's logo.
     *
     * @return array<string, ThemeAsset>
     */
    private function assetsOf(ResolvedTheme $theme): array
    {
        $lookup = new ThemeAssets($this->organisationId, $this->projectId);
        $assets = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->type !== TokenType::Asset) {
                continue;
            }

            $id = $theme->serialised($name);

            if ($id === null) {
                continue;
            }

            $asset = $lookup->find($id);

            if ($asset instanceof ThemeAsset) {
                $assets[$name] = $asset;
            }
        }

        return $assets;
    }

    /**
     * The font rows a `@font-face` needs, keyed by asset id.
     *
     * @return array<string, ThemeAsset>
     */
    private function fontsOf(ResolvedTheme $theme): array
    {
        $lookup = new ThemeAssets($this->organisationId, $this->projectId);
        $fonts = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->type !== TokenType::FontStack || ! $theme->has($name)) {
                continue;
            }

            foreach ([ColourScheme::Light, ColourScheme::Dark] as $scheme) {
                $value = $theme->value($name, $scheme);

                if (! $value instanceof Values\FontStackValue) {
                    continue;
                }

                foreach ($value->assetHandles() as $handle) {
                    if (isset($fonts[$handle])) {
                        continue;
                    }

                    $asset = $lookup->find($handle);

                    if ($asset instanceof ThemeAsset && $asset->kind === 'font') {
                        $fonts[$handle] = $asset;
                    }
                }
            }
        }

        return $fonts;
    }

    /**
     * §8.14.3's structured content, from the deepest revision that declared it.
     *
     * 🛑 **Chrome content does not cascade field by field, and tokens do.** A
     * navigation list half inherited from an organisation and half overridden
     * by a project would be a menu nobody wrote; the two sets of links are two
     * editorial decisions, not two values for one slider. So the deepest
     * revision that declared *any* chrome content supplies all of it, which is
     * the same reasoning {@see TokenPair} applies to a light/dark pair.
     */
    private function chromeOf(ResolvedTheme $theme): ChromeContent
    {
        foreach (array_reverse(CascadeLevel::revisionScopes()) as $level) {
            $revisionId = $theme->revisionIds[$level->value] ?? null;

            if ($revisionId === null) {
                continue;
            }

            $revision = ThemeRevision::query()
                ->whereKey(Uuid::tryToBytes($revisionId) ?? str_repeat("\xff", 16))
                ->first();

            if (! $revision instanceof ThemeRevision || $revision->chrome === []) {
                continue;
            }

            $content = ChromeContent::fromStorage($revision->chrome, $level);

            if (! $content->isEmpty()) {
                return $content;
            }
        }

        return ChromeContent::empty();
    }
}
