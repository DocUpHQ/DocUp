<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.12, and §17's one 🛑 exit criterion for this phase.
 *
 * > "Pages that accept credentials MUST carry **no project or organisation
 * > branding**. All authentication MUST redirect to the dashboard host with
 * > installation branding only, so a tenant-controlled domain can never present
 * > a DocUp-styled login form."
 *
 * > §17: "🛑 A login page renders **installation** branding only, regardless of
 * > which tenant domain the reader arrived from."
 *
 * ## The attack this closes
 *
 * A tenant controls a custom domain (§8.10) and a theme (§8.14). If a
 * credential page inherited their theme, the tenant could make
 * `docs.acme.example` present a login form carrying their own logo and
 * wording — on DocUp's dashboard host, with DocUp's real session cookie. A
 * reader who typed their operator-directory password into it would have typed
 * it into a form the tenant designed. The password still goes to the right
 * place, which is what makes it hard to see: nothing is stolen, and the tenant
 * has been handed the ability to phrase an authentication prompt however they
 * like, on an origin they do not own.
 *
 * ## 🛑 Why this is a type and not a rule
 *
 * The refusal could have been "remember not to pass the project theme to a
 * credential page", and that would hold until the next credential page. So
 * instead there is one function that returns branding, it takes no arguments,
 * and {@see ThemeTarget::installation()} is the only target it can build — so
 * a credential page has nothing to pass even if it wanted to. The test asserts
 * the **response body**, over the whole of it rather than the props, because a
 * shared Inertia prop or a layout could reintroduce a tenant name without any
 * controller changing.
 *
 * Phase 26b wrote §8.12.16's reader credential page to this rule before the
 * mechanism existed and recorded it as owed; this is the mechanism.
 */
final readonly class CredentialPageBranding
{
    /**
     * @param  array<string, mixed>  $tokens  the installation's values, serialised
     */
    private function __construct(
        public array $tokens,
        public string $installationName,
        public ?string $logoUrl,
        public ?string $faviconUrl,
        public string $stylesheetUrl,
    ) {}

    /**
     * 🛑 The installation's branding. No parameters, by design.
     *
     * There is no `forProject()`, no `forDomain()` and no optional argument
     * that could widen it. A credential page cannot express a tenant even by
     * mistake, which is a stronger guarantee than a code review.
     */
    public static function resolve(): self
    {
        /*
         * 🛑 Through {@see ThemeDelivery} rather than {@see Themes} alone, so
         * the stylesheet bytes exist before this page emits a `<link>` to
         * them. {@see StylesheetStore} explains why minting a URL and storing
         * the file have to happen in one call.
         *
         * 🛑 And with **no organisation and no project** passed to
         * `make()` — so the asset lookup behind the grammar sees installation
         * assets only. A project logo is not merely omitted from the props; it
         * could not have contributed a value to resolve in the first place.
         */
        $delivered = ThemeDelivery::make()->deliver(ThemeTarget::installation());
        $theme = $delivered->theme;
        $assets = ThemeAssets::installationOnly();

        return new self(
            tokens: self::serialise($theme),
            installationName: $theme->serialised('brand.name') ?? 'DocUp',
            logoUrl: self::assetUrl($theme, 'asset.logo', $assets),
            faviconUrl: self::assetUrl($theme, 'asset.favicon', $assets),
            stylesheetUrl: $delivered->stylesheetUrl,
        );
    }

    /**
     * The props a credential page carries.
     *
     * 🛑 **Deliberately only these five keys.** Not the whole resolved theme,
     * which would put forty-five values in a page that needs a logo and a
     * palette — and would be a place a future token could leak a tenant string
     * into a credential page without anybody noticing the shape had changed.
     *
     * @return array{installation: string, logo: string|null, favicon: string|null, stylesheet: string, tokens: array<string, mixed>}
     */
    public function toProps(): array
    {
        return [
            'installation' => $this->installationName,
            'logo' => $this->logoUrl,
            'favicon' => $this->faviconUrl,
            'stylesheet' => $this->stylesheetUrl,
            'tokens' => $this->tokens,
        ];
    }

    /**
     * The handful of tokens a credential page renders with.
     *
     * Colours, the two font stacks and the two radii. Enough for a form that
     * looks like the installation; far short of the chrome payload.
     *
     * @return array<string, mixed>
     */
    private static function serialise(ResolvedTheme $theme): array
    {
        $wanted = [
            'color.surface.page', 'color.surface.raised', 'color.border.subtle', 'color.border.strong',
            'color.text.primary', 'color.text.secondary', 'color.text.link',
            'color.brand.primary', 'color.brand.on-primary', 'color.state.danger', 'color.focus.ring',
            'font.body', 'font.heading', 'radius.small', 'radius.medium', 'scheme.default',
        ];

        $tokens = [];

        foreach ($wanted as $name) {
            if (! $theme->has($name)) {
                continue;
            }

            $tokens[$name] = [
                'light' => $theme->serialised($name, ColourScheme::Light),
                'dark' => $theme->serialised($name, ColourScheme::Dark),
            ];
        }

        return $tokens;
    }

    private static function assetUrl(ResolvedTheme $theme, string $token, ThemeAssets $assets): ?string
    {
        $id = $theme->serialised($token);

        if ($id === null) {
            return null;
        }

        $asset = $assets->find($id);

        return $asset === null ? null : ThemeAssets::urlFor($asset);
    }
}
