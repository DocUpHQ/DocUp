<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\FontEntry;
use App\Branding\Values\FontEntryKind;
use App\Branding\Values\FontStackValue;
use App\Models\ThemeAsset;

/**
 * 🛑 §8.14.4's per-theme stylesheet: custom properties, and nothing else.
 *
 * > "Tailwind MUST compile **once at release time** with utilities mapped onto
 * > CSS custom properties. Each theme revision MUST publish as an immutable
 * > content-addressed stylesheet with `max-age=31536000, immutable`, so 500
 * > projects cost one bundle plus 500 small files and a token edit mints a new
 * > URL with nothing to purge. 🛑 No per-tenant CSS or JavaScript toolchain
 * > MUST run in any request or save path."
 *
 * ## 🛑 Why this is a string builder and not a compiler
 *
 * The last sentence of §8.14.4 is the design. Tailwind runs **once**, at
 * release time, over `resources/css/chrome.css`, and every utility it emits
 * resolves a `var(--docup-…)`. What a tenant's theme produces is therefore not
 * CSS that needs compiling — it is a `:root { … }` block of forty-odd
 * declarations. Writing it with `sprintf` is not a shortcut; it is the
 * requirement. A per-tenant Tailwind invocation on a save path would be an
 * arbitrary-length Node process triggered by a tenant's form submission.
 *
 * So: one bundle, shipped in the image and cached by the browser across every
 * project on the installation, plus one tiny file per distinct theme.
 *
 * ## 🛑 Only {@see TokenType::emitsCss()} types reach the output
 *
 * Three types never do, each for its own reason — the enum says which and why.
 * The loop here asks the type rather than listing names, so a token added later
 * is excluded until somebody says otherwise, which is the right default for a
 * value that arrived from a tenant.
 *
 * ## 🛑 Every value is re-serialised (§8.14.2)
 *
 * The compiler takes {@see ResolvedTheme}, whose values are
 * {@see Values\TokenValue} objects. It has no method that accepts a string, so
 * there is no path by which a stored byte reaches a stylesheet unparsed. That
 * is also why the property **names** are derived from the registry
 * ({@see BrandingToken::customProperty()}) rather than taken from the theme's
 * own keys: a token name is validated against a closed registry, so a name in
 * the output cannot be a name a tenant chose.
 *
 * ## The dark block
 *
 * Emitted under two selectors, which is the arrangement that makes a scheme
 * default and a reader's own preference compose:
 *
 * - `@media (prefers-color-scheme: dark)` guarded by `:root:not([data-docup-scheme="light"])`
 * - `:root[data-docup-scheme="dark"]`
 *
 * So a reader whose system is dark gets dark unless the page says light, and a
 * page that says dark gets dark whatever the system says. The `scheme.default`
 * token decides which attribute chrome writes.
 */
final readonly class StylesheetCompiler
{
    /**
     * @param  array<string, ThemeAsset>  $fonts  asset id => row, for `@font-face`
     */
    public function __construct(private array $fonts = []) {}

    /**
     * Build the stylesheet for one resolved theme.
     *
     * The output is deterministic — token order is the registry's, not the
     * theme's — because the bytes are content-addressed and a stylesheet whose
     * declaration order varied would mint a new URL on every save.
     */
    public function compile(ResolvedTheme $theme): string
    {
        $lines = [
            '/* DocUp theme '.$theme->contentHash().' — generated; see SPEC 8.14.4. */',
        ];

        foreach ($this->fontFaces($theme) as $rule) {
            $lines[] = $rule;
        }

        $light = [];
        $dark = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if (! $token->type->emitsCss() || ! $theme->has($name)) {
                continue;
            }

            $pair = $theme->tokens[$name];
            $property = $token->customProperty();

            $light[] = sprintf('  %s: %s;', $property, $pair->light->serialise());

            /*
             * Only the properties that actually differ go in the dark block.
             * A dark block that restated all forty would be three times the
             * bytes for no behaviour, on a file every reader downloads.
             */
            if ($pair->differs()) {
                $dark[] = sprintf('  %s: %s;', $property, $pair->dark->serialise());
            }
        }

        $lines[] = ':root {';
        $lines[] = '  color-scheme: light dark;';
        foreach ($light as $declaration) {
            $lines[] = $declaration;
        }
        $lines[] = '}';

        if ($dark !== []) {
            $lines[] = '@media (prefers-color-scheme: dark) {';
            $lines[] = '  :root:not([data-docup-scheme="light"]) {';
            foreach ($dark as $declaration) {
                $lines[] = '  '.$declaration;
            }
            $lines[] = '  }';
            $lines[] = '}';

            $lines[] = ':root[data-docup-scheme="dark"] {';
            foreach ($dark as $declaration) {
                $lines[] = $declaration;
            }
            $lines[] = '}';
        }

        return implode("\n", $lines)."\n";
    }

    /**
     * `@font-face` for each uploaded font the theme names.
     *
     * 🛑 **The one place a URL appears in branding CSS, and it is DocUp's
     * own.** §8.14.2 forbids a remote font URL in a token value and
     * {@see FontStackValue} has no production that could express one; the font
     * is *named* there and bound to bytes here, from the asset row's content
     * hash. §8.14.10 requires `font-src 'self'`, so the path is relative and
     * resolves against whichever origin served the stylesheet — the dashboard
     * for the dashboard, the documentation host for documentation. A font
     * served from the asset host would need `font-src <asset-host>`, which
     * §8.14.10 deliberately does not grant: an image can be sandboxed on
     * another origin, and a font is parsed by the operating system.
     *
     * 🛑 `font-display: swap`, so a reader sees text in a fallback face rather
     * than nothing while the font loads. A branding token must not be able to
     * make the documentation unreadable for three seconds.
     *
     * @return list<string>
     */
    private function fontFaces(ResolvedTheme $theme): array
    {
        $rules = [];
        $seen = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->type !== TokenType::FontStack || ! $theme->has($name)) {
                continue;
            }

            foreach ([ColourScheme::Light, ColourScheme::Dark] as $scheme) {
                $value = $theme->value($name, $scheme);

                if (! $value instanceof FontStackValue) {
                    continue;
                }

                foreach ($value->entries as $entry) {
                    if ($entry->kind !== FontEntryKind::Asset || isset($seen[$entry->name])) {
                        continue;
                    }

                    $seen[$entry->name] = true;
                    $asset = $this->fonts[$entry->name] ?? null;

                    /*
                     * A named font with no row is skipped rather than emitted
                     * as a broken rule. The grammar refuses an unknown asset at
                     * write time, so this can only happen if the row was
                     * deleted after the theme was published — and a `@font-face`
                     * pointing at a 404 would make every reader wait for a
                     * timeout before the fallback rendered.
                     */
                    if (! $asset instanceof ThemeAsset) {
                        continue;
                    }

                    $rules[] = sprintf(
                        "@font-face {\n  font-family: \"%s\";\n  src: url(\"/_/theme/font/%s.woff2\") format(\"woff2\");\n  font-display: swap;\n}",
                        FontEntry::assetFamily($entry->name),
                        $asset->content_hash,
                    );
                }
            }
        }

        return $rules;
    }
}
