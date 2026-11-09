<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\AssetReferenceValue;
use App\Branding\Values\ColourValue;
use App\Branding\Values\CountValue;
use App\Branding\Values\FlagValue;
use App\Branding\Values\FontStackValue;
use App\Branding\Values\LengthValue;
use App\Branding\Values\OptionValue;
use App\Branding\Values\OriginListValue;
use App\Branding\Values\RatioValue;
use App\Console\Commands\BrandingTableCommand;

/**
 * The types a branding token may have (§8.14.1's "**typed** design tokens").
 *
 * 🛑 **Ten types, each with exactly one parser.** The alternative — a `string`
 * column and validation at each write site — is what §8.14.2 is reacting to
 * when it says "Validation MUST be a **grammar, not a filter**": a filter is
 * per call site and a grammar is per type, and only one of those has a single
 * place to be wrong.
 *
 * 🛑 **{@see self::emitsCss()} is the containment boundary for the stylesheet.**
 * Three types never reach CSS, each for its own reason, and the stylesheet
 * writer takes only the types that say yes — so there is no path by which a
 * text token's bytes land in a stylesheet an operator's documentation loads.
 */
enum TokenType: string
{
    /** §8.14.2's colour grammar. {@see ColourValue} */
    case Colour = 'colour';

    /** §8.14.2's "clamped number plus an allowlisted unit". {@see LengthValue} */
    case Length = 'length';

    /** A bounded unitless number — a type scale, a line height. {@see RatioValue} */
    case Ratio = 'ratio';

    /** A bounded integer — a font weight. {@see CountValue} */
    case Count = 'count';

    /** A boolean. {@see FlagValue} */
    case Flag = 'flag';

    /** One value from the token's own closed option list. {@see OptionValue} */
    case Option = 'option';

    /**
     * Short plain text — a wordmark, a copyright line.
     *
     * 🛑 Never reaches CSS. A text token's value is reader-visible prose and
     * belongs in the JSON chrome payload, where the renderer escapes it for
     * HTML. Admitting it to a stylesheet would put tenant prose inside a
     * `content:` declaration, which is one unescaped quotation mark away from
     * ending the rule — and would also hide the text from a screen reader,
     * since generated content is not reliably announced.
     */
    case Text = 'text';

    /** §8.14.2's font grammar. {@see FontStackValue} */
    case FontStack = 'font_stack';

    /**
     * A reference to a `theme_assets` row. {@see AssetReferenceValue}
     *
     * 🛑 Never reaches CSS, because §8.14.11 renders an uploaded image "only
     * via `<img src>`". A `background-image` would defeat that: the asset host
     * sends `default-src 'none'; sandbox` precisely so the image is in its own
     * neutered context, and a CSS background pulls it into the documentation's.
     */
    case Asset = 'asset';

    /** §8.14.16's `frame-ancestors` allowlist. {@see OriginListValue} */
    case OriginList = 'origin_list';

    /**
     * Whether a value of this type may be emitted as a CSS custom property.
     *
     * 🛑 The whitelist direction. A type added later is **not** CSS-emittable
     * until somebody says so here, which is the correct default for a value
     * that arrives from a tenant.
     */
    public function emitsCss(): bool
    {
        return match ($this) {
            self::Colour, self::Length, self::Ratio, self::Count, self::Flag, self::Option, self::FontStack => true,
            self::Text, self::Asset, self::OriginList => false,
        };
    }

    /**
     * Whether {@see ForbiddenFunctions} runs over a value of this type.
     *
     * 🛑 **True for everything except {@see self::OriginList}, and that
     * exception is a category correction rather than a relaxation.**
     * `ForbiddenFunctions` refuses CSS comment delimiters, and every
     * `https://` URL contains the sequence `/*` — so running it over an origin
     * list refuses `https://*.example.com` as a *comment* and never reaches the
     * wildcard check that §8.14.16 actually cares about. The rejection would
     * name the wrong control, which is precisely the failure the detector
     * exists to avoid: a value refused for a reason nobody can act on.
     *
     * Nothing is lost. An origin list is a CSP header value and never a CSS
     * value, {@see self::emitsCss()} says so, and
     * {@see OriginListValue} is a closed grammar that
     * admits two keywords and a scheme-host-port production — which cannot
     * express a function call, a backslash or a comment, and which refuses
     * every wildcard before anything else.
     */
    public function refusesCssFunctions(): bool
    {
        return $this !== self::OriginList;
    }

    /**
     * A one-line grammar, for the operator documentation's table (§17).
     *
     * 🛑 Here rather than in the Markdown page, and
     * {@see BrandingTableCommand} renders the page from
     * it. A table maintained by hand beside a registry maintained in code is
     * two registries, and the documented one is the one that goes stale.
     */
    public function grammar(): string
    {
        return match ($this) {
            self::Colour => '`#rgb` / `#rrggbb` / `#rrggbbaa` / `rgb()` / `hsl()` / `oklch()`, bounded numerics',
            self::Length => 'a positive number in the token\'s range plus `px`, `rem`, `em`, `ch` or `%`; bare `0`',
            self::Ratio => 'a plain decimal in the token\'s range, no unit',
            self::Count => 'an integer in the token\'s range',
            self::Flag => '`true` or `false`',
            self::Option => 'one of the token\'s listed options',
            self::Text => 'plain text to the token\'s length; no angle brackets, control characters or bidi overrides',
            self::FontStack => 'comma-separated catalogue names, CSS generics or `asset:<id>`; no URL ever',
            self::Asset => 'a `theme_assets` id of the token\'s kind',
            self::OriginList => "`'self'`, `'none'` or `https://` origins; never a wildcard",
        };
    }
}
