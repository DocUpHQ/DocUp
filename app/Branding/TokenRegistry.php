<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.1's closed registry: forty-five typed tokens, and no others.
 *
 * > "Branding MUST be a **closed registry of typed design tokens** cascading
 * > installation → organisation → project → domain mount, with per-path locking
 * > at any level, roughly 45 tokens defined in a table, plugin-extendable,
 * > **unknown keys rejected**."
 *
 * §17 makes this phase "where the list becomes real", so the list is here and
 * the operator documentation's table is rendered from it by
 * `php artisan docup:branding-table`. One source, two readers.
 *
 * ## 🛑 Closed means a key the registry does not define is refused
 *
 * Not ignored, not stored for later: refused, with
 * {@see TokenRejection::UnknownToken}. Phase 26b's build log records the same
 * choice being made about provider configuration and the reason it is the
 * right one — "a config key nothing reads is a key an operator believes is
 * doing something". A theme that silently dropped `colour.brand.primary`
 * (British spelling, wrong key) would be a theme that saved cleanly and
 * changed nothing, and the operator would go looking in the CSS.
 *
 * ## 🛑 Why the count matters
 *
 * "Roughly 45" is a budget, not a target. Every token is a column in the
 * operator's mental model, a row in the documentation table, a value the
 * §8.14.5 contrast gate may have to reason about, and a property the §8.15.9
 * Read the Docs mapping has to find a counterpart for. Forty-five covers
 * §8.14.7's enumerated surfaces; ninety would cover them twice and be
 * abandoned halfway through by every operator who met it.
 *
 * The honest trade is recorded where it was made: light and dark are **one**
 * token with two values ({@see BrandingToken::$dark}), not two tokens. Nineteen
 * paired colours would otherwise be thirty-eight entries, and §8.14.7's
 * "explicit pairs" would have been chosen for the wrong reason.
 *
 * ## 🛑 Plugin-extendable, and what that does not mean
 *
 * {@see self::extend()} admits further tokens at boot, which is what §8.14.1's
 * "plugin-extendable" asks for. It refuses a name the core registry already
 * holds and it refuses a name outside the `x-` prefix — so a plugin can add
 * `x-acme.callout.surface` and cannot redefine `color.text.primary`. A plugin
 * that could overwrite a core token could move the contrast gate's own inputs.
 *
 * ## What is deliberately absent
 *
 * - **Raw HTML of any kind.** §8.14.8 admits installation-scope raw head HTML
 *   behind an unsafe flag; it is not a token, it lives on
 *   {@see Chrome\ChromeContent} where the flag and the scope check are, and the
 *   registry stays safe by construction rather than by one exception.
 * - **Per-project custom CSS** (§8.14.9). §18.22's assumption — that a CSS
 *   parser exists which is "bounded in time and memory against malformed and
 *   deeply nested input" and whose "serialiser never re-emits constructs the
 *   filter dropped" — is unverified, and its pre-decided consequence is "Ship
 *   the token system alone. Custom CSS is off by default and is the only
 *   feature depending on it, so this is a feature drop, not a redesign."
 *   §17's Phase 27 deliverables do not name it. This is that drop, taken
 *   deliberately rather than by omission.
 */
final class TokenRegistry
{
    /** The prefix a plugin's token name must carry. */
    public const EXTENSION_PREFIX = 'x-';

    /**
     * Tokens added by a plugin at boot.
     *
     * @var array<string, BrandingToken>
     */
    private static array $extensions = [];

    /**
     * @var array<string, BrandingToken>|null
     */
    private static ?array $cache = null;

    /**
     * Every token, keyed by name, in documentation order.
     *
     * @return array<string, BrandingToken>
     */
    public static function all(): array
    {
        if (self::$cache === null) {
            $tokens = [];

            foreach (self::core() as $token) {
                $tokens[$token->name] = $token;
            }

            self::$cache = $tokens;
        }

        return [...self::$cache, ...self::$extensions];
    }

    /** Whether a name is in the registry. §8.14.1's "unknown keys rejected". */
    public static function has(string $name): bool
    {
        return array_key_exists($name, self::all());
    }

    /**
     * One token, or a refusal.
     *
     * @throws TokenRefused when the registry does not define `$name`
     */
    public static function get(string $name): BrandingToken
    {
        $token = self::all()[$name] ?? null;

        if (! $token instanceof BrandingToken) {
            throw TokenRefused::of(
                TokenRejection::UnknownToken,
                $name,
                'the branding registry is closed; see the token table in the operator guide',
            );
        }

        return $token;
    }

    /**
     * The names, in registry order.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::all());
    }

    /**
     * The tokens of one group, for the documentation table.
     *
     * @return list<BrandingToken>
     */
    public static function group(string $group): array
    {
        return array_values(array_filter(
            self::all(),
            static fn (BrandingToken $token): bool => $token->group === $group,
        ));
    }

    /**
     * The groups, in registry order.
     *
     * @return list<string>
     */
    public static function groups(): array
    {
        $groups = [];

        foreach (self::all() as $token) {
            if (! in_array($token->group, $groups, true)) {
                $groups[] = $token->group;
            }
        }

        return $groups;
    }

    /**
     * Register a plugin's token.
     *
     * @throws TokenRefused when the name collides with a core token or lacks
     *                      the {@see self::EXTENSION_PREFIX}
     */
    public static function extend(BrandingToken $token): void
    {
        if (! str_starts_with($token->name, self::EXTENSION_PREFIX)) {
            throw TokenRefused::of(
                TokenRejection::UnknownToken,
                $token->name,
                'a plugin token name must begin with '.self::EXTENSION_PREFIX,
            );
        }

        if (array_key_exists($token->name, self::$cache ?? self::all())) {
            throw TokenRefused::of(TokenRejection::UnknownToken, $token->name, 'already defined by the core registry');
        }

        self::$extensions[$token->name] = $token;
    }

    /** For tests: forget plugin tokens. */
    public static function forgetExtensions(): void
    {
        self::$extensions = [];
    }

    /**
     * The forty-five.
     *
     * 🛑 **The defaults are a theme that passes §8.14.5's own gate**, asserted
     * by `DefaultThemeContrastTest`. A shipped default that only warned would
     * teach every operator that the warning is decoration — the same failure
     * ADR 0002 names for injection warnings, where "every Antora site warns on
     * every build forever and operators learn to ignore injection warnings".
     *
     * @return list<BrandingToken>
     */
    private static function core(): array
    {
        return [
            // ── Identity ─────────────────────────────────────────────────────
            new BrandingToken(
                name: 'brand.name',
                type: TokenType::Text,
                group: 'Identity',
                default: 'DocUp',
                purpose: 'The wordmark, used wherever no logo asset is set and as the logo’s alt text.',
                maxLength: 60,
            ),
            new BrandingToken(
                name: 'asset.logo',
                type: TokenType::Asset,
                group: 'Identity',
                default: '',
                purpose: 'The light-scheme logo. Rendered via `<img src>` from the asset host (§8.14.11).',
                assetKind: 'logo',
            ),
            new BrandingToken(
                name: 'asset.logo.dark',
                type: TokenType::Asset,
                group: 'Identity',
                default: '',
                purpose: 'The dark-scheme logo. Falls back to `asset.logo` when unset.',
                assetKind: 'logo',
            ),
            new BrandingToken(
                name: 'asset.favicon',
                type: TokenType::Asset,
                group: 'Identity',
                default: '',
                purpose: 'The favicon, re-encoded to PNG at ingest.',
                assetKind: 'favicon',
            ),
            new BrandingToken(
                name: 'asset.social.card',
                type: TokenType::Asset,
                group: 'Identity',
                default: '',
                purpose: 'The Open Graph and social card image (§8.14.7).',
                assetKind: 'social_card',
            ),

            // ── Surfaces ─────────────────────────────────────────────────────
            new BrandingToken(
                name: 'color.surface.page',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#ffffff',
                dark: '#0b0e14',
                purpose: 'The page background, and the backdrop every text pair in the contrast matrix is judged against.',
            ),
            new BrandingToken(
                name: 'color.surface.raised',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#f6f7f9',
                dark: '#141a23',
                purpose: 'Cards, the header and the flyout.',
            ),
            new BrandingToken(
                name: 'color.surface.sunken',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#eceef2',
                dark: '#05080c',
                purpose: 'Wells and inset regions.',
            ),
            new BrandingToken(
                name: 'color.border.subtle',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#dfe3e8',
                dark: '#242c38',
                purpose: 'Dividers that separate without being seen.',
            ),
            new BrandingToken(
                name: 'color.border.strong',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#8b93a1',
                dark: '#5d6878',
                purpose: 'Control outlines. Judged as a non-text pair at WCAG 1.4.11’s 3:1.',
            ),
            new BrandingToken(
                name: 'color.focus.ring',
                type: TokenType::Colour,
                group: 'Surfaces',
                default: '#0b5cd5',
                dark: '#79b8ff',
                purpose: '🛑 The focus indicator. §9.5’s WCAG 2.2 AA posture makes this a requirement, not a preference.',
            ),

            // ── Text ─────────────────────────────────────────────────────────
            new BrandingToken(
                name: 'color.text.primary',
                type: TokenType::Colour,
                group: 'Text',
                default: '#16191f',
                dark: '#e7eaf0',
                purpose: 'Body copy.',
            ),
            new BrandingToken(
                name: 'color.text.secondary',
                type: TokenType::Colour,
                group: 'Text',
                default: '#4b5563',
                dark: '#a9b2c1',
                purpose: 'Metadata and captions. Still held to 4.5:1 — small text is where a muted palette fails readers.',
            ),
            new BrandingToken(
                name: 'color.text.inverse',
                type: TokenType::Colour,
                group: 'Text',
                default: '#ffffff',
                dark: '#0b0e14',
                purpose: 'Text on an accent fill.',
            ),
            new BrandingToken(
                name: 'color.text.link',
                type: TokenType::Colour,
                group: 'Text',
                default: '#0b5cd5',
                dark: '#79b8ff',
                purpose: 'Links in chrome.',
            ),

            // ── Brand and state ──────────────────────────────────────────────
            new BrandingToken(
                name: 'color.brand.primary',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#0b5cd5',
                dark: '#4d93ff',
                purpose: 'Primary fills and the active state.',
            ),
            new BrandingToken(
                name: 'color.brand.on-primary',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#ffffff',
                dark: '#06111f',
                purpose: 'Text on `color.brand.primary`. Its own token because deriving it is how a button ends up unreadable.',
            ),
            new BrandingToken(
                name: 'color.brand.accent',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#a21f6b',
                dark: '#f58ac2',
                purpose: 'The secondary brand fill.',
            ),
            new BrandingToken(
                name: 'color.state.success',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#0f6b35',
                dark: '#5bd98d',
                purpose: 'A build that passed, a verified domain.',
            ),
            new BrandingToken(
                name: 'color.state.warning',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#8a4b00',
                dark: '#e8a33d',
                purpose: 'A degraded binding, a stale version notice.',
            ),
            new BrandingToken(
                name: 'color.state.danger',
                type: TokenType::Colour,
                group: 'Brand and state',
                default: '#b3261e',
                dark: '#ff8f85',
                purpose: 'A failed build, a refusal.',
            ),

            // ── Code ─────────────────────────────────────────────────────────
            new BrandingToken(
                name: 'color.code.surface',
                type: TokenType::Colour,
                group: 'Code',
                default: '#f3f4f6',
                dark: '#10151d',
                purpose: 'The background of chrome’s own code spans. A generator styles its own blocks.',
            ),
            new BrandingToken(
                name: 'color.code.text',
                type: TokenType::Colour,
                group: 'Code',
                default: '#16191f',
                dark: '#e7eaf0',
                purpose: 'Monospace text on `color.code.surface`.',
            ),

            // ── Typography ───────────────────────────────────────────────────
            new BrandingToken(
                name: 'font.body',
                type: TokenType::FontStack,
                group: 'Typography',
                default: 'system-ui, sans-serif',
                purpose: 'Body text. 🛑 Catalogue names or `asset:<id>` only — DocUp never fetches a remote font (§8.14.2).',
            ),
            new BrandingToken(
                name: 'font.heading',
                type: TokenType::FontStack,
                group: 'Typography',
                default: 'system-ui, sans-serif',
                purpose: 'Headings.',
            ),
            new BrandingToken(
                name: 'font.mono',
                type: TokenType::FontStack,
                group: 'Typography',
                default: 'ui-monospace, monospace',
                purpose: 'Code and identifiers.',
            ),
            new BrandingToken(
                name: 'font.size.root',
                type: TokenType::Length,
                group: 'Typography',
                default: '16px',
                purpose: 'The root font size every `rem` is relative to.',
                minimum: 12,
                maximum: 24,
            ),
            new BrandingToken(
                name: 'font.weight.heading',
                type: TokenType::Count,
                group: 'Typography',
                default: '650',
                purpose: 'Heading weight, as a variable-font axis value.',
                minimum: 100,
                maximum: 900,
            ),
            new BrandingToken(
                name: 'font.line-height.body',
                type: TokenType::Ratio,
                group: 'Typography',
                default: '1.6',
                purpose: '🛑 Unitless, so it scales when a reader enlarges the text (WCAG 2.2 SC 1.4.12).',
                minimum: 1.0,
                maximum: 2.5,
            ),

            // ── Shape and space ──────────────────────────────────────────────
            new BrandingToken(
                name: 'radius.small',
                type: TokenType::Length,
                group: 'Shape and space',
                default: '4px',
                purpose: 'Inputs, badges and tags.',
                minimum: 0,
                maximum: 24,
            ),
            new BrandingToken(
                name: 'radius.medium',
                type: TokenType::Length,
                group: 'Shape and space',
                default: '8px',
                purpose: 'Cards, the flyout and modals.',
                minimum: 0,
                maximum: 48,
            ),
            new BrandingToken(
                name: 'space.unit',
                type: TokenType::Length,
                group: 'Shape and space',
                default: '4px',
                purpose: 'The spacing step every chrome gap is a multiple of.',
                minimum: 2,
                maximum: 16,
            ),
            new BrandingToken(
                name: 'border.width',
                type: TokenType::Length,
                group: 'Shape and space',
                default: '1px',
                purpose: 'Default border thickness.',
                minimum: 0,
                maximum: 8,
            ),

            // ── Layout and chrome ────────────────────────────────────────────
            new BrandingToken(
                name: 'layout.content.width',
                type: TokenType::Length,
                group: 'Layout and chrome',
                default: '48rem',
                purpose: 'The measure chrome’s own text columns are capped at.',
                minimum: 20,
                maximum: 120,
            ),
            new BrandingToken(
                name: 'layout.sidebar.width',
                type: TokenType::Length,
                group: 'Layout and chrome',
                default: '18rem',
                purpose: 'The navigation column’s width.',
                minimum: 10,
                maximum: 32,
            ),
            new BrandingToken(
                name: 'chrome.header.style',
                type: TokenType::Option,
                group: 'Layout and chrome',
                default: 'bordered',
                purpose: 'How the header separates from the page.',
                options: ['solid', 'bordered', 'transparent'],
            ),
            new BrandingToken(
                name: 'chrome.header.sticky',
                type: TokenType::Flag,
                group: 'Layout and chrome',
                default: 'true',
                purpose: 'Whether the header stays on screen while the reader scrolls.',
            ),
            new BrandingToken(
                name: 'chrome.sidebar.position',
                type: TokenType::Option,
                group: 'Layout and chrome',
                default: 'start',
                purpose: '🛑 `start`/`end`, not left/right, because §9.5 requires RTL and the sides swap.',
                options: ['start', 'end', 'none'],
            ),
            new BrandingToken(
                name: 'chrome.footer.style',
                type: TokenType::Option,
                group: 'Layout and chrome',
                default: 'bordered',
                purpose: 'How the footer separates from the page (§8.14.7).',
                options: ['solid', 'bordered', 'minimal'],
            ),
            new BrandingToken(
                name: 'chrome.density',
                type: TokenType::Option,
                group: 'Layout and chrome',
                default: 'comfortable',
                purpose: 'The spacing multiplier chrome applies to `space.unit`.',
                options: ['comfortable', 'compact'],
            ),

            // ── Scheme and behaviour ─────────────────────────────────────────
            new BrandingToken(
                name: 'scheme.default',
                type: TokenType::Option,
                group: 'Scheme and behaviour',
                default: 'system',
                deepest: CascadeLevel::Version,
                purpose: '🛑 One of the two things §8.14.1 lets a **version** set. Reconciled with `prefers-color-scheme` per §8.15.8.',
                options: ['light', 'dark', 'system'],
            ),
            new BrandingToken(
                name: 'scheme.toggle',
                type: TokenType::Flag,
                group: 'Scheme and behaviour',
                default: 'true',
                purpose: 'Whether chrome offers the reader a scheme switch.',
            ),
            new BrandingToken(
                name: 'motion.allow',
                type: TokenType::Flag,
                group: 'Scheme and behaviour',
                default: 'true',
                purpose: 'False suppresses chrome animation for every reader. `prefers-reduced-motion` is honoured regardless (§8.15.8).',
            ),
            new BrandingToken(
                name: 'banner.text',
                type: TokenType::Text,
                group: 'Scheme and behaviour',
                default: '',
                deepest: CascadeLevel::Version,
                purpose: '🛑 The other thing §8.14.1 lets a version set. Plain text; §8.14.3’s inline allowlist is for the announcement, not here.',
                maxLength: 160,
            ),
            new BrandingToken(
                name: 'banner.tone',
                type: TokenType::Option,
                group: 'Scheme and behaviour',
                default: 'notice',
                deepest: CascadeLevel::Version,
                purpose: 'Which state colour the banner takes.',
                options: ['notice', 'warning', 'danger'],
            ),

            // ── Security ─────────────────────────────────────────────────────
            new BrandingToken(
                name: 'security.frame-ancestors',
                type: TokenType::OriginList,
                group: 'Security',
                default: "'self'",
                deepest: CascadeLevel::Project,
                purpose: "🛑 §8.14.16: per project, defaults to `'self'`, an explicit allowlist, never a wildcard.",
            ),
        ];
    }
}
