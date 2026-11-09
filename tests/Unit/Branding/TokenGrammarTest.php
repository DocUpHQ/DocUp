<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Branding;

use App\Branding\AssetLookup;
use App\Branding\BrandingToken;
use App\Branding\CascadeLevel;
use App\Branding\TokenGrammar;
use App\Branding\TokenRefused;
use App\Branding\TokenRegistry;
use App\Branding\TokenRejection;
use App\Branding\TokenType;
use App\Branding\Values\ColourValue;
use App\Branding\Values\FontEntry;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.14.2's grammar, and §17's third exit criterion.
 *
 * > "A token value containing `url(`, `var(`, `calc(` or `expression(` is
 * > rejected by the grammar."
 *
 * Pure: a grammar is a function from text to a value or a refusal, and both
 * sides of that are decided before anything touches a database. The asset
 * lookup is the one collaborator and it is an interface for exactly this
 * reason — a colour parser whose tests need a migration is a colour parser
 * with fewer tests.
 */
final class TokenGrammarTest extends TestCase
{
    private TokenGrammar $grammar;

    protected function setUp(): void
    {
        parent::setUp();

        $this->grammar = new TokenGrammar(
            new class implements AssetLookup
            {
                public function kindOf(string $assetId): ?string
                {
                    return match ($assetId) {
                        '018f0000-0000-7000-8000-000000000001' => 'logo',
                        '018f0000-0000-7000-8000-000000000002' => 'font',
                        default => null,
                    };
                }
            },
            ['Instrument Sans'],
        );
    }

    /**
     * 🛑 §17's exit criterion, one case per named function plus `expression(`.
     *
     * Asserted against {@see TokenRejection::ForbiddenFunction} and not merely
     * "something threw": a value refused as a typo would satisfy a weaker
     * assertion, and then the criterion would be testing luck rather than the
     * control.
     *
     * @param  non-empty-string  $value
     */
    #[DataProvider('forbiddenFunctionValues')]
    public function test_a_forbidden_function_is_refused_by_the_grammar(string $value): void
    {
        $token = TokenRegistry::get('color.brand.primary');

        try {
            $this->grammar->value($token, $value);
            $this->fail('the grammar accepted '.$value);
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::ForbiddenFunction, $refused->rejection, $value);
        }
    }

    /** @return iterable<string, array{string}> */
    public static function forbiddenFunctionValues(): iterable
    {
        yield 'url' => ['url(https://evil.example/x.png)'];
        yield 'var' => ['var(--docup-color-text-primary)'];
        yield 'calc' => ['calc(100% - 2px)'];
        yield 'expression' => ['expression(alert(1))'];
        yield 'env' => ['env(safe-area-inset-top)'];
        yield 'attr' => ['attr(data-colour)'];

        /*
         * 🛑 The evasions. Each of these would defeat a fixed-string search
         * for `url(` and none of them defeats the detector, which is the
         * difference §8.14.2 is drawing between a grammar and a filter.
         */
        yield 'whitespace before the parenthesis' => ['url (https://evil.example/x.png)'];
        yield 'mixed case' => ['UrL(https://evil.example/x.png)'];
        yield 'a CSS escape spelling url' => ['\\75 rl(https://evil.example/x.png)'];
        yield 'a comment splitting the name' => ['u/*x*/rl(https://evil.example/x.png)'];
        yield 'nested inside an accepted function' => ['rgb(var(--x) 0 0)'];
    }

    /**
     * And every accepted colour notation round-trips.
     *
     * The assertion is on the **re-serialised** output rather than on
     * "no exception", because §8.14.2's second clause is the one a test can
     * most easily miss: a parser that accepted the value and then echoed the
     * input would pass a test that only checked for a refusal.
     *
     * @param  non-empty-string  $authored
     * @param  non-empty-string  $expected
     */
    #[DataProvider('acceptedColours')]
    public function test_an_accepted_colour_is_re_serialised_from_its_components(string $authored, string $expected): void
    {
        $value = $this->grammar->value(TokenRegistry::get('color.brand.primary'), $authored);

        $this->assertInstanceOf(ColourValue::class, $value);
        $this->assertSame($expected, $value->serialise());
    }

    /** @return iterable<string, array{string, string}> */
    public static function acceptedColours(): iterable
    {
        yield 'short hex expands and lowercases' => ['#FFF', '#ffffff'];
        yield 'long hex lowercases' => ['#0B5CD5', '#0b5cd5'];
        yield 'hex with alpha keeps it' => ['#0b5cd580', '#0b5cd580'];
        yield 'legacy rgb becomes modern' => ['rgb(11, 92, 213)', 'rgb(11 92 213)'];
        yield 'modern rgb with alpha' => ['rgb(11 92 213 / 0.5)', 'rgb(11 92 213 / 0.5)'];
        yield 'rgb percentages become channels' => ['rgb(100%, 0%, 0%)', 'rgb(255 0 0)'];
        yield 'hsl keeps its units' => ['hsl(217, 90%, 44%)', 'hsl(217 90% 44%)'];
        yield 'oklch keeps its notation' => ['oklch(62% 0.21 29)', 'oklch(0.62 0.21 29)'];
        yield 'oklch with a unit lightness' => ['oklch(0.62 0.21 29)', 'oklch(0.62 0.21 29)'];
    }

    /** 🛑 §8.14.1: "unknown keys rejected" — not ignored, not stored. */
    public function test_an_unknown_token_name_is_refused(): void
    {
        $this->expectException(TokenRefused::class);

        /* The British spelling, which is the mistake this will actually meet. */
        $this->grammar->parseAll(['colour.brand.primary' => '#fff'], CascadeLevel::Project);
    }

    public function test_an_unknown_token_names_the_right_rejection(): void
    {
        try {
            $this->grammar->parseAll(['colour.brand.primary' => '#fff'], CascadeLevel::Project);
            $this->fail('an unknown key was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::UnknownToken, $refused->rejection);
            $this->assertSame('colour.brand.primary', $refused->path);
        }
    }

    /**
     * 🛑 §8.14.1: "Version scope is limited to colour-scheme default and a
     * banner."
     *
     * Asserted from both sides, because a one-sided test would pass if the
     * depth check were inverted.
     */
    public function test_a_version_may_set_only_the_scheme_default_and_the_banner(): void
    {
        $allowed = $this->grammar->parseAll([
            'scheme.default' => 'dark',
            'banner.text' => 'This version is in maintenance.',
            'banner.tone' => 'warning',
        ], CascadeLevel::Version);

        $this->assertCount(3, $allowed);

        try {
            $this->grammar->parseAll(['color.brand.primary' => '#fff'], CascadeLevel::Version);
            $this->fail('a version set a colour token');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::ScopeTooDeep, $refused->rejection);
        }
    }

    /** 🛑 §8.14.16: `frame-ancestors` is per project, so a mount may not set it. */
    public function test_frame_ancestors_stops_at_project_scope(): void
    {
        $this->grammar->parseAll(['security.frame-ancestors' => "'self'"], CascadeLevel::Project);

        try {
            $this->grammar->parseAll(['security.frame-ancestors' => "'none'"], CascadeLevel::Mount);
            $this->fail('a mount set frame-ancestors');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::ScopeTooDeep, $refused->rejection);
        }
    }

    /** 🛑 §8.14.16: "never `*`", including a subdomain wildcard. */
    public function test_a_wildcard_frame_ancestor_is_refused(): void
    {
        foreach (['*', 'https://*.example.com', "'self' *"] as $value) {
            try {
                $this->grammar->value(TokenRegistry::get('security.frame-ancestors'), $value);
                $this->fail('accepted '.$value);
            } catch (TokenRefused $refused) {
                $this->assertSame(TokenRejection::WildcardOrigin, $refused->rejection, $value);
            }
        }
    }

    /** 🛑 §8.14.2: "no remote font URL ever". */
    public function test_a_remote_font_reference_is_refused_as_remote(): void
    {
        foreach ([
            'https://fonts.googleapis.com/css2?family=Inter',
            '//fonts.example/inter.woff2',
            'fonts.example',
        ] as $value) {
            try {
                $this->grammar->value(TokenRegistry::get('font.body'), $value);
                $this->fail('accepted '.$value);
            } catch (TokenRefused $refused) {
                $this->assertSame(TokenRejection::RemoteFontReference, $refused->rejection, $value);
            }
        }
    }

    /**
     * An uploaded font is named in CSS, never addressed.
     *
     * The serialised stack carries DocUp's own minted family name; the
     * `@font-face` that binds it to bytes is the stylesheet's, which is the
     * only place a URL exists.
     */
    public function test_an_uploaded_font_serialises_as_a_minted_family_name(): void
    {
        $value = $this->grammar->value(
            TokenRegistry::get('font.body'),
            'asset:018f0000-0000-7000-8000-000000000002, sans-serif',
        );

        $this->assertSame(
            '"'.FontEntry::assetFamily('018f0000-0000-7000-8000-000000000002').'", sans-serif',
            $value->serialise(),
        );
        $this->assertStringNotContainsString('http', $value->serialise());
        $this->assertStringNotContainsString('url', $value->serialise());
    }

    /** An asset of the wrong kind is refused, and says so. */
    public function test_an_asset_token_refuses_the_wrong_kind(): void
    {
        try {
            $this->grammar->value(
                TokenRegistry::get('asset.logo'),
                '018f0000-0000-7000-8000-000000000002',
            );
            $this->fail('a font was accepted as a logo');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::WrongAssetKind, $refused->rejection);
        }
    }

    /**
     * 🛑 An asset this writer cannot see is {@see TokenRejection::UnknownAsset},
     * which is §8.2.2's 404-never-403 applied to a token value: "not yours" and
     * "no such row" are one answer.
     */
    public function test_an_invisible_asset_is_indistinguishable_from_a_missing_one(): void
    {
        try {
            $this->grammar->value(
                TokenRegistry::get('asset.logo'),
                '018f0000-0000-7000-8000-00000000ffff',
            );
            $this->fail('an invisible asset was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::UnknownAsset, $refused->rejection);
        }
    }

    /** A length outside the registry's clamp is refused rather than clamped. */
    public function test_a_length_outside_its_clamp_is_refused_not_clamped(): void
    {
        try {
            $this->grammar->value(TokenRegistry::get('font.size.root'), '400px');
            $this->fail('a 400px root font size was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::NumericOutOfRange, $refused->rejection);
        }
    }

    /** And a unit outside the allowlist names the unit, not the number. */
    public function test_a_viewport_unit_is_refused_as_a_unit(): void
    {
        try {
            $this->grammar->value(TokenRegistry::get('layout.sidebar.width'), '20vw');
            $this->fail('a viewport unit was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::DisallowedUnit, $refused->rejection);
        }
    }

    /**
     * 🛑 §8.14.3: chrome content is structured data, "never free HTML" — so a
     * text token carrying an angle bracket is refused at the grammar rather
     * than escaped at the renderer.
     */
    public function test_a_text_token_refuses_markup(): void
    {
        try {
            $this->grammar->value(TokenRegistry::get('brand.name'), '<script>alert(1)</script>');
            $this->fail('markup was accepted in a text token');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::MarkupRefused, $refused->rejection);
        }
    }

    /** A bidirectional override cannot escape a wordmark into DocUp's own chrome. */
    public function test_a_text_token_refuses_a_bidi_override(): void
    {
        try {
            $this->grammar->value(TokenRegistry::get('brand.name'), "ACME\u{202E} reversed");
            $this->fail('a bidi override was accepted');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::TextRefused, $refused->rejection);
        }
    }

    /**
     * 🛑 A paired token overrides as a pair.
     *
     * Half a pair is the failure this prevents: inheriting dark from the
     * installation while light comes from a project produces a scheme nobody
     * designed, and §8.14.5's gate would be judging two levels' palettes
     * spliced together.
     */
    public function test_a_paired_colour_takes_both_schemes_or_one_value_for_both(): void
    {
        $both = $this->grammar->parseAll([
            'color.surface.page' => ['light' => '#ffffff', 'dark' => '#000000'],
        ], CascadeLevel::Project);

        $this->assertSame('#ffffff', $both['color.surface.page']->light->serialise());
        $this->assertSame('#000000', $both['color.surface.page']->dark->serialise());

        $one = $this->grammar->parseAll([
            'color.brand.primary' => '#0b5cd5',
        ], CascadeLevel::Project);

        $this->assertSame('#0b5cd5', $one['color.brand.primary']->light->serialise());
        $this->assertSame('#0b5cd5', $one['color.brand.primary']->dark->serialise());
        $this->assertFalse($one['color.brand.primary']->differs());
    }

    /** A misspelled key inside a pair is refused, not silently dropped. */
    public function test_an_unknown_key_inside_a_pair_is_refused(): void
    {
        $this->expectException(TokenRefused::class);

        $this->grammar->parseAll([
            'color.surface.page' => ['light' => '#ffffff', 'ligth' => '#000000'],
        ], CascadeLevel::Project);
    }

    /** An unpaired token given a pair is refused. */
    public function test_an_unpaired_token_refuses_a_pair(): void
    {
        $this->expectException(TokenRefused::class);

        $this->grammar->parseAll([
            'font.body' => ['light' => 'sans-serif', 'dark' => 'serif'],
        ], CascadeLevel::Project);
    }

    /**
     * 🛑 Every registry default satisfies its own grammar.
     *
     * A default that did not would be a theme that could not be edited: the
     * first save re-parses the inherited values and refuses.
     */
    public function test_every_registry_default_parses(): void
    {
        $defaults = $this->grammar->defaults();

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->type === TokenType::Asset || ($token->type === TokenType::Text && $token->default === '')) {
                $this->assertArrayNotHasKey($name, $defaults, $name.' has no default and should be absent');

                continue;
            }

            $this->assertArrayHasKey($name, $defaults, $name);
            $this->assertNotSame('', $defaults[$name]->light->serialise(), $name);
        }
    }

    /** A plugin may add a token and may not redefine one. */
    public function test_a_plugin_token_must_be_prefixed_and_may_not_collide(): void
    {
        TokenRegistry::forgetExtensions();

        TokenRegistry::extend(new BrandingToken(
            name: 'x-acme.callout.surface',
            type: TokenType::Colour,
            group: 'ACME',
            default: '#eef6ff',
            dark: '#0d1b2a',
        ));

        $this->assertTrue(TokenRegistry::has('x-acme.callout.surface'));

        try {
            TokenRegistry::extend(new BrandingToken(
                name: 'color.text.primary',
                type: TokenType::Colour,
                group: 'ACME',
                default: '#ff0000',
            ));
            $this->fail('a plugin redefined a core token');
        } catch (TokenRefused) {
            // expected
        } finally {
            TokenRegistry::forgetExtensions();
        }
    }
}
