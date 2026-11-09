<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Branding;

use App\Branding\AssetLookup;
use App\Branding\CascadeLevel;
use App\Branding\ColourScheme;
use App\Branding\StylesheetCompiler;
use App\Branding\ThemeCascade;
use App\Branding\ThemeLayer;
use App\Branding\ThemeLocks;
use App\Branding\Themes;
use App\Branding\TokenGrammar;
use App\Branding\TokenRefused;
use App\Branding\TokenRegistry;
use App\Branding\TokenRejection;
use App\Branding\TokenType;
use PHPUnit\Framework\TestCase;

/**
 * §8.14.1's cascade and §8.14.4's stylesheet, as functions.
 *
 * 🛑 **The positive paths.** `BrandingCorpusTest` drives the hostile input and
 * `ThemePublishTest` drives the rows; what is here is that the cascade actually
 * resolves and that the stylesheet actually says what the tokens say — which no
 * refusal test can show. A cascade that refused everything would pass every
 * adversarial test in the suite.
 */
final class ThemeCascadeTest extends TestCase
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
                    return null;
                }
            },
            [],
        );
    }

    /** 🛑 The deepest level that set a token wins. */
    public function test_the_deepest_level_wins(): void
    {
        $resolved = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Installation, ['color.brand.primary' => '#111111']),
            $this->layer(CascadeLevel::Organisation, ['color.brand.primary' => '#222222']),
            $this->layer(CascadeLevel::Project, ['color.brand.primary' => '#333333']),
            $this->layer(CascadeLevel::Mount, ['color.brand.primary' => '#444444']),
        ]);

        $this->assertSame('#444444', $resolved->serialised('color.brand.primary'));
        $this->assertSame(CascadeLevel::Mount, $resolved->origin('color.brand.primary'));
    }

    /**
     * 🛑 The layers are sorted here, not by the caller.
     *
     * {@see Themes} assembles them in whatever order the rows
     * come back, so a cascade that depended on the array's order would resolve
     * differently depending on a query plan.
     */
    public function test_the_order_the_layers_arrive_in_does_not_matter(): void
    {
        $forwards = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Installation, ['radius.small' => '2px']),
            $this->layer(CascadeLevel::Project, ['radius.small' => '8px']),
        ]);

        $backwards = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Project, ['radius.small' => '8px']),
            $this->layer(CascadeLevel::Installation, ['radius.small' => '2px']),
        ]);

        $this->assertSame('8px', $forwards->serialised('radius.small'));
        $this->assertSame($forwards->contentHash(), $backwards->contentHash());
    }

    /** A token nobody overrode keeps the installation's value and says so. */
    public function test_an_untouched_token_reports_its_origin_as_the_installation(): void
    {
        $resolved = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, ['radius.small' => '8px']),
        ]);

        $this->assertSame(CascadeLevel::Installation, $resolved->origin('font.body'));
        $this->assertSame(CascadeLevel::Project, $resolved->origin('radius.small'));
    }

    /** 🛑 §8.14.1's lock drops a deeper value already stored. */
    public function test_a_shallower_lock_drops_a_deeper_value(): void
    {
        $resolved = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Organisation, ['color.brand.primary' => '#222222'], ['color.brand.primary']),
            $this->layer(CascadeLevel::Project, ['color.brand.primary' => '#333333']),
        ]);

        $this->assertSame('#222222', $resolved->serialised('color.brand.primary'));
        $this->assertSame(CascadeLevel::Organisation, $resolved->origin('color.brand.primary'));
        $this->assertTrue($resolved->locks->locks('color.brand.primary'));
    }

    /**
     * 🛑 And a level may lock a token **and set it** in the same revision.
     *
     * That is the normal case — "this is the brand colour and nobody below
     * changes it" — so a fold that merged a level's locks before its values
     * would make locking useless.
     */
    public function test_a_level_may_lock_a_token_it_sets_itself(): void
    {
        $resolved = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Installation, ['color.brand.primary' => '#111111']),
            $this->layer(CascadeLevel::Organisation, ['color.brand.primary' => '#222222'], ['color.brand.primary']),
        ]);

        $this->assertSame('#222222', $resolved->serialised('color.brand.primary'));
    }

    /** A lock declared deeper than a value does not reach back up. */
    public function test_a_deeper_lock_does_not_affect_a_shallower_value(): void
    {
        $resolved = ThemeCascade::resolve([
            $this->layer(CascadeLevel::Organisation, ['color.brand.primary' => '#222222']),
            $this->layer(CascadeLevel::Project, [], ['color.brand.primary']),
        ]);

        $this->assertSame('#222222', $resolved->serialised('color.brand.primary'));
        $this->assertTrue($resolved->locks->locks('color.brand.primary'));
    }

    /** 🛑 The write-time half refuses, with the path named. */
    public function test_the_write_check_refuses_a_locked_path(): void
    {
        $tokens = $this->grammar->parseAll(['color.brand.primary' => '#333333'], CascadeLevel::Project);

        try {
            ThemeCascade::assertWritable($tokens, ThemeLocks::fromAuthored(['color.brand.primary']), CascadeLevel::Project);
            $this->fail('a locked path was writable');
        } catch (TokenRefused $refused) {
            $this->assertSame(TokenRejection::PathLocked, $refused->rejection);
            $this->assertSame('color.brand.primary', $refused->path);
        }
    }

    /**
     * 🛑 §8.14.4's content address is over the **re-serialised** values.
     *
     * So two themes that typed `#FFF` and `#ffffff` are one theme and share one
     * stylesheet. Hashing the authored input would mint two URLs for identical
     * bytes, and the operator who corrected their capitalisation would
     * invalidate every reader's cache for nothing.
     */
    public function test_the_content_hash_is_over_the_serialised_values(): void
    {
        $short = ThemeCascade::resolve([$this->layer(CascadeLevel::Project, ['color.brand.primary' => '#FFF'])]);
        $long = ThemeCascade::resolve([$this->layer(CascadeLevel::Project, ['color.brand.primary' => '#ffffff'])]);

        $this->assertSame($short->contentHash(), $long->contentHash());

        $other = ThemeCascade::resolve([$this->layer(CascadeLevel::Project, ['color.brand.primary' => '#fffffe'])]);

        $this->assertNotSame($short->contentHash(), $other->contentHash());
    }

    /** The hash covers the dark value too, not only the light one. */
    public function test_the_content_hash_covers_both_schemes(): void
    {
        $one = ThemeCascade::resolve([$this->layer(CascadeLevel::Project, [
            'color.brand.primary' => ['light' => '#ffffff', 'dark' => '#000000'],
        ])]);

        $two = ThemeCascade::resolve([$this->layer(CascadeLevel::Project, [
            'color.brand.primary' => ['light' => '#ffffff', 'dark' => '#010101'],
        ])]);

        $this->assertNotSame($one->contentHash(), $two->contentHash());
    }

    // ------------------------------------------------------- the stylesheet

    /** 🛑 §8.14.4: the stylesheet says what the tokens say. */
    public function test_the_stylesheet_emits_every_css_token_as_a_custom_property(): void
    {
        $resolved = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, [
                'color.brand.primary' => ['light' => '#0f6b35', 'dark' => '#5bd98d'],
                'radius.medium' => '12px',
                'chrome.header.sticky' => 'false',
            ]),
        ]);

        $css = (new StylesheetCompiler)->compile($resolved);

        $this->assertStringContainsString(':root {', $css);
        $this->assertStringContainsString('--docup-color-brand-primary: #0f6b35;', $css);
        $this->assertStringContainsString('--docup-radius-medium: 12px;', $css);

        /* A flag emits 1/0, so a container-style query can test it numerically. */
        $this->assertStringContainsString('--docup-chrome-header-sticky: 0;', $css);

        /* Both dark selectors, so a scheme default and a reader preference compose. */
        $this->assertStringContainsString('@media (prefers-color-scheme: dark)', $css);
        $this->assertStringContainsString(':root:not([data-docup-scheme="light"])', $css);
        $this->assertStringContainsString(':root[data-docup-scheme="dark"]', $css);
        $this->assertStringContainsString('--docup-color-brand-primary: #5bd98d;', $css);
    }

    /**
     * 🛑 Only the types {@see TokenType::emitsCss()} admits.
     *
     * A text token in a stylesheet would be tenant prose inside a declaration;
     * an asset token would be an identifier where a URL is expected, and
     * §8.14.11 renders an uploaded image only through `<img src>`.
     */
    public function test_the_stylesheet_omits_the_three_types_that_never_reach_css(): void
    {
        $resolved = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, ['brand.name' => 'Acme Docs']),
        ]);

        $css = (new StylesheetCompiler)->compile($resolved);

        $this->assertStringNotContainsString('Acme Docs', $css);
        $this->assertStringNotContainsString('--docup-brand-name', $css);
        $this->assertStringNotContainsString('--docup-asset-logo', $css);
        $this->assertStringNotContainsString('--docup-security-frame-ancestors', $css);
    }

    /**
     * 🛑 A token whose two schemes agree is emitted once.
     *
     * A dark block restating all forty would be three times the bytes for no
     * behaviour, on a file every reader downloads.
     */
    public function test_a_token_that_does_not_differ_is_not_restated_in_the_dark_block(): void
    {
        $resolved = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, ['radius.medium' => '12px']),
        ]);

        $css = (new StylesheetCompiler)->compile($resolved);

        $this->assertSame(1, substr_count($css, '--docup-radius-medium: 12px;'));
    }

    /** And the output is deterministic, because the URL is its hash. */
    public function test_the_stylesheet_is_deterministic(): void
    {
        $tokens = ['radius.small' => '3px', 'color.brand.primary' => '#0b5cd5', 'font.size.root' => '17px'];

        $first = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, $tokens),
        ]);

        $second = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
            $this->layer(CascadeLevel::Project, array_reverse($tokens, true)),
        ]);

        $compiler = new StylesheetCompiler;

        $this->assertSame($compiler->compile($first), $compiler->compile($second));
        $this->assertSame($first->contentHash(), $second->contentHash());
    }

    /** Every registry token resolves, so nothing downstream handles an absence. */
    public function test_the_defaults_resolve_every_token_that_has_one(): void
    {
        $resolved = ThemeCascade::resolve([
            new ThemeLayer(CascadeLevel::Installation, $this->grammar->defaults(), ThemeLocks::none()),
        ]);

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->default === '') {
                continue;
            }

            $this->assertTrue($resolved->has($name), $name.' did not resolve');
            $this->assertNotNull($resolved->serialised($name, ColourScheme::Dark), $name);
        }
    }

    /**
     * @param  array<string, mixed>  $tokens
     * @param  list<string>  $locks
     */
    private function layer(CascadeLevel $level, array $tokens, array $locks = []): ThemeLayer
    {
        return new ThemeLayer(
            $level,
            $this->grammar->parseAll($tokens, $level),
            ThemeLocks::fromAuthored($locks),
        );
    }
}
