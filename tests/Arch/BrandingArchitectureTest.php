<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Arch;

use App\Branding\CascadeLevel;
use App\Branding\Chrome\ChromeContent;
use App\Branding\CredentialPageBranding;
use App\Branding\StylesheetCompiler;
use App\Branding\ThemeDelivery;
use App\Branding\Themes;
use App\Branding\TokenGrammar;
use App\Branding\TokenRegistry;
use App\Branding\TokenType;
use PHPUnit\Framework\TestCase;

/**
 * §8.14's invariants, as architecture tests.
 *
 * Each of these is a rule that a correct implementation satisfies today and
 * that a later change could break without failing any behavioural test —
 * which is the only reason an architecture test earns its place. They run in
 * the `Arch` suite, which CLAUDE.md rule 5 makes one of the three that always
 * run however narrow the change.
 */
final class BrandingArchitectureTest extends TestCase
{
    /**
     * 🛑 §8.14.2: "Validation MUST be a **grammar, not a filter**" — and a
     * grammar with two call sites is a filter again.
     *
     * {@see TokenGrammar} is the only thing that may parse a branding value.
     * A controller that reached for `ColourValue::parse()` directly would skip
     * the registry lookup, the cascade-depth check and the asset resolution
     * that `TokenGrammar` runs first — and would do so in a way that looked
     * careful.
     */
    public function test_only_the_grammar_parses_a_branding_value(): void
    {
        /*
         * Allowlisted by path **and by which type**, so an exemption cannot be
         * claimed for more than it was granted for.
         */
        $permitted = [
            'app/Branding/TokenGrammar.php' => ['*'],
            /*
             * The value types call each other: a font stack builds entries, a
             * colour builds its own components. "Inside the grammar" rather
             * than "this file", so the exemption is the directory.
             */
            'app/Branding/Values/' => ['*'],
            /*
             * 🛑 §8.14.3's chrome labels reuse the **text** grammar, and only
             * that one. A navigation label is short plain text and refusing an
             * angle bracket in one is the same rule as refusing one in a
             * wordmark — so `ChromeContent` calls `ShortTextValue` rather than
             * carrying a second text grammar that would have to be kept in
             * step. It may not reach for a colour or an asset.
             */
            'app/Branding/Chrome/ChromeContent.php' => ['ShortTextValue::parse'],
        ];

        $types = [
            'ColourValue::parse', 'LengthValue::parse', 'RatioValue::parse',
            'CountValue::parse', 'FlagValue::parse', 'OptionValue::parse',
            'ShortTextValue::parse', 'FontStackValue::parse',
            'AssetReferenceValue::parse', 'OriginListValue::parse',
        ];

        $offenders = [];

        foreach (self::sourceFiles() as $relative => $source) {
            $allowed = [];

            foreach ($permitted as $path => $exemptions) {
                if (str_starts_with($relative, $path)) {
                    $allowed = $exemptions;
                }
            }

            if ($allowed === ['*']) {
                continue;
            }

            foreach ($types as $direct) {
                if (in_array($direct, $allowed, true)) {
                    continue;
                }

                if (str_contains($source, $direct)) {
                    $offenders[] = $relative.' calls '.$direct.'()';
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.14.2: one grammar, one call site — '.implode('; ', $offenders),
        );
    }

    /**
     * 🛑 §8.14.11: the pipeline is the only writer of `theme_assets`.
     *
     * A row in that table is a claim that DocUp re-encoded or sanitised the
     * bytes it addresses. A second writer would make the claim untrue without
     * changing a line of the pipeline — which is exactly the shape of defect
     * `provider-022` and `provider-023` were added to the corpus for.
     */
    public function test_only_the_asset_pipeline_writes_the_asset_table(): void
    {
        $permitted = [
            'app/Branding/Assets/AssetIntake.php',
            'database/migrations/2026_11_13_090000_create_branding_tables.php',
            'app/Models/ThemeAsset.php',
        ];

        $offenders = [];

        foreach (self::sourceFiles() as $relative => $source) {
            if (in_array($relative, $permitted, true)) {
                continue;
            }

            /*
             * 🛑 The needles are **write constructions**, not the class name.
             *
             * The first version of this test looked for `ThemeAsset;` and
             * `new ThemeAsset`, and flagged seven files that only imported the
             * model or constructed `ThemeAssets` — the lookup, whose name is
             * one character longer. An architecture test that fires on a `use`
             * statement is a test somebody adds to an allowlist rather than
             * reads, so the needles name the three ways a row is actually
             * written.
             */
            foreach ([
                'new ThemeAsset;',
                'new ThemeAsset(',
                'ThemeAsset::create',
                "table('theme_assets')->insert",
                "table('theme_assets')->update",
            ] as $write) {
                if (str_contains($source, $write)) {
                    $offenders[] = $relative.' writes theme_assets ('.$write.')';
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.14.11: one pipeline writes an asset row — '.implode('; ', $offenders),
        );
    }

    /**
     * 🛑 §8.14.12: no credential page may reach a tenant-scoped theme.
     *
     * > "Pages that accept credentials MUST carry **no project or organisation
     * > branding**."
     *
     * {@see CredentialPageBranding} takes no arguments, so the rule holds by
     * construction *for the pages that use it*. What this asserts is the other
     * half: that a credential page does not acquire a tenant theme by some
     * other route. The two files that render credential pages may name
     * `CredentialPageBranding` and may not name {@see ThemeDelivery} or
     * {@see Themes}.
     */
    public function test_no_credential_page_reaches_a_tenant_theme(): void
    {
        $credentialPages = [
            'app/Providers/FortifyServiceProvider.php',
            'app/Http/Controllers/Readers/LdapSignInController.php',
        ];

        $offenders = [];

        foreach (self::sourceFiles() as $relative => $source) {
            if (! in_array($relative, $credentialPages, true)) {
                continue;
            }

            foreach (['ThemeDelivery', 'Themes::', 'ThemeTarget', 'ThemeRevision'] as $tenantRoute) {
                if (str_contains($source, $tenantRoute)) {
                    $offenders[] = $relative.' names '.$tenantRoute;
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.14.12: a credential page resolves branding only through CredentialPageBranding — '
            .implode('; ', $offenders),
        );

        /*
         * 🛑 And the files really are what this test thinks they are, so a
         * rename does not quietly empty the assertion above.
         */
        foreach ($credentialPages as $page) {
            $this->assertStringContainsString(
                'CredentialPageBranding',
                (string) file_get_contents(self::root().'/'.$page),
                $page.' no longer renders a credential page, or no longer carries installation branding',
            );
        }
    }

    /**
     * 🛑 §8.14.8: tenant JavaScript below installation scope is permanently out
     * of scope, so there is no field for it.
     *
     * §17: "**Explicitly not in scope:** Tenant JavaScript at any scope below
     * installation — permanently out of scope (§8.14.8)."
     *
     * Asserted against the two places such a field could appear: a token type
     * whose grammar is raw markup, and a chrome content key. `head_html` is
     * the one admitted surface and it is installation-only behind §20.4's
     * flag; anything else named like a script surface is the thing this test
     * exists to catch.
     */
    public function test_no_token_type_admits_raw_markup_or_script(): void
    {
        foreach (TokenType::cases() as $type) {
            $this->assertNotContains(
                $type->value,
                ['html', 'raw_html', 'markup', 'script', 'javascript', 'css'],
                '§8.14.8: a token type named '.$type->value.' would be a raw surface in the closed registry',
            );
        }

        /*
         * And the chrome content key list, read from the class's own refusal
         * rather than from a copy: `parse()` names the closed set, so a key
         * added there is a key this test sees.
         */
        $source = (string) file_get_contents(self::root().'/app/Branding/Chrome/ChromeContent.php');

        $this->assertMatchesRegularExpression(
            "/\\['navigation', 'footer', 'announcement', 'homepage', 'head_html'\\]/",
            $source,
            '§8.14.3: the chrome content keys are a closed set; this test must be updated deliberately',
        );

        foreach (['tenant_js', 'custom_js', 'script_html', 'body_html', 'custom_css'] as $forbidden) {
            $this->assertStringNotContainsString(
                "'".$forbidden."'",
                $source,
                '§8.14.8: '.$forbidden.' would be a tenant code surface in chrome',
            );
        }
    }

    /**
     * 🛑 §8.14.2: no branding value can name a host, so no value type may
     * carry one.
     *
     * The grammar has no production that could emit a URL, and this is the
     * assertion that keeps it that way: a scheme literal inside
     * `App\Branding\Values` would mean somebody had begun to build one.
     */
    public function test_no_value_type_names_a_scheme_or_a_host(): void
    {
        $offenders = [];

        foreach (self::sourceFiles() as $relative => $source) {
            if (! str_starts_with($relative, 'app/Branding/Values/')) {
                continue;
            }

            /*
             * `OriginListValue` is the one exception and it is the point of
             * the exception: §8.14.16's token IS a list of origins, and its
             * grammar has to name the two schemes it accepts.
             */
            if ($relative === 'app/Branding/Values/OriginListValue.php') {
                continue;
            }

            foreach (['http://', 'https://'] as $scheme) {
                if (str_contains($source, $scheme)) {
                    $offenders[] = $relative.' names '.$scheme;
                }
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.14.2: a branding value is a name or an identifier, never an address — '
            .implode('; ', $offenders),
        );
    }

    /**
     * 🛑 Only {@see StylesheetCompiler} may emit a `--docup-` custom property.
     *
     * §8.14.2's re-serialisation requirement is carried by the type system —
     * the compiler takes `TokenValue` objects and has no method that accepts a
     * string. A second emitter that took strings would undo that without
     * touching the compiler, and the stylesheet is the one place a tenant's
     * bytes reach a file every reader downloads.
     *
     * `resources/css/` is where the Tailwind mapping and the chrome bundle
     * *read* those properties, which is a different act and is not source.
     */
    public function test_only_the_compiler_emits_a_custom_property(): void
    {
        $offenders = [];

        foreach (self::sourceFiles() as $relative => $source) {
            if (in_array($relative, ['app/Branding/StylesheetCompiler.php', 'app/Branding/BrandingToken.php'], true)) {
                continue;
            }

            if (str_contains($source, '--docup-')) {
                $offenders[] = $relative;
            }
        }

        $this->assertSame(
            [],
            $offenders,
            '§8.14.4: one place builds the stylesheet — '.implode('; ', $offenders),
        );
    }

    /**
     * 🛑 §8.14.1's count, asserted so a forty-sixth token is a decision.
     *
     * "roughly 45 tokens defined in a table". Every token is a row in the
     * operator documentation, a value the §8.14.5 gate may have to reason
     * about, and a property §8.15.9's Read the Docs mapping has to find a
     * counterpart for. The registry had forty-six once and `chrome.density`
     * was dropped rather than the number being rounded up.
     */
    public function test_the_registry_holds_forty_five_tokens(): void
    {
        $this->assertCount(
            45,
            TokenRegistry::all(),
            '§8.14.1 budgets "roughly 45"; changing the count is a deliberate act',
        );
    }

    /**
     * 🛑 Exactly three tokens reach version scope, and they are the two things
     * §8.14.1 names.
     *
     * > "Version scope is limited to colour-scheme default and a banner."
     *
     * Asserted on the set rather than on the count, because a fourth token
     * given version depth would be §8.14.1 quietly widened — and the banner is
     * two fields, which is why the number is three and not two.
     */
    public function test_only_the_scheme_default_and_the_banner_reach_version_scope(): void
    {
        $versionScoped = [];

        foreach (TokenRegistry::all() as $name => $token) {
            if ($token->deepest === CascadeLevel::Version) {
                $versionScoped[] = $name;
            }
        }

        sort($versionScoped);

        $this->assertSame(
            ['banner.text', 'banner.tone', 'scheme.default'],
            $versionScoped,
            '§8.14.1: "Version scope is limited to colour-scheme default and a banner"',
        );
    }

    /**
     * 🛑 The Tailwind mapping's fallbacks are the registry's defaults.
     *
     * §8.14.4 maps utilities onto custom properties, and the fallback in each
     * mapping is what the dashboard renders with before a theme stylesheet has
     * loaded. A fallback that drifted from the registry would give a flash of
     * a palette nobody chose — and in the worst case a flash of black on
     * black, which is an accessibility defect rather than a cosmetic one.
     */
    public function test_the_tailwind_fallbacks_match_the_registry_defaults(): void
    {
        $css = (string) file_get_contents(self::root().'/resources/css/tokens.css');

        preg_match_all('/var\((--docup-[a-z0-9-]+),\s*([^)]+)\)/', $css, $matches, PREG_SET_ORDER);

        $this->assertNotSame([], $matches, 'tokens.css declares no mappings');

        $byProperty = [];

        foreach (TokenRegistry::all() as $token) {
            $byProperty[$token->customProperty()] = $token;
        }

        $wrong = [];

        foreach ($matches as $match) {
            $property = $match[1];
            $fallback = trim($match[2]);

            $token = $byProperty[$property] ?? null;

            if ($token === null) {
                $wrong[] = $property.' is not a registry token';

                continue;
            }

            if ($fallback !== $token->default) {
                $wrong[] = sprintf('%s falls back to %s; the registry default is %s', $property, $fallback, $token->default);
            }
        }

        $this->assertSame([], $wrong, implode('; ', $wrong));
    }

    /** Referenced so the grammar's single call site is discoverable from here. */
    public function test_the_grammar_is_the_class_this_file_names(): void
    {
        $this->assertTrue(class_exists(TokenGrammar::class));
        $this->assertTrue(class_exists(ChromeContent::class));
    }

    /**
     * Every first-party source file, keyed by its repository-relative path.
     *
     * @return array<string, string>
     */
    private static function sourceFiles(): array
    {
        $files = [];

        foreach (['app', 'config', 'database', 'routes', 'bootstrap'] as $root) {
            $directory = self::root().'/'.$root;

            if (! is_dir($directory)) {
                continue;
            }

            /** @var \SplFileInfo $file */
            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory)) as $file) {
                if (! $file->isFile() || $file->getExtension() !== 'php') {
                    continue;
                }

                if (str_contains($file->getPathname(), DIRECTORY_SEPARATOR.'cache'.DIRECTORY_SEPARATOR)) {
                    continue;
                }

                $relative = str_replace(DIRECTORY_SEPARATOR, '/', substr($file->getPathname(), strlen(self::root()) + 1));

                $files[$relative] = self::withoutComments($file->getPathname());
            }
        }

        return $files;
    }

    /**
     * 🛑 Comments stripped, for the reason {@see ArchitectureTest} strips them:
     * these tests search for names, and a docblock explaining why a class must
     * NOT be used here would otherwise be the thing that fails the test.
     */
    private static function withoutComments(string $file): string
    {
        $out = '';

        foreach (token_get_all((string) file_get_contents($file)) as $token) {
            if (is_array($token)) {
                if (in_array($token[0], [T_COMMENT, T_DOC_COMMENT], true)) {
                    continue;
                }

                $out .= $token[1];

                continue;
            }

            $out .= $token;
        }

        return $out;
    }

    private static function root(): string
    {
        return dirname(__DIR__, 2);
    }
}
