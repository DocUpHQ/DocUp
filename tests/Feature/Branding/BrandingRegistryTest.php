<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Branding\ApiOnlyChrome;
use App\Branding\TokenRegistry;
use App\Console\Commands\BrandingReferenceCommand;
use App\Models\TokenDefinition;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Storage;
use Tests\Feature\Docs\DogfoodManualTest;
use Tests\TestCase;

/**
 * §10.7's `token_definitions`, §8.14.14's reference example, and §17's
 * published token table — each asserted against the registry that defines it.
 *
 * 🛑 **Every test here is a drift test.** The phase ships three artefacts
 * derived from one registry: a database table, a JSON payload with its rendered
 * chrome, and a Markdown table. Each is useful and each would be worse than
 * absent if it were wrong — an integrator builds against the reference, an
 * operator reads the table, and `doctor` reports from the rows. So the
 * generators all carry a `--check` mode and these tests run it.
 */
final class BrandingRegistryTest extends TestCase
{
    use DatabaseTransactions;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('theme-assets');
    }

    /** The sync records every token, and a second run changes nothing. */
    public function test_the_registry_syncs_into_the_definitions_table_and_is_idempotent(): void
    {
        $this->assertSame(0, Artisan::call('docup:branding-sync'));

        $this->assertSame(count(TokenRegistry::all()), TokenDefinition::query()->count());

        /* 🛑 And `--check` agrees immediately afterwards. */
        $this->assertSame(0, Artisan::call('docup:branding-sync --check'));

        /* A second write is a no-op rather than a churn of rows. */
        $this->assertSame(0, Artisan::call('docup:branding-sync'));
        $this->assertSame(count(TokenRegistry::all()), TokenDefinition::query()->count());
    }

    /** Each row carries what the registry says, column for column. */
    public function test_each_row_matches_its_registry_entry(): void
    {
        Artisan::call('docup:branding-sync');

        foreach (TokenRegistry::all() as $name => $token) {
            $row = TokenDefinition::query()->where('name', $name)->first();

            $this->assertInstanceOf(TokenDefinition::class, $row, $name.' was not recorded');
            $this->assertSame($token->type->value, $row->type, $name);
            $this->assertSame($token->group, $row->token_group, $name);
            $this->assertSame($token->default, $row->default_value, $name);
            $this->assertSame($token->dark, $row->dark_value, $name);
            $this->assertSame($token->deepest->value, $row->deepest_level, $name);
            $this->assertSame($token->options, $row->options, $name);
            $this->assertSame($token->assetKind, $row->asset_kind, $name);
            $this->assertSame('core', $row->source, $name);
        }
    }

    /**
     * 🛑 `--check` fails when the table drifts.
     *
     * The assertion that makes the other three meaningful: a `--check` that
     * could not fail would be a CI step that proved nothing.
     */
    public function test_check_fails_when_a_row_drifts(): void
    {
        Artisan::call('docup:branding-sync');

        TokenDefinition::query()
            ->where('name', 'color.brand.primary')
            ->update(['default_value' => '#ff0000']);

        $this->assertSame(1, Artisan::call('docup:branding-sync --check'));

        /* And is repaired by a plain run. */
        $this->assertSame(0, Artisan::call('docup:branding-sync'));
        $this->assertSame(0, Artisan::call('docup:branding-sync --check'));
    }

    /** And when a row is missing entirely. */
    public function test_check_fails_when_a_row_is_missing(): void
    {
        Artisan::call('docup:branding-sync');

        TokenDefinition::query()->where('name', 'font.mono')->delete();

        $this->assertSame(1, Artisan::call('docup:branding-sync --check'));
    }

    /**
     * 🛑 §8.14.14's reference example matches what DocUp emits.
     *
     * > "A versioned `chrome_mode: api_only` contract with a **reference
     * > example theme** MUST ship."
     *
     * A reference that drifts from the implementation is worse than none: an
     * integrator builds against it and discovers the difference in production.
     * So the committed files are regenerated and compared here, which is the
     * only thing that makes shipping them honest.
     */
    public function test_the_api_only_reference_matches_what_docup_emits(): void
    {
        $this->assertSame(
            0,
            Artisan::call('docup:branding-reference --check'),
            'resources/themes/ is out of date; run php artisan docup:branding-reference',
        );
    }

    /** Both reference files exist and are what they claim to be. */
    public function test_the_reference_files_are_present_and_versioned(): void
    {
        $json = base_path(ApiOnlyChrome::REFERENCE_PATH);
        $html = base_path(BrandingReferenceCommand::HTML_PATH);

        $this->assertFileExists($json);
        $this->assertFileExists($html);

        /** @var array<string, mixed> $payload */
        $payload = json_decode((string) file_get_contents($json), true, 512, JSON_THROW_ON_ERROR);

        $this->assertSame(ApiOnlyChrome::VERSION, $payload['contract']);
        $this->assertArrayHasKey('theme', $payload);
        $this->assertArrayHasKey('assets', $payload);
        $this->assertArrayHasKey('chrome', $payload);
        $this->assertArrayHasKey('scheme', $payload);

        /*
         * 🛑 The payload carries no raw HTML beyond the announcement's
         * sanitised fragment, and no `head_html` at all. A payload that
         * carried a tenant's raw HTML would make every `api_only` consumer
         * responsible for §8.14.8, and most of them would inject it with
         * `innerHTML`.
         */
        $this->assertArrayNotHasKey('head_html', $payload['chrome']);

        /* And the rendered page is the reference an integrator reads. */
        $rendered = (string) file_get_contents($html);

        $this->assertStringContainsString('<!DOCTYPE html>', $rendered);
        $this->assertStringContainsString('--docup-color-surface-page', $rendered);
        $this->assertStringContainsString('Skip to content', $rendered);
        $this->assertStringNotContainsString('<script', $rendered);
    }

    /**
     * 🛑 §17's published table is in the operator documentation and generated.
     *
     * {@see DogfoodManualTest} already runs
     * `docup:docs:render --check` over every registered block, so this asserts
     * the narrower thing a drift check cannot: that the page exists, that the
     * table is inside it, and that it names every token. A generated block
     * whose renderer returned an empty string would pass a drift check
     * perfectly.
     */
    public function test_the_operator_documentation_publishes_every_token(): void
    {
        $page = (string) file_get_contents(base_path('docs/operator/docs/branding.md'));

        $this->assertStringContainsString('<!-- BEGIN GENERATED: token-table -->', $page);

        foreach (TokenRegistry::names() as $name) {
            $this->assertStringContainsString('`'.$name.'`', $page, $name.' is not in the published table');
        }

        /* §17's four columns. */
        foreach (['Token', 'Type', 'Grammar', 'Cascade level'] as $column) {
            $this->assertStringContainsString($column, $page);
        }

        /*
         * 🛑 §8.14.5: "The documentation MUST state honestly that this gate is
         * a safety net and still permits shipping AA-failing themes."
         */
        $this->assertStringContainsString('still lets you ship a theme that fails AA', $page);

        /* 🛑 §8.14.8's permanence, and §18.22's feature drop, both stated. */
        $this->assertStringContainsString('There is no tenant JavaScript, at any scope, ever', $page);
        $this->assertStringContainsString('Per-project custom CSS is not available', $page);
    }
}
