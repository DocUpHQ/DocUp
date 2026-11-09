<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Addons;

use App\Addons\MappingKind;
use App\Addons\ReadTheDocsMapping;
use App\Branding\TokenRegistry;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.15.9's mapping, checked against the two things it could lie about.
 *
 * > "The ~45 branding tokens MUST be published with a documented mapping to
 * > Read the Docs' **33 addon CSS custom properties**, so a migrating project's
 * > custom CSS has a stated translation."
 *
 * A published translation has exactly two ways to be wrong, and both are the
 * kind a reader cannot detect: it can be **incomplete**, so a migrating team
 * concludes a property they rely on has no answer when it has one; or it can
 * name a **token that does not exist**, so they write an override that does
 * nothing and blame their own CSS. Nobody comes back to a migration guide to
 * check it.
 */
final class ReadTheDocsMappingTest extends TestCase
{
    /**
     * 🛑 Thirty-three, which is the number §8.15.9 states.
     *
     * Read verbatim from Read the Docs' own "CSS variables reference" — one
     * global, nine flyout, eight notification, fifteen search — and asserted
     * here so that a dropped row makes the published mapping fail a test
     * rather than quietly become incomplete.
     */
    public function test_every_one_of_the_thirty_three_properties_is_mapped(): void
    {
        $entries = ReadTheDocsMapping::all();

        $this->assertCount(33, $entries, '§8.15.9 names 33 addon CSS custom properties');

        $properties = array_column($entries, 'property');

        $this->assertSame(
            $properties,
            array_values(array_unique($properties)),
            'no property appears twice',
        );

        foreach ($properties as $property) {
            $this->assertStringStartsWith('--readthedocs-', $property);
        }

        // The groups, and their sizes, as Read the Docs publishes them.
        $counts = array_count_values(array_column($entries, 'group'));

        $this->assertSame(
            ['Global' => 1, 'Flyout' => 9, 'Notifications' => 8, 'Search' => 15],
            $counts,
        );
    }

    /**
     * 🛑 Every token this mapping names is a token the registry defines.
     *
     * The failure this prevents is §8.14.16's own, arrived at from the
     * documentation side: a published instruction to set something that does
     * nothing. Phase 27 recorded the general rule — "a config key nothing reads
     * is a key an operator believes is doing something" — and a mapping row is
     * the same thing in prose.
     */
    public function test_every_mapped_token_exists_in_the_registry(): void
    {
        $registry = array_keys(TokenRegistry::all());

        foreach (ReadTheDocsMapping::tokens() as $token) {
            $this->assertContains(
                $token,
                $registry,
                $token.' is published as a translation target and must exist',
            );
        }
    }

    /** A row with no token says so, and a row with one does not say so. */
    public function test_the_three_kinds_are_used_consistently(): void
    {
        foreach (ReadTheDocsMapping::all() as $entry) {
            if ($entry['kind'] === MappingKind::Mapped) {
                $this->assertIsString($entry['token'], $entry['property'].' is mapped and must name a token');
            } else {
                $this->assertNull($entry['token'], $entry['property'].' is not mapped and must name none');
            }

            /*
             * 🛑 Every row carries a reason, and an unmapped row's reason is
             * the point of the whole table. "No equivalent" with no explanation
             * reads as an oversight; with one, it reads as a decision.
             */
            $this->assertNotSame('', trim($entry['note']), $entry['property'].' must say why');
        }
    }

    /** The rendered table is the data, with nothing written beside it. */
    public function test_the_markdown_renders_every_row(): void
    {
        $markdown = ReadTheDocsMapping::toMarkdown();

        foreach (ReadTheDocsMapping::all() as $entry) {
            $this->assertStringContainsString('`'.$entry['property'].'`', $markdown);
        }

        $this->assertStringContainsString('Read the Docs documents 33 addon CSS custom properties', $markdown);

        // One header row, one separator, and 33 data rows. Counted as lines
        // rather than with substr_count: the header has no newline before it.
        $rows = array_filter(
            explode("\n", $markdown),
            static fn (string $line): bool => str_starts_with($line, '|'),
        );

        $this->assertCount(
            35,
            $rows,
            'the table has one row per property and no hand-written extras',
        );
    }

    /**
     * 🛑 The tokens with no Read the Docs counterpart are reported, not hidden.
     *
     * Read the Docs theme 33 properties and DocUp has roughly 45 tokens, so the
     * mapping is necessarily partial in **both** directions. This asserts the
     * other direction exists and is non-empty — if it were ever empty, either
     * the registry had shrunk to Read the Docs' surface or somebody had mapped
     * a token twice to make the table look complete.
     */
    public function test_tokens_with_no_counterpart_are_knowable(): void
    {
        $unmatched = ReadTheDocsMapping::unmatchedTokens();

        $this->assertNotSame([], $unmatched);

        // A few that certainly have no Read the Docs equivalent, because Read
        // the Docs has no concept of them at all.
        foreach (['security.frame-ancestors', 'brand.name', 'chrome.header.sticky'] as $token) {
            $this->assertContains($token, $unmatched);
        }
    }
}
