<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Collections;

use App\Collections\CollectionAlias;
use App\Collections\CollectionRefused;
use App\Collections\CollectionRejection;
use App\Versions\VersionSlug;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 Two of the three refusals Phase 16's exit criterion names.
 *
 * > "A collection alias colliding with a version slug, a language code or
 * > `/_/` is rejected."
 *
 * The language code and `/_/` are decidable from the alias alone and are
 * asserted here; the version-slug collision needs a parent project and lives
 * in `CollectionsTest`.
 */
final class CollectionAliasTest extends TestCase
{
    /**
     * 🛑 A language code is refused where it stands in a language's position.
     *
     * §8.2.6's `alias` convention puts the alias at `/<alias>/<lang>/<ver>/`,
     * which is §7.3's language step — so `ja` there is the collision Phase
     * 16's exit criterion names.
     */
    public function test_a_language_code_is_refused_under_the_alias_convention(): void
    {
        foreach (['ja', 'en', 'fr', 'zho', 'pt-br', 'zh-hant'] as $code) {
            $this->assertRefused($code, CollectionRejection::AliasReserved, 'alias');
        }
    }

    /**
     * 🛑 And accepted under the default convention, where it is not one.
     *
     * `/projects/ja/en/v1/` has the alias and the language in different
     * segments, so nothing is ambiguous — and the alias that forces this
     * distinction is `api`, three lowercase letters, the commonest Read the
     * Docs subproject name there is and one §8.21.2 promises keeps
     * resolving.
     */
    public function test_a_language_shaped_alias_is_accepted_under_the_projects_convention(): void
    {
        foreach (['api', 'ja', 'sdk', 'cli'] as $alias) {
            $this->assertTrue(
                CollectionAlias::isUsable($alias, 'projects'),
                $alias.' is one segment deeper than a language and must be usable',
            );
        }
    }

    /** 🛑 §7.3's reserved first segments, and §8.6.10's. */
    public function test_a_reserved_segment_is_refused(): void
    {
        foreach (['_', '.well-known', 'page'] as $segment) {
            $this->assertRefused($segment, CollectionRejection::AliasReserved);
        }
    }

    /**
     * 🛑 `static` and `media` are **not** alias refusals, although a version
     * slug may not be either.
     *
     * Those two entries in {@see VersionSlug::RESERVED} are version-slug
     * precautions rather than §7.3 reservations, and the documentation origin
     * serves neither — §8.1.4 puts the REST API and the asset host on other
     * registrable domains. Asserted so that widening the version list later
     * does not silently narrow this one.
     */
    public function test_the_version_slug_precautions_are_not_alias_refusals(): void
    {
        foreach (['static', 'media'] as $alias) {
            $this->assertTrue(CollectionAlias::isUsable($alias, 'alias'), $alias.' must remain a usable alias');
            $this->assertTrue(VersionSlug::isReserved($alias), $alias.' is still refused as a version slug');
        }
    }

    /**
     * 🛑 And `projects`, the literal §8.2.6's own convention puts in front of
     * every alias.
     *
     * `/projects/projects/` is a legal URL and an unreadable one — and under
     * the `alias` convention it is the collision the whole rule is about.
     */
    public function test_the_convention_segment_is_refused_as_an_alias(): void
    {
        $this->assertRefused('projects', CollectionRejection::AliasReserved);
    }

    /**
     * 🛑 The language-code rule is one function, asserted rather than assumed.
     *
     * Under §8.2.6's `alias` convention an alias stands exactly where a
     * version slug stands, so the two must answer identically — and this is
     * what fails if somebody gives the alias its own copy of the pattern.
     */
    public function test_the_language_code_rule_is_shared_with_version_slugs(): void
    {
        foreach (['ja', 'en', 'pt-br', 'zho', 'guides', 'sdk', 'v2docs', 'x1'] as $segment) {
            $this->assertSame(
                VersionSlug::isLanguageCodeShaped($segment),
                ! CollectionAlias::isUsable($segment, 'alias'),
                $segment.': the alias rule and the slug rule disagree about language codes',
            );
        }
    }

    /** 🛑 §7.3's own two reserved segments are refused by both. */
    public function test_the_grammar_s_reserved_segments_are_refused_by_both(): void
    {
        foreach (['_', '.well-known', 'page'] as $segment) {
            $this->assertFalse(CollectionAlias::isUsable($segment));
            $this->assertTrue(VersionSlug::isReserved($segment));
        }
    }

    /** The shape: a URL segment, lowercase, never edged with a separator. */
    public function test_a_malformed_alias_is_refused(): void
    {
        foreach (['', 'Api', 'two words', 'a/b', '-lead', 'trail-', 'v1.2', 'ümlaut', '_under'] as $alias) {
            $this->assertRefused($alias, CollectionRejection::AliasMalformed);
        }
    }

    /** `isUsable()` defaults to the convention the column does. */
    public function test_the_default_convention_is_the_schema_default(): void
    {
        $this->assertTrue(CollectionAlias::isUsable('api'));
        $this->assertFalse(CollectionAlias::isUsable('api', 'alias'));
    }

    /** 🛑 Length is refused here, before MySQL truncates it past the check. */
    public function test_an_overlong_alias_is_refused(): void
    {
        $this->assertRefused(str_repeat('a', CollectionAlias::MAX_LENGTH + 1), CollectionRejection::AliasMalformed);
    }

    /** And the ordinary ones are accepted. */
    public function test_a_usable_alias_is_accepted(): void
    {
        foreach (['guides', 'user-guide', 'sdk_python', 'v2docs', 'x1'] as $alias) {
            $this->assertTrue(CollectionAlias::isUsable($alias), $alias.' should be usable');
        }
    }

    private function assertRefused(
        string $alias,
        CollectionRejection $expected,
        string $convention = 'projects',
    ): void {
        try {
            CollectionAlias::assertUsable($alias, $convention);
        } catch (CollectionRefused $refused) {
            $this->assertSame($expected, $refused->rejection, 'wrong refusal for "'.$alias.'"');

            return;
        }

        $this->fail('"'.$alias.'" was accepted and should have been refused');
    }
}
