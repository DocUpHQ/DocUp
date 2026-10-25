<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Builds;

use App\Builds\PathGlob;
use App\Builds\SafePattern;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * The two matchers §8.5.4 and §8.6.8 are written in terms of.
 *
 * Both take operator input, and both are the sort of code that looks
 * obviously correct and is quietly wrong at the edges — which is why they
 * have a file to themselves rather than being exercised only through the
 * rules that use them.
 */
final class PathGlobAndPatternTest extends TestCase
{
    /**
     * @param  list<string>  $paths
     */
    #[DataProvider('globCases')]
    public function test_globs_match_what_they_should(string $glob, array $paths, bool $expected): void
    {
        $this->assertSame($expected, PathGlob::anyMatches([$glob], $paths), $glob);
    }

    /** @return array<string, array{0: string, 1: list<string>, 2: bool}> */
    public static function globCases(): array
    {
        return [
            'double star crosses slashes' => ['docs/**', ['docs/a/b/c.md'], true],
            'double star matches one level' => ['docs/**', ['docs/index.md'], true],
            // 🛑 The push that CREATES the directory names it without a
            // trailing path, and a rule written for a directory must not
            // miss it.
            'double star matches the directory itself' => ['docs/**', ['docs'], true],
            'double star does not match a sibling prefix' => ['docs/**', ['docsite/index.md'], false],
            'single star stops at a slash' => ['docs/*.md', ['docs/a/b.md'], false],
            'single star matches within a segment' => ['docs/*.md', ['docs/index.md'], true],
            'question mark is one character' => ['v?.md', ['v1.md'], true],
            'question mark is not two' => ['v?.md', ['v10.md'], false],
            'question mark does not cross a slash' => ['a?b', ['a/b'], false],
            // 🛑 A dot is a dot. Unescaped it would make `*.md` match
            // `READMEmd`, which is the kind of wrong nobody notices.
            'a dot is literal' => ['*.md', ['READMEmd'], false],
            'leading double star' => ['**/conf.py', ['src/docs/conf.py'], true],
            'empty path list' => ['docs/**', [], false],
        ];
    }

    /**
     * 🛑 A glob containing regex metacharacters is matched literally and
     * does not blow up.
     *
     * An unescaped `(` makes the compiled pattern a PCRE error, which
     * `preg_match` reports by returning `false` — a falsy value, so a
     * broken rule would read as "did not match" and the operator would
     * never learn their rule did nothing.
     */
    public function test_regex_metacharacters_in_a_glob_are_literal(): void
    {
        $this->assertTrue(PathGlob::anyMatches(['docs/(draft)/**'], ['docs/(draft)/x.md']));
        $this->assertFalse(PathGlob::anyMatches(['docs/(draft)/**'], ['docs/draft/x.md']));
        $this->assertTrue(PathGlob::anyMatches(['a+b.md'], ['a+b.md']));
        $this->assertFalse(PathGlob::anyMatches(['a+b.md'], ['aab.md']));
    }

    public function test_any_of_several_globs_matching_is_a_match(): void
    {
        $this->assertTrue(PathGlob::anyMatches(['docs/**', 'mkdocs.yml'], ['mkdocs.yml']));
        $this->assertFalse(PathGlob::anyMatches(['docs/**', 'mkdocs.yml'], ['src/main.go']));
    }

    public function test_patterns_are_substring_searches_not_anchored(): void
    {
        $this->assertTrue(SafePattern::matches('release', 'release/2.0'));
        $this->assertTrue(SafePattern::matches('^release/', 'release/2.0'));
        $this->assertFalse(SafePattern::matches('^release/', 'hotfix/release/2.0'));
    }

    /**
     * 🛑 A pattern that does not compile reports false rather than
     * throwing or warning.
     *
     * Passing over is the safe direction: an unmatched rule falls through
     * to the next, and a push that matches nothing builds. The reverse
     * default would let one bad regex stop a project building for ever.
     */
    public function test_an_uncompilable_pattern_matches_nothing(): void
    {
        $this->assertFalse(SafePattern::isValid('(unclosed'));
        $this->assertFalse(SafePattern::matches('(unclosed', 'anything'));
        $this->assertTrue(SafePattern::isValid('^v\d+$'));
    }

    /**
     * 🛑 The operator's own delimiter character does not end the pattern.
     *
     * `#\d+` is a realistic commit-message rule — "built for issue #42" —
     * and a naive `str_replace` of `#` would turn an already-escaped `\#`
     * into `\\#`, which closes the pattern early and silently changes what
     * it matches.
     */
    public function test_the_delimiter_character_can_appear_in_a_pattern(): void
    {
        $this->assertTrue(SafePattern::isValid('#\d+'));
        $this->assertTrue(SafePattern::matches('#\d+', 'fixes #42'));
        $this->assertFalse(SafePattern::matches('#\d+', 'fixes nothing'));

        // Already escaped by the operator: still one literal hash.
        $this->assertTrue(SafePattern::matches('\#\d+', 'fixes #42'));
    }

    /** `matchesAny` is an OR over subjects, used for commit-message lists. */
    public function test_matches_any_searches_every_subject(): void
    {
        $this->assertTrue(SafePattern::matchesAny('\[skip ci\]', 'docs: tidy', 'chore: [skip ci]'));
        $this->assertFalse(SafePattern::matchesAny('\[skip ci\]', 'docs: tidy', 'chore: release'));
    }

    /**
     * 🛑 A catastrophically backtracking pattern returns rather than
     * hanging the webhook endpoint.
     *
     * PCRE's `pcre.backtrack_limit` bounds it and `preg_match` returns
     * false, which lands in the same branch as a compile failure: no
     * match, next rule.
     */
    public function test_a_catastrophic_pattern_does_not_hang(): void
    {
        $started = microtime(true);

        $matched = SafePattern::matches('(a+)+$', str_repeat('a', 40).'b');

        $this->assertLessThan(2.0, microtime(true) - $started, 'PCRE\'s backtrack limit is what bounds this');
        $this->assertFalse($matched);
    }
}
