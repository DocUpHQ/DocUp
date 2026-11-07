<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\CachePolicy;
use App\Serving\NotFoundChain;
use App\Serving\PenaltyBox;
use Illuminate\Support\Facades\Cache;
use Tests\TestCase;

/**
 * 🛑 §8.11.5's chain and §8.11.8's two halves — including §17's exit
 * criterion, which asks for both at once.
 *
 * > "🛑 A 404 burst trips the penalty box and 404s remain edge-cacheable
 * > throughout."
 *
 * **"Throughout" is the word being tested.** The two requirements in
 * §8.11.8 pull in opposite directions: edge-cacheable means the edge
 * answers a repeat without asking the application, and rate-limited means
 * the application answers fewer. A limiter that suppressed caching while it
 * was engaged would hand an attacker exactly what they wanted — every
 * request reaching the origin — as a side effect of the defence.
 */
final class NotFoundTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        Cache::flush();
    }

    /**
     * 🛑 The exit criterion: the burst trips the box, and the cache
     * directives are the same before, during and after.
     */
    public function test_a_burst_trips_the_penalty_box_and_404s_stay_edge_cacheable(): void
    {
        $box = new PenaltyBox;
        $source = '198.51.100.'.random_int(1, 254);

        $before = CachePolicy::forAbsence()->headers();

        $this->assertStringContainsString('public', $before['Cache-Control'] ?? '');

        $tripped = false;

        for ($i = 0; $i < PenaltyBox::FREE_PER_MINUTE + 5; $i++) {
            $tripped = $box->record($source) || $tripped;
        }

        $this->assertTrue($tripped, 'a burst past the free allowance must trip the box');
        $this->assertTrue($box->isPenalised($source));
        $this->assertNotNull($box->secondsRemaining($source));

        /*
         * 🛑 And the directives are unchanged while the box is engaged. The
         * assertion is identity rather than "still public", because the
         * requirement is that the limiter has no effect at all on
         * cacheability — a shorter TTL under load would be the same mistake
         * in a smaller size.
         */
        $this->assertSame($before, CachePolicy::forAbsence()->headers(), '🛑 "edge-cacheable throughout"');
    }

    /** An ordinary reader with a stale bookmark is never penalised. */
    public function test_an_ordinary_reader_is_not_penalised(): void
    {
        $box = new PenaltyBox;
        $source = '203.0.113.7';

        for ($i = 0; $i < 10; $i++) {
            $this->assertFalse($box->record($source));
        }

        $this->assertFalse($box->isPenalised($source));
        $this->assertNull($box->secondsRemaining($source));
    }

    /**
     * 🛑 Progressive: the second penalty is longer than the first, and the
     * level survives the penalty lapsing.
     *
     * Without the memory the progression resets the moment a penalty
     * expires, so a source that waits sixty seconds between bursts is never
     * held for more than sixty seconds — the whole attack, with a timer.
     */
    public function test_the_penalty_grows_with_repetition(): void
    {
        $box = new PenaltyBox;
        $source = '192.0.2.44';

        $this->trip($box, $source);
        $first = $box->secondsRemaining($source);

        // The penalty lapses; the level does not.
        Cache::forget('serving:penalty:until:'.$this->keyFor($source));

        $this->trip($box, $source);
        $second = $box->secondsRemaining($source);

        $this->assertNotNull($first);
        $this->assertNotNull($second);
        $this->assertGreaterThan($first, $second, 'the second penalty must be longer than the first');
    }

    /** And it is capped, because an hour is as long as holding anybody helps. */
    public function test_the_penalty_is_capped(): void
    {
        $box = new PenaltyBox;
        $source = '192.0.2.99';

        for ($round = 0; $round < 12; $round++) {
            Cache::forget('serving:penalty:until:'.$this->keyFor($source));
            $this->trip($box, $source);
        }

        $this->assertLessThanOrEqual(PenaltyBox::MAX_PENALTY_SECONDS, (int) $box->secondsRemaining($source));
    }

    /**
     * 🛑 §20.3 gives a raw IP a 7-day retention and calls it "the only place
     * a raw IP exists". A cache key is not that place.
     */
    public function test_the_source_is_hashed_before_it_becomes_a_key(): void
    {
        $box = new PenaltyBox;
        $source = '198.51.100.123';

        $this->trip($box, $source);

        $this->assertTrue($box->isPenalised($source));

        /*
         * 🛑 Two facts, and both are needed. That the derived key contains
         * no raw address is the requirement; that it is the key the box
         * actually uses is what makes the first fact about the box rather
         * than about this test's own arithmetic — so clearing it must
         * release the penalty.
         *
         * Asserted this way rather than by listing the keyspace, because
         * the store differs between environments (array here, Redis in the
         * container) and a test that only works on one of them is how
         * a driver-specific defect survives — as this very class found.
         */
        $key = $this->keyFor($source);

        $this->assertStringNotContainsString($source, $key, 'a raw IP reached a cache key');
        $this->assertStringNotContainsString('198.51.100', $key);

        Cache::forget('serving:penalty:until:'.$key);

        $this->assertFalse($box->isPenalised($source), 'the box does not use the key this test derived');
    }

    /**
     * 🛑 §9.3.2 is not weakened: a 404 about something private is **not**
     * publicly cacheable.
     *
     * §12 answers a private page with a 404 on purpose, and caching that
     * publicly would serve one reader's refusal to a member who should have
     * been let in — and would confirm, to anyone watching the cache, which
     * paths are the interesting ones.
     */
    public function test_a_404_about_a_private_project_is_not_publicly_cacheable(): void
    {
        $private = CachePolicy::forAbsence(projectIsPublic: false, versionIsPublic: true)->headers();

        $this->assertStringContainsString('no-store', $private['Cache-Control'] ?? '');
        $this->assertStringNotContainsString('public', $private['Cache-Control'] ?? '');
        $this->assertStringNotContainsString('public', $private['CDN-Cache-Control'] ?? '');

        // A version that was reached but is not public is the same answer.
        $hidden = CachePolicy::forAbsence(projectIsPublic: true, versionIsPublic: false)->headers();

        $this->assertStringContainsString('no-store', $hidden['Cache-Control'] ?? '');
    }

    /**
     * 🛑 And a rejection that fired before any project was identified **is**
     * cacheable, because there was no tenant for it to be about.
     */
    public function test_a_404_about_nothing_is_publicly_cacheable(): void
    {
        $headers = CachePolicy::forAbsence()->headers();

        $this->assertStringContainsString('public', $headers['Cache-Control'] ?? '');
        $this->assertStringContainsString('public', $headers['CDN-Cache-Control'] ?? '');

        /*
         * Short, because a 404 is a claim about absence and absence is the
         * one answer a publish makes wrong.
         */
        $this->assertMatchesRegularExpression('/max-age=(?:[1-9]|[1-5]\d|60)\b/', $headers['Cache-Control'] ?? '');
    }

    /**
     * 🛑 §8.11.5 / ADR 0003: a `404.html` with root-absolute references is
     * skipped under a prefix.
     *
     * "MkDocs Material's measured output puts all 8 of its root-absolute
     * references in that one file", and at `/docs/` those references belong
     * to whatever is at the root instead. The choice is between a
     * stylesheet-less copy of the project's page and DocUp's own, and the
     * requirement picks DocUp's.
     */
    public function test_a_root_absolute_404_page_is_skipped_under_a_prefix(): void
    {
        // At the origin root the references resolve, so the build's page wins.
        $this->assertTrue(NotFoundChain::mayServeBuildPage('', '', true));

        // Under a domain-mount path prefix they do not.
        $this->assertFalse(NotFoundChain::mayServeBuildPage('/docs', '', true));

        // Nor under a component mount, which breaks them identically.
        $this->assertFalse(NotFoundChain::mayServeBuildPage('', '/reference', true));

        // A page with no root-absolute references works at any depth.
        $this->assertTrue(NotFoundChain::mayServeBuildPage('/docs', '/reference', false));
    }

    /**
     * 🛑 **Null is treated as true.** A build that predates the ingest check
     * has no answer, and "unknown" must not read as "safe".
     */
    public function test_an_unmeasured_404_page_is_treated_as_root_absolute(): void
    {
        $this->assertFalse(
            NotFoundChain::mayServeBuildPage('/docs', '', null),
            'a build with no recorded answer must fall through to the built-in page',
        );

        $this->assertTrue(NotFoundChain::mayServeBuildPage('', '', null), 'at the root it works either way');
    }

    /**
     * 🛑 The branded built-in depends on no path.
     *
     * It is served for a URL that does not exist, at a depth nobody chose,
     * and §8.11.8 makes it the response a flood receives — so it cannot
     * reference a stylesheet, a script, a font or an image, because each
     * would be a second request and each would be root-absolute or
     * relative and wrong.
     */
    public function test_the_built_in_page_references_nothing(): void
    {
        $html = NotFoundChain::builtIn();

        foreach (['<link', '<script', '<img', 'url(', 'src='] as $reference) {
            $this->assertStringNotContainsString($reference, $html, 'the built-in 404 must be self-contained');
        }

        $this->assertStringContainsString('<!doctype html>', $html);
        $this->assertLessThan(2048, strlen($html), 'this is the response a flood receives');
    }

    private function trip(PenaltyBox $box, string $source): void
    {
        Cache::forget('serving:penalty:count:'.$this->keyFor($source));

        for ($i = 0; $i < PenaltyBox::FREE_PER_MINUTE + 2; $i++) {
            $box->record($source);
        }
    }

    /** The same hash the box uses, so a test can clear one key. */
    private function keyFor(string $source): string
    {
        $salt = config('app.key');

        return hash('sha256', $source.'|'.(is_string($salt) ? $salt : ''));
    }
}
