<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Addons;

use App\Artifacts\ChromeInjector;
use App\Artifacts\InjectionOutcome;
use App\Http\Controllers\Serving\AddonsController;
use App\Serving\CanonicalPath;
use Illuminate\Support\Facades\File;
use Tests\Support\AddonsHostiles;
use Tests\TestCase;

/**
 * 🛑 §9.4's abuse corpus, `addons` category.
 *
 * > §9.4: "Security-critical phases additionally append a named case to the
 * > permanent abuse corpus."
 *
 * Twenty-three cases, in three subjects. This file drives the two that are
 * PHP's; `tests/Js/chrome-corpus.test.mjs` drives the third, reading the same
 * `corpus.json`, because a closed shadow root in a DOM is not something PHP can
 * be pointed at. 🛑 One corpus, one index, two runners — and
 * {@see self::test_every_case_has_a_driver_somewhere()} asserts that every case
 * is claimed by one of them, so a case cannot be added and silently never run.
 *
 * ## 🛑 Two cases were real defects, not confirmations
 *
 * `addons-001` and `addons-002` were written as "this surely works" and did
 * not. §8.15.3's `</head\s*>` pattern inserted DocUp's two tags inside a
 * JavaScript string literal and inside an HTML comment respectively — breaking
 * the document in the first case and silently losing chrome in the second,
 * with the coverage record claiming `injected` both times. The fix is in
 * {@see ChromeInjector}, the injector version is bumped to 2, and
 * §8.15.3's own wording is proposed for amendment.
 *
 * That is what the corpus is for. §9.4's phrasing — append a case — reads like
 * bookkeeping until a case fails.
 *
 * ## 🛑 Not every case is a rejection
 *
 * Phase 25's lesson, recorded in `BrandingCorpusTest`: one surviving control
 * keeps every coarse case green, so each case names an **exact** outcome.
 * `addons-016` is `accepted` on purpose — a whole URL in the `path` parameter
 * is reduced to its path and the request's own host still decides the project,
 * which is §8.9.4 working rather than a gap. A corpus that only ever expected
 * refusals could not express that, and the distinction is the interesting part.
 */
final class AddonsCorpusTest extends TestCase
{
    /**
     * The outcomes a case may name that are not {@see InjectionOutcome} values.
     *
     * Declared, so a typo in a case's `expect` fails
     * {@see self::test_every_case_names_a_real_outcome()} rather than silently
     * matching nothing.
     */
    private const array OUTCOMES = [
        // The `addons_path` subject.
        'reject',
        'accepted',
        // The `chrome_css` subject, driven by tests/Js/chrome-corpus.test.mjs.
        'chrome_survives',
        'chrome_refuses',
    ];

    /** Which subjects each runner claims. */
    private const array PHP_SUBJECTS = ['injection', 'addons_path'];

    private const array JS_SUBJECTS = ['chrome_css'];

    public function test_the_category_exists_and_is_not_empty(): void
    {
        $cases = self::cases();

        $this->assertNotSame([], $cases, '§9.4 requires at least one named case for this phase');

        $ids = array_column($cases, 'id');

        $this->assertSame($ids, array_values(array_unique($ids)), 'no case id appears twice');

        foreach ($cases as $case) {
            $this->assertMatchesRegularExpression('/^addons-\d{3}$/', $case['id']);
            $this->assertNotSame('', trim((string) $case['defends']), $case['id'].' must name what it defends');
            $this->assertNotSame('', trim((string) $case['note']), $case['id'].' must say why it matters');
        }
    }

    /** 🛑 Every case names an outcome something can actually produce. */
    public function test_every_case_names_a_real_outcome(): void
    {
        $outcomes = array_map(
            static fn (InjectionOutcome $outcome): string => $outcome->value,
            InjectionOutcome::cases(),
        );

        foreach (self::cases() as $case) {
            $this->assertContains(
                $case['expect'],
                [...$outcomes, ...self::OUTCOMES],
                $case['id'].' expects "'.$case['expect'].'", which is neither an '
                .'InjectionOutcome nor a declared outcome',
            );
        }
    }

    /**
     * 🛑 Every case is claimed by exactly one runner.
     *
     * The failure this prevents is the quiet one: a case added with a subject
     * neither runner knows about would sit in the corpus looking like coverage
     * and never execute. The JS half asserts the mirror of this.
     */
    public function test_every_case_has_a_driver_somewhere(): void
    {
        foreach (self::cases() as $case) {
            $this->assertContains(
                $case['subject'],
                [...self::PHP_SUBJECTS, ...self::JS_SUBJECTS],
                $case['id'].' has a subject no runner drives',
            );
        }
    }

    /** 🛑 And every builder a case names produces something. */
    public function test_every_builder_a_case_names_exists(): void
    {
        foreach (self::cases() as $case) {
            if (! isset($case['builder'])) {
                continue;
            }

            $this->assertNotSame(
                '',
                AddonsHostiles::build((string) $case['builder']),
                $case['id'].': '.$case['builder'].' produced nothing',
            );
        }
    }

    /**
     * 🛑 Each injection case produces its expected outcome — and each one that
     * is not injected is proven **byte-identical**.
     *
     * The second half is §17's exit criterion two: "provably never corrupts
     * them". A case asserting only the outcome identifier would pass for an
     * injector that refused a document and appended a newline to it on the way
     * out.
     */
    public function test_every_injection_case_behaves(): void
    {
        $injector = new ChromeInjector(4 * 1024 * 1024);
        $failures = [];

        foreach (self::cases() as $case) {
            if ($case['subject'] !== 'injection') {
                continue;
            }

            $document = isset($case['builder'])
                ? AddonsHostiles::build((string) $case['builder'])
                : (string) $case['document'];

            $buildId = isset($case['build_id'])
                ? (string) $case['build_id']
                : '0192f0a0-0000-7000-8000-000000000001';

            $result = $injector->inject($document, $buildId);

            if ($result->outcome->value !== $case['expect']) {
                $failures[] = $case['id'].': expected '.$case['expect'].', got '.$result->outcome->value;

                continue;
            }

            /*
             * 🛑 "Provably never corrupts them." Asserted for every case that
             * says so, as an exact byte comparison.
             */
            if (($case['unchanged'] ?? false) === true && $result->bytes !== $document) {
                $failures[] = $case['id'].': the bytes were modified by a refusal';
            }

            /*
             * 🛑 `addons-001`, `-002` and `-012`: the tags must land AFTER the
             * raw-text or comment region that holds the decoy `</head>`, never
             * inside it. Checked by position rather than by presence, because
             * the broken output contained the tags too — that is exactly why
             * the defect was invisible.
             */
            if (($case['assert_after_raw_text'] ?? false) === true) {
                $at = strpos($result->bytes, ChromeInjector::LOADER_PATH);
                $decoy = stripos($result->bytes, '</head>');

                if ($at === false || $decoy === false || $at < $decoy) {
                    $failures[] = $case['id'].': the tags were inserted before the decoy </head>';
                }
            }

            /* `addons-010`: the build id reaches the document escaped. */
            if (($case['assert_escaped'] ?? false) === true) {
                if (str_contains($result->bytes, '<script>alert(1)</script>')) {
                    $failures[] = $case['id'].': the build id was not escaped';
                }

                if (! str_contains($result->bytes, '&quot;&gt;&lt;script&gt;')) {
                    $failures[] = $case['id'].': the build id is not escaped as expected';
                }
            }
        }

        $this->assertSame([], $failures, implode("\n", $failures));
    }

    /**
     * Each `addons_path` case is refused or accepted as it says.
     *
     * 🛑 Driven against {@see CanonicalPath} and the endpoint's own cap rather
     * than through HTTP, because the claim is about the **check** rather than
     * about one project's routing — and a corpus case that needed a published
     * project would be a corpus case that could fail for reasons the corpus is
     * not about. `ExitCriteriaTest` asserts the same inputs end to end.
     */
    public function test_every_path_case_behaves(): void
    {
        $failures = [];

        foreach (self::cases() as $case) {
            if ($case['subject'] !== 'addons_path') {
                continue;
            }

            $raw = isset($case['builder'])
                ? AddonsHostiles::build((string) $case['builder'])
                : (string) $case['input'];

            $outcome = self::drivePath($raw);

            if ($outcome !== $case['expect']) {
                $failures[] = $case['id'].': expected '.$case['expect'].', got '.$outcome;
            }
        }

        $this->assertSame([], $failures, implode("\n", $failures));
    }

    /**
     * The endpoint's own reading of a `path` parameter, in one place.
     *
     * Mirrors {@see AddonsController::pathFrom()}
     * — the cap, the path extraction, the canonical check, in that order.
     */
    private static function drivePath(string $raw): string
    {
        if (strlen($raw) > 2_048) {
            return 'reject';
        }

        $path = parse_url($raw, PHP_URL_PATH);

        if (! is_string($path) || $path === '' || ! str_starts_with($path, '/')) {
            return 'reject';
        }

        return CanonicalPath::isCanonical($path) ? 'accepted' : 'reject';
    }

    /**
     * The `addons` cases, from the one corpus index.
     *
     * @return list<array<string, mixed>>
     */
    private static function cases(): array
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            (string) File::get(base_path('tests/Fixtures/AbuseCorpus/corpus.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        return array_values(array_filter(
            $corpus['cases'],
            static fn (array $case): bool => ($case['category'] ?? null) === 'addons',
        ));
    }
}
