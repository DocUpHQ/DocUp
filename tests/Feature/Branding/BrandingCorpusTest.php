<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Auth\OrganisationContext;
use App\Branding\Assets\AssetIntake;
use App\Branding\Assets\AssetKind;
use App\Branding\Assets\SvgSanitiser;
use App\Branding\CascadeLevel;
use App\Branding\Chrome\ChromeContent;
use App\Branding\Email\EmailSlot;
use App\Branding\Email\EmailSlots;
use App\Branding\Email\EmailVariables;
use App\Branding\Email\SlotMarkdown;
use App\Branding\ThemeAssets;
use App\Branding\TokenGrammar;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Models\Organisation;
use Illuminate\Foundation\Testing\DatabaseTransactions;
use Illuminate\Support\Facades\Storage;
use Tests\Support\BrandingHostiles;
use Tests\TestCase;

/**
 * 🛑 §9.4's abuse corpus for a security-critical phase.
 *
 * > "Security-critical phases […] additionally [require] a mutation score
 * > ≥75% on changed domain code, a written threat-model delta, and 🛑 **one
 * > named adversarial test appended to a permanent abuse corpus**."
 *
 * Forty cases, in the `branding` category. Phase 25's lesson about `reject`
 * applies in full and is the reason every case here names an exact
 * {@see TokenRejection} value or one of two declared non-rejection outcomes:
 * "`reject` cannot tell fourteen controls apart. One surviving control would
 * keep every case green while thirteen had regressed."
 *
 * ## 🛑 The two non-rejection outcomes, declared rather than described
 *
 * - **`sanitised`** — the input is **accepted** and the hostile construct is
 *   absent from the output. §17's own criterion for an SVG is "sanitised and
 *   renders", so a case asserting a refusal would be asserting the opposite of
 *   the requirement.
 * - **`accepted`** — the input is accepted unchanged in form, and the hostile
 *   payload is inert. A re-encoded polyglot and an escaped Markdown slot are
 *   both this.
 *
 * Phase 06 put the same distinction in the corpus for `runner-002` and
 * `runner-006`, and recorded that "the distinction is the interesting part".
 *
 * ## 🛑 What this test enforces that a review cannot
 *
 * 1. Every `expect` is either a real `TokenRejection` value or one of the two
 *    literals above, so a renamed rejection breaks the build rather than
 *    orphaning a case that still reads as plausible.
 * 2. Every case names a `subject` this file has a driver for, so a case cannot
 *    be appended and silently not run.
 * 3. Every `builder` a case names exists, for the reason the archive corpus
 *    gives: a case without a fixture stops running while the suite reports
 *    green.
 * 4. Every case actually produces its expected outcome.
 */
final class BrandingCorpusTest extends TestCase
{
    use DatabaseTransactions;

    /** The two non-rejection outcomes this category admits. */
    private const array OUTCOMES = ['sanitised', 'accepted'];

    private OrganisationContext $context;

    private Organisation $organisation;

    private TokenGrammar $grammar;

    protected function setUp(): void
    {
        parent::setUp();

        Storage::fake('theme-assets');

        $this->context = app(OrganisationContext::class);
        $this->context->spanAllOrganisations();

        $this->organisation = Organisation::query()->create([
            'name' => 'Corpus Co',
            'slug' => 'corp-'.bin2hex(random_bytes(4)),
        ]);

        $this->context->for($this->organisation->id);

        $this->grammar = new TokenGrammar(new ThemeAssets((string) $this->organisation->id), []);
    }

    protected function tearDown(): void
    {
        $this->context->forget();

        parent::tearDown();
    }

    /** The corpus holds branding cases at all — a guard on the loader. */
    public function test_the_corpus_holds_branding_cases(): void
    {
        $this->assertGreaterThanOrEqual(1, count(self::cases()), '§9.4 requires at least one');
    }

    /**
     * 🛑 Every `expect` names an outcome that exists.
     *
     * The assertion Phase 25 added for `saml`, for the same reason: a case
     * whose expectation is a string nobody checks is a case that passes
     * because nothing looked.
     */
    public function test_every_case_names_a_real_outcome(): void
    {
        $identifiers = array_map(
            static fn (TokenRejection $rejection): string => $rejection->value,
            TokenRejection::cases(),
        );

        foreach (self::cases() as $case) {
            $this->assertContains(
                $case['expect'],
                [...$identifiers, ...self::OUTCOMES],
                $case['id'].' expects "'.$case['expect'].'", which is neither a TokenRejection nor a declared outcome',
            );
        }
    }

    /** 🛑 And a `subject` this file can drive, so no case is silently skipped. */
    public function test_every_case_names_a_subject_with_a_driver(): void
    {
        foreach (self::cases() as $case) {
            $this->assertContains(
                $case['subject'] ?? '',
                ['token', 'chrome', 'svg', 'asset', 'email'],
                $case['id'].' has no driver',
            );
        }
    }

    /** 🛑 And every builder it names exists. */
    public function test_every_builder_a_case_names_exists(): void
    {
        foreach (self::cases() as $case) {
            if (! isset($case['builder'])) {
                continue;
            }

            $this->assertNotSame(
                '',
                BrandingHostiles::build($case['builder']),
                $case['id'].': '.$case['builder'].' produced nothing',
            );
        }
    }

    /**
     * 🛑 And each case produces its expected outcome.
     *
     * One test rather than forty, because the corpus is the list and a
     * `#[DataProvider]` over it would need the fixtures at provider time —
     * before the application has booted. The failure message names the case,
     * which is what matters when one regresses.
     */
    public function test_every_case_produces_its_expected_outcome(): void
    {
        $unexpected = [];

        foreach (self::cases() as $case) {
            $outcome = $this->drive($case);

            if ($outcome !== $case['expect']) {
                $unexpected[] = sprintf(
                    '%s (%s): expected %s, got %s',
                    $case['id'],
                    $case['subject'],
                    $case['expect'],
                    $outcome,
                );
            }
        }

        $this->assertSame([], $unexpected, implode("\n", $unexpected));
    }

    /**
     * Drive one case, and return the outcome identifier it produced.
     *
     * @param  array<string, mixed>  $case
     */
    private function drive(array $case): string
    {
        try {
            return match ($case['subject']) {
                'token' => $this->driveToken($case),
                'chrome' => $this->driveChrome($case),
                'svg' => $this->driveSvg($case),
                'asset' => $this->driveAsset($case),
                'email' => $this->driveEmail($case),
                default => 'no-driver',
            };
        } catch (TokenRefused $refused) {
            return $refused->rejection->value;
        }
    }

    /**
     * @param  array<string, mixed>  $case
     *
     * @throws TokenRefused
     */
    private function driveToken(array $case): string
    {
        $level = CascadeLevel::from(is_string($case['scope'] ?? null) ? $case['scope'] : 'project');

        $this->grammar->parseAll([(string) $case['token'] => (string) $case['input']], $level);

        return 'accepted';
    }

    /**
     * @param  array<string, mixed>  $case
     *
     * @throws TokenRefused
     */
    private function driveChrome(array $case): string
    {
        $level = CascadeLevel::from(is_string($case['scope'] ?? null) ? $case['scope'] : 'project');

        /** @var array<array-key, mixed> $payload */
        $payload = $case['payload'];

        $content = ChromeContent::parse($payload, $level);

        /*
         * 🛑 For an announcement case, "sanitised" means the construct is gone
         * from the OUTPUT — so the outcome is read from the markup rather than
         * from the absence of an exception. A parser that accepted the
         * fragment and echoed it would otherwise report `accepted` here and
         * look like a pass.
         */
        if ($content->announcement !== null) {
            $markup = $content->announcement->markup;

            $leaked = str_contains(strtolower($markup), 'script')
                || str_contains(strtolower($markup), 'onerror')
                || str_contains(strtolower($markup), '<img');

            return $leaked ? 'leaked' : 'sanitised';
        }

        return 'accepted';
    }

    /**
     * @param  array<string, mixed>  $case
     *
     * @throws TokenRefused
     */
    private function driveSvg(array $case): string
    {
        $sanitised = SvgSanitiser::sanitise(BrandingHostiles::build((string) $case['builder']));
        $svg = strtolower($sanitised->svg);

        /*
         * 🛑 The construct must be gone from the re-serialised document. Each
         * needle is one of the vectors the `svg` cases carry; a sanitiser that
         * returned its input unchanged would pass a test that only asked
         * whether it threw.
         */
        foreach ([
            'script', 'onload', 'foreignobject', 'animate', 'xlink',
            'evil.example', 'javascript:', 'style=', '<use', '<image',
        ] as $needle) {
            if (str_contains($svg, $needle)) {
                return 'leaked:'.$needle;
            }
        }

        return 'sanitised';
    }

    /**
     * @param  array<string, mixed>  $case
     *
     * @throws TokenRefused
     */
    private function driveAsset(array $case): string
    {
        $kind = AssetKind::from((string) $case['kind']);

        $accepted = AssetIntake::make()->accept(
            bytes: BrandingHostiles::build((string) $case['builder']),
            kind: $kind,
            label: $case['id'].' fixture',
            scope: CascadeLevel::Organisation,
            scopeId: (string) $this->organisation->id,
            organisationId: (string) $this->organisation->id,
        );

        /*
         * 🛑 "accepted" for an asset means the hostile payload is absent from
         * what DocUp **stored**, which is the claim §8.14.11 actually makes.
         * Asserting only that the upload succeeded would pass for a pipeline
         * that stored the polyglot verbatim.
         */
        $stored = (string) ThemeAssets::store()->get(
            $accepted->asset->content_hash,
            ThemeAssets::extensionFor($accepted->asset->media_type),
        );

        foreach (['script', 'alert', '<html', '<?php', 'eval('] as $needle) {
            if (str_contains(strtolower($stored), $needle)) {
                return 'leaked:'.$needle;
            }
        }

        return 'accepted';
    }

    /**
     * @param  array<string, mixed>  $case
     *
     * @throws TokenRefused
     */
    private function driveEmail(array $case): string
    {
        $slot = EmailSlot::from((string) $case['slot']);

        /* Validated as a save would validate it. */
        EmailSlots::parse([$slot->value => (string) $case['payload']]);

        $rendered = SlotMarkdown::render(
            (string) $case['payload'],
            'email.'.$slot->value,
            $slot->maxCharacters(),
            EmailVariables::availableTo($slot),
        );

        foreach (['<script', 'onerror', 'javascript:'] as $needle) {
            if (str_contains(strtolower($rendered), $needle)) {
                return 'leaked:'.$needle;
            }
        }

        return 'accepted';
    }

    /**
     * The `branding` cases, from the one index.
     *
     * @return list<array<string, mixed>>
     */
    private static function cases(): array
    {
        /** @var array{cases: list<array<string, mixed>>} $corpus */
        $corpus = json_decode(
            (string) file_get_contents(base_path('tests/Fixtures/AbuseCorpus/corpus.json')),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        return array_values(array_filter(
            $corpus['cases'],
            static fn (array $case): bool => ($case['category'] ?? null) === 'branding',
        ));
    }
}
