<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Branding;

use App\Branding\AssetLookup;
use App\Branding\ColourScheme;
use App\Branding\ContrastFinding;
use App\Branding\ContrastGate;
use App\Branding\ContrastMatrix;
use App\Branding\ContrastReport;
use App\Branding\ContrastRole;
use App\Branding\ContrastVerdict;
use App\Branding\TokenGrammar;
use App\Branding\TokenPair;
use App\Branding\TokenRegistry;
use App\Branding\TokenType;
use App\Branding\Values\ColourValue;
use App\Branding\Values\TokenValue;
use PHPUnit\Framework\TestCase;

/**
 * 🛑 §8.14.5's gate, and §17's fourth exit criterion.
 *
 * > "A 2.9:1 contrast pair **refuses publication**; a 4.0:1 pair warns."
 *
 * The two fixtures are chosen arithmetically rather than by eye.
 * `#979797` on `#ffffff` is 2.92:1 and `#7f7f7f` on `#ffffff` is 4.00:1, both
 * computed from WCAG's own relative-luminance formula — so the criterion is
 * asserted at the numbers it names rather than at "some dark grey".
 */
final class ContrastGateTest extends TestCase
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

    /** The arithmetic first, so a failure downstream is attributable. */
    public function test_the_two_exit_criterion_fixtures_are_the_ratios_they_claim(): void
    {
        $this->assertSame(2.92, round($this->ratioOf('#979797', '#ffffff'), 2));
        $this->assertSame(4.0, round($this->ratioOf('#7f7f7f', '#ffffff'), 2));
    }

    /** 🛑 §17: "A 2.9:1 contrast pair **refuses publication**." */
    public function test_a_two_point_nine_pair_refuses(): void
    {
        $report = $this->judgeWithPrimaryText('#979797');

        $this->assertTrue($report->refuses(), 'a 2.92:1 text pair must refuse publication');
        $this->assertSame(ContrastVerdict::Refuse, $report->worst());

        $refusal = $report->refusals()[0];
        $this->assertSame('color.text.primary', $refusal->foreground);
        $this->assertSame(ColourScheme::Light, $refusal->scheme);
    }

    /** 🛑 §17: "a 4.0:1 pair warns." */
    public function test_a_four_point_zero_pair_warns_and_does_not_refuse(): void
    {
        $report = $this->judgeWithPrimaryText('#7f7f7f');

        $this->assertFalse($report->refuses(), 'a 4.00:1 text pair must not refuse');
        $this->assertTrue($report->warns());
        $this->assertSame(ContrastVerdict::Warn, $report->worst());
    }

    /**
     * 🛑 The thresholds are "at least", so a pair just over the line is a
     * warning rather than a refusal.
     *
     * This matters because a designer who computes a palette to the standard
     * lands on or just above it, and a gate using `<=` would refuse the one
     * theme built most carefully.
     *
     * Asserted on the **page** pair specifically rather than on the whole
     * report, and the reason is the finding that wrote this comment: the
     * matrix judges `color.text.primary` against three surfaces, so a grey
     * chosen to sit at 3.04:1 against white sits at 2.61:1 against the sunken
     * surface and the report as a whole correctly refuses. A test asserting
     * `refuses() === false` would have been asserting something about the
     * other two surfaces without meaning to.
     */
    public function test_a_pair_just_over_a_threshold_is_a_warning_not_a_refusal(): void
    {
        $ratio = $this->ratioOf('#949494', '#ffffff');

        $this->assertGreaterThanOrEqual(3.0, $ratio);
        $this->assertLessThan(4.5, $ratio);

        $finding = $this->pageFinding($this->judgeWithPrimaryText('#949494'));

        $this->assertSame(ContrastVerdict::Warn, $finding->verdict, $finding->describe());
    }

    /**
     * 🛑 The shipped default theme passes its own gate in both schemes, with
     * no warnings.
     *
     * A default that only warned would teach every operator that the contrast
     * warning is decoration — the same failure ADR 0002 names for injection
     * warnings, where "operators learn to ignore injection warnings". It is
     * also the one assertion that checks the nineteen paired colours were
     * chosen rather than guessed.
     */
    public function test_the_default_theme_passes_every_pair_in_both_schemes(): void
    {
        $defaults = $this->grammar->defaults();
        $report = ContrastGate::judge(
            $this->scheme($defaults, ColourScheme::Light),
            $this->scheme($defaults, ColourScheme::Dark),
        );

        $failures = array_map(
            static fn ($finding): string => $finding->describe(),
            [...$report->refusals(), ...$report->warnings()],
        );

        $this->assertSame([], $failures, implode("\n", $failures));
        $this->assertSame(ContrastVerdict::Pass, $report->worst());
    }

    /** Every pair is judged in both schemes, which is §8.14.5's own word. */
    public function test_every_pair_is_judged_in_both_schemes(): void
    {
        $defaults = $this->grammar->defaults();
        $report = ContrastGate::judge(
            $this->scheme($defaults, ColourScheme::Light),
            $this->scheme($defaults, ColourScheme::Dark),
        );

        $this->assertCount(count(ContrastMatrix::pairs()) * 2, $report->findings);
    }

    /**
     * 🛑 Every token the matrix names is a colour token the registry defines.
     *
     * {@see ContrastGate} skips a pair whose tokens it cannot find, which is
     * the right behaviour at runtime and would make the gate silently empty if
     * the matrix drifted from the registry. This is the assertion that stops
     * that: a renamed colour token breaks the build rather than the gate.
     */
    public function test_the_matrix_names_only_colour_tokens_the_registry_defines(): void
    {
        foreach (ContrastMatrix::tokens() as $name) {
            $this->assertTrue(TokenRegistry::has($name), $name.' is in the matrix and not in the registry');
            $this->assertSame(TokenType::Colour, TokenRegistry::get($name)->type, $name);
            $this->assertTrue(TokenRegistry::get($name)->isPaired(), $name.' must be a paired colour');
        }
    }

    /**
     * 🛑 A translucent colour is composited rather than skipped.
     *
     * The failure this prevents is subtle: a gate that read a translucent
     * colour's own channels would judge `#000000` at alpha 0.1 as the darkest
     * possible text, pass it at 21:1 and ship a page nobody can read.
     */
    public function test_a_translucent_foreground_is_composited_over_its_background(): void
    {
        /* Black at 10% over white is a very light grey: nowhere near 3:1. */
        $report = $this->judgeWithPrimaryText('#0000001a');

        $this->assertTrue($report->refuses());
    }

    /**
     * 🛑 A focus ring is judged at WCAG's 3:1, not at 4.5:1.
     *
     * {@see ContrastRole} says why: warning at 4.5:1 on a pair WCAG requires
     * 3:1 for would fire on every conforming theme, and an operator who learns
     * the warning cries wolf stops reading it. The refusal floor is unchanged.
     */
    public function test_a_non_text_pair_warns_at_three_not_four_point_five(): void
    {
        $this->assertSame(3.0, ContrastRole::NonText->warnBelow());
        $this->assertSame(3.0, ContrastRole::NonText->refuseBelow());
        $this->assertSame(4.5, ContrastRole::Text->warnBelow());
        $this->assertSame(3.0, ContrastRole::Text->refuseBelow());

        $defaults = $this->grammar->defaults();
        $light = $this->scheme($defaults, ColourScheme::Light);

        /*
         * A ring conforming to SC 1.4.11 and below 4.5:1 against **both**
         * surfaces the matrix pairs it with — 4.03:1 on the page and 3.77:1 on
         * the raised surface. Chosen for both, because picking it for one is
         * how the first version of this test asserted the wrong thing.
         */
        $light['color.focus.ring'] = $this->grammar->value(TokenRegistry::get('color.focus.ring'), '#777f8d');

        $report = ContrastGate::judge($light, $this->scheme($defaults, ColourScheme::Dark));

        foreach ($report->findings as $finding) {
            if ($finding->foreground === 'color.focus.ring' && $finding->scheme === ColourScheme::Light) {
                $this->assertSame(ContrastVerdict::Pass, $finding->verdict, $finding->describe());
            }
        }
    }

    /** The report carries §8.14.5's honesty about its own limits. */
    public function test_the_report_states_its_limits(): void
    {
        $report = $this->judgeWithPrimaryText('#16191f');

        $this->assertSame(ContrastMatrix::LIMITS, $report->toArray()['limits']);
        $this->assertNotSame([], ContrastMatrix::LIMITS);
    }

    /** The light-scheme finding for body copy on the page. */
    private function pageFinding(ContrastReport $report): ContrastFinding
    {
        foreach ($report->findings as $finding) {
            if (
                $finding->foreground === 'color.text.primary'
                && $finding->background === 'color.surface.page'
                && $finding->scheme === ColourScheme::Light
            ) {
                return $finding;
            }
        }

        $this->fail('the matrix no longer judges body copy on the page');
    }

    private function ratioOf(string $foreground, string $background): float
    {
        $token = TokenRegistry::get('color.text.primary');

        $first = $this->grammar->value($token, $foreground);
        $second = $this->grammar->value($token, $background);

        /*
         * Narrowed rather than asserted away: `srgb()` is ColourValue's and
         * the grammar returns the TokenValue interface, so a colour token that
         * stopped being a colour would fail here loudly instead of at a
         * missing method.
         */
        $this->assertInstanceOf(ColourValue::class, $first);
        $this->assertInstanceOf(ColourValue::class, $second);

        return ContrastGate::ratio($first->srgb(), $second->srgb());
    }

    /**
     * The default theme with `color.text.primary` replaced in the light scheme.
     *
     * The page background stays `#ffffff`, which is what makes the two
     * fixtures' arithmetic the arithmetic of the pair under test.
     */
    private function judgeWithPrimaryText(string $light): ContrastReport
    {
        $defaults = $this->grammar->defaults();
        $lightValues = $this->scheme($defaults, ColourScheme::Light);
        $lightValues['color.text.primary'] = $this->grammar->value(
            TokenRegistry::get('color.text.primary'),
            $light,
        );

        return ContrastGate::judge($lightValues, $this->scheme($defaults, ColourScheme::Dark));
    }

    /**
     * @param  array<string, TokenPair>  $pairs
     * @return array<string, TokenValue>
     */
    private function scheme(array $pairs, ColourScheme $scheme): array
    {
        $values = [];

        foreach ($pairs as $name => $pair) {
            $values[$name] = $pair->for($scheme);
        }

        return $values;
    }
}
