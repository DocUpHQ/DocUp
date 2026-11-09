<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\ColourValue;
use App\Branding\Values\TokenValue;

/**
 * 🛑 §8.14.5's contrast gate.
 *
 * > "WCAG 2.2 contrast MUST be computed over a fixed foreground/background
 * > matrix in both colour schemes at publish: warn below 4.5:1, **refuse
 * > publication below 3:1**, operator override audited. 🛑 The documentation
 * > MUST state honestly that this gate is a safety net and still permits
 * > shipping AA-failing themes."
 *
 * ## The one formula, and where it comes from
 *
 * WCAG 2.x defines relative luminance as a weighted sum of linearised sRGB
 * channels, and contrast as `(L_lighter + 0.05) / (L_darker + 0.05)`. Both are
 * reproduced here exactly, including the 0.04045 / 12.92 piecewise transfer
 * function — which is **not** the sRGB specification's own 0.03928 breakpoint.
 * WCAG's numbers are the normative ones for a conformance claim, so they are
 * the numbers used, and a reader comparing this against the sRGB standard
 * should not "fix" it.
 *
 * ## 🛑 Translucency
 *
 * A colour with alpha has no contrast ratio of its own. The gate composites it
 * over the pair's background, and composites a translucent *background* over
 * {@see ColourScheme::fallbackBackdrop()} — white in light, black in dark. Both
 * choices push the measured ratio down rather than up, so a translucent colour
 * is never flattered by the gate.
 *
 * ## What this class deliberately does not do
 *
 * It does not decide whether publication proceeds. {@see ContrastReport} says
 * what it found; {@see ThemeRevisions} decides, because the decision needs the
 * override and the audit event and this needs neither.
 */
final class ContrastGate
{
    /**
     * Judge one resolved token set, in both schemes.
     *
     * @param  array<string, TokenValue>  $light  resolved light-scheme values
     * @param  array<string, TokenValue>  $dark  resolved dark-scheme values
     */
    public static function judge(array $light, array $dark): ContrastReport
    {
        $findings = [];

        foreach (ColourScheme::both() as $scheme) {
            $values = $scheme === ColourScheme::Light ? $light : $dark;

            foreach (ContrastMatrix::pairs() as $pair) {
                $foreground = $values[$pair['foreground']] ?? null;
                $background = $values[$pair['background']] ?? null;

                /*
                 * 🛑 A missing or non-colour token is skipped rather than
                 * assumed. The resolver always supplies every registry token,
                 * so this can only happen if the matrix names a token the
                 * registry dropped — and `ContrastMatrixTest` asserts that it
                 * does not. Silently defaulting to black-on-white here would
                 * make that test unnecessary and the gate wrong.
                 */
                if (! $foreground instanceof ColourValue || ! $background instanceof ColourValue) {
                    continue;
                }

                $backdrop = $background->over($scheme->fallbackBackdrop());
                $ratio = self::ratio($foreground->over($backdrop), $backdrop);

                $findings[] = new ContrastFinding(
                    foreground: $pair['foreground'],
                    background: $pair['background'],
                    scheme: $scheme,
                    role: $pair['role'],
                    surface: $pair['surface'],
                    ratio: $ratio,
                    verdict: self::verdict($ratio, $pair['role']),
                );
            }
        }

        return new ContrastReport($findings);
    }

    /**
     * WCAG 2.2's contrast ratio between two opaque sRGB colours.
     *
     * @param  array{float, float, float}  $a  each channel 0-1, gamma-encoded
     * @param  array{float, float, float}  $b
     */
    public static function ratio(array $a, array $b): float
    {
        $first = self::relativeLuminance($a);
        $second = self::relativeLuminance($b);

        $lighter = max($first, $second);
        $darker = min($first, $second);

        return ($lighter + 0.05) / ($darker + 0.05);
    }

    /**
     * WCAG 2.2's relative luminance.
     *
     * @param  array{float, float, float}  $srgb  each channel 0-1, gamma-encoded
     */
    public static function relativeLuminance(array $srgb): float
    {
        return 0.2126 * self::linearise($srgb[0])
            + 0.7152 * self::linearise($srgb[1])
            + 0.0722 * self::linearise($srgb[2]);
    }

    /**
     * 🛑 §8.14.5's two thresholds, applied with {@see ContrastRole}'s reading.
     *
     * The comparison is `<` and not `<=`, so a pair at exactly 3.00:1 passes
     * the refusal and a pair at exactly 4.50:1 passes the warning. That is
     * WCAG's own reading of "at least", and it matters: a theme computed to
     * land exactly on the line is a theme somebody designed to the standard.
     */
    private static function verdict(float $ratio, ContrastRole $role): ContrastVerdict
    {
        if ($ratio < $role->refuseBelow()) {
            return ContrastVerdict::Refuse;
        }

        return $ratio < $role->warnBelow() ? ContrastVerdict::Warn : ContrastVerdict::Pass;
    }

    /**
     * 🛑 WCAG's piecewise transfer function, with WCAG's breakpoint.
     *
     * 0.04045 and 12.92 are the figures in the WCAG 2.x definition of relative
     * luminance. The sRGB standard itself uses 0.03928, and the two disagree in
     * the fourth decimal place over a range where nothing rounds differently —
     * but a conformance claim is made against WCAG, so WCAG's constants are the
     * ones that belong in a gate that reports WCAG ratios.
     */
    private static function linearise(float $channel): float
    {
        $channel = max(0.0, min(1.0, $channel));

        return $channel <= 0.04045
            ? $channel / 12.92
            : (($channel + 0.055) / 1.055) ** 2.4;
    }
}
