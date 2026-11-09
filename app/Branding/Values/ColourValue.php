<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\ContrastGate;
use App\Branding\ForbiddenFunctions;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 §8.14.2's colour grammar: a parser, not a filter.
 *
 * > "Colours accept only `#rgb|#rrggbb|#rrggbbaa|rgb()|hsl()|oklch()` with
 * > bounded numerics — no `var()`, `url()`, `env()`, `attr()`, `calc()`."
 *
 * ## The two things this class exists to make possible
 *
 * 1. **Re-serialisation** (§8.14.2). The value is held as components and
 *    {@see self::serialise()} builds CSS from them, so nothing an operator
 *    typed reaches a stylesheet.
 * 2. **sRGB, for the contrast gate** (§8.14.5). {@see self::srgb()} is why the
 *    notation list is closed: a colour the gate cannot reduce to sRGB is a
 *    colour the gate skips.
 *
 * ## 🛑 The authored notation is kept
 *
 * A colour written `oklch(62% 0.21 29)` serialises as `oklch(...)`, not as the
 * `#rrggbb` its sRGB reduction would give. Two reasons: OKLCH covers colours
 * sRGB cannot express, so normalising to hex would quietly change what a
 * wide-gamut display shows; and an operator who typed OKLCH and read back hex
 * would reasonably conclude the system had not understood them.
 *
 * The sRGB reduction is therefore the gate's view of the colour rather than the
 * stored one, and {@see ContrastGate} says what that costs.
 */
final readonly class ColourValue implements TokenValue
{
    /**
     * 🛑 The chroma ceiling, which is what "bounded numerics" means for OKLCH.
     *
     * OKLCH chroma is unbounded in the specification: `oklch(60% 400 30)` is
     * syntactically fine and is a colour no display can show, which clamps to
     * a gamut edge after conversion. 0.5 is comfortably outside the sRGB gamut
     * at every lightness and inside what a P3 display reaches, so it refuses
     * nonsense without refusing wide-gamut intent.
     */
    private const float OKLCH_MAX_CHROMA = 0.5;

    /**
     * @param  list<float>  $components  in the authored notation's own units:
     *                                   0-255 for every hex form and for
     *                                   `rgb()`, degrees and percentages for
     *                                   `hsl()`, L (0-1), C and H for `oklch()`
     * @param  float  $alpha  0-1
     */
    private function __construct(
        public ColourForm $form,
        public array $components,
        public float $alpha,
    ) {}

    /**
     * Parse one colour, or refuse it.
     *
     * @param  string  $raw  as the operator wrote it
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path): self
    {
        $raw = trim($raw);

        ForbiddenFunctions::assertAbsent($raw, $path);

        if ($raw === '') {
            throw TokenRefused::of(TokenRejection::UnsupportedColourForm, $path, 'empty');
        }

        if ($raw[0] === '#') {
            return self::parseHex($raw, $path);
        }

        $lower = strtolower($raw);

        foreach (['rgb' => ColourForm::Rgb, 'hsl' => ColourForm::Hsl, 'oklch' => ColourForm::Oklch] as $name => $form) {
            if (str_starts_with($lower, $name.'(')) {
                return self::parseFunction($form, $lower, $name, $path);
            }
        }

        /*
         * 🛑 Named keywords land here, and refusing them is deliberate. `red`
         * is harmless; `currentcolor` inherits a value from a cascade DocUp
         * does not control, and the keyword set is a hundred-odd names whose
         * sRGB values DocUp would have to table to run the contrast gate. One
         * closed list of notations is cheaper to keep right than two.
         */
        throw TokenRefused::of(
            TokenRejection::UnsupportedColourForm,
            $path,
            'accepted forms are #rgb, #rrggbb, #rrggbbaa, rgb(), hsl() and oklch()',
        );
    }

    /**
     * 🛑 §8.14.2's re-serialisation: built from the components, every time.
     *
     * Modern CSS syntax for the functional forms — space separated, with
     * `/ alpha` — because it is what every target browser of a 2026 release
     * parses and because one output shape means one thing to review.
     */
    public function serialise(): string
    {
        [$a, $b, $c] = [$this->components[0], $this->components[1], $this->components[2]];

        return match ($this->form) {
            ColourForm::HexShort, ColourForm::Hex => sprintf(
                '#%02x%02x%02x',
                (int) round($a),
                (int) round($b),
                (int) round($c),
            ),
            ColourForm::HexAlpha => sprintf(
                '#%02x%02x%02x%02x',
                (int) round($a),
                (int) round($b),
                (int) round($c),
                (int) round($this->alpha * 255),
            ),
            ColourForm::Rgb => $this->isOpaque()
                ? sprintf('rgb(%d %d %d)', (int) round($a), (int) round($b), (int) round($c))
                : sprintf(
                    'rgb(%d %d %d / %s)',
                    (int) round($a),
                    (int) round($b),
                    (int) round($c),
                    self::number($this->alpha),
                ),
            ColourForm::Hsl => $this->isOpaque()
                ? sprintf('hsl(%s %s%% %s%%)', self::number($a), self::number($b), self::number($c))
                : sprintf(
                    'hsl(%s %s%% %s%% / %s)',
                    self::number($a),
                    self::number($b),
                    self::number($c),
                    self::number($this->alpha),
                ),
            ColourForm::Oklch => $this->isOpaque()
                ? sprintf('oklch(%s %s %s)', self::number($a), self::number($b), self::number($c))
                : sprintf(
                    'oklch(%s %s %s / %s)',
                    self::number($a),
                    self::number($b),
                    self::number($c),
                    self::number($this->alpha),
                ),
        };
    }

    public function toStorage(): string
    {
        return $this->serialise();
    }

    /**
     * The colour as sRGB, each channel 0-1, for {@see ContrastGate}.
     *
     * Alpha is **not** applied: a translucent colour has no contrast ratio of
     * its own, so compositing is the gate's job and the gate is the side that
     * knows the backdrop. {@see self::over()} is how.
     *
     * @return array{float, float, float}
     */
    public function srgb(): array
    {
        [$a, $b, $c] = [$this->components[0], $this->components[1], $this->components[2]];

        return match ($this->form) {
            ColourForm::HexShort,
            ColourForm::Hex,
            ColourForm::HexAlpha,
            ColourForm::Rgb => [$a / 255, $b / 255, $c / 255],
            ColourForm::Hsl => self::hslToSrgb($a, $b / 100, $c / 100),
            ColourForm::Oklch => self::oklchToSrgb($a, $b, $c),
        };
    }

    /**
     * This colour composited over an opaque backdrop, as sRGB 0-1.
     *
     * 🛑 Source-over in **gamma-encoded** sRGB, which is what a browser does
     * when it paints one `background-color` over another. Compositing in
     * linear light would be more correct physically and would not match what
     * the reader sees — and matching the reader is the entire purpose of a
     * contrast measurement.
     *
     * @param  array{float, float, float}  $backdrop
     * @return array{float, float, float}
     */
    public function over(array $backdrop): array
    {
        $source = $this->srgb();

        if ($this->isOpaque()) {
            return $source;
        }

        return [
            $source[0] * $this->alpha + $backdrop[0] * (1 - $this->alpha),
            $source[1] * $this->alpha + $backdrop[1] * (1 - $this->alpha),
            $source[2] * $this->alpha + $backdrop[2] * (1 - $this->alpha),
        ];
    }

    public function isOpaque(): bool
    {
        return $this->alpha >= 1.0;
    }

    /** @throws TokenRefused */
    private static function parseHex(string $raw, string $path): self
    {
        $digits = substr($raw, 1);

        /*
         * 🛑 Exactly the three forms §8.14.2 names. `#rgba` — the four-digit
         * short form with alpha — is legal CSS and is absent here, because the
         * requirement lists three and being stricter than an allowlist is the
         * one direction that is always safe.
         */
        if (preg_match('/^(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/', $digits) !== 1) {
            throw TokenRefused::of(
                TokenRejection::UnsupportedColourForm,
                $path,
                'a hex colour is #rgb, #rrggbb or #rrggbbaa',
            );
        }

        $digits = strtolower($digits);

        if (strlen($digits) === 3) {
            return new self(ColourForm::HexShort, [
                (float) hexdec($digits[0].$digits[0]),
                (float) hexdec($digits[1].$digits[1]),
                (float) hexdec($digits[2].$digits[2]),
            ], 1.0);
        }

        $components = [
            (float) hexdec(substr($digits, 0, 2)),
            (float) hexdec(substr($digits, 2, 2)),
            (float) hexdec(substr($digits, 4, 2)),
        ];

        if (strlen($digits) === 6) {
            return new self(ColourForm::Hex, $components, 1.0);
        }

        return new self(ColourForm::HexAlpha, $components, hexdec(substr($digits, 6, 2)) / 255);
    }

    /**
     * Parse `rgb(...)`, `hsl(...)` or `oklch(...)`.
     *
     * 🛑 Legacy comma syntax and modern space syntax are both accepted, with
     * the separators normalised before the components are read. Refusing the
     * comma form would refuse what every design tool still exports, and the
     * two forms differ in punctuation rather than in meaning.
     *
     * @throws TokenRefused
     */
    private static function parseFunction(ColourForm $form, string $lower, string $name, string $path): self
    {
        if (! str_ends_with($lower, ')')) {
            throw TokenRefused::of(TokenRejection::UnsupportedColourForm, $path, $name.'() is unterminated');
        }

        $inner = substr($lower, strlen($name) + 1, -1);

        /*
         * The modern alpha separator. Split first, because in the legacy comma
         * form the alpha is simply a fourth component.
         */
        $parts = explode('/', $inner);

        if (count($parts) > 2) {
            throw TokenRefused::of(TokenRejection::UnsupportedColourForm, $path, 'more than one alpha separator');
        }

        $components = self::split($parts[0], $path);
        $alphaText = $parts[1] ?? null;

        if (count($components) === 4 && $alphaText === null) {
            $alphaText = array_pop($components);
        }

        if (count($components) !== 3) {
            throw TokenRefused::of(
                TokenRejection::UnsupportedColourForm,
                $path,
                $name.'() takes three components and an optional alpha',
            );
        }

        $alpha = $alphaText === null ? 1.0 : self::alpha(trim($alphaText), $path);

        $parsed = match ($form) {
            ColourForm::Rgb => [
                self::channel($components[0], $path),
                self::channel($components[1], $path),
                self::channel($components[2], $path),
            ],
            ColourForm::Hsl => [
                self::bounded($components[0], -360, 360, $path, 'hue'),
                self::percentage($components[1], $path, 'saturation'),
                self::percentage($components[2], $path, 'lightness'),
            ],
            ColourForm::Oklch => [
                self::oklchLightness($components[0], $path),
                self::bounded($components[1], 0, self::OKLCH_MAX_CHROMA, $path, 'chroma'),
                self::bounded($components[2], -360, 360, $path, 'hue'),
            ],
            default => throw TokenRefused::of(TokenRejection::UnsupportedColourForm, $path, 'not a function form'),
        };

        return new self($form, $parsed, $alpha);
    }

    /**
     * @return list<string>
     *
     * @throws TokenRefused
     */
    private static function split(string $inner, string $path): array
    {
        $parts = preg_split('/\s+/', trim(str_replace(',', ' ', $inner)), -1, PREG_SPLIT_NO_EMPTY);

        if ($parts === false || $parts === []) {
            throw TokenRefused::of(TokenRejection::UnsupportedColourForm, $path, 'no components');
        }

        return $parts;
    }

    /**
     * An `rgb()` channel: 0-255, or a percentage of it.
     *
     * @throws TokenRefused
     */
    private static function channel(string $text, string $path): float
    {
        if (str_ends_with($text, '%')) {
            return self::percentage($text, $path, 'channel') * 255 / 100;
        }

        return self::bounded($text, 0, 255, $path, 'channel');
    }

    /** @throws TokenRefused */
    private static function percentage(string $text, string $path, string $what): float
    {
        if (! str_ends_with($text, '%')) {
            throw TokenRefused::of(TokenRejection::NumericOutOfRange, $path, $what.' must be a percentage');
        }

        return self::bounded(substr($text, 0, -1), 0, 100, $path, $what);
    }

    /**
     * OKLCH lightness: `0`-`1` or `0%`-`100%`, normalised to 0-1.
     *
     * @throws TokenRefused
     */
    private static function oklchLightness(string $text, string $path): float
    {
        if (str_ends_with($text, '%')) {
            return self::bounded(substr($text, 0, -1), 0, 100, $path, 'lightness') / 100;
        }

        return self::bounded($text, 0, 1, $path, 'lightness');
    }

    /** @throws TokenRefused */
    private static function alpha(string $text, string $path): float
    {
        if (str_ends_with($text, '%')) {
            return self::bounded(substr($text, 0, -1), 0, 100, $path, 'alpha') / 100;
        }

        return self::bounded($text, 0, 1, $path, 'alpha');
    }

    /**
     * A plain decimal in range, or a refusal.
     *
     * 🛑 The pattern refuses exponents, a leading `+`, hex and `NaN`/`INF`.
     * PHP's `is_numeric` accepts `1e3` and `0x1A` and CSS does not, so a value
     * DocUp accepted and a browser ignored would make the stylesheet silently
     * lose a token — a theme that looked saved and did nothing.
     *
     * @throws TokenRefused
     */
    private static function bounded(string $text, float $min, float $max, string $path, string $what): float
    {
        if (preg_match('/^-?(?:\d+(?:\.\d+)?|\.\d+)$/', $text) !== 1) {
            throw TokenRefused::of(TokenRejection::NumericOutOfRange, $path, $what.' is not a plain decimal');
        }

        $value = (float) $text;

        if ($value < $min || $value > $max) {
            throw TokenRefused::of(
                TokenRejection::NumericOutOfRange,
                $path,
                sprintf('%s %s is outside %s to %s', $what, $text, self::number($min), self::number($max)),
            );
        }

        return $value;
    }

    /** Trim a float to the shortest text that reads as the same number. */
    private static function number(float $value): string
    {
        $text = rtrim(rtrim(sprintf('%.4F', $value), '0'), '.');

        return $text === '' || $text === '-' ? '0' : $text;
    }

    /**
     * HSL to sRGB, each out channel 0-1.
     *
     * @return array{float, float, float}
     */
    private static function hslToSrgb(float $hue, float $saturation, float $lightness): array
    {
        $hue = fmod(fmod($hue, 360) + 360, 360);

        $chroma = (1 - abs(2 * $lightness - 1)) * $saturation;
        $segment = $hue / 60;
        $second = $chroma * (1 - abs(fmod($segment, 2) - 1));
        $match = $lightness - $chroma / 2;

        [$red, $green, $blue] = match ((int) floor($segment) % 6) {
            0 => [$chroma, $second, 0.0],
            1 => [$second, $chroma, 0.0],
            2 => [0.0, $chroma, $second],
            3 => [0.0, $second, $chroma],
            4 => [$second, 0.0, $chroma],
            default => [$chroma, 0.0, $second],
        };

        return [$red + $match, $green + $match, $blue + $match];
    }

    /**
     * OKLCH to gamma-encoded sRGB, clamped to the gamut.
     *
     * 🛑 **Clamped per channel, which is not gamut mapping.** A colour outside
     * sRGB comes back as the nearest value on each axis independently, which
     * shifts hue. For the contrast gate that is acceptable and conservative in
     * the direction that matters: clamping moves a channel toward 0 or 1, so an
     * out-of-gamut colour is measured as more extreme in luminance than the
     * display will actually show. The gate therefore judges such a colour at
     * least as favourably as the reader sees it, never more favourably. Proper
     * chroma reduction would make the gate's numbers depend on a gamut-mapping
     * algorithm nobody reviewed.
     *
     * The coefficients are Björn Ottosson's published OKLab matrices.
     *
     * @return array{float, float, float}
     */
    private static function oklchToSrgb(float $lightness, float $chroma, float $hue): array
    {
        $radians = deg2rad($hue);
        $a = $chroma * cos($radians);
        $b = $chroma * sin($radians);

        $long = ($lightness + 0.3963377774 * $a + 0.2158037573 * $b) ** 3;
        $medium = ($lightness - 0.1055613458 * $a - 0.0638541728 * $b) ** 3;
        $short = ($lightness - 0.0894841775 * $a - 1.2914855480 * $b) ** 3;

        return [
            self::gammaEncode(4.0767416621 * $long - 3.3077115913 * $medium + 0.2309699292 * $short),
            self::gammaEncode(-1.2684380046 * $long + 2.6097574011 * $medium - 0.3413193965 * $short),
            self::gammaEncode(-0.0041960863 * $long - 0.7034186147 * $medium + 1.7076147010 * $short),
        ];
    }

    /** Linear light through the sRGB transfer function, clamped to 0-1. */
    private static function gammaEncode(float $linear): float
    {
        $linear = max(0.0, min(1.0, $linear));

        return $linear <= 0.0031308
            ? $linear * 12.92
            : 1.055 * $linear ** (1 / 2.4) - 0.055;
    }
}
