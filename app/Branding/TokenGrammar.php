<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

use App\Branding\Values\AssetReferenceValue;
use App\Branding\Values\ColourValue;
use App\Branding\Values\CountValue;
use App\Branding\Values\FlagValue;
use App\Branding\Values\FontStackValue;
use App\Branding\Values\LengthValue;
use App\Branding\Values\OptionValue;
use App\Branding\Values\OriginListValue;
use App\Branding\Values\RatioValue;
use App\Branding\Values\ShortTextValue;
use App\Branding\Values\TokenValue;

/**
 * 🛑 §8.14.2's single parse site: "Validation MUST be a **grammar, not a
 * filter**".
 *
 * Every branding value in DocUp passes through {@see self::value()}. Not "every
 * value an API accepts" — every value, including a value read back out of the
 * database, because §8.14.2's second clause is that "Every emitted value MUST
 * be **re-serialised from the parsed representation**, never echoed from
 * storage". A stored value is a value whose parser has not run yet.
 *
 * ## The difference a grammar makes
 *
 * A filter answers "does this look dangerous?", which is a question about the
 * attacker's imagination. A grammar answers "is this one of the things I can
 * construct?", which is a question about DocUp. The first has to be updated
 * every time somebody thinks of a new encoding; the second does not.
 *
 * {@see ForbiddenFunctions} looks like a filter and is not the defence — it
 * runs first so the *rejection identifier* names the reason, which is what
 * §17's exit criterion asks for. The defence is that there is no production in
 * any grammar here that can express a function call.
 *
 * ## 🛑 Four checks, in this order, and the order is the design
 *
 * 1. **Is the key in the registry?** (§8.14.1's "unknown keys rejected")
 * 2. **May this level set it?** (§8.14.1's cascade; §8.14.8's installation-only
 *    surfaces expressed as {@see BrandingToken::$deepest})
 * 3. **Is a lock in force above it?** — {@see ThemeLocks}, checked by the
 *    caller, because a lock is a fact about the cascade and not about a value
 * 4. **Does the value parse?**
 *
 * Checking the key first means an unknown key never reaches a parser, and a
 * typo gets a rejection that names the typo rather than a grammar error about a
 * token that does not exist.
 */
final readonly class TokenGrammar
{
    /**
     * @param  list<string>  $fontCatalogue  the installation's self-hosted families
     */
    public function __construct(
        private AssetLookup $assets,
        private array $fontCatalogue,
    ) {}

    /**
     * Parse one authored token map for one cascade level.
     *
     * The authored shape is `{"<name>": <scalar>}` for an unpaired token and
     * `{"<name>": {"light": <scalar>, "dark": <scalar>}}` for a paired one. A
     * paired token given a scalar takes that value in both schemes, which is
     * the right spelling for a brand colour that must not change; an unpaired
     * token given an object is refused, because a per-scheme font would be a
     * feature nothing in §8.14 asks for and the stylesheet would not emit it.
     *
     * @param  array<array-key, mixed>  $authored
     * @return array<string, TokenPair>
     *
     * @throws TokenRefused
     */
    public function parseAll(array $authored, CascadeLevel $level): array
    {
        $parsed = [];

        foreach ($authored as $name => $value) {
            $name = (string) $name;
            $token = TokenRegistry::get($name);

            if (! $token->settableAt($level)) {
                throw TokenRefused::of(
                    TokenRejection::ScopeTooDeep,
                    $name,
                    sprintf('settable at %s; this is %s', $token->levelLabel(), $level->value),
                );
            }

            $parsed[$name] = $this->pair($token, $value);
        }

        return $parsed;
    }

    /**
     * The registry's own defaults, parsed. The root of every cascade.
     *
     * 🛑 Parsed rather than trusted, and the whole suite depends on it: a
     * default that did not satisfy its own grammar would be a theme that could
     * not be edited, because the first save would re-parse it and refuse.
     * `TokenRegistryTest` asserts this for all forty-five.
     *
     * @return array<string, TokenPair>
     *
     * @throws TokenRefused
     */
    public function defaults(): array
    {
        $parsed = [];

        foreach (TokenRegistry::all() as $name => $token) {
            /*
             * An asset token's default is the empty string: there is no
             * installation logo until an operator uploads one. An empty asset
             * reference is "unset", which the chrome payload renders as the
             * wordmark — so it is skipped rather than parsed, because
             * AssetReferenceValue correctly refuses an empty id.
             */
            if ($token->type === TokenType::Asset && $token->default === '') {
                continue;
            }

            if ($token->type === TokenType::Text && $token->default === '') {
                continue;
            }

            $parsed[$name] = new TokenPair(
                $this->value($token, $token->default),
                $this->value($token, $token->dark ?? $token->default),
            );
        }

        return $parsed;
    }

    /**
     * Parse one value for one token.
     *
     * @throws TokenRefused
     */
    public function value(BrandingToken $token, string $raw): TokenValue
    {
        /*
         * 🛑 First, before any grammar. See the class docblock: this is the
         * diagnosis, not the defence, and running it first is what makes §17's
         * exit criterion a test about the control rather than about luck.
         *
         * {@see TokenType::refusesCssFunctions()} carries the one exception
         * and the reason for it — an origin list is not a CSS value, and every
         * `https://` URL contains the sequence a CSS comment opens with.
         */
        if ($token->type->refusesCssFunctions()) {
            ForbiddenFunctions::assertAbsent($raw, $token->name);
        }

        return match ($token->type) {
            TokenType::Colour => ColourValue::parse($raw, $token->name),
            TokenType::Length => LengthValue::parse($raw, $token->name, $token->minimum, $token->maximum),
            TokenType::Ratio => RatioValue::parse($raw, $token->name, $token->minimum, $token->maximum),
            TokenType::Count => CountValue::parse($raw, $token->name, (int) $token->minimum, (int) $token->maximum),
            TokenType::Flag => FlagValue::parse($raw, $token->name),
            TokenType::Option => OptionValue::parse($raw, $token->name, $token->options),
            TokenType::Text => ShortTextValue::parse($raw, $token->name, $token->maxLength),
            TokenType::FontStack => $this->fontStack($token, $raw),
            TokenType::Asset => $this->asset($token, $raw),
            TokenType::OriginList => OriginListValue::parse($raw, $token->name),
        };
    }

    /**
     * @param  mixed  $value  as it arrived from JSON or a form
     *
     * @throws TokenRefused
     */
    private function pair(BrandingToken $token, mixed $value): TokenPair
    {
        if (is_array($value)) {
            if (! $token->isPaired()) {
                throw TokenRefused::of(
                    TokenRejection::WrongType,
                    $token->name,
                    'this token has one value in both colour schemes',
                );
            }

            /*
             * 🛑 Unknown keys inside the pair are refused too. `{"light": …,
             * "ligth": …}` would otherwise save with a dark value silently
             * equal to light, which is §8.14.1's "unknown keys rejected"
             * failing one level down from where it was written.
             */
            foreach (array_keys($value) as $key) {
                if ($key !== 'light' && $key !== 'dark') {
                    throw TokenRefused::of(
                        TokenRejection::WrongType,
                        $token->name,
                        sprintf('a paired value has only "light" and "dark"; found "%s"', (string) $key),
                    );
                }
            }

            if (! array_key_exists('light', $value)) {
                throw TokenRefused::of(TokenRejection::WrongType, $token->name, 'a paired value needs "light"');
            }

            $light = $this->value($token, self::scalar($value['light'], $token->name));

            return array_key_exists('dark', $value)
                ? new TokenPair($light, $this->value($token, self::scalar($value['dark'], $token->name)))
                : TokenPair::same($light);
        }

        return TokenPair::same($this->value($token, self::scalar($value, $token->name)));
    }

    /**
     * 🛑 A scalar, coerced explicitly and never by PHP's own rules.
     *
     * `true` from JSON must become `"true"` and not `"1"`, because
     * {@see FlagValue} accepts both and only one of them round-trips through a
     * form. An integer must become its decimal text. An array or object has
     * already been handled; anything else — `null`, a resource — is a refusal,
     * because a token whose value is null is a token somebody meant to clear
     * and `null` is not how clearing is spelled.
     *
     * @throws TokenRefused
     */
    private static function scalar(mixed $value, string $path): string
    {
        return match (true) {
            is_string($value) => $value,
            is_bool($value) => $value ? 'true' : 'false',
            is_int($value) => (string) $value,
            is_float($value) => rtrim(rtrim(sprintf('%.4F', $value), '0'), '.'),
            default => throw TokenRefused::of(
                TokenRejection::WrongType,
                $path,
                'a token value is text, a number or a boolean; remove the key to clear it',
            ),
        };
    }

    /** @throws TokenRefused */
    private function fontStack(BrandingToken $token, string $raw): FontStackValue
    {
        $stack = FontStackValue::parse($raw, $token->name, $this->fontCatalogue);

        /*
         * 🛑 The asset handles are resolved here and not in the value object,
         * so an `asset:<id>` naming another organisation's font is refused
         * before the stylesheet mints a `@font-face` pointing at it. The value
         * object cannot do this: it has no scope.
         */
        foreach ($stack->assetHandles() as $handle) {
            $kind = $this->assets->kindOf($handle);

            if ($kind === null) {
                throw TokenRefused::of(TokenRejection::UnknownAsset, $token->name, 'asset:'.$handle);
            }

            if ($kind !== 'font') {
                throw TokenRefused::of(
                    TokenRejection::WrongAssetKind,
                    $token->name,
                    sprintf('asset:%s is a %s, not a font', $handle, $kind),
                );
            }
        }

        return $stack;
    }

    /** @throws TokenRefused */
    private function asset(BrandingToken $token, string $raw): AssetReferenceValue
    {
        $reference = AssetReferenceValue::parse($raw, $token->name);
        $kind = $this->assets->kindOf($reference->assetId);

        if ($kind === null) {
            throw TokenRefused::of(TokenRejection::UnknownAsset, $token->name, $reference->assetId);
        }

        if ($token->assetKind !== null && $kind !== $token->assetKind) {
            throw TokenRefused::of(
                TokenRejection::WrongAssetKind,
                $token->name,
                sprintf('expected a %s, found a %s', $token->assetKind, $kind),
            );
        }

        return $reference;
    }
}
