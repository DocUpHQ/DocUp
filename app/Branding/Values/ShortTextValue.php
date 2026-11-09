<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Branding\TokenType;

/**
 * A short plain-text token — a wordmark, a copyright line, a banner sentence.
 *
 * 🛑 **`<` and `>` are refused outright**, which is stricter than escaping.
 * §8.14.3 makes chrome content structured data, "never free HTML", and
 * §8.14.8 refuses tenant raw HTML below installation scope — so a value
 * carrying an angle bracket is either an attempt at markup or a mistake, and
 * in neither case is it a brand name. Escaping on output would be correct and
 * would leave the decision in the renderer, where one template that forgot is
 * the whole defence gone. Refusing at the grammar means every renderer is
 * safe without knowing it.
 *
 * 🛑 **Control characters and the Unicode line separators are refused.**
 * U+2028 and U+2029 terminate a line inside a JavaScript string literal, and
 * these values reach the reader through a JSON chrome payload. The modern JSON
 * parsers tolerate them; a payload inlined into a `<script type="application/
 * json">` block by some future renderer would not, and the cost of refusing
 * them now is nothing.
 *
 * 🛑 **Bidirectional overrides are refused**, because a wordmark is rendered
 * beside DocUp's own interface chrome and an unterminated RLO reverses
 * everything after it — including text the operator wrote, not the tenant.
 * §9.5 requires RTL support, which is why the plain RTL marks and Arabic,
 * Hebrew and Persian text are all fine: it is the *override* and *isolate*
 * controls that leak out of the value, and a brand name needs none of them.
 */
final readonly class ShortTextValue implements TokenValue
{
    /**
     * The Unicode bidirectional formatting characters this type refuses.
     *
     * LRE, RLE, PDF, LRO, RLO and the three isolates plus their terminator.
     * Not the plain LRM/RLM/ALM marks, which affect one character's direction
     * and cannot escape the value.
     *
     * @var list<string>
     */
    private const BIDI_CONTROLS = [
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
    ];

    private function __construct(public string $text) {}

    /**
     * @param  string  $path  the token name, for the rejection
     * @param  int  $maximum  characters, not bytes
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, int $maximum): self
    {
        if (! mb_check_encoding($raw, 'UTF-8')) {
            throw TokenRefused::of(TokenRejection::TextRefused, $path, 'not valid UTF-8');
        }

        /*
         * Whitespace runs collapse to one space and the ends are trimmed. A
         * value differing from another only in trailing whitespace would mint
         * a second content-addressed stylesheet with identical bytes, which
         * costs an operator a cache miss for nothing.
         */
        $text = trim((string) preg_replace('/\s+/u', ' ', $raw));

        if (str_contains($text, '<') || str_contains($text, '>')) {
            throw TokenRefused::of(
                TokenRejection::MarkupRefused,
                $path,
                'angle brackets are refused: chrome content is structured data, never HTML (§8.14.3)',
            );
        }

        if (preg_match('/[\x00-\x1F\x7F]/u', $text) === 1) {
            throw TokenRefused::of(TokenRejection::TextRefused, $path, 'a control character');
        }

        foreach (["\u{2028}", "\u{2029}", ...self::BIDI_CONTROLS] as $forbidden) {
            if (str_contains($text, $forbidden)) {
                throw TokenRefused::of(
                    TokenRejection::TextRefused,
                    $path,
                    'a Unicode line separator or bidirectional override',
                );
            }
        }

        if (mb_strlen($text) > $maximum) {
            throw TokenRefused::of(
                TokenRejection::TextRefused,
                $path,
                sprintf('%d characters; the limit is %d', mb_strlen($text), $maximum),
            );
        }

        return new self($text);
    }

    /**
     * 🛑 The plain text, unescaped.
     *
     * Escaping belongs to the renderer that knows its context, and this type's
     * contract is that there is nothing in the value that needs escaping in
     * HTML text position. Nothing emits a text token into CSS:
     * {@see TokenType::emitsCss()} says which types the
     * stylesheet writer will take, and this is not one of them.
     */
    public function serialise(): string
    {
        return $this->text;
    }

    public function toStorage(): string
    {
        return $this->text;
    }
}
