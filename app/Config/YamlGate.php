<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * §8.4.9's hard caps, applied to the **bytes** before any parser runs.
 *
 * > "The system MUST parse configuration **outside any sandbox** under hard
 * > caps: ≤256 KiB, nesting depth ≤32, YAML aliases disabled, single
 * > document, validated against a published JSON Schema."
 *
 * 🛑 **The ordering is the whole defence, exactly as §8.9.6's is.** Every
 * check here is answered from a scan of the input with no structure built, so
 * a 200 MB file is refused in the time it takes to read its length and an
 * alias bomb is refused on sight of the `*`. Move any of this after the parse
 * and the cap becomes a description of what the parser already survived.
 *
 * 🛑 **Aliases are refused rather than disabled, because there is no switch.**
 * `symfony/yaml` resolves anchors and aliases unconditionally and exposes no
 * option to turn them off, so "YAML aliases disabled" is implemented as
 * "a document containing one is not a document we accept". That is also the
 * better behaviour: an author whose aliases were silently ignored would get a
 * build from configuration that does not say what they wrote.
 *
 * The scan is a small state machine rather than a set of regular expressions
 * because `&` and `*` are ordinary characters inside shell commands —
 * `make -j2 && make html`, `rm -rf build/*` — and a pattern that flagged
 * those would refuse half the real configuration files in existence. YAML's
 * own rule is used instead: an anchor or an alias is only one when it begins
 * a **node**, which is the first non-space character after `:`, `-`, `[`, `{`
 * or `,`, or at the start of a line's content.
 */
final class YamlGate
{
    /**
     * Refuse the document, or return it unchanged.
     *
     * @throws ConfigRefused
     */
    public static function admit(string $yaml): string
    {
        // 1. Size. First because it is the only check whose cost does not
        //    depend on the size of the input.
        if (strlen($yaml) > ConfigRejection::MAX_BYTES) {
            throw ConfigRefused::of(
                ConfigRejection::TooLarge,
                strlen($yaml).' bytes, limit '.ConfigRejection::MAX_BYTES,
            );
        }

        // 2. One linear pass for aliases, document separators and depth.
        //    Separate methods would mean three passes over the same bytes for
        //    no gain in clarity; the state machine has to track quoting for
        //    all three anyway.
        self::scan($yaml);

        return $yaml;
    }

    /**
     * The single pass.
     *
     * @throws ConfigRefused
     */
    private static function scan(string $yaml): void
    {
        $lines = preg_split('/\R/', $yaml);

        if ($lines === false) {
            throw ConfigRefused::of(ConfigRejection::Unparseable, 'the file is not valid text');
        }

        $documents = 0;
        $indents = [];          // the monotonic stack of block indent levels
        $maxDepth = 0;
        $blockScalarIndent = null;   // inside a `|` or `>` literal, and at what indent

        foreach ($lines as $number => $line) {
            $content = ltrim($line, " \t");
            $indent = strlen($line) - strlen($content);

            /*
             * A literal or folded block scalar's body is TEXT, not structure.
             * Counting its indentation as nesting would refuse a legitimate
             * file whose `build.jobs` holds a shell script with deeply
             * indented conditionals — which is a real shape, not a contrived
             * one, and failing it would be the kind of false refusal that
             * makes people patch the check out.
             */
            if ($blockScalarIndent !== null) {
                if ($content === '' || $indent > $blockScalarIndent) {
                    continue;
                }

                $blockScalarIndent = null;
            }

            if ($content === '' || str_starts_with($content, '#')) {
                continue;
            }

            /*
             * §8.4.9: "single document".
             *
             * 🛑 A leading `---` is idiomatic and allowed; what is refused is
             * a separator that opens a document after something has already
             * been in one. Counting separators alone would accept
             * `a: 1` / `---` / `b: 2` — two documents with one separator,
             * which is exactly the case that matters, because the second
             * document's keys would never be seen by anything.
             */
            if ($content === '---' || str_starts_with($content, '--- ')) {
                $documents++;

                if ($documents > 1 || $indents !== []) {
                    throw ConfigRefused::of(
                        ConfigRejection::MultipleDocuments,
                        'line '.($number + 1),
                    );
                }

                continue;
            }

            while ($indents !== [] && $indent <= end($indents)) {
                array_pop($indents);
            }

            $indents[] = $indent;

            $inspection = self::inspectLine($content, $number + 1);

            $maxDepth = max($maxDepth, count($indents) + $inspection['flow'] + $inspection['inline']);

            if ($maxDepth > ConfigRejection::MAX_DEPTH) {
                throw ConfigRefused::of(
                    ConfigRejection::TooDeep,
                    'depth '.$maxDepth.' at line '.($number + 1).', limit '.ConfigRejection::MAX_DEPTH,
                );
            }

            if ($inspection['block_scalar']) {
                $blockScalarIndent = $indent;
            }
        }
    }

    /**
     * One line, outside any block scalar.
     *
     * Returns the deepest flow nesting reached on the line, how many inline
     * sequence indicators precede the first real node (`- - - x` is three
     * levels on one line), and whether the line opens a block scalar.
     *
     * @return array{flow: int, inline: int, block_scalar: bool}
     *
     * @throws ConfigRefused on an anchor or an alias
     */
    private static function inspectLine(string $content, int $lineNumber): array
    {
        $length = strlen($content);
        $flow = 0;
        $maxFlow = 0;
        $inline = 0;
        $countingInline = true;
        $blockScalar = false;

        // True while the next non-space character would begin a YAML node.
        // At the start of a line's content it always does.
        $atNodeStart = true;

        for ($i = 0; $i < $length; $i++) {
            $char = $content[$i];

            if ($char === ' ' || $char === "\t") {
                continue;
            }

            if ($char === '#' && ($i === 0 || $content[$i - 1] === ' ' || $content[$i - 1] === "\t")) {
                break;      // a comment: nothing after it is structure
            }

            if ($char === "'" || $char === '"') {
                $i = self::skipQuoted($content, $i, $char);
                $atNodeStart = false;
                $countingInline = false;

                continue;
            }

            if ($atNodeStart && ($char === '&' || $char === '*')) {
                $next = $content[$i + 1] ?? '';

                // An anchor or alias name is at least one character and does
                // not start with a space — `- *base` is an alias, `- rm *` is
                // a scalar whose node began at `r`.
                if ($next !== '' && $next !== ' ' && $next !== "\t") {
                    throw ConfigRefused::of(
                        ConfigRejection::AliasesForbidden,
                        ($char === '&' ? 'anchor' : 'alias').' at line '.$lineNumber,
                    );
                }
            }

            if ($char === '[' || $char === '{') {
                $flow++;
                $maxFlow = max($maxFlow, $flow);
                $atNodeStart = true;
                $countingInline = false;

                continue;
            }

            if ($char === ']' || $char === '}') {
                $flow = max(0, $flow - 1);
                $atNodeStart = false;

                continue;
            }

            if ($char === ',' && $flow > 0) {
                $atNodeStart = true;

                continue;
            }

            if ($char === '-' && $flow === 0 && (($content[$i + 1] ?? ' ') === ' ')) {
                // A block sequence indicator. Several on one line are several
                // levels of nesting, which is the one way a single line can
                // deepen the block structure.
                if ($countingInline) {
                    $inline++;
                }

                $atNodeStart = true;

                continue;
            }

            if ($char === ':' && (($content[$i + 1] ?? ' ') === ' ' || $i === $length - 1)) {
                $atNodeStart = true;
                $countingInline = false;

                continue;
            }

            if (($char === '|' || $char === '>') && self::opensBlockScalar($content, $i)) {
                $blockScalar = true;

                break;
            }

            $atNodeStart = false;
            $countingInline = false;
        }

        return ['flow' => $maxFlow, 'inline' => $inline, 'block_scalar' => $blockScalar];
    }

    /**
     * Is this `|` or `>` a block-scalar indicator rather than a character in
     * a scalar?
     *
     * It is one only at the end of the line, optionally followed by a chomping
     * or indentation indicator — `|`, `|-`, `>+`, `|2`. A `|` in the middle of
     * `make html | tee log` is not one, and treating it as one would swallow
     * the rest of the file.
     */
    private static function opensBlockScalar(string $content, int $position): bool
    {
        $rest = trim(substr($content, $position + 1));

        return $rest === '' || preg_match('/^[+-]?\d?[+-]?$/', $rest) === 1;
    }

    /**
     * Skip a quoted scalar, returning the index of its closing quote.
     *
     * Single quotes escape by doubling (`''`); double quotes escape with a
     * backslash. Getting this wrong in either direction matters: treat a
     * closing quote as an opening one and the rest of the file is "inside a
     * string", and every alias in it goes unseen.
     */
    private static function skipQuoted(string $content, int $start, string $quote): int
    {
        $length = strlen($content);

        for ($i = $start + 1; $i < $length; $i++) {
            if ($quote === '"' && $content[$i] === '\\') {
                $i++;

                continue;
            }

            if ($content[$i] !== $quote) {
                continue;
            }

            if ($quote === "'" && ($content[$i + 1] ?? '') === "'") {
                $i++;

                continue;
            }

            return $i;
        }

        // Unterminated. The parser will say so with a line number; returning
        // the end of the line here just stops this scan from looping.
        return $length - 1;
    }

    /**
     * The exact depth of the parsed structure.
     *
     * Belt and braces to {@see scan()}'s lexical estimate, which is
     * deliberately conservative and can only over-count. This runs on a value
     * that is already known to be under 256 KiB with no aliases, so it cannot
     * be made to recurse further than the document actually nests.
     */
    public static function depthOf(mixed $value, int $depth = 1): int
    {
        if (! is_array($value) || $value === []) {
            return $depth;
        }

        $deepest = $depth;

        foreach ($value as $child) {
            $deepest = max($deepest, self::depthOf($child, $depth + 1));
        }

        return $deepest;
    }
}
