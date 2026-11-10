<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * 🛑 §8.15.1 — two tags, inserted at **ingest**, never at serve time.
 *
 * §8.15.1: "Chrome MUST be injected into built HTML **at artifact ingest**,
 * before the pointer flip so direct uploads are covered, as exactly two
 * **project- and version-agnostic** tags before the first `</head>`: a deferred
 * script at a **stable, non-content-hashed** path, and
 * `<meta name="docup" content="b=<build_uuid>">`, whose content MUST carry the
 * build identifier and nothing else."
 *
 * Every clause there is load-bearing:
 *
 * - **At ingest, before the pointer flip**, so a direct upload (§8.21.6) gets
 *   chrome without the runner being involved.
 * - **Project- and version-agnostic**, because "baking project or version
 *   identifiers into HTML would destroy cross-project build reuse (§8.7.9) and
 *   make the theme stylesheet project-scoped in the artifact, defeating
 *   rebranding without rebuilding". The build id is permitted and is the only
 *   identifier present.
 * - **Non-content-hashed path**, because "hashing the loader path would orphan
 *   chrome on every historical artifact at each upgrade".
 * - **There is no serve-time rewriting anywhere in DocUp** (§4.3/2, §4.3/6,
 *   §8.9.8, §19/6). This class is the only thing that ever changes a
 *   documentation byte, and it runs before the bytes are stored.
 *
 * 🛑 **No parsing, ever** (§8.15.3): "Injection MUST NOT parse or re-serialise
 * third-party markup — a byte-level, **case-insensitive** search tolerating
 * whitespace before the delimiter (`</head\s*>`), because `</HEAD>` and
 * `</head >` are both legal and both occur, and a naive fixed-string search
 * produces false failures on valid documents."
 *
 * Re-serialising would also be the larger sin: a parser normalises a document,
 * and normalising attacker-supplied markup changes what a browser renders in
 * ways nobody reviewed.
 */
final class ChromeInjector
{
    /**
     * 🛑 Stamped on every build (§8.15.4), so a re-ingest job knows which
     * artifacts predate a change here.
     *
     * §8.15.4: "`builds.injector_version` MUST be stamped and a re-ingest job
     * MUST ship." Without the stamp, an upgrade that changes the tags has no
     * way to find the artifacts that still carry the old ones — and historical
     * artifacts are immutable, so the only remedy is a deliberate re-ingest of
     * a known set.
     *
     * 🛑 **2 since Phase 28**, and the bump is what this constant was for. The
     * tags did not change; the **insertion point** did. Version 1 inserted
     * before the first `</head>` wherever it appeared, including inside a
     * comment or inside a `<script>` string — see {@see self::headCloseAt()}
     * for the two documents that corrupts and why. An artifact stamped `1` may
     * carry either defect and only a re-ingest can fix it, which is
     * `docup:reingest-chrome`.
     *
     * 🛑 The stamp cannot say WHICH artifacts were affected, only which predate
     * the fix — so a re-ingest after this upgrade republishes builds that were
     * always fine. Over-reporting is the honest direction here: the alternative
     * is an operator deciding from a number that under-reports.
     */
    public const VERSION = 2;

    /**
     * The loader path: stable, under the reserved namespace, never hashed.
     *
     * `/_/` is §7.3's reserved first segment, so no project can mount a path
     * that shadows it, and "nothing under `/_/` is publicly cacheable" — which
     * is what lets the loader change without any artifact changing.
     */
    public const LOADER_PATH = '/_/addons/docup.js';

    /**
     * Extensions this class will touch.
     *
     * HTML only. §8.15.1 says "built HTML", and an injector that guessed at
     * other types would be rewriting documents nobody asked it to.
     */
    private const HTML_EXTENSIONS = ['html', 'htm', 'xhtml'];

    public function __construct(private readonly int $maxBytes) {}

    public static function fromConfig(): self
    {
        $max = config('artifacts.chrome.max_html_bytes');

        return new self(is_numeric($max) ? (int) $max : 4 * 1024 * 1024);
    }

    /** Whether a manifest path is a document this class considers. */
    public static function handles(string $path): bool
    {
        return in_array(strtolower(pathinfo($path, PATHINFO_EXTENSION)), self::HTML_EXTENSIONS, true);
    }

    /**
     * Inject into one document.
     *
     * @param  string  $html  the document's bytes, exactly as built
     * @param  string  $buildIdText  canonical UUID text
     */
    public function inject(string $html, string $buildIdText): Injection
    {
        if (strlen($html) > $this->maxBytes) {
            // §8.15.4's third non-injectable class. Checked first, because
            // everything below holds the whole document in memory.
            return Injection::refused(InjectionOutcome::RefusedTooLarge, $html);
        }

        /*
         * 🛑 §8.15.4: non-UTF-8 is refused rather than injected. A mis-declared
         * charset is an XSS vector, and the declaration cannot be checked
         * without the parsing §8.15.3 forbids — so the bytes themselves have to
         * be well-formed UTF-8 or the document is left alone.
         */
        if (preg_match('//u', $html) !== 1) {
            return Injection::refused(InjectionOutcome::RefusedNonUtf8, $html);
        }

        $at = self::headCloseAt($html);

        if ($at === null) {
            return $this->isNavigationalStub($html)
                ? Injection::refused(InjectionOutcome::SkippedStub, $html)
                : Injection::refused(InjectionOutcome::RefusedNoHead, $html);
        }

        return Injection::injected(
            substr($html, 0, $at).$this->tags($buildIdText).substr($html, $at),
        );
    }

    /**
     * 🛑 The offset of the first `</head>` it is **safe** to insert before.
     *
     * §8.15.3 requires "a byte-level, **case-insensitive** search tolerating
     * whitespace before the delimiter (`</head\s*>`), because `</HEAD>` and
     * `</head >` are both legal and both occur, and a naive fixed-string search
     * produces false failures on valid documents."
     *
     * This is that search, with one refinement Phase 28 added after the abuse
     * corpus found two real documents the plain pattern **corrupts**:
     *
     * 🛑 **1. A `</head>` inside a `<script>` string.** A page documenting HTML
     * templating writes `<script>var s = "</head>";</script>` in its head. The
     * plain pattern inserts the tags inside that string literal — and the
     * `</script>` in the inserted loader tag terminates the script element, so
     * everything after it becomes markup and `";` leaks into the page as text.
     * The document is visibly broken and nothing reports it: the coverage
     * record says `injected`.
     *
     * 🛑 **2. A `</head>` inside an HTML comment.** The tags land inside the
     * comment, so the loader never runs. Chrome is **silently absent** and the
     * record still says `injected` — a lie in the audit trail, which is worse
     * than the visible breakage above because nobody goes looking for it.
     *
     * So the scan skips comments, CDATA sections and the two raw-text elements,
     * and returns the first `</head>` outside all of them. 🛑 That is still a
     * byte-level search and still not a parse: it builds no tree, normalises
     * nothing and re-serialises nothing — it produces one integer. §8.15.3
     * forbids parsing and re-serialising because "a parser normalises a
     * document, and normalising attacker-supplied markup changes what a browser
     * renders in ways nobody reviewed". Nothing here normalises anything.
     *
     * 🛑 **A document whose only `</head>` sits inside such a region returns
     * null** and therefore gets §8.15.4's `refused_no_head` plus a warning.
     * That is the right answer: there is no safe insertion point, and §8.15.4's
     * posture is that an uninjectable artifact is published without chrome
     * rather than published broken.
     *
     * **Proposed amendment to §8.15.3.** Its parenthetical offers `</head\s*>`
     * as the illustration of the tolerance required; it should say "the first
     * `</head>` **outside** any comment, CDATA section, `<script>` or
     * `<style>`", because the pattern alone is what produced both defects above
     * and the requirement reads as though it were sufficient.
     */
    private static function headCloseAt(string $html): ?int
    {
        $length = strlen($html);
        $at = 0;

        while ($at < $length) {
            if ($html[$at] !== '<') {
                $at++;

                continue;
            }

            // A comment runs to `-->`, or to the end of the document.
            if (substr_compare($html, '<!--', $at, 4) === 0) {
                $at = self::skipPast($html, '-->', $at + 4);

                continue;
            }

            // A CDATA section, which XHTML output carries.
            if (substr_compare($html, '<![CDATA[', $at, 9, true) === 0) {
                $at = self::skipPast($html, ']]>', $at + 9);

                continue;
            }

            /*
             * The one being looked for, checked BEFORE the raw-text elements
             * below so that a `</head>` immediately following `</script>` is
             * found rather than skipped past.
             */
            if (self::closesHeadAt($html, $at)) {
                return $at;
            }

            /*
             * 🛑 Raw-text elements. Inside `<script>` and `<style>` nothing is
             * markup until the matching end tag — which is exactly why their
             * contents can hold a `</head>` a browser never sees as one.
             */
            foreach (['script', 'style'] as $element) {
                if (self::opensElementAt($html, $at, $element)) {
                    $at = self::skipTo($html, '</'.$element, $at + 1 + strlen($element));

                    continue 2;
                }
            }

            $at++;
        }

        return null;
    }

    /**
     * Whether a `</head>` with optional trailing whitespace begins here.
     *
     * Matched by hand rather than with a pattern anchored at an offset: a
     * `preg_match` per `<` would scan the remainder of the document each time
     * and turn a linear scan into a quadratic one. A documentation build has
     * tens of thousands of documents and §9.2 budgets ingest.
     */
    private static function closesHeadAt(string $html, int $at): bool
    {
        if (substr_compare($html, '</head', $at, 6, true) !== 0) {
            return false;
        }

        $cursor = $at + 6;
        $length = strlen($html);

        while ($cursor < $length && strspn($html[$cursor], " \t\n\r\f") === 1) {
            $cursor++;
        }

        return $cursor < $length && $html[$cursor] === '>';
    }

    /**
     * Whether a `<script` or `<style` **start tag** begins at this offset.
     *
     * 🛑 The character after the name has to be one that may follow a tag name,
     * or `<scripture-notes>` would be read as a script and the rest of the
     * document skipped. That is not a hypothetical class of mistake — it is the
     * reason a fixed-string search for `<script` is wrong, and a documentation
     * site about scripture is a real thing.
     */
    private static function opensElementAt(string $html, int $at, string $element): bool
    {
        $name = strlen($element);

        if (substr_compare($html, '<'.$element, $at, $name + 1, true) !== 0) {
            return false;
        }

        $next = $html[$at + $name + 1] ?? '>';

        return $next === '>' || $next === '/' || strspn($next, " \t\n\r\f") === 1;
    }

    /**
     * The offset of `$needle`, or the end of the document.
     *
     * 🛑 Returning the end rather than null when a terminator is missing is
     * what makes an unterminated comment or script safe: the scan runs out, no
     * `</head>` is found outside it, and §8.15.4's refusal applies. A document
     * with an unclosed `<script>` has no head a browser sees either.
     */
    private static function skipTo(string $html, string $needle, int $from): int
    {
        $found = stripos($html, $needle, $from);

        return $found === false ? strlen($html) : $found;
    }

    /** {@see self::skipTo()}, continuing after the terminator rather than at it. */
    private static function skipPast(string $html, string $needle, int $from): int
    {
        $found = stripos($html, $needle, $from);

        return $found === false ? strlen($html) : $found + strlen($needle);
    }

    /**
     * The two tags (§8.15.1), and nothing else.
     *
     * 🛑 The build id is escaped even though it is a UUID. It arrives as a
     * string from a caller, and a value that is "always a UUID" is exactly the
     * kind of assumption that holds until something passes a path or a user's
     * input — at which point this is an injection point into every page of a
     * documentation site. `ENT_QUOTES` costs nothing.
     */
    private function tags(string $buildIdText): string
    {
        $build = htmlspecialchars($buildIdText, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        return '<script defer src="'.self::LOADER_PATH.'"></script>'
            .'<meta name="docup" content="b='.$build.'">';
    }

    /**
     * Whether a document with no `<head>` is a navigational stub (§8.15.3).
     *
     * 🛑 The ADR 0002 case: "a document with no `<head>` element whose body is
     * only a meta-refresh or a `location=` assignment, which is what Antora
     * emits at a site root and which no reader ever sees."
     *
     * Three conditions, and the size bound is what stops this excusing a real
     * page. A genuine document that merely happens to mention `location=` in
     * its text must still raise the warning — otherwise the exemption swallows
     * the thing it was carved out of.
     */
    private function isNavigationalStub(string $html): bool
    {
        // A stub is a few hundred bytes. The bound is generous and still far
        // below any document a reader would be shown.
        if (strlen($html) > 4096) {
            return false;
        }

        $redirects = preg_match('/http-equiv\s*=\s*["\']?\s*refresh/i', $html) === 1
            || preg_match('/\blocation\s*(?:\.\s*(?:replace|assign|href)\s*(?:\(|=)|=)/i', $html) === 1;

        if (! $redirects) {
            return false;
        }

        /*
         * And the body must be only that. Tags and whitespace removed, a stub
         * has essentially no text; a real page has prose. Checked so a document
         * that redirects AND says something is treated as a document.
         */
        $text = trim((string) preg_replace('/<[^>]*>/', ' ', $html));
        $text = trim((string) preg_replace('/\s+/', ' ', $text));

        return strlen($text) <= 64;
    }
}
