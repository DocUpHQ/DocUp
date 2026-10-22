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
     */
    public const VERSION = 1;

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

        /*
         * The first `</head>`, case-insensitively, tolerating whitespace before
         * the `>`. §8.15.3's exact rule, and `preg_quote`-free on purpose: this
         * is the one pattern the requirement spells out.
         */
        if (preg_match('#</head\s*>#i', $html, $matches, PREG_OFFSET_CAPTURE) !== 1) {
            return $this->isNavigationalStub($html)
                ? Injection::refused(InjectionOutcome::SkippedStub, $html)
                : Injection::refused(InjectionOutcome::RefusedNoHead, $html);
        }

        $at = $matches[0][1];

        return Injection::injected(
            substr($html, 0, $at).$this->tags($buildIdText).substr($html, $at),
        );
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
