<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §8.6.13's notification banner, as data.
 *
 * > "A missing page in a non-default language MUST return 404 plus a
 * > notification banner, never a silent fallback to another language. Locale
 * > negotiation MUST be URL-only; `Vary: Accept-Language` on documentation
 * > would destroy edge cacheability."
 *
 * 🛑 **The 404 is the requirement and the banner is the courtesy** — in that
 * order, and the order is the whole rule. Serving the English page at a
 * Japanese URL is the failure mode this forbids: it is indistinguishable from
 * a translated page to a reader who cannot read English well enough to notice,
 * it poisons the cache entry for the Japanese URL, and it tells a crawler that
 * two URLs hold the same document in different languages. So nothing in this
 * class or its callers can produce a 200.
 *
 * 🛑 **No `Vary: Accept-Language` anywhere.** The reader's header plays no
 * part: which language was asked for is read from the path and from nothing
 * else. That is why this class takes a language rather than a request.
 *
 * The three kinds are different facts and a banner that conflated them would
 * be useless: "this project has no Japanese at all" is an invitation to switch
 * language, "this page is not translated yet" is an invitation to read the
 * English one, and "this page exists nowhere" is a plain 404 with nothing to
 * offer.
 */
final readonly class TranslationNotice
{
    /** The project publishes nothing in the requested language. */
    public const LANGUAGE_ABSENT = 'translation.language_absent';

    /** The language exists; this page is not in it, and is elsewhere. */
    public const PAGE_UNTRANSLATED = 'translation.page_untranslated';

    /**
     * @param  string  $code  one of the two constants above
     * @param  string  $requestedLanguage  the language in the URL
     * @param  list<array{language: string, href: string}>  $available  where the reader can go instead
     */
    public function __construct(
        public string $code,
        public string $requestedLanguage,
        public array $available,
    ) {}

    /**
     * The header the §8.15 addons runtime reads.
     *
     * A header rather than a rewritten document, because 🛑 nothing rewrites
     * documentation on the serving path (§4.3/2, §8.9.8) — and a 404 has no
     * document to rewrite in any case. §8.15.6's three banners are rendered
     * by the closed-shadow-root component in Phase 28; this is the value it
     * renders, available now so that the refusal and the banner cannot
     * disagree about what happened.
     *
     * Deliberately not JSON: a header is read by a proxy, a log line and a
     * person running `curl -I`, and §8.6.13's failure mode is one somebody
     * has to be able to see from outside.
     */
    public function header(): string
    {
        $languages = array_map(
            static fn (array $entry): string => $entry['language'],
            $this->available,
        );

        return $this->code
            .'; requested='.$this->requestedLanguage
            .($languages === [] ? '' : '; available='.implode(',', $languages));
    }

    /**
     * The banner, as the smallest HTML document that can carry it.
     *
     * 🛑 Hand-built rather than rendered through a view, and the reason is
     * §9.3.5: 404 bursts are a named abuse class and "the uncached-404
     * pattern" is in the DDoS runbook, so the cheapest request to generate
     * must not become the most expensive to answer. A Blade layout with
     * translations and a theme lookup would make a 404 cost more than a page.
     * Phase 20's branded built-in 404 replaces this body; the banner survives
     * it, because §8.6.13 is about what the reader is told and not about what
     * it looks like.
     *
     * Every interpolated value is escaped even though all of them come from
     * constrained grammars — a language code, a version slug, a mount prefix.
     * Relying on the grammar would make this the one place a widened
     * character set turns into injected markup.
     */
    public function body(): string
    {
        $heading = $this->code === self::LANGUAGE_ABSENT
            ? 'This documentation is not published in '.$this->escape($this->requestedLanguage).'.'
            : 'This page has not been translated into '.$this->escape($this->requestedLanguage).'.';

        $links = '';

        foreach ($this->available as $entry) {
            $links .= '<li><a href="'.$this->escape($entry['href']).'" hreflang="'
                .$this->escape($entry['language']).'">'
                .$this->escape($entry['language']).'</a></li>';
        }

        $alternatives = $links === ''
            ? '<p>It is not available in another language either.</p>'
            : '<p>It is available in:</p><ul>'.$links.'</ul>';

        return '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            .'<title>Not found</title></head><body>'
            .'<main role="alert"><h1>'.$heading.'</h1>'.$alternatives.'</main>'
            .'</body></html>';
    }

    private function escape(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
