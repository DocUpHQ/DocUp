<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

/**
 * 🛑 §8.11.6's `hreflang`, "generated across versions, mounts **and** domains".
 *
 * Three axes, and each one is a different mistake if it is dropped:
 *
 * - **versions** — the alternates of `/ja/v2/guide/` are the *same documentation*
 *   in other languages, which §8.6.12 identifies by `translation_group_id` and
 *   **not** by an equal slug. A translator who slugs the Japanese version
 *   `v2-ja` has not stopped translating `v2`.
 * - **mounts and domains** — every alternate is built on the project's
 *   **canonical** mount, whichever mount served the request. §8.11.9 already
 *   points `rel=canonical` there "for N domains serving identical content", and
 *   an alternate set that pointed at the serving alias would annotate pages the
 *   same response tells a crawler not to index.
 *
 * 🛑 **An alternate is only emitted for a page that exists.** The whole point
 * of §8.6.13 is that DocUp never implies a translation it does not have, and
 * an `hreflang` pointing at a missing page is that implication in the one
 * place a reader cannot see it — it reaches a search engine, which indexes the
 * annotation and sends somebody to a 404. The existence filter is the caller's,
 * because it reads file manifests and this class is pure.
 *
 * Self-referential, per the annotation's own rules: the page being served is in
 * its own alternate set. A one-sided annotation is discarded by every consumer
 * that checks reciprocity, so omitting self would make the whole set inert.
 */
final class Hreflang
{
    /**
     * Build the alternate set.
     *
     * `$origin` is the canonical mount's `scheme://host`, which is why this
     * function cannot derive it: a pure class has no configuration and no
     * database, and the canonical host is a row.
     *
     * @param  list<array{language: string, path: string}>  $pages  one per language, canonical-mount paths, existence already checked
     * @param  string|null  $defaultLanguage  the project default version's language; gets `x-default`
     * @return list<array{hreflang: string, href: string}>
     */
    public static function alternates(array $pages, string $origin, ?string $defaultLanguage = null): array
    {
        if (count($pages) < 2) {
            /*
             * 🛑 One language is not a translation. Annotating a page as the
             * only alternate of itself tells a crawler nothing and costs a
             * header on every document of every untranslated project — which
             * is almost all of them.
             */
            return [];
        }

        $alternates = [];
        $default = null;

        foreach ($pages as $page) {
            $href = $origin.$page['path'];

            $alternates[] = ['hreflang' => $page['language'], 'href' => $href];

            if ($page['language'] === $defaultLanguage) {
                $default = $href;
            }
        }

        /*
         * `x-default` is the page a reader whose language matches nothing
         * should get, and the project's default version answers that by
         * definition (§8.6.14 makes it an explicit stored pointer). Omitted
         * rather than guessed when that language's page is missing: a wrong
         * `x-default` sends every unmatched reader to one arbitrary
         * translation, which is the silent fallback §8.6.13 forbids wearing a
         * different hat.
         */
        if ($default !== null) {
            $alternates[] = ['hreflang' => 'x-default', 'href' => $default];
        }

        return $alternates;
    }

    /**
     * The alternates as one RFC 8288 `Link` header value.
     *
     * A header rather than a DOM edit, for the reason §8.11.9 gives
     * `rel=canonical` the same treatment: 🛑 nothing rewrites documentation on
     * the serving path (§4.3/2, §4.3/6, §8.9.8), so an annotation DocUp
     * computes cannot be written into the document's `<head>`. §8.11.6's
     * sitemap carries the same set and is Phase 20's.
     *
     * @param  list<array{hreflang: string, href: string}>  $alternates
     */
    public static function header(array $alternates): ?string
    {
        if ($alternates === []) {
            return null;
        }

        $parts = [];

        foreach ($alternates as $alternate) {
            /*
             * No escaping of the href, because there is nothing here to
             * escape: the origin comes from a `domains.host` row and the path
             * is built by {@see VersionUrl} from a mount prefix, a language
             * code and a version slug, each of which is held to a character
             * set that excludes `<`, `>`, `"` and every control byte. A
             * quote here would be a sign the grammar had been widened
             * somewhere, and silently stripping it would hide that.
             */
            $parts[] = '<'.$alternate['href'].'>; rel="alternate"; hreflang="'.$alternate['hreflang'].'"';
        }

        return implode(', ', $parts);
    }
}
