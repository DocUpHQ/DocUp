<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Composition\Navigation;

use App\Audit\CanonicalJson;

/**
 * 🛑 §8.7.6's **normalised** nav fragment — and the trust boundary.
 *
 * > "Each build emits a normalised **nav fragment** with hrefs relative to
 * > the component root, lifted from `.docup.yaml` `nav:` or the generator's
 * > own output (MkDocs `nav`, Sphinx `-b json` toctree, `SUMMARY.md`,
 * > `sidebars.js`)."
 *
 * Every one of those sources is **repository content**, which is to say
 * attacker-supplied. A fragment is spliced into a project's navigation and
 * rendered beside other teams' sections, so the normalisation here is not
 * tidying — it is the control that stops one contributing repository
 * putting an arbitrary link, an arbitrary depth or an arbitrary megabyte
 * into another team's sidebar.
 *
 * What {@see self::normalise()} guarantees to everything downstream:
 *
 *  - **Every href is relative to the component root.** No scheme, no
 *    protocol-relative `//host`, no leading `/`, no `..` segment, no
 *    backslash. An href that is not is dropped and the node survives as a
 *    label — because §8.7.6 degrades rather than fails, and a nav entry
 *    with no link is still a legible heading.
 *  - **Depth, breadth and label length are bounded**, so the spliced tree
 *    cannot be a denial of service against the dashboard that renders it.
 *  - **Labels are plain text**, control characters removed. The consumer is
 *    a Vue template that escapes, and this is the belt to that's braces.
 *
 * Encoded through {@see CanonicalJson} so a build's nav bytes are
 * byte-identical for identical input, which is what lets the fragment live
 * under the build prefix beside `provenance.json` and be compared.
 */
final readonly class NavFragment
{
    public const SCHEMA = 'docup.nav-fragment/1';

    /** §8.7.6's tree, bounded so a repository cannot nest its way out. */
    public const MAX_DEPTH = 8;

    /** Total nodes, counted across the whole tree. */
    public const MAX_NODES = 2000;

    public const MAX_LABEL_BYTES = 200;

    public const MAX_HREF_BYTES = 512;

    /** @param  list<NavNode>  $nodes */
    private function __construct(public array $nodes) {}

    public static function empty(): self
    {
        return new self([]);
    }

    public function isEmpty(): bool
    {
        return $this->nodes === [];
    }

    /**
     * Build a fragment from untrusted input.
     *
     * Accepts the loose shape every source produces once decoded: a list
     * whose items are either `{label, href?, children?}` maps or
     * `{"Label": "page.html"}` / `{"Label": [...]}` single-pair maps, which
     * is how MkDocs and `.docup.yaml` spell the same thing.
     *
     * @param  mixed  $raw  anything; a non-list is an empty fragment
     */
    public static function normalise(mixed $raw): self
    {
        $budget = self::MAX_NODES;

        return new self(self::normaliseList($raw, 1, $budget));
    }

    /**
     * @param  int  $budget  remaining node allowance, decremented in place
     * @return list<NavNode>
     */
    private static function normaliseList(mixed $raw, int $depth, int &$budget): array
    {
        if (! is_array($raw) || $depth > self::MAX_DEPTH) {
            return [];
        }

        $nodes = [];

        foreach ($raw as $key => $item) {
            if ($budget <= 0) {
                break;
            }

            $node = self::normaliseNode($key, $item, $depth, $budget);

            if ($node instanceof NavNode) {
                $nodes[] = $node;
            }
        }

        return $nodes;
    }

    private static function normaliseNode(mixed $key, mixed $item, int $depth, int &$budget): ?NavNode
    {
        /*
         * `{"Getting started": "intro.html"}` — the one-pair form MkDocs and
         * `.docup.yaml` both use. Reached when the enclosing array is a map,
         * so the key is the label.
         */
        if (is_string($key)) {
            $budget--;

            if (is_string($item)) {
                return new NavNode(self::label($key), self::href($item));
            }

            return new NavNode(self::label($key), null, self::normaliseList($item, $depth + 1, $budget));
        }

        if (is_string($item)) {
            // A bare path with no label: the path is the label, which is
            // what every generator does when an author writes one.
            $budget--;
            $href = self::href($item);

            return new NavNode(self::label($href ?? $item), $href);
        }

        if (! is_array($item)) {
            return null;
        }

        // The explicit `{label, href, children}` form, which is what
        // `.docup.yaml` and a re-read of a stored fragment produce.
        $label = $item['label'] ?? $item['title'] ?? null;
        $href = $item['href'] ?? $item['path'] ?? $item['page'] ?? null;
        $children = $item['children'] ?? $item['items'] ?? null;

        if (! is_string($label)) {
            // A single-pair map that arrived inside a list:
            // `- {"Getting started": "intro.html"}`.
            $first = array_key_first($item);

            if (! is_string($first)) {
                return null;
            }

            return self::normaliseNode($first, $item[$first], $depth, $budget);
        }

        $budget--;

        return new NavNode(
            self::label($label),
            is_string($href) ? self::href($href) : null,
            self::normaliseList($children, $depth + 1, $budget),
        );
    }

    /**
     * 🛑 An href the splicer may prefix, or null.
     *
     * Anything that is not a plain relative path is refused rather than
     * sanitised. Prefixing `https://evil.example/x` with `guide/` produces
     * `guide/https://evil.example/x`, which is not an attack but is
     * nonsense; refusing it keeps the one rule — "relative to the component
     * root" — true for every href the rest of the system handles.
     */
    private static function href(string $raw): ?string
    {
        $href = trim($raw);

        /*
         * 🛑 The empty href is **the component root**, not a missing one.
         *
         * MkDocs under its default `use_directory_urls` serves the home
         * page at the directory itself, so the nav entry for `index.md`
         * has no path below the component. Spliced at a mount of
         * `glossary` it becomes `glossary/`, and at the root mount it
         * stays empty — both of which name a real page. Treating it as
         * "no link" would silently unlink every composed component's home
         * page, which is the entry a reader uses most.
         *
         * An href key that is ABSENT is still null: the caller only
         * reaches this method when the key is a string.
         */
        if ($href === '') {
            return '';
        }

        if (strlen($href) > self::MAX_HREF_BYTES) {
            return null;
        }

        if (str_contains($href, '\\') || str_contains($href, "\0")) {
            return null;
        }

        // Scheme, protocol-relative, root-relative, or a fragment/query-only
        // reference. None is "relative to the component root".
        if (preg_match('#^[a-zA-Z][a-zA-Z0-9+.-]*:#', $href) === 1) {
            return null;
        }

        if (str_starts_with($href, '//') || str_starts_with($href, '/')
            || str_starts_with($href, '#') || str_starts_with($href, '?')) {
            return null;
        }

        foreach (explode('/', $href) as $segment) {
            if ($segment === '..') {
                return null;
            }
        }

        return $href;
    }

    private static function label(string $raw): string
    {
        $label = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $raw) ?? $raw;
        $label = trim($label);

        if ($label === '') {
            $label = '—';
        }

        return mb_strcut($label, 0, self::MAX_LABEL_BYTES);
    }

    /** @return array<string, mixed> */
    public function toArray(): array
    {
        return [
            'schema' => self::SCHEMA,
            'nodes' => array_map(static fn (NavNode $node): array => $node->toArray(), $this->nodes),
        ];
    }

    public function toJson(): string
    {
        return CanonicalJson::encode($this->toArray());
    }

    /** Re-read a stored fragment. Normalised again, because storage is not trust. */
    public static function decode(string $bytes): self
    {
        $decoded = json_decode($bytes, true);

        if (! is_array($decoded)) {
            return self::empty();
        }

        return self::normalise($decoded['nodes'] ?? []);
    }

    /** Every node, with the mount's prefix applied to every href (§8.7.6). */
    public function withPrefix(string $prefix): self
    {
        return new self(array_map(
            static fn (NavNode $node): NavNode => $node->withPrefix($prefix),
            $this->nodes,
        ));
    }
}
