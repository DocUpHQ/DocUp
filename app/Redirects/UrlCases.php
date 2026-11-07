<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Redirects;

/**
 * 🛑 §17's Phase 20 exit criterion: "A documented table of **twelve URL
 * cases** each produce the specified status and `Location`."
 *
 * **One table, three readers.** The cases are declared here so that the
 * operator documentation, the test suite and this comment cannot disagree:
 * `GeneratedBlocks` renders them into the operator guide, and
 * `UrlCasesTest` drives the engine with them. Phase 17 found what happens
 * when a documented table and the code that implements it are two things —
 * §8.7.13's mode matrix was prose that had drifted — so this one is
 * generated from the same source the assertions read.
 *
 * 🛑 Each case names the §8.11 clause it demonstrates, because the point of
 * a table of twelve is not twelve examples: it is that each of §8.11's
 * mechanisms has one, and a reader can see which. The rule set below is
 * ordinary — six rule types, four status codes, one forced rule, one cycle
 * — and the cases are what an operator would actually hit.
 */
final class UrlCases
{
    /**
     * The rule set the twelve cases are evaluated against.
     *
     * Positions are explicit and contiguous, which is also the
     * demonstration: §8.11.2's "explicit ordering" means case 11 below
     * resolves the way it does because `prefix#2` sits above
     * `regex#6`, not because one is more specific.
     *
     * @return list<array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}>
     */
    public static function rules(): array
    {
        return [
            // §8.11.1's forced pass: wins over a file that still exists.
            self::rule(1, RedirectKind::Exact, '/en/v2/retired.html', '/en/v2/replacement.html', 301, forced: true),

            // §8.11.2's prefix with `:splat` — a section that moved.
            self::rule(2, RedirectKind::Prefix, '/en/v2/guide/:splat', '/en/v2/handbook/:splat', 301),

            // §8.11.2's version-agnostic page — one rule, every version.
            self::rule(3, RedirectKind::VersionAgnostic, '/api/old.html', '/reference/new.html', 301),

            // §8.11.2's clean-URL style change, scoped to a subtree.
            self::rule(4, RedirectKind::CleanUrl, '/en/v2/tutorials', '/en/v2/tutorials', 301),

            // §8.11.2's 307, which preserves the method — a moved endpoint.
            self::rule(5, RedirectKind::Exact, '/en/v2/hooks/receive', '/en/v2/webhooks/receive', 307),

            // §8.11.2's regex, with a back-reference.
            self::rule(6, RedirectKind::Regex, '/en/v2/rfc-(\d+)\.html', '/en/v2/proposals/$1/', 302),

            // §8.11.2's 308: permanent AND method-preserving.
            self::rule(7, RedirectKind::Exact, '/en/v2/upload', '/en/v2/uploads/', 308),

            // A two-hop chain, to demonstrate §8.11.3's cap is not reached.
            self::rule(8, RedirectKind::Exact, '/en/v2/a.html', '/en/v2/b.html', 301),
            self::rule(9, RedirectKind::Exact, '/en/v2/b.html', '/en/v2/c.html', 301),
        ];
    }

    /**
     * The twelve cases.
     *
     * @return list<array{case: int, clause: string, path: string, status: int|null, location: string|null, rule: string|null, note: string}>
     */
    public static function cases(): array
    {
        return [
            [
                'case' => 1,
                'clause' => '§8.11.1 forced',
                'path' => '/en/v2/retired.html',
                'status' => 301,
                'location' => '/en/v2/replacement.html',
                'rule' => 'exact#1',
                'note' => 'A forced rule fires before the existence probe, so it retires a page the generator still emits.',
            ],
            [
                'case' => 2,
                'clause' => '§8.11.2 prefix',
                'path' => '/en/v2/guide/install.html',
                'status' => 301,
                'location' => '/en/v2/handbook/install.html',
                'rule' => 'prefix#2',
                'note' => 'The remainder after the prefix is substituted for `:splat`.',
            ],
            [
                'case' => 3,
                'clause' => '§8.11.2 prefix',
                'path' => '/en/v2/guide/',
                'status' => 301,
                'location' => '/en/v2/handbook/',
                'rule' => 'prefix#2',
                'note' => 'An empty remainder still matches: a section that moved moved its index too.',
            ],
            [
                'case' => 4,
                'clause' => '§8.11.2 version-agnostic',
                'path' => '/en/v2/api/old.html',
                'status' => 301,
                'location' => '/en/v2/reference/new.html',
                'rule' => 'version_agnostic#3',
                'note' => 'The rule names neither language nor version; the engine re-attaches what the request carried.',
            ],
            [
                'case' => 5,
                'clause' => '§8.11.2 version-agnostic',
                'path' => '/ja/v9/api/old.html',
                'status' => 301,
                'location' => '/ja/v9/reference/new.html',
                'rule' => 'version_agnostic#3',
                'note' => 'The same single rule covers a language and a version that did not exist when it was written.',
            ],
            [
                'case' => 6,
                'clause' => '§8.11.2 clean URL',
                'path' => '/en/v2/tutorials/first.html',
                'status' => 301,
                'location' => '/en/v2/tutorials/first/',
                'rule' => 'clean_url#4',
                'note' => 'The target is computed, not written; the rule supplies only the scope.',
            ],
            [
                'case' => 7,
                'clause' => '§8.11.2 clean URL',
                'path' => '/en/v2/tutorials/index.html',
                'status' => 301,
                'location' => '/en/v2/tutorials/',
                'rule' => 'clean_url#4',
                'note' => 'An index becomes its directory, not `…/index/`. Getting this wrong 404s every section root.',
            ],
            [
                'case' => 8,
                'clause' => '§8.11.2 status 307',
                'path' => '/en/v2/hooks/receive',
                'status' => 307,
                'location' => '/en/v2/webhooks/receive',
                'rule' => 'exact#5',
                'note' => 'Method and body preserved. Read the Docs has only 301/302 and cannot express this.',
            ],
            [
                'case' => 9,
                'clause' => '§8.11.2 status 308',
                'path' => '/en/v2/upload',
                'status' => 308,
                'location' => '/en/v2/uploads/',
                'rule' => 'exact#7',
                'note' => 'Permanent and method-preserving: the pair 301 cannot give.',
            ],
            [
                'case' => 10,
                'clause' => '§8.11.2 regex',
                'path' => '/en/v2/rfc-42.html',
                'status' => 302,
                'location' => '/en/v2/proposals/42/',
                'rule' => 'regex#6',
                'note' => 'A back-reference in the target. Contained by all six of §8.11.4\'s controls.',
            ],
            [
                'case' => 11,
                'clause' => '§8.11.3 chain',
                'path' => '/en/v2/a.html',
                'status' => 301,
                'location' => '/en/v2/c.html',
                'rule' => 'exact#9',
                'note' => 'Two hops followed server-side, so the reader gets one redirect rather than two round trips.',
            ],
            [
                'case' => 12,
                'clause' => '§8.11.5 absence',
                'path' => '/en/v2/never-existed.html',
                'status' => null,
                'location' => null,
                'rule' => null,
                'note' => 'No rule matches, so the 404 chain answers. A rule set is not a catch-all.',
            ],
        ];
    }

    /** The table, as the operator guide renders it. */
    public static function toMarkdown(): string
    {
        $out = "| # | Clause | Request | Status | `Location` | Rule | Why |\n";
        $out .= "|---|---|---|---|---|---|---|\n";

        foreach (self::cases() as $case) {
            $out .= '| '.$case['case']
                .' | '.$case['clause']
                .' | `'.$case['path'].'`'
                .' | '.($case['status'] ?? '404')
                .' | '.($case['location'] === null ? '—' : '`'.$case['location'].'`')
                .' | '.($case['rule'] === null ? '—' : '`'.$case['rule'].'`')
                .' | '.$case['note']
                ." |\n";
        }

        return $out;
    }

    /**
     * @return array{id: string, position: int, kind: string, forced: bool, from: string, to: string, status: int}
     */
    private static function rule(
        int $position,
        RedirectKind $kind,
        string $from,
        string $to,
        int $status,
        bool $forced = false,
    ): array {
        return [
            'id' => $kind->value.'-'.$position,
            'position' => $position,
            'kind' => $kind->value,
            'forced' => $forced,
            'from' => $from,
            'to' => $to,
            'status' => $status,
        ];
    }
}
