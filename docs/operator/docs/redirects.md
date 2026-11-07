# Redirects, 404s and crawler surfaces

A documentation URL that somebody linked to is a promise. This page is how
you keep it after a reorganisation, and what DocUp does when you have not.

## The evaluation order

Every request goes through the same eleven steps, in the same order, and
nothing is skipped or reordered under load:

1. ACME challenge escape — `/.well-known/acme-challenge/*`
2. HTTP → HTTPS
3. Host canonicalisation
4. Path normalisation
5. Domain-mount resolution
6. Version and path resolution
7. Authorisation
8. **Forced** redirect rules
9. Implicit redirects — the ones composition generates
10. The existence probe
11. **Unforced** redirect rules, by position

Steps 8 and 11 are both your rules. The difference is the existence probe
between them, and it is the only thing you need to understand about redirect
rules to use them well:

- A **forced** rule fires even when the path names a page that still exists.
  It is how you retire a page your generator keeps emitting.
- An **unforced** rule fires only once the path has been shown to name
  nothing. It is how you catch inbound links to pages that were removed.

If you are unsure, leave a rule unforced. A forced rule with a pattern that
is wider than you meant will shadow a page that works.

## The six rule types

| Type | Use it when | Pattern | Target |
|---|---|---|---|
| `exact` | one page moved | `/en/v2/old.html` | `/en/v2/new.html` |
| `prefix` | a section moved | `/en/v2/guide/:splat` | `/en/v2/handbook/:splat` |
| `version_agnostic` | a page moved in **every** version | `/api/old.html` | `/reference/new.html` |
| `clean_url` | you switched to directory URLs | a scope, e.g. `/en/v2/` | computed |
| `html_extension` | you switched away from them | a scope | computed |
| `regex` | nothing above fits | a PCRE pattern | `$1`-style references |

`version_agnostic` is the one worth reaching for first when a page moved: it
is written without the language and version segments, and DocUp supplies
whatever the request carried. One rule covers every version you have and
every version you will add.

### Patterns are relative to the mount

Write `/en/v2/guide/install.html`, not
`/docs/handbook/en/v2/guide/install.html`. Your rules do not know where the
project is mounted, which is deliberate: the mount can move and your rules
survive it.

### Status codes

301, 302, 307 and 308. Reach for **307 or 308** if the URL is an API
endpoint rather than a page: they preserve the request method and body,
where 301 and 302 are permitted to turn a POST into a GET.

### Targets

A target must be a root-relative path on this origin, **or** an absolute URL
on a hostname your organisation has verified. An absolute target to anything
else is refused when you save it — a redirect rule pointing at a host you do
not control is an open redirect on a domain your readers trust.

## What is refused when you save a rule

| Refusal | Why |
|---|---|
| `redirect.cycle_detected` | your rules would form a loop |
| `redirect.self_redirect` | the pattern and the target are the same path |
| `redirect.splat_missing` | a `:splat` pattern with a target that discards it sends a whole section to one page |
| `redirect.target_not_proven` | an absolute target to a hostname you have not verified |
| `redirect.status_refused` | not 301, 302, 307 or 308 |
| `redirect.regex_nested_quantifier` | a pattern like `(a+)+`, which backtracks exponentially |
| `redirect.regex_too_long` | over 255 bytes |

Cycle detection runs over the literal rules you wrote. It cannot see a loop
formed by a `prefix` rule pointing under its own pattern, because that is a
template rather than a path — so there is also a **runtime hop cap of four**.
A chain longer than that answers 404 rather than looping.

## Regular expressions are contained, deliberately

Six controls, and you may hit any of them:

- patterns are capped at 255 bytes;
- a nested quantifier is refused by shape, before it ever runs;
- the pattern must compile;
- PCRE is given a lowered backtracking budget;
- at most **20** regex rules are evaluated per request;
- the operator can turn regex rules off for the whole installation.

The evaluation cap is a fixed count and not a time budget, on purpose. A
rule that fires on a quiet morning and not under load is a rule whose
behaviour you cannot reproduce — so DocUp would rather be predictably
limited than unpredictably fast.

Patterns are anchored at both ends. `/guide/.*` does not match
`/not-the-guide/page.html`.

## Twelve worked cases

Each of these is asserted by the test suite, against the rule set below the
table. The table is generated from the same source the tests use, so it
cannot drift from the behaviour.

Rules, in order: a forced `exact` at position 1; `prefix` at 2;
`version_agnostic` at 3; `clean_url` at 4; `exact` (307) at 5; `regex` at 6;
`exact` (308) at 7; and a two-link chain at 8 and 9.

<!-- BEGIN GENERATED: url-cases -->

| # | Clause | Request | Status | `Location` | Rule | Why |
|---|---|---|---|---|---|---|
| 1 | §8.11.1 forced | `/en/v2/retired.html` | 301 | `/en/v2/replacement.html` | `exact#1` | A forced rule fires before the existence probe, so it retires a page the generator still emits. |
| 2 | §8.11.2 prefix | `/en/v2/guide/install.html` | 301 | `/en/v2/handbook/install.html` | `prefix#2` | The remainder after the prefix is substituted for `:splat`. |
| 3 | §8.11.2 prefix | `/en/v2/guide/` | 301 | `/en/v2/handbook/` | `prefix#2` | An empty remainder still matches: a section that moved moved its index too. |
| 4 | §8.11.2 version-agnostic | `/en/v2/api/old.html` | 301 | `/en/v2/reference/new.html` | `version_agnostic#3` | The rule names neither language nor version; the engine re-attaches what the request carried. |
| 5 | §8.11.2 version-agnostic | `/ja/v9/api/old.html` | 301 | `/ja/v9/reference/new.html` | `version_agnostic#3` | The same single rule covers a language and a version that did not exist when it was written. |
| 6 | §8.11.2 clean URL | `/en/v2/tutorials/first.html` | 301 | `/en/v2/tutorials/first/` | `clean_url#4` | The target is computed, not written; the rule supplies only the scope. |
| 7 | §8.11.2 clean URL | `/en/v2/tutorials/index.html` | 301 | `/en/v2/tutorials/` | `clean_url#4` | An index becomes its directory, not `…/index/`. Getting this wrong 404s every section root. |
| 8 | §8.11.2 status 307 | `/en/v2/hooks/receive` | 307 | `/en/v2/webhooks/receive` | `exact#5` | Method and body preserved. Read the Docs has only 301/302 and cannot express this. |
| 9 | §8.11.2 status 308 | `/en/v2/upload` | 308 | `/en/v2/uploads/` | `exact#7` | Permanent and method-preserving: the pair 301 cannot give. |
| 10 | §8.11.2 regex | `/en/v2/rfc-42.html` | 302 | `/en/v2/proposals/42/` | `regex#6` | A back-reference in the target. Contained by all six of §8.11.4's controls. |
| 11 | §8.11.3 chain | `/en/v2/a.html` | 301 | `/en/v2/c.html` | `exact#9` | Two hops followed server-side, so the reader gets one redirect rather than two round trips. |
| 12 | §8.11.5 absence | `/en/v2/never-existed.html` | 404 | — | — | No rule matches, so the 404 chain answers. A rule set is not a catch-all. |

<!-- END GENERATED: url-cases -->

## When nothing matches: the 404 chain

1. `{path}/index.html` — a 302 to the slash form
2. your ordered redirect rules
3. the matched mount's own `404.html`
4. the primary mount's
5. the default version's
6. DocUp's built-in page

### Why your `404.html` is sometimes skipped

A 404 page is served for a URL that does not exist, at a depth nobody chose
— so it cannot use relative asset paths, and every generator therefore emits
root-absolute ones. MkDocs Material puts all eight of its root-absolute
references in that one file.

Those references are correct when your project is at the root of its host
and wrong the moment it is at `/docs/`, where `/css/main.css` belongs to
whatever is at the root instead. DocUp records at ingest whether your
`404.html` contains root-absolute references, and **skips it** when the
project is served under a path prefix or a component mount — falling through
to its own page rather than serving yours without styling.

If you want your own 404 page under a prefix, emit it with no root-absolute
references.

### 404s are cached, and bursts are limited

A 404 about something that genuinely does not exist is cacheable at the edge
for a short time. A 404 that is hiding something private is not, and never
will be.

A source producing more than sixty 404s a minute is held off for a period
that doubles each time it happens, up to an hour. Ordinary readers with
stale bookmarks are never affected.

## Crawler and agent surfaces

Four files are generated per domain mount and rewritten whenever you
publish:

| File | What it is |
|---|---|
| `robots.txt` | crawl policy, with a `Sitemap:` line |
| `sitemap.xml` | every listed, published, public version and page, with `hreflang` |
| `llms.txt` | an index of the navigation tree, for agents |
| `llms-full.txt` | the same index plus the Markdown your generator emitted |

**A file your build ships always wins.** If your generator emits a
`robots.txt`, that is what is served and DocUp's generated one is never
consulted.

**Only your canonical domain is indexable.** Every other verified domain
serves the same documentation with `Disallow: /` and `X-Robots-Tag:
noindex`, because the content is genuinely reachable at several hostnames and
a crawler should index it once.

**Hidden versions are omitted from the sitemap.** A version with `listed` off
still answers by direct URL — that is what the axis is for — and a sitemap
listing it would undo the point.

### `.md` siblings

DocUp serves the Markdown files **your generator emitted**, beside the HTML.
It does not convert HTML to Markdown at request time and never will: the
result would be DocUp's reconstruction of your document rather than your
document, and an agent quoting it would be quoting the reconstruction.
