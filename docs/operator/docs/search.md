# Search

DocUp ships with search that needs no extra service, and with limits that are
real rather than approximate. This page says what they are, because the first
support question about documentation search is always the same one.

## Why `go` returns nothing

The default engine is MySQL's InnoDB FULLTEXT index. It does not index words
shorter than three characters, so a search for `go` returns **no results** — not
few, none. The word is not in the index at all, and no rephrasing finds it.

That is the surprise, and it is the one nobody meets until a reader reports it:
every example a documentation author reaches for is three characters or more
(`api`, `ssl`, `jwt`, `ssh`), so search looks fine right up to the day somebody
searches for `go`, `js`, `go` again, or a two-letter language code.

Four limits, all of them absolute on the default engine:

| Searching for | Returns | Why |
|---|---|---|
| `go` | nothing | two characters, below the minimum indexed word length |
| `the` | nothing | a stopword; the server ships 36 of them |
| `authentcation` | nothing | a misspelling, and there is no typo tolerance |
| `deploying` | no match for `deploy` | there is no stemming: a word matches only itself |
| `api` | about 100,000 results at 200,000 sections | three characters clears the minimum, so a common term matches half the corpus |

Every project's **Search** page in the dashboard states these, read from the
running server rather than from this document — because the minimum word length
is a MySQL variable and an operator who changes it changes the answer.

### Changing the minimum

`innodb_ft_min_token_size` is a MySQL **server** variable, not a DocUp setting.
Lowering it to 2 makes two-character terms findable and requires rebuilding
every FULLTEXT index on the server, which for DocUp means a full reindex:

```ini
[mysqld]
innodb_ft_min_token_size = 2
```

Restart MySQL, then run `php artisan docup:search-index --force`. The dashboard
will then say 2, because it reads the server.

## Choosing an engine

| | MySQL FULLTEXT (default) | Meilisearch |
|---|---|---|
| Extra service | none | one |
| Shortest word | 3 characters | 1 |
| Stopwords | 36 | none |
| Typo tolerance | no | yes |
| Stemming | no | no |
| Recommended | below 200,000 sections | above |

The threshold is measured rather than guessed. At 200,000 sections the default
engine answers an unfiltered query in about 10 ms and a **filtered** one — which
every real search is, because DocUp applies visibility filtering server-side —
at about 80 ms at the 95th percentile. MySQL cannot combine a FULLTEXT index
with a secondary index, so the filter is applied after the match and the cost
grows with **how many sections match**, not with how many results you asked
for. A smaller result limit does not make a broad query cheap.

`php artisan docup:doctor` warns when an installation crosses the threshold.

### Switching to Meilisearch

```bash
DOCUP_SEARCH_DRIVER=meilisearch
DOCUP_MEILISEARCH_URL=http://meilisearch:7700
DOCUP_MEILISEARCH_KEY=<the master key>
DOCUP_MEILISEARCH_INDEX=docup_search
```

Then reindex:

```bash
php artisan docup:search-index
```

The engine's address is installation configuration, in the same class as
`DB_HOST`. The key never leaves the application: DocUp proxies every search
server-side and issues **no** browser-readable search token of any kind, because
a Meilisearch tenant token is a plain HS256 JWT that a browser can read and that
cannot be revoked before it expires.

!!! warning "Adding a filter later is a reindex"

    DocUp declares Meilisearch's complete filterable attribute set on the first
    pass. Changing that set forces Meilisearch to reindex everything, so a later
    addition would be an upgrade step rather than a deployment. If DocUp ever
    needs a new filter, the release notes will say so and `docup:search-index`
    will refuse until you reindex deliberately.

## What gets indexed

One search document per **heading**, so a result links to the section rather
than to the top of the page.

- The `default`, `stable` and `latest` versions of each project. Hidden and
  inactive versions are excluded: a version you unlisted does not appear in its
  own search results.
- Navigation, scripts, stylesheets and the `¶` permalinks generators append to
  headings are stripped. Without that, a Sphinx sidebar — which repeats the
  whole table of contents on every page — would make every page match every
  query.
- Where a generator ships its own search index, DocUp reads that instead of
  re-parsing the HTML. Material for MkDocs' `search/search_index.json` is
  picked up automatically.

### Sphinx's JSON build

DocUp will read a `sphinx-build -b json` output if your build produces one, and
it is better input than HTML: each page's `body` is the content with no theme
around it, so there is no sidebar to strip and no guess about where the content
begins.

DocUp does **not** run the second build for you — that is a second
`sphinx-build` and the cost is yours to choose. To produce one:

```yaml
build:
  jobs:
    post_build:
      - sphinx-build -b json docs $DOCUP_OUTPUT/html/_json
```

DocUp looks for a `globalcontext.json` under the HTML output and reads the
`.fjson` pages beside it. Both `html` and `dirhtml` builders work: each page is
matched against what was actually published.

### Ranking and exclusions

`search.ranking` and `search.ignore` in `.docup.yaml` work exactly as they do in
`.readthedocs.yaml`, including the parts that surprise people:

```yaml
search:
  ranking:
    api/v1/*: -1
    api/v2/*: 4
  ignore:
    - internal/*
```

- Ranks run from −10 to +10. A page at −10 is effectively never surfaced; one at
  +10 outranks an equally good match on a page at 0.
- **The last matching pattern wins**, not the most specific. In the example
  above `api/v2/index.html` ranks +4.
- `*` matches across `/`, so `api/*` matches `api/v2/reference/index.html`.
- 🛑 **Declaring `ignore` replaces the defaults.** Without an `ignore` key DocUp
  excludes `search.html`, `search/index.html`, `404.html` and `404/index.html`,
  as Read the Docs does. Writing `ignore: [internal/*]` makes your 404 page
  searchable again.

Patterns are matched against the file path relative to the HTML output —
`guide/index.html`, not `/en/latest/guide/`.

The project's **Search** page shows the patterns the indexed builds actually
declared, which is where to look when a page is findable and should not be.

## Freshness, and when search switches itself off

Indexing runs hourly. A page published between passes is searchable at the next
one; its content is served immediately, only search lags.

🛑 **One exception, and it is deliberate.** When a project's reader policy
changes, its search index is older than its authorisation rules — so DocUp
**disables** search for that project until the next indexing pass, rather than
answering from the stale index.

That is the safe direction and it is the only safe direction: a stale index
would return sections the new policy refuses, and a disclosure cannot be undone
while an hour without search can. The project's Search page says so in words,
and `docup:doctor` counts the projects affected:

```
 warn   Search generation gate   3 projects have search DISABLED because
                                 their index predates the current policy.
```

To re-enable immediately:

```bash
php artisan docup:search-index --project=<slug>
```

## Shared components are indexed once

A component mounted by several projects is extracted **once** and searched from
all of them, with each project's own URLs computed when the query runs. Reusing
a component costs no index space and no indexing time after the first project.

## Maintenance

The index table cannot be partitioned — MySQL supports neither FULLTEXT indexes
nor FULLTEXT search on partitioned tables — so DocUp retires old documents with
batched deletes rather than by dropping partitions. Those deletes free space
*inside* the table and do not return it to the filesystem: measured over 50
republish cycles the index grew about 28% and then stopped growing, rather than
shrinking back.

The nightly sweep reports how much is reclaimable:

```
search_documents: 412.0 MiB data, 980.1 MiB index, 290.4 MiB reclaimable (20.9%)
```

Only `OPTIMIZE TABLE` returns it, and that rebuilds the table and **locks** it
while it does — which would stall every reader mid-search and every publish
mid-ingest. So DocUp never schedules it. Run it in a maintenance window:

```bash
php artisan docup:search-retention --optimize
```

## Commands

```bash
# Index every project's default, stable and latest versions.
php artisan docup:search-index

# One project, and re-read every artifact rather than reusing what is indexed.
php artisan docup:search-index --project=my-docs --force

# Retire orphaned documents and report reclaimable space.
php artisan docup:search-retention
```

`--force` costs a full re-extraction of every build the projects touch. Without
it, a build that is already indexed is skipped and its artifact is not read at
all — which is what makes a shared component cheap.

## Query syntax

The same syntax on both engines, so switching changes performance and not
behaviour:

- **Terms are combined with AND.** `access token` finds pages holding both.
- **A phrase in double quotes is matched exactly.** `"access token"` finds the
  words in that order.
- **Scope filters** narrow a search: `project:my-docs`,
  `project:my-docs/v2`, `collection:platform`, `self:me`.

Everything else is searched for as ordinary text. `OR`, `~`, `*`, a leading `-`
and a trailing `^5` are **not** operators — they are characters in a word — so a
query never fails with a syntax error. A reader searching for `C++` gets a
search for `C++`.

Two consequences worth knowing:

- `foo OR bar` searches for three words and finds nothing, because `OR` is a
  word and no page contains it next to both others. It is not an error, and it
  is not an `OR`.
- A leading `-` cannot exclude anything. That is on purpose: DocUp applies
  visibility filtering server-side, and an exclusion operator from the client
  would let a reader subtract from a result set the filter had just defined.

Meilisearch additionally tolerates typos and matches the last word of a query as
a prefix, automatically and with no syntax. DocUp offers no operator for either,
because the default engine has none and one syntax that works everywhere is
worth more than two that differ.
