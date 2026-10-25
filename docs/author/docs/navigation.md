# Navigation

In a single-repository project your generator's own navigation is the
navigation and there is nothing to do.

In a composed project there are two layers, because the project decides the
order and the repository decides its own contents — and neither can do the
other's job.

## The fragment your repository emits

Every build emits a **nav fragment**: a normalised tree whose hrefs are
relative to your component's root. DocUp lifts it from your `.docup.yaml`
`nav:` key if you wrote one, and from your generator's own output otherwise.

```yaml
nav:
  - Getting started: index.html
  - Guides:
      - Authentication: guides/auth.html
      - Webhooks: guides/webhooks.html
```

🛑 Hrefs are **component-relative**, and an absolute or root-relative href is
dropped rather than prefixed into nonsense. The project prefixes its mount
path onto every one of them, so `index.html` becomes `/reference/index.html`
when your component is mounted at `reference` — and the same fragment is
correct when another project mounts it somewhere else.

Your repository does not know where it is mounted, and this is the feature
rather than a limitation.

## The tree the project splices it into

The project holds a layout tree with `{include:}` placeholders, one per
component:

```yaml
- Introduction: index.html
- Using it:
    - {include: author}
- Reference:
    - {include: reference}
```

That is what lets three repositories arrange by **topic** rather than by
repository: a reader sees "Using it" and "Reference", not "repository one" and
"repository two".

A required include that cannot be resolved fails the publication rather than
quietly serving a site with a missing section.

## In `single_pass` mode there is one layer

A `single_pass` project's navigation is the generator's own, produced inside
the one build that made the whole site. The layout tree does not apply, which
means a `single_pass` project cannot arrange its content by topic the way a
`mount` project can. That is the mode's nature rather than a gap, and it is
the first thing an operator notices after switching.

## Cross-references between components

Link to another component through the serve-time namespace:

```markdown
See the [glossary](/_/x/glossary/terms.html).
```

DocUp resolves it against the published manifest and redirects to wherever
that component is currently mounted — so moving a mount moves every link to
it, with no rebuild of the repository that wrote the link.

A reference that cannot be resolved is recorded as a **link issue** on the
manifest. It does not fail your build, and it does not fail the other
repository's build either: one broken link in one component must not stop a
whole manual publishing.

Sphinx users get the mechanism they already have: `objects.inv` is served
directly, at a stable path, with no redirect, so intersphinx never depends on
redirect-following.
