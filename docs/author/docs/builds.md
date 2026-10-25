# Builds

## The pipeline, and where you can get in

DocUp runs a predefined pipeline and gives you the Read the Docs hook names to
extend it. `pre_` and `post_` **append** to a step; the bare name **replaces**
it.

```yaml
build:
  jobs:
    post_checkout:
      - git fetch --unshallow
    pre_build:
      - python scripts/generate-api.py
```

`build.commands` discards the predefined pipeline entirely. You then own every
step, including writing `$DOCUP_OUTPUT/html` — and `html/index.html` is
mandatory, so a build that produces no front page fails ingest rather than
publishing a site with a hole in it.

!!! warning "`set -euo pipefail`"

    Every command runs under it. This is a deliberate incompatibility with
    Read the Docs' unflagged `/bin/sh -c`, and it is the one most likely to
    surface on a first build: a command that referenced an unset variable, or
    whose first pipe stage failed, used to produce an empty page and a green
    build.

## What your build can and cannot reach

Your build runs in a sandbox with:

- **no route to the database**, no route to another build, no route to the
  host;
- **egress through an allowlisting proxy** — your package manager works, and
  an arbitrary host does not;
- hard caps on wall time, memory, disk and log output;
- a checkout DocUp performed before any of your code ran, with `.git`
  removed.

Secrets you configure are available as environment variables and are redacted
from the log by value, not by name.

## Offline formats

```yaml
formats: [pdf, epub, htmlzip]
```

or the literal `all`. They are produced by the same build and downloaded from
`/_/downloads/<language>/<version>/<format>`, named after the project and
version rather than after the file in the store.

In a composed project only the **primary** component emits them. Per-mount
downloads would need a URL contract of their own, and one manual that is
several repositories is still one manual.

## Monorepos

```yaml
sparse:
  - docs
  - shared/snippets
```

narrows the checkout with git's sparse-checkout in cone mode, and **fails
loudly** rather than falling back to a full clone — a silent fallback would
turn a deliberate narrowing into an accidental ten-minute fetch nobody
notices.

A push that touches nothing under those paths does not trigger a build.

## Reading the log

Build logs stream line by line while the build runs and are capped at the head
and the tail, so a build that produces a million lines of npm output still
shows you its first and last moments. Cancellation takes effect in seconds,
not at the next step boundary.
