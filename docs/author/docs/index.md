# Writing for DocUp

You add one file to your repository:

```yaml
version: 2
toolchain: mkdocs
mkdocs:
  configuration: mkdocs.yml
```

That is a complete `.docup.yaml`. Every key is documented in the
**`.docup.yaml` reference**, beside this guide in the navigation; this guide
is about the parts that are easy to get wrong.

## It is a superset of `.readthedocs.yaml`

Every key and every accepted value of Read the Docs' v2 configuration is
accepted here unchanged, including the ones that are only there for
compatibility: `ubuntu-20.04` after its upstream removal, `htmldir` as a
retired spelling of `dirhtml`, the literal `all` for `formats`. A repository
migrating should not have to edit a file to be accepted.

There are deliberate incompatibilities, and each one is a behaviour change you
would rather find here than in a build log:

| Difference | Why |
|---|---|
| build commands run under `set -euo pipefail` | an unset variable or a failed pipe stage silently producing an empty site is the most common broken build there is |
| `conda` is parsed and refused | accepted by the schema so the refusal can say what is wrong, rather than `unknown key: conda` |
| translations are versions, not sibling projects | one project, one domain set, one policy, one brand, and a real language switcher |

## What the file may not say

🛑 No key in `.docup.yaml` names a project, a mount path, a domain, an
authentication policy, a visibility level, a version channel or a retention
policy — and the schema sets `additionalProperties: false` everywhere, so one
cannot be added by accident.

The reason is that the same repository is mounted by different projects at
different paths. A repository that could name its own mount path would be
deciding something that is not its to decide, and in a multi-tenant
installation that is a privilege escalation with a YAML syntax.

The single exception is `suggested_mount_path`, and it is advisory: read once
when a component is attached, and never read again.

## Picking a toolchain

Seven presets ship, each a data file rather than code: `sphinx`, `mkdocs`,
`docusaurus`, `antora`, `mdbook`, `vitepress`, `starlight`. Name one with
`toolchain:` and you are done — omit it and DocUp infers it the Read the Docs
way, which works for exactly two generators.

Each preset builds a real site from twelve lines of configuration or fewer,
and that budget is asserted in CI rather than claimed.
