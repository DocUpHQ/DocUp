# The `.docup.yaml` reference

Every key DocUp accepts in a repository's configuration file, with what it
accepts and why it is shaped that way.

!!! info "Generated from the schema, not written beside it"

    This page is rendered from
    `resources/schema/docup-yaml-v1.schema.json`, which is the contract the
    application validates against. A key documented here and absent from the
    schema, or the reverse, is a failing build rather than a surprise in a
    build log.

The file is a key- and value-compatible **superset of `.readthedocs.yaml` v2**:
every key and every accepted value of that file is accepted here unchanged.
`additionalProperties` is `false` everywhere, so a key that would let a
repository name a project, a mount path, a domain, an authentication policy, a
visibility level, a version channel or a retention policy cannot be added by
accident.

<!-- BEGIN GENERATED: docup-yaml -->

## `version`

**Required.** Takes the literal `2`.

The configuration format version. Read the Docs v2 requires this and so do we; §8.1.11 requires this contract to carry its own version field with a two-minor deprecation policy, and a file that does not say which contract it speaks cannot be deprecated against.

## `toolchain`

Takes one of `sphinx`, `mkdocs`, `docusaurus`, `antora`, `mdbook`, `vitepress`, `starlight`.

DocUp addition: name the generator outright. Read the Docs infers it from the presence of a `sphinx` or `mkdocs` key, which works for exactly two generators; §11.4 makes the toolchain a declarative data file, and this is the key that names one. Omit it and the generator is inferred the Read the Docs way (`sphinx` key, `mkdocs` key, else `build.commands`).

## `formats`

Takes one of several forms.

Offline formats to emit alongside HTML. §8.4.2 preserves the literal `all`.

## `build`

The image, the language tools, the system packages and the pipeline.

| Key | Accepts | Notes |
|---|---|---|
| `os` | one of `ubuntu-20.04`, `ubuntu-22.04`, `ubuntu-24.04`, `ubuntu-26.04`, `ubuntu-lts-latest` |  |
| `tools` | an object |  |
| `apt_packages` | a list of strings | At most 64 entries |
| `jobs` | an object |  |
| `commands` | a list of shell commands |  |

## `python`

| Key | Accepts | Notes |
|---|---|---|
| `install` | a list whose entries take one of several forms | At most 32 entries |

## `conda`

§8.4.14: accepted by the schema for configuration compatibility and NOT RUNNABLE in v1. A file using it is refused by ConfigRejection::CONDA_UNSUPPORTED, which names the limitation and the two alternatives. It is accepted here rather than rejected as an unknown key so that the refusal can say what is actually wrong instead of `unknown key: conda`.

| Key | Accepts | Notes |
|---|---|---|
| `environment` | a path inside the checkout | Required |

## `sphinx`

| Key | Accepts | Notes |
|---|---|---|
| `builder` | one of `html`, `dirhtml`, `singlehtml`, `htmldir` | Default `html` |
| `configuration` | a path inside the checkout |  |
| `fail_on_warning` | a boolean | Default `false` |

## `mkdocs`

| Key | Accepts | Notes |
|---|---|---|
| `configuration` | a path inside the checkout |  |
| `fail_on_warning` | a boolean | Default `false` |

## `antora`

| Key | Accepts | Notes |
|---|---|---|
| `configuration` | a path inside the checkout |  |
| `start_page` | a string | At most 255 characters |

## `submodules`

| Key | Accepts | Notes |
|---|---|---|
| `include` | one of several forms |  |
| `exclude` | one of several forms |  |
| `recursive` | a boolean | Default `false` |

## `search`

Consumed by §8.16.3's indexer, not by the build.

| Key | Accepts | Notes |
|---|---|---|
| `ranking` | an object |  |
| `ignore` | a list of strings | At most 128 entries |

## `sparse`

A list of paths inside the checkout.

§8.4.11: monorepo checkout narrowing, declarative. The fetcher applies these as git sparse-checkout patterns in cone mode and MUST fail loudly rather than silently falling back to a full clone.

## `suggested_mount_path`

A string.

§8.4.8's one exception, and it is advisory: consumed ONCE at attach time and never read again. It is not where this component is mounted — a repository does not get to decide that, because the same repository is mounted at different paths by different projects, which is the entire reason the component model exists.

## `nav`

A list of objects.

§8.7.6's nav fragment, as the repository declares it, and the first of the sources that requirement names — it takes precedence over the generator's own output. Hrefs are relative to the COMPONENT root, because the project prefixes its mount path onto every one of them when the fragment is spliced into the project's layout tree; an absolute or root-relative href is dropped during normalisation rather than prefixed into nonsense.

<!-- END GENERATED: docup-yaml -->
