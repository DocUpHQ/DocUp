<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * The sentence an author reads for each §8.5.15 identifier.
 *
 * Phase 07's exit criteria are seven hostile builds that must each reach "a
 * **distinct** terminal state with a **specific user-facing message** and a
 * **stable failure identifier**". The identifier is {@see BuildFailure}'s;
 * this is the message, and the two are kept apart deliberately:
 *
 *  - 🛑 **the identifier is a contract and never changes.** §8.1.11 makes
 *    API v3 a versioned public contract and operators build alerts on these
 *    strings, so `resource.oom_killed` means the same thing in two years;
 *  - the message is prose, translated, and reworded whenever a clearer
 *    wording is found. Putting the wording in the identifier would freeze
 *    the prose; putting the identifier in the prose would make an alert rule
 *    depend on a translation.
 *
 * 🛑 **Every message names the thing the author can change.** A build that
 * fails with no next action produces a support request, and the most common
 * shape of that is a message describing a control rather than a remedy.
 * `CatalogueCompletenessTest` asserts that every identifier the pipeline and
 * the runner can produce has an entry here — a terminal state with no message
 * is an author staring at a hex string.
 */
final class FailureCatalogue
{
    /**
     * @var array<string, string>
     */
    private const MESSAGES = [

        // ------------------------------------------------- refused outright
        'rejected.builds_disabled' => 'This installation does not build documentation: it runs in hosting-only mode (§8.1.7), where documentation is uploaded through the API rather than built from a repository. Ask your administrator, or publish with the direct-upload endpoint.',
        'rejected.webhook_triggering_disabled' => 'Automatic builds are paused for this project: its default version failed too many times in a row for reasons a change to the project can fix (§8.5.17). You can still build manually, and a successful manual build is what clears it. Builds that failed for reasons on our side are never counted.',
        'rejected.fork_builds_disabled' => 'This build came from a fork, and builds from forks are off by default (§8.5.10). A fork build would run code from outside your organisation; enable it per project only if you have read the threat statement, and note that it receives no secrets either way.',
        'rejected.runtime_socket_requested' => 'The build asked for access to the container runtime, which no build may have (§8.5.13). The runner is the only process that may start containers, and it accepts a fixed specification that has no field for a mount, a capability or a runtime. If this was not something you configured, tell your administrator: a build does not ask for this by accident.',
        'rejected.run_specification_refused' => 'The runner refused the instructions for this build as malformed (§8.5.13). This is a fault on our side rather than yours; the build can be triggered again.',
        'rejected.no_component' => 'This version has no component to build. Attach a repository component to the project before triggering a build.',
        'rejected.no_repository_attached' => 'No repository is attached to this project, so there is nothing to fetch. Connect one first.',
        'rejected.version_missing' => 'The version this build was triggered for no longer exists.',

        // ------------------------------------------------- §8.4 the config file
        //
        // 🛑 Every one of these names the key, not the value. The message is
        // written into the build log, and §8.5.21's redaction has not seen
        // this file yet — echoing a line back would be the one way to put an
        // un-redactable secret into a log. `ConfigRefused::userMessage()`
        // appends the offending key to these sentences.
        'config.too_large' => 'The configuration file is larger than 256 KiB and was not read (§8.4.9). A `.docup.yaml` describes how to build documentation; nothing legitimate reaches that size, so this is almost always a file that was generated or concatenated by mistake.',
        'config.aliases_forbidden' => 'The configuration file uses a YAML anchor or alias (`&name` or `*name`), which DocUp does not accept (§8.4.9). Aliases let a small file expand into an enormous one while it is being parsed, so the document is refused rather than expanded. Write the repeated section out in full.',
        'config.too_deep' => 'The configuration file nests more than 32 levels deep (§8.4.9). Nothing in the schema is more than four levels deep, so this is either a generated file or a mistake in the indentation.',
        'config.multiple_documents' => 'The configuration file contains more than one YAML document (§8.4.9). A `---` separator after the first document starts a second one; DocUp reads a single document, so remove the separator or split the file.',
        'config.unparseable' => 'The configuration file is not valid YAML, or is not a mapping of keys to values. The line number is in the detail; an unclosed quote or a tab used for indentation are the two usual causes — YAML forbids tabs.',
        'config.unknown_key' => 'The configuration file contains a key the schema does not define (§8.4.8). The schema is published and complete: every accepted key is in it, and anything else is refused rather than ignored, so that a typo is an error instead of a setting that silently did nothing.',
        'config.project_scoped_key' => '🛑 The configuration file names something a repository does not get to decide (§8.4.8). A project, a mount path, a domain, a visibility level, a version channel and a retention policy are all properties of the *project that mounts this component*, not of the repository — the same repository is mounted by different projects at different paths with different audiences, which is the whole reason components exist. Configure these in the dashboard. The one advisory exception is `suggested_mount_path`, which is read once when the component is attached and never again.',
        'config.missing_key' => 'A section of the configuration file is missing a key it cannot work without. The detail names it. A misspelling is the usual cause — the schema rejects the misspelled key and reports the correct one as absent, which are two views of the same mistake.',
        'config.invalid_value' => 'A value in the configuration file is not one the schema allows. The path to it is in the detail; the published schema lists the accepted values for every key, and an editor pointed at it will complete them for you.',
        'config.commands_with_apt_packages' => '`build.commands` cannot be combined with `build.apt_packages` (§8.4.4). `build.commands` discards the predefined pipeline entirely, and installing system packages is part of that pipeline — so the two together describe a build that does and does not have a predefined pipeline. Remove one.',
        'config.conda_unsupported' => '`conda.environment` is accepted by the schema and is not runnable in this version (§8.4.14). The egress allowlist carries no conda channel and the pre-baked build images carry no conda distribution, so a conda build would fail at dependency-install time with something far less clear than this. Use `python.install` with a requirements file, or `build.commands` to drive your own tooling.',
        'config.no_toolchain' => 'The configuration file does not say which documentation generator to use. Add a `toolchain:` key naming one — the detail says which generators the checkout looks like — or a `sphinx:` or `mkdocs:` section, or `build.commands` to run the build yourself.',
        'config.unknown_toolchain' => 'The `toolchain:` key names a generator this installation does not ship. The detail lists the ones it does; a generator is a data file rather than code, so adding one is a change an operator can make.',
        'config.missing_generator_configuration' => 'The generator needs its own configuration file and none was found. The detail lists the names that were looked for, relative to this component\'s source path; name the file explicitly if it is somewhere else.',
        'config.sparse_checkout_failed' => '🛑 A `sparse` checkout was requested and narrowed nothing (§8.4.11). The build is stopped rather than continued with a full checkout, because a sparse checkout that silently did not apply is a build that reads files it was told to exclude. Check that the paths exist at this commit and are directories.',

        // ------------------------------------------------- §8.6 versions
        //
        // Operator-facing rather than author-facing: these are refusals of
        // something somebody typed into the dashboard, so each names the
        // input and what to do about it.
        'version.slug_not_normalised' => 'That version slug is not in the permitted form (§8.6.6). A slug is lowercase, and anything outside letters, digits, `.`, `_` and `-` becomes a hyphen — it is a URL segment, so the restriction is the URL\'s rather than ours. The suggested spelling is in the detail.',
        'version.slug_reserved' => 'That version slug is reserved (§8.6.6). `_` is where this installation\'s own endpoints live, and anything shaped like a language code (`en`, `fr`, `pt-br`) is refused because a project using the language-and-version URL scheme puts a language in the same position — a version slugged `fr` becomes unreachable the day somebody adds a French translation.',
        'version.duplicate_language_in_group' => 'Two of those versions are in the same language, so they cannot be translations of each other (§8.6.12). A translation group holds one version per language — that is what makes a language switcher unambiguous.',
        'version.slug_taken' => 'Another version of this project already uses that slug in this language. Slugs are unique per project and language, which is what makes `/en/v2/` and `/ja/v2/` two different pages rather than a collision.',

        // ------------------------------------------------- the author's code
        'user.build_command_failed' => 'The documentation generator exited with an error. The build log holds its output; the last few lines are usually the cause.',
        'user.dependency_install_failed' => 'Installing the build\'s dependencies failed (§8.4.2). The build log holds the package manager\'s output. A host that is not on this installation\'s egress allowlist and a lockfile that disagrees with `package.json` are the two usual causes.',

        // ------------------------------------------------- §8.5.9 egress
        'user.egress_host_not_allowlisted' => 'The build tried to reach a host that is not on this installation\'s egress allowlist, and the proxy refused it (§8.5.9). Builds may reach the package indexes and git hosts your administrator has listed, and nothing else. Vendor the dependency, or ask for the host to be added.',
        'user.package_host_not_allowlisted' => 'Installing dependencies needed a package host that is not on this installation\'s egress allowlist (§8.5.9). The default list covers PyPI, npm, crates.io, the Go module proxy and RubyGems; a distribution package manager such as apt is not on it, because build images are pre-baked (§8.5.14) and cannot install system packages.',
        'user.egress_metadata_endpoint_denied' => 'The build tried to reach the cloud instance metadata endpoint at 169.254.169.254. That address is never reachable from a build, in any configuration: it is where a cloud host keeps its own credentials. If this came from a dependency rather than from your configuration, treat it as a supply-chain compromise and tell your administrator.',
        'user.egress_blocked_at_layer3' => 'The build opened a network connection directly, going around the egress proxy, and the sandbox refused the packet (§8.5.9). Set http_proxy and https_proxy — the build environment already does — or use a tool that honours them.',

        // ------------------------------------------------- §8.5.18 resources
        'resource.oom_killed' => 'The build ran out of memory and the kernel killed it. Reduce what the generator holds at once — large image sets and full-text indexes are the usual causes — or ask your administrator to raise the per-build memory limit.',
        'resource.pid_limit_exceeded' => 'The build tried to start more processes than its limit allows, and the kernel refused (§8.5.18). A parallel build step with an unbounded worker count is the usual cause; pin the job count explicitly.',
        'resource.disk_quota_exceeded' => 'The build filled its workspace. The workspace is a fixed size (§8.5.18) and holds both the checkout and the generated site, so a very large output or a dependency cache written into the working tree will exhaust it.',

        // ------------------------------------------------- §8.5.15 clocks
        'timeout.stage_timeout' => 'The build exceeded its time limit and was stopped (§8.5.18). Builds are not retried on a timeout, because a build that took too long once will take too long again — shorten it, or ask for a longer limit.',
        'timeout.stalled_without_output' => 'The build produced no output for ten minutes and was stopped (§8.5.15). Something was waiting: a prompt, a lock, or a network call the sandbox will never let through.',

        // ------------------------------------------------- §8.4.5 contract
        'contract.no_output_directory' => 'The build finished but wrote nothing to $DOCUP_OUTPUT (§8.4.5). Point your generator\'s output directory at that path — it is set in the build environment.',

        // ------------------------------------------------- ours, never theirs
        'infra.runtime_refused_the_container' => 'The container runtime refused to start this build. This is a fault on our side; it does not count against your project and the build can be triggered again.',
        'infra.runner_did_not_answer' => 'The build runner did not answer in time. This is a fault on our side; it does not count against your project.',
        'infra.runner_lost' => 'The build runner stopped while this build was running. This is a fault on our side; the build can be triggered again.',
        'infra.sandbox_self_test_failed' => 'Builds are unavailable: the build sandbox failed its isolation self-test (§8.5.12) and this installation refuses to run repository code until it passes. Your administrator has the details.',

        // ------------------------------------------------- asked for
        'cancelled.voluntary_cancel' => 'The build cancelled itself.',
        'cancelled.cancelled_by_request' => 'This build was cancelled. Nothing was published, and the version still serves whatever it served before.',
    ];

    /**
     * The sentence for an identifier.
     *
     * 🛑 Falls back to a sentence that names the identifier rather than to
     * an empty string or the identifier alone. A build that reaches a state
     * nobody wrote a message for is a gap in this file, and the author
     * should be given something they can quote in a support request instead
     * of a blank panel.
     */
    public static function message(string $identifier): string
    {
        return self::MESSAGES[$identifier]
            ?? 'The build failed with "'.$identifier.'". No description is recorded for that '
              .'state, which is itself a defect — please report it with the build reference.';
    }

    public static function has(string $identifier): bool
    {
        return array_key_exists($identifier, self::MESSAGES);
    }

    /** @return array<string, string> */
    public static function all(): array
    {
        return self::MESSAGES;
    }
}
