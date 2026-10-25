<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| The build pipeline (SPEC 8.5)
|------------------------------------------------------------------------------
| 🛑 The image list is an ALLOWLIST, not a default. SPEC 8.5.14: "Build images
| MUST be pre-baked and digest-pinned from an allowlisted `build.os` enum ...
| User-supplied Dockerfiles and arbitrary images MUST NOT be supported."
| Nothing in a repository, a webhook or a YAML file can name an image that is
| not a key below, and `RunSpecification` refuses a name that is not.
*/

return [

    /*
     * The spool the worker and the runner exchange work through.
     *
     * 🛑 A directory, not a socket or a queue, and the reason is SPEC 8.5.13:
     * the runner is the sole holder of the container-runtime socket and must
     * hold no database credentials. A Laravel queue would give it the
     * database; an HTTP endpoint would give it a listening port on a host
     * that runs other tenants' code moments later. A directory gives it
     * neither, and the exchange is auditable by listing it.
     */
    'spool' => env('DOCUP_RUNNER_SPOOL', '/var/lib/docup/spool'),

    /*
     * How often the runner looks for work, and how long it holds a step.
     *
     * 🛑 The lease is deliberately short relative to a stage's timeout
     * (SPEC 8.5.6) and is RENEWED while the runner is alive. A lease as long
     * as the stage would mean a runner that died at the first second kept the
     * work locked for the whole timeout; a lease shorter than the renewal
     * interval would be lost by a healthy runner. 60 and 20 give three
     * renewals per lease, so two consecutive missed renewals are needed before
     * work is reclaimed.
     */
    /*
     *--------------------------------------------------------------------
     * SPEC 8.5.21-8.5.23: the log a build can be watched through
     *--------------------------------------------------------------------
     */

    /*
     * Where a RUNNING build's log is appended, line by line.
     *
     * 🛑 Not the artifact store, and that is a consequence of what each
     * one is for. SPEC 8.8.1 makes the artifact store WRITE-ONCE, because
     * a published artifact that can be replaced is not an artifact; a log
     * is appended to thousands of times and deleted at 90 days (SPEC
     * 20.3). Forcing one into the other would mean either weakening
     * write-once or re-uploading a growing object on every line.
     *
     * Under `storage/`, which the application and the worker already
     * share in every deployment profile - the runner does not mount it,
     * and does not need to: it writes raw lines into the spool and this
     * side redacts them before they land here.
     *
     * The FINISHED log is a different thing and does go to the artifact
     * store, gzipped, at SPEC 10.3's
     * `logs/<project_uuid>/<build_uuid>/log.ndjson.gz`.
     */
    'log_spool' => env('DOCUP_BUILD_LOG_SPOOL', storage_path('docup/build-logs')),

    /*
     * How many lines one page of SPEC 8.5.22's offset contract carries.
     *
     * Large enough that a browser catching up on a finished build does so
     * in a handful of requests, small enough that one response is not a
     * megabyte. A client never needs to know this number: the response
     * carries `next` and `more`.
     */
    'log_page_lines' => 2000,

    /*
     * SPEC 8.5.17's governor: consecutive user-caused failures of a
     * project's DEFAULT VERSION before webhook triggering is disabled.
     *
     * 🛑 The specification says 25 and the exit criterion says the 26th
     * failure trips it, so this is the number of failures TOLERATED.
     * Configurable because an installation building a thousand projects
     * has a different tolerance from one building three - but never zero,
     * which `BuildGovernor` floors.
     */
    'governor_threshold' => (int) env('DOCUP_GOVERNOR_THRESHOLD', 25),

    'poll_interval_ms' => 250,
    'lease_seconds' => 60,
    'lease_renew_seconds' => 20,

    /*
     * 🛑 SPEC 8.1.7's hosting-only mode. With this false the application
     * boots with no runner at all and a build trigger is REFUSED with a
     * stable identifier rather than queued for a runner that will never
     * arrive - which is the difference between "this installation does not
     * build" and "your build is taking a very long time".
     *
     * "This is the single most important enterprise concession: it lets a
     * security team adopt DocUp with the RCE surface removed and builds
     * running in their own CI."
     */
    'enabled' => filter_var(env('DOCUP_BUILDS_ENABLED', true), FILTER_VALIDATE_BOOL),

    /*
     * SPEC 8.5.18's defaults: "30 minutes, 4 GB, 1 CPU, 512 PIDs — all
     * operator-configurable, with none of Read the Docs' unenforced soft
     * limits". Enforced by the runtime, not by a watchdog that notices late.
     */
    'limits' => [
        'wall_clock_seconds' => (int) env('DOCUP_BUILD_WALL_CLOCK', 1800),
        'memory_mb' => (int) env('DOCUP_BUILD_MEMORY_MB', 4096),
        'cpus' => env('DOCUP_BUILD_CPUS', '1'),
        'pids' => (int) env('DOCUP_BUILD_PIDS', 512),
        'tmpfs_mb' => (int) env('DOCUP_BUILD_TMPFS_MB', 512),

        /*
         * SPEC 8.5.18's disk limit, which has no Docker flag on most
         * installations: `--storage-opt size=` is "supported only for
         * overlay over xfs with 'pquota'", measured and refused by the
         * daemon on an ordinary ext4 host (ADR 0011).
         *
         * 🛑 A sized tmpfs volume was the first answer and does not work
         * either: a `local` volume with `type=tmpfs` is remounted EMPTY for
         * every container, so the fetch stage's checkout would be gone
         * before the build stage saw it. Measured, not assumed.
         *
         * So the workspace is a bind mount the runner can see (see
         * `workspace_root`) and the cap is enforced by MEASUREMENT, polled
         * from the runner's own process while the container runs. The
         * build is killed at the cap rather than refused a write, so the
         * author gets `resource.disk_quota_exceeded` instead of whatever
         * their generator says about ENOSPC.
         */
        'disk_mb' => (int) env('DOCUP_BUILD_DISK_MB', 2048),
    ],

    /*
     *--------------------------------------------------------------------
     * SPEC 8.5.8-8.5.12: the sandbox, its trust zone and its egress
     *--------------------------------------------------------------------
     */
    'sandbox' => [

        /*
         * 🛑 SPEC 8.5.11: "Isolation default MUST be hardened `runc`, with
         * gVisor (`runsc`) documented as the recommended production
         * runtime", and the application "MUST refuse to boot with
         * APP_ENV=production, builds enabled and no explicit isolation
         * declaration".
         *
         * Null is NOT a default of `runc`. It is the absence of a
         * declaration, which is exactly what production boot refuses -
         * SPEC 19/23's reasoning is that an operator who has not chosen
         * has not understood the choice, and the fix is to make them make
         * it rather than to pick for them.
         */
        'isolation' => env('DOCUP_BUILD_ISOLATION'),

        /*
         * 🛑 A TEST AFFORDANCE, and the only one in this file.
         *
         * `BuildServiceProvider::boot()` refuses a misconfigured
         * installation, which would otherwise refuse the whole test suite
         * - every test boots the application, and almost none of them has
         * anything to say about sandboxing. Tests that DO exercise the
         * refusal set this true and assert both directions.
         *
         * It is read only under `runningUnitTests()`, so setting it in a
         * real environment does nothing at all. `ArchitectureTest` asserts
         * that, because an affordance that worked in production would be
         * the gate with a switch beside it that SPEC 20.4 forbids.
         */
        'assert_at_boot' => false,

        /*
         * The container runtimes `isolation` may name. A key, never a
         * reference - the same rule as the image allowlist, for the same
         * reason: this value reaches `docker run --runtime`.
         */
        'runtimes' => [
            'runc' => 'runc',
            'gvisor' => 'runsc',
        ],

        /*
         * 🛑 SPEC 8.5.9's default, and the second half of SPEC 8.5.11's
         * boot refusal: "`runc` plus open egress together MUST require
         * DOCUP_ACKNOWLEDGE_UNSANDBOXED=true".
         *
         *   `allowlist` - the shipped default: the sandboxes network, the
         *                 warden's nftables backstop, and the one CONNECT
         *                 proxy. Nothing else is reachable.
         *   `none`      - no network namespace at all (`--network none`),
         *                 which is what Phase 06 shipped and is STRICTER
         *                 than the allowlist rather than weaker.
         *   `open`      - a routed network with no proxy and no backstop.
         *                 This is the one that needs the acknowledgement.
         */
        'egress' => env('DOCUP_SANDBOX_EGRESS', 'allowlist'),

        /*
         * The SPEC 11.2 `sandboxes` zone. `internal: true` in compose, so
         * there is no route off the host - and the nftables backstop
         * closes the route ACROSS it, which internal does not.
         */
        'network' => env('DOCUP_SANDBOX_NETWORK', 'docup_sandboxes'),

        /*
         * The network-namespace warden of SPEC 8.5.9 (ADR 0011). Holds
         * CAP_NET_ADMIN so the build container can hold none.
         */
        'warden_image' => env('DOCUP_IMAGE_WARDEN', 'docup/warden:1'),

        /*
         * How the runner finds the proxy. A LABEL rather than a name,
         * because the container name depends on the compose project name
         * and an operator who renamed their project would silently get a
         * build with no egress at all.
         */
        'proxy_label' => 'docup.role=egress-proxy',
        'proxy_port' => (int) env('DOCUP_PROXY_PORT', 3128),

        /*
         * 🛑 ONE FILE, TWO READERS (ADR 0011). The proxy renders its squid
         * configuration from this file; the application reads the same file
         * for `docup:doctor`, for the SPEC 8.5.12 self-test and for the
         * message an author sees when a host is refused. A PHP copy of the
         * list would drift from the one actually enforced.
         */
        'allowlist_file' => env('DOCUP_EGRESS_ALLOWLIST', base_path('deploy/egress-allowlist.conf')),

        /*
         * Where the runner mounts the host's cgroup hierarchy, read-only.
         *
         * SPEC 8.5.15 requires OOM to be read "authoritatively from cgroup
         * `memory.events:oom_kill`" rather than inferred. 🛑 Measured in
         * Phase 07: a container's cgroup is REMOVED when the container
         * exits, so the file can only be read while the build is running -
         * `CgroupSampler` polls it in the runner's existing output loop.
         * Empty disables sampling, and the driver then says so rather than
         * silently falling back.
         */
        'cgroup_root' => env('DOCUP_CGROUP_ROOT', '/hostcg'),

        /*
         * SPEC 8.5.12's boot self-test. The addresses it must NOT reach.
         * Hostnames resolved inside the sandbox namespace, so these are the
         * compose service names of the data zone.
         */
        'self_test' => [
            'forbidden' => [
                'database' => env('DB_HOST', 'db').':'.env('DB_PORT', '3306'),
                'cache' => env('REDIS_HOST', 'cache').':'.env('REDIS_PORT', '6379'),
                'metadata' => '169.254.169.254:80',
            ],

            /*
             * ...and the one it MUST reach, through the proxy. A self-test
             * that only proved unreachability would pass just as well on a
             * container with no network at all, which is not what SPEC
             * 8.5.12 asks for: "a proxied request succeeds".
             */
            'reachable' => env('DOCUP_SELF_TEST_URL', 'https://pypi.org/simple/'),
        ],
    ],

    /*
     * The allowlist. One entry per image DocUp will ever run.
     *
     * `digest` pins the image by content (SPEC 8.5.14), and it is part of
     * `env_digest` so that a rebuilt image invalidates the SPEC 8.5.2
     * short-circuit — otherwise a security fix to the toolchain would never
     * reach a project whose inputs had not changed.
     *
     * A null digest means "resolve from the local daemon at run time", which
     * is how a development machine works before anything has been published
     * to a registry. `docup:doctor` reports it, and SPEC 20.4's
     * DOCUP_ALLOW_UNVERIFIED_BUILD_IMAGES is what a production installation
     * needs in order to boot that way.
     */
    /*
     * SPEC 8.7.12's `single_pass` composition.
     *
     * 🛑 Antora needs a UI bundle and a generated playbook has to name one,
     * because the repository's own playbook — the file that would normally
     * carry it — is deliberately not read in this mode. A remote URL,
     * fetched during the build stage through SPEC 8.5.9's CONNECT proxy;
     * gitlab.com is already on the allowlist because it is a git host, and
     * the Phase 09 Antora fixture has fetched the same bundle since then.
     *
     * Configuration rather than a literal, because an air-gapped
     * installation has to be able to point this at its own mirror and a
     * constant in a generated playbook would make that a code change.
     */
    'antora' => [
        'ui_bundle' => env(
            'DOCUP_ANTORA_UI_BUNDLE',
            'https://gitlab.com/antora/antora-ui-default/-/jobs/artifacts/HEAD/raw/build/ui-bundle.zip?job=bundle-stable',
        ),
    ],

    'images' => [

        /*
         * 🛑 SPEC 8.5.7: "`fetch` MUST run in a DocUp-authored image
         * containing **no repository code**". This image holds git and a
         * credential helper and nothing else — no interpreter a repository
         * could target, no toolchain, no shell history.
         */
        'fetch' => [
            'reference' => env('DOCUP_IMAGE_FETCH', 'docup/fetch:1'),
            'digest' => env('DOCUP_IMAGE_FETCH_DIGEST'),
        ],

        /*
         * 🛑 The toolchain images, and the KEY is what a preset names.
         *
         * `resources/toolchains/*.yaml` carries an `image:` that must be one
         * of these keys - never a reference - so SPEC 11.4's "a new
         * generator is a data file" has not quietly become "a new image is a
         * YAML value". `ToolchainPresetTest` asserts every shipped preset
         * names a key that exists here.
         *
         * Four images for seven presets, because the division that matters
         * is the language runtime rather than the generator: Sphinx and
         * MkDocs are Python, Docusaurus, VitePress, Starlight and Antora are
         * Node, and mdBook is one static binary.
         */
        'mkdocs' => [
            'reference' => env('DOCUP_IMAGE_MKDOCS', 'docup/build-mkdocs:1'),
            'digest' => env('DOCUP_IMAGE_MKDOCS_DIGEST'),
        ],

        'sphinx' => [
            'reference' => env('DOCUP_IMAGE_SPHINX', 'docup/build-sphinx:1'),
            'digest' => env('DOCUP_IMAGE_SPHINX_DIGEST'),
        ],

        'node' => [
            'reference' => env('DOCUP_IMAGE_NODE', 'docup/build-node:1'),
            'digest' => env('DOCUP_IMAGE_NODE_DIGEST'),
        ],

        'mdbook' => [
            'reference' => env('DOCUP_IMAGE_MDBOOK', 'docup/build-mdbook:1'),
            'digest' => env('DOCUP_IMAGE_MDBOOK_DIGEST'),
        ],
    ],

    /*
     * Where a build's volumes are named from. One volume per build, created
     * and removed by the runner.
     *
     * 🛑 Per build, never shared. A volume shared between builds is a
     * cross-tenant write channel, which SPEC 8.5.20 forbids for caches and
     * which applies with more force to a working tree.
     */
    'volume_prefix' => 'docup-build-',

    /*
     * Where those workspaces live.
     *
     * 🛑 THE SAME PATH INSIDE THE RUNNER AND ON THE HOST, and that is the
     * whole trick. The runner is itself a container, so a path it passes to
     * `docker run -v` is resolved by the DAEMON against the host - binding
     * the same path into the runner at the same name is what lets one
     * directory be both "the workspace the build writes to" and "a
     * directory this process can measure with `stat`".
     *
     * It replaces the per-build named volume Phase 06 used, for a reason
     * measured in Phase 07: SPEC 8.5.18 requires an ENFORCED disk limit, and
     * neither portable alternative works. `--storage-opt size=` is
     * "supported only for overlay over xfs with 'pquota'" (the daemon's own
     * refusal on an ordinary host), and a `local` volume with
     * `type=tmpfs` - which does carry a kernel-enforced size - is REMOUNTED
     * EMPTY for every container, so the fetch stage's checkout is gone
     * before the build stage starts. Both were tried.
     *
     * With a bind the runner can measure the tree in microseconds from its
     * own process, on every poll of the output loop, and kill a container
     * the moment it passes the cap. That is continuous enforcement rather
     * than a limit checked once at the end - which is the distinction SPEC
     * 8.5.18 draws when it rules out "Read the Docs' unenforced soft
     * limits".
     */
    'workspace_root' => env('DOCUP_WORKSPACE_ROOT', '/var/lib/docup/workspaces'),

    /*
     *--------------------------------------------------------------------
     * SPEC 8.5.5's two admission profiles
     *--------------------------------------------------------------------
     * `simple`: concurrency is the worker count, per project non-overlapping
     *           with a queued cap and coalescing.
     * `fair`:   a leader-locked dispatcher, nested installation /
     *           organisation / project semaphores, and deficit round-robin
     *           weighted by organisation share.
     *
     * 🛑 "Read the Docs holds an organisation-scoped lock over a per-project
     * FIFO queue — a verified fairness bug where one organisation's backlog
     * starves another's first build. Neither profile may reproduce it."
     * `FairAdmissionTest` is that sentence as an assertion.
     */
    'admission' => [
        'profile' => env('DOCUP_ADMISSION', 'simple'),

        /*
         * The nested semaphores, outermost first. Each is a ceiling on
         * builds RUNNING in that scope, never on builds queued: a queue cap
         * that refuses work is SPEC 8.5.5's `simple` coalescing, which is a
         * different control with a different failure mode.
         */
        'installation_slots' => (int) env('DOCUP_ADMISSION_SLOTS', 4),
        'organisation_slots' => (int) env('DOCUP_ADMISSION_ORG_SLOTS', 2),
        'project_slots' => 1,

        /*
         * SPEC 8.5.5's `simple` queued cap. Beyond this, an older queued
         * build for the same version is superseded rather than a new one
         * refused - SPEC 8.5.4's fourth dedup layer, which is why the cap
         * can be small without anybody losing a build.
         */
        'queued_cap_per_version' => 1,

        /*
         * Deficit round-robin's quantum, in slot-grants. An organisation's
         * share is its weight; the deficit counter is what stops a large
         * weight becoming a monopoly between dispatcher passes.
         */
        'default_organisation_weight' => 1,
    ],
];
