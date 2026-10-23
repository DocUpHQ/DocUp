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
    'poll_interval_ms' => 250,
    'lease_seconds' => 60,
    'lease_renew_seconds' => 20,

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
         * The one toolchain Phase 06 ships. SPEC 17 scopes this phase to
         * "config schema beyond what MkDocs needs" being out of scope, so
         * one pre-baked MkDocs image is the whole `build.os` enum for now;
         * Phase 09's declarative toolchain presets (SPEC 11.4's
         * `DocToolAdapter`) are what make adding the next one a data file.
         */
        'mkdocs' => [
            'reference' => env('DOCUP_IMAGE_MKDOCS', 'docup/build-mkdocs:1'),
            'digest' => env('DOCUP_IMAGE_MKDOCS_DIGEST'),
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
     * SPEC 8.5.5's two admission profiles. Phase 06 ships `simple`;
     * `fair` arrives with the rest of admission control in Phase 07.
     */
    'admission' => env('DOCUP_ADMISSION', 'simple'),
];
