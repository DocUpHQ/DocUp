<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    /*
    |---------------------------------------------------------------------------
    | Origins (SPEC 8.1.4, 8.1.5)
    |---------------------------------------------------------------------------
    | 🛑 The dashboard and published documentation MUST occupy distinct
    | registrable domains, and the application refuses to boot when they do not.
    | Built documentation is attacker-controlled HTML and JavaScript; on a shared
    | registrable domain it can toss cookies at the dashboard, Clear-Site-Data
    | spans tenants, and Laravel's TrustHosts default trusts subdomains of
    | APP_URL.
    |
    | The sole exception is DOCUP_UNSAFE_SINGLE_ORIGIN (SPEC 8.1.5), which forces
    | every project public and disables private sharing and tenant CSS.
    */
    'origins' => [
        'app' => env('DOCUP_APP_HOST'),
        'docs' => env('DOCUP_DOCS_APEX'),
        'preview' => env('DOCUP_PREVIEW_APEX'),
        'assets' => env('DOCUP_ASSET_HOST'),
    ],

    /*
    |---------------------------------------------------------------------------
    | Unsafe modes (SPEC 8.22.11, 20.4)
    |---------------------------------------------------------------------------
    | 🛑 One registry. Every installation-level escape hatch lives here, and an
    | architecture test asserts that no DOCUP_UNSAFE_*, DOCUP_DANGEROUSLY_*,
    | DOCUP_ACKNOWLEDGE_* or DOCUP_ALLOW_* variable exists outside it.
    |
    | Invariant: no security control sits behind a flag that defaults open.
    */
    'unsafe' => [
        'single_origin' => env('DOCUP_UNSAFE_SINGLE_ORIGIN', false),
        'acknowledge_unsandboxed' => env('DOCUP_ACKNOWLEDGE_UNSANDBOXED', false),
        'allow_unlisted_auth_types' => env('DOCUP_DANGEROUSLY_ALLOW_UNLISTED_AUTH_TYPES', false),
        'allow_raw_html_branding' => env('DOCUP_ALLOW_RAW_HTML_BRANDING', false),
        'allow_unverified_build_images' => env('DOCUP_ALLOW_UNVERIFIED_BUILD_IMAGES', false),
    ],

    /*
    |---------------------------------------------------------------------------
    | Quality gates (SPEC 9.4)
    |---------------------------------------------------------------------------
    | Three tiers. These thresholds are committed configuration protected by
    | CODEOWNERS, and `docup:gate --check-thresholds` fails when one DECREASES
    | relative to git HEAD - so a phase under time pressure cannot lower the bar
    | instead of fixing the code.
    */
    'gates' => [
        'baseline' => [
            'phpstan_level' => 8,
            'phpstan_level_strict_paths' => 9,
            'strict_paths' => [
                'app/Serving',
                'app/Auth',
                'app/Artifacts',
                'app/Config',
            ],
            'pest_presets' => ['php', 'security', 'laravel', 'strict'],
        ],
        'security_critical' => [
            'mutation_min_score' => 75,
            'requires_threat_model_delta' => true,
            'requires_abuse_corpus_case' => true,
        ],
        'release' => [
            'requires_asvs_matrix' => true,
            'requires_sbom' => true,
            'requires_signed_provenance' => true,
        ],
    ],

    /*
    |---------------------------------------------------------------------------
    | Artifact storage (SPEC 8.8.1, 10.3)
    |---------------------------------------------------------------------------
    | Write-once, keyed only by the build identifier. 🛑 No project slug, version
    | slug, language or user-supplied name may appear in a storage key, so that
    | renaming can never strand or invalidate stored artifacts.
    */
    'artifacts' => [
        'disk' => env('DOCUP_ARTIFACT_DISK', 'artifacts'),
        'max_files' => (int) env('DOCUP_ARTIFACT_MAX_FILES', 50_000),
        'max_bytes' => (int) env('DOCUP_ARTIFACT_MAX_BYTES', 5 * 1024 * 1024 * 1024),
        'max_file_bytes' => (int) env('DOCUP_ARTIFACT_MAX_FILE_BYTES', 1024 * 1024 * 1024),
        'max_compression_ratio' => (int) env('DOCUP_ARTIFACT_MAX_RATIO', 100),
    ],

    /*
    |---------------------------------------------------------------------------
    | Edge driver (SPEC 11.3, ADR 0001)
    |---------------------------------------------------------------------------
    | Both drivers exist from day one behind one ArtifactHandoff interface and
    | both run in the CI matrix. caddy-intercept is the default because it
    | preserves the application's response headers through the handoff natively;
    | nginx-accel replaces the whole header set and needs the re-emission list in
    | its own configuration (SPEC 8.9.8).
    */
    'edge' => [
        'driver' => env('DOCUP_EDGE_DRIVER', 'caddy-intercept'),
        'internal_prefix' => '/_internal',
    ],

    /*
    |---------------------------------------------------------------------------
    | Search (SPEC 8.16.1, ADR 0004)
    |---------------------------------------------------------------------------
    | MySQL FULLTEXT is the shipped default so that a default installation needs
    | no search service. Measured at 200k sections: 10 ms unfiltered, 80 ms with
    | the mandatory scope filter, because the WHERE defeats the early-LIMIT
    | optimisation and cost scales with match-set size rather than result limit.
    */
    'search' => [
        'driver' => env('DOCUP_SEARCH_DRIVER', 'mysql_fulltext'),
        'meilisearch_recommended_above_sections' => 200_000,
    ],

    /*
    |---------------------------------------------------------------------------
    | Telemetry (SPEC 8.22.12)
    |---------------------------------------------------------------------------
    | 🛑 Off by default, opt-in, aggregate only, and it will never gate a feature.
    */
    'telemetry' => [
        'enabled' => env('DOCUP_TELEMETRY', false),
        'advisory_check' => env('DOCUP_ADVISORY_CHECK', false),
    ],

];
