<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

return [

    /*
    |---------------------------------------------------------------------------
    | Driver (SPEC 8.8.1, 17 Phase 03)
    |---------------------------------------------------------------------------
    | Which ArtifactStore implementation serves. Both are the same interface;
    | 'local' is the single-node default profile of SPEC 11 and 's3' is the
    | multi-node one. The choice is deployment shape, not a feature tier --
    | SPEC 4.4 forbids an open core and there is no paid driver.
    */
    'driver' => env('DOCUP_ARTIFACT_DRIVER', 'local'),

    'disks' => [
        'local' => 'artifacts',
        's3' => 'artifacts-s3',
    ],

    /*
    |---------------------------------------------------------------------------
    | Ingest caps (SPEC 8.8.2)
    |---------------------------------------------------------------------------
    | 🛑 The defaults are SPEC 8.8.2's, verbatim: 50,000 files, 5 GB total,
    | 1 GB per file, 100:1 compression. They are a ceiling on what one build may
    | produce, not a quota -- a quota is per organisation and lives in the
    | database (SPEC 8.8.10), because it is a commercial limit that an operator
    | varies per tenant, while these are a defence against a malicious archive
    | and are the same for everyone on the installation.
    |
    | Raising a cap is an operator decision with a real cost: the file count
    | bounds how long one ingest can occupy a worker, and the ratio is the only
    | thing standing between a 40 KB upload and a full disk.
    */
    'caps' => [
        'files' => (int) env('DOCUP_ARTIFACT_MAX_FILES', 50_000),
        'total_bytes' => (int) env('DOCUP_ARTIFACT_MAX_TOTAL_BYTES', 5 * 1024 * 1024 * 1024),
        'file_bytes' => (int) env('DOCUP_ARTIFACT_MAX_FILE_BYTES', 1024 * 1024 * 1024),
        'compression_ratio' => (float) env('DOCUP_ARTIFACT_MAX_COMPRESSION_RATIO', 100.0),
    ],

    /*
    |---------------------------------------------------------------------------
    | Soft-landing window (SPEC 8.8.6)
    |---------------------------------------------------------------------------
    | How long the previous manifest stays resolvable after a pointer flip, so a
    | page loaded a second before the flip can still fetch its relative assets.
    | Five minutes is SPEC 8.8.6's default. Zero would make every flip a visible
    | breakage for whoever was mid-page-load; an hour would keep withdrawn
    | content reachable long after someone pressed rollback, which is the other
    | failure and the worse one.
    */
    'soft_landing_seconds' => (int) env('DOCUP_SOFT_LANDING_SECONDS', 300),

    /*
    |---------------------------------------------------------------------------
    | Quotas (SPEC 8.8.10)
    |---------------------------------------------------------------------------
    | Installation-wide defaults, overridable per organisation once the
    | administration surface exists. Enforced AT INGEST from the authoritative
    | manifest -- free and exact -- never by a `du` poll or a nightly job.
    |
    | A null value means unlimited, which is the right default for a
    | self-hosted installation whose operator owns the disk. SPEC 8.8.10 requires
    | the quota to EXIST and be enforced, not to be restrictive out of the box.
    */
    'quotas' => [
        'organisation_artifact_bytes' => env('DOCUP_QUOTA_ORG_ARTIFACT_BYTES') !== null
            ? (int) env('DOCUP_QUOTA_ORG_ARTIFACT_BYTES')
            : null,
        'versions_per_project' => env('DOCUP_QUOTA_VERSIONS_PER_PROJECT') !== null
            ? (int) env('DOCUP_QUOTA_VERSIONS_PER_PROJECT')
            : null,
        'redirects_per_project' => (int) env('DOCUP_QUOTA_REDIRECTS_PER_PROJECT', 200),
    ],

];
