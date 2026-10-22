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
    | The artifact root (SPEC 8.9.8)
    |---------------------------------------------------------------------------
    | 🛑 This path MUST match what the edge serves, and a test asserts that it
    | does against both deploy/Caddyfile and deploy/nginx.conf.
    |
    | It did not, and the failure was invisible: the edge served
    | /var/lib/docup/artifacts while the store wrote to storage/app/artifacts,
    | so every handoff pointed at a file the edge could not see. The application
    | returns a correct 200 with a correct X-Accel-Redirect and the reader gets
    | a 404 from the edge -- nothing is logged as wrong, because nothing in the
    | application IS wrong.
    |
    | Stated here rather than only in config/filesystems.php because this is the
    | value the parity test compares, and the disk reads the same environment
    | variable.
    */
    'root' => env('DOCUP_ARTIFACT_ROOT', '/var/lib/docup/artifacts'),

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

        /*
         * 🛑 SPEC 8.21.6's ceiling on the UPLOAD itself, which is a different
         * number from `total_bytes` above: that one bounds the uncompressed
         * tree (SPEC 8.8.2's 5 GB), this one bounds the archive that arrives.
         * SPEC 8.21.6 states the upload API's defaults as "1 GB, 50,000 files,
         * 100:1", and 1 GB is the archive.
         *
         * It is also the number PHP's own upload_max_filesize must meet. They
         * did not: the image shipped PHP's 2M default, so the upload API
         * rejected anything over 2 MB while documenting 1 GB -- and no test
         * caught it, because Laravel's UploadedFile(test: true) bypasses PHP's
         * upload machinery entirely. A test now asserts the two agree.
         */
        'archive_bytes' => (int) env('DOCUP_ARTIFACT_MAX_ARCHIVE_BYTES', 1024 * 1024 * 1024),
    ],

    /*
    |---------------------------------------------------------------------------
    | Chrome injection (SPEC 8.15.1, SPEC 8.15.4)
    |---------------------------------------------------------------------------
    | Injection happens at INGEST, never at serve time -- SPEC 4.3/2, SPEC
    | 4.3/6, SPEC 8.9.8 and SPEC 19/6 all say so, and the artifact handoff
    | depends on it: the edge moves bytes it does not read, so nothing could
    | rewrite them on the way out even if the architecture allowed it.
    |
    | 🛑 The ceiling is SPEC 8.15.4's third non-injectable class. It is a memory
    | bound rather than a policy: injection holds one whole document while it
    | works, so an uncapped ceiling is an uncapped allocation driven by an
    | uploaded file. A document over 4 MiB is left alone and the build falls back
    | to api_only, which SPEC 8.15.4 prefers to refusing to publish it.
    */
    'chrome' => [
        'max_html_bytes' => (int) env('DOCUP_CHROME_MAX_HTML_BYTES', 4 * 1024 * 1024),
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
