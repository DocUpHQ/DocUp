<?php

declare(strict_types=1);

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

return [

    /*
    |--------------------------------------------------------------------------
    | Default Filesystem Disk
    |--------------------------------------------------------------------------
    |
    | Here you may specify the default filesystem disk that should be used
    | by the framework. The "local" disk, as well as a variety of cloud
    | based disks are available to your application for file storage.
    |
    */

    'default' => env('FILESYSTEM_DISK', 'local'),

    /*
    |--------------------------------------------------------------------------
    | Filesystem Disks
    |--------------------------------------------------------------------------
    |
    | Below you may configure as many filesystem disks as necessary, and you
    | may even configure multiple disks for the same driver. Examples for
    | most supported storage drivers are configured here for reference.
    |
    | Supported drivers: "local", "ftp", "sftp", "s3"
    |
    */

    'disks' => [

        'local' => [
            'driver' => 'local',
            'root' => storage_path('app/private'),
            'serve' => true,
            'throw' => false,
            'report' => false,
        ],

        'public' => [
            'driver' => 'local',
            'root' => storage_path('app/public'),
            'url' => rtrim((string) env('APP_URL', 'http://localhost'), '/').'/storage',
            'visibility' => 'public',
            'throw' => false,
            'report' => false,
        ],

        's3' => [
            'driver' => 's3',
            'key' => env('AWS_ACCESS_KEY_ID'),
            'secret' => env('AWS_SECRET_ACCESS_KEY'),
            'region' => env('AWS_DEFAULT_REGION'),
            'bucket' => env('AWS_BUCKET'),
            'url' => env('AWS_URL'),
            'endpoint' => env('AWS_ENDPOINT'),
            'use_path_style_endpoint' => env('AWS_USE_PATH_STYLE_ENDPOINT', false),
            'throw' => false,
            'report' => false,
        ],

        /*
         * 🛑 Artifact storage (§8.8.1). `throw => true` on both artifact disks,
         * unlike the Laravel defaults above: a swallowed write failure means a
         * build that reports success while its bytes are missing, and the
         * missing bytes are discovered by a reader, in production, at a URL
         * somebody shared. An exception at ingest fails the build instead,
         * which is the correct outcome and the recoverable one.
         *
         * `visibility` is deliberately absent — private is Flysystem's default
         * for the local driver and the bucket policy's job on S3. §8.12.22's
         * containment self-test is what actually proves it, not this line.
         */
        'artifacts' => [
            'driver' => 'local',
            /*
             * 🛑 The default is the path the EDGE serves, not a Laravel storage
             * path. deploy/Caddyfile and deploy/nginx.conf both serve
             * /var/lib/docup/artifacts, and a store writing anywhere else makes
             * every handoff point at a file the edge cannot see -- a correct
             * 200 from the application and a 404 for the reader, with nothing
             * logged as wrong. A test asserts the two agree.
             */
            'root' => env('DOCUP_ARTIFACT_ROOT', '/var/lib/docup/artifacts'),
            'serve' => false,
            'throw' => true,
            'report' => false,

            /*
             * 🛑 Explicit, because Flysystem's default is 'private' and private
             * means directory mode 0700 -- and under SPEC 8.9.8 the process that
             * reads these bytes is NOT the one that wrote them. The application
             * authorises and hands off; a separate edge process opens the file.
             * With 0700 directories owned by the application's user, nginx got
             * `openat() ... failed (13: Permission denied)` and the reader got a
             * 403 behind a correct authorisation -- found by the nginx CI matrix
             * leg, and invisible under caddy-intercept because FrankenPHP serves
             * as root and can traverse anything.
             *
             * 🛑 These modes are NOT the containment boundary and MUST NOT be
             * read as one. What makes an artifact unreachable without
             * authorisation is the `internal` location plus the application's
             * decision (SPEC 8.9.8), proven by the private-asset containment
             * self-test (SPEC 8.12.22). Tightening these modes would not add a
             * boundary; it would only break the handoff.
             *
             * The rejected alternative is a shared group -- 0750/0440 with the
             * edge's user in the application's group. It is tighter on a host
             * with untrusted local users, and it requires two containers to
             * agree on a numeric gid that neither declares. When it is wrong the
             * symptom is this same 403, which is SPEC 18.18's "silent security
             * degradation" shape: a configuration that fails to apply looking
             * like one that works. Recorded as a proposed amendment to SPEC
             * 8.9.8 rather than decided here.
             *
             * The file mode is 0444 to agree with LocalArtifactStore's
             * write-once chmod; disagreeing would make the first write fight the
             * adapter.
             */
            'permissions' => [
                'file' => ['public' => 0o444, 'private' => 0o444],
                'dir' => ['public' => 0o755, 'private' => 0o755],
            ],
        ],

        'artifacts-s3' => [
            'driver' => 's3',
            'key' => env('DOCUP_ARTIFACT_S3_KEY', env('AWS_ACCESS_KEY_ID')),
            'secret' => env('DOCUP_ARTIFACT_S3_SECRET', env('AWS_SECRET_ACCESS_KEY')),
            'region' => env('DOCUP_ARTIFACT_S3_REGION', env('AWS_DEFAULT_REGION')),
            'bucket' => env('DOCUP_ARTIFACT_S3_BUCKET'),
            'endpoint' => env('DOCUP_ARTIFACT_S3_ENDPOINT'),
            'use_path_style_endpoint' => env('DOCUP_ARTIFACT_S3_PATH_STYLE', false),
            'throw' => true,
            'report' => false,
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Symbolic Links
    |--------------------------------------------------------------------------
    |
    | Here you may configure the symbolic links that will be created when the
    | `storage:link` Artisan command is executed. The array keys should be
    | the locations of the links and the values should be their targets.
    |
    */

    'links' => [
        public_path('storage') => storage_path('app/public'),
    ],

];
