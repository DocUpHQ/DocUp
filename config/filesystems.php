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
