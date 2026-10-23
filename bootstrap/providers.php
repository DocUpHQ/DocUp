<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Providers\AppServiceProvider;
use App\Providers\ArtifactServiceProvider;
use App\Providers\AuthServiceProvider;
use App\Providers\BuildServiceProvider;
use App\Providers\FortifyServiceProvider;
use App\Providers\SchemaServiceProvider;
use App\Providers\SourceServiceProvider;

return [
    AppServiceProvider::class,
    ArtifactServiceProvider::class,
    AuthServiceProvider::class,
    BuildServiceProvider::class,
    FortifyServiceProvider::class,
    SchemaServiceProvider::class,
    SourceServiceProvider::class,
];
