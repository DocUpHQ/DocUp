<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Providers\AppServiceProvider;
use App\Providers\ArtifactServiceProvider;
use App\Providers\AuthServiceProvider;
use App\Providers\FortifyServiceProvider;
use App\Providers\SchemaServiceProvider;

return [
    AppServiceProvider::class,
    ArtifactServiceProvider::class,
    AuthServiceProvider::class,
    FortifyServiceProvider::class,
    SchemaServiceProvider::class,
];
