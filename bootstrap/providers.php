<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

use App\Providers\AppServiceProvider;
use App\Providers\SchemaServiceProvider;

return [
    AppServiceProvider::class,
    SchemaServiceProvider::class,
];
