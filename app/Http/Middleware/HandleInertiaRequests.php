<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use Illuminate\Http\Request;
use Inertia\Middleware;

final class HandleInertiaRequests extends Middleware
{
    protected $rootView = 'app';

    /**
     * Props shared with every Inertia response.
     *
     * 🛑 Deliberately minimal. SPEC 8.14.10 requires that chrome carries no
     * secrets, and anything shared here is sent to every page including the
     * credential-entry page. Nothing tenant-scoped belongs in this array.
     */
    public function share(Request $request): array
    {
        return [
            ...parent::share($request),
            'locale' => app()->getLocale(),
            'installationName' => config('app.name', 'DocUp'),
        ];
    }
}
