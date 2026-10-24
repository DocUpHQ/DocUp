<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use App\Builds\Sandbox\SandboxPolicy;
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
            'unsafeBanners' => $this->unsafeBanners(),
        ];
    }

    /**
     * §8.22.11's "dashboard banner", for every unsafe mode that is on.
     *
     * 🛑 **A list of sentences, not a list of flag names.** §20.4 requires
     * each escape hatch to show a banner, and a banner reading
     * "DOCUP_ACKNOWLEDGE_UNSANDBOXED is set" tells a reader which variable
     * somebody typed, not what is true of their installation. The wording
     * belongs with the policy that knows what the flag costs — see
     * {@see SandboxPolicy::banner()} — rather than with the component that
     * paints it.
     *
     * Deliberately not tenant-scoped: these describe the installation, and
     * the class docblock's rule about tenant data still holds.
     *
     * @return list<string>
     */
    private function unsafeBanners(): array
    {
        $banners = [];

        if ((bool) config('docup.unsafe.single_origin')) {
            // §8.1.5: the degraded mode, stated in the terms an operator
            // needs rather than as the name of a variable.
            $banners[] = 'This installation serves the dashboard and documentation from one '
                .'registrable domain. Every project is forced public, private sharing is off '
                .'and tenant CSS is disabled.';
        }

        $sandbox = SandboxPolicy::fromConfig()->banner();

        if ($sandbox !== null) {
            $banners[] = $sandbox;
        }

        return $banners;
    }
}
