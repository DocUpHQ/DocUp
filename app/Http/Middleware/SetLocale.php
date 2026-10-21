<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Middleware;

use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Dashboard locale selection.
 *
 * 🛑 SPEC 9.5.2 keeps the DASHBOARD locale strictly separate from
 * documentation-content locale routing. This middleware is the dashboard's, and
 * runs only on the `web` group. Documentation locale is a property of a project
 * version (SPEC 8.6.12) resolved from the URL by the resolver, and SPEC 8.6.13
 * forbids content-negotiating it at all, because `Vary: Accept-Language` on
 * documentation would destroy edge cacheability.
 *
 * So: negotiate here, never on the documentation path.
 */
final class SetLocale
{
    public function handle(Request $request, \Closure $next): Response
    {
        $locale = $this->resolve($request);

        if ($locale !== null) {
            app()->setLocale($locale);
        }

        return $next($request);
    }

    private function resolve(Request $request): ?string
    {
        $available = $this->available();

        // An explicit query parameter wins, so a reviewer can check a locale
        // without changing their browser. Validated against the available set,
        // never trusted as a path or a file name.
        $requested = $request->query('locale');

        if (is_string($requested) && in_array($requested, $available, true)) {
            return $requested;
        }

        $session = $request->hasSession() ? $request->session()->get('locale') : null;

        if (is_string($session) && in_array($session, $available, true)) {
            return $session;
        }

        $preferred = $request->getPreferredLanguage($available);

        return is_string($preferred) ? $preferred : null;
    }

    /**
     * The locales that actually have message files, discovered rather than
     * hard-coded, so adding `lang/<locale>/` is all it takes to add a locale.
     *
     * @return list<string>
     */
    private function available(): array
    {
        $base = lang_path();

        if (! is_dir($base)) {
            return ['en'];
        }

        $locales = [];

        foreach ((array) scandir($base) as $entry) {
            if (! is_string($entry) || str_starts_with($entry, '.')) {
                continue;
            }

            if (is_dir($base.DIRECTORY_SEPARATOR.$entry)) {
                $locales[] = $entry;
            }
        }

        return $locales === [] ? ['en'] : $locales;
    }
}
