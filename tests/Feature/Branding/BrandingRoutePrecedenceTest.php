<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Branding;

use App\Http\Controllers\Branding\BrandingAssetController;
use App\Http\Controllers\Branding\ThemeFontController;
use App\Http\Controllers\Branding\ThemeStylesheetController;
use App\Http\Controllers\Edge\AcmeChallengeController;
use App\Http\Controllers\Serving\DocumentController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Tests\TestCase;

/**
 * 🛑 What `routes/branding.php` must not have taken over.
 *
 * Phase 27 inserts a **wildcard-domain** route group between
 * `routes/edge.php` and `routes/docs.php`, and Phase 19 measured why that is
 * the only position that works: Laravel matches a route declaring a domain
 * ahead of every route that does not, whatever the registration order, so the
 * branding routes have to declare one to be in the same bucket as the
 * documentation groups and have to be required before them to win inside it.
 *
 * That is a change to the matching order of the whole application, and the two
 * things it could plausibly have broken are both silent:
 *
 * - §8.10.18 requires `/.well-known/acme-challenge/*` to be "matched **before**
 *   the documentation catch-all". A branding group registered before
 *   `routes/edge.php` would have taken it, every on-demand issuance would have
 *   failed at the certificate authority, and nothing would be logged here.
 * - The documentation catch-all must still answer everything that is not a
 *   branding path. A pattern loose enough to swallow `/en/latest/guide.html`
 *   would make every page on every host a 404 while the stylesheet tests
 *   passed.
 *
 * Asserted against the **route table** rather than through HTTP, because that
 * is where the ordering lives — and a request-level test would need a servable
 * project to distinguish "the wrong route matched" from "the right route said
 * no".
 */
final class BrandingRoutePrecedenceTest extends TestCase
{
    /** 🛑 §8.10.18: the ACME challenge still wins. */
    public function test_the_acme_challenge_is_still_matched_before_everything(): void
    {
        $this->assertSame(
            AcmeChallengeController::class,
            self::controllerFor('GET', 'https://docs.example.test/.well-known/acme-challenge/abc123'),
        );
    }

    /** And the documentation catch-all still answers a documentation path. */
    public function test_a_documentation_path_still_reaches_the_document_controller(): void
    {
        $apex = config('docup.origins.docs');
        $this->assertIsString($apex);

        $this->assertSame(
            DocumentController::class,
            self::controllerFor('GET', 'https://project.'.$apex.'/en/latest/guide.html'),
        );
    }

    /**
     * 🛑 A path that merely *looks* like a theme path is documentation.
     *
     * `/_/theme/` is reserved by §7.3 and unmountable, so a project cannot
     * serve from it — but a hash of the wrong length or a stray segment must
     * fall through rather than be answered by a branding controller with a
     * 404 that looks like an absent stylesheet.
     */
    public function test_a_near_miss_theme_path_is_not_a_branding_route(): void
    {
        $apex = config('docup.origins.docs');
        $this->assertIsString($apex);

        foreach ([
            '/_/theme/short.css',
            '/_/theme/'.str_repeat('a', 63).'.css',
            '/_/theme/'.str_repeat('a', 64).'.map',
            '/_/theme/nested/'.str_repeat('a', 64).'.css',
        ] as $path) {
            $this->assertNotSame(
                ThemeStylesheetController::class,
                self::controllerFor('GET', 'https://project.'.$apex.$path),
                $path.' reached the stylesheet controller',
            );
        }
    }

    /** The stylesheet answers on every origin, which is §8.14.10's requirement. */
    public function test_the_stylesheet_answers_on_the_dashboard_and_on_documentation(): void
    {
        $hash = str_repeat('a', 64);
        $app = config('docup.origins.app');
        $docs = config('docup.origins.docs');

        $this->assertIsString($app);
        $this->assertIsString($docs);

        foreach ([$app, 'project.'.$docs, 'docs.acme.example'] as $host) {
            $this->assertSame(
                ThemeStylesheetController::class,
                self::controllerFor('GET', 'https://'.$host.'/_/theme/'.$hash.'.css'),
                'the stylesheet must answer on '.$host,
            );

            $this->assertSame(
                ThemeFontController::class,
                self::controllerFor('GET', 'https://'.$host.'/_/theme/font/'.$hash.'.woff2'),
                'the font must answer on '.$host,
            );
        }
    }

    /**
     * 🛑 And the asset host's root route answers **only** on the asset host.
     *
     * The default asset host is a subdomain of the documentation apex, so both
     * patterns match it and only registration order decides. The inverse is
     * the assertion that matters: a documentation host must not have acquired
     * a root-level `/{hash}.{ext}` route, which would shadow a project's own
     * top-level page.
     */
    public function test_the_asset_route_answers_only_on_the_asset_host(): void
    {
        $assets = config('docup.origins.assets');
        $docs = config('docup.origins.docs');

        $this->assertIsString($assets);
        $this->assertIsString($docs);

        $hash = str_repeat('b', 64);

        $this->assertSame(
            BrandingAssetController::class,
            self::controllerFor('GET', 'https://'.$assets.'/'.$hash.'.png'),
        );

        $this->assertNotSame(
            BrandingAssetController::class,
            self::controllerFor('GET', 'https://project.'.$docs.'/'.$hash.'.png'),
            'a documentation host must not serve branding assets at its root',
        );
    }

    /**
     * Which controller the router would dispatch, or `''`.
     *
     * The route table is consulted directly: a request through the kernel
     * would be answered, and an answer cannot distinguish "the wrong route
     * matched and refused" from "the right route matched and refused".
     */
    private static function controllerFor(string $method, string $url): string
    {
        $request = Request::create($url, $method);

        foreach (Route::getRoutes()->getRoutes() as $route) {
            if (! in_array($method, $route->methods(), true)) {
                continue;
            }

            if (! $route->matches($request)) {
                continue;
            }

            $action = $route->getAction('uses');

            if (! is_string($action)) {
                return 'closure';
            }

            return str_contains($action, '@') ? explode('@', $action)[0] : $action;
        }

        return '';
    }
}
