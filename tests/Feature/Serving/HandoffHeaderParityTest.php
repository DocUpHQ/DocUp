<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Feature\Serving;

use App\Serving\ArtifactHandoff;
use App\Serving\CachePolicy;
use App\Serving\CaddyInterceptHandoff;
use App\Serving\NginxAccelHandoff;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\TestCase;

/**
 * 🛑 §18.18's permanent integration test, in the form this repository can run.
 *
 * §18.18's pre-decided mitigation: "Each header is re-emitted explicitly inside
 * the handoff block, guarded by a **permanent** integration test — because the
 * failure mode here is silent security degradation, not a visible error."
 *
 * §8.9.8 adds where it must run: "A permanent integration test MUST assert, **on
 * every driver in the CI matrix**, that each header is present and not
 * duplicated — allowing multiple `Vary` headers with **distinct** values."
 *
 * **What this file can and cannot prove.** It proves two things statically, and
 * both are the things that actually drift: that each driver sets every preserved
 * header exactly once, and that `deploy/nginx.conf`'s re-emission list matches
 * {@see ArtifactHandoff::PRESERVED_HEADERS} exactly. What it cannot prove is
 * that a running nginx then emits them — that needs the nginx CI matrix leg
 * against a real server, which is recorded as owed.
 *
 * The static half is not a consolation prize. The failure §18.18 fears is
 * somebody adding a security header to the serving path and it reaching readers
 * on Caddy and not on nginx, with nothing failing. That is a list-drift bug, and
 * list drift is exactly what a static assertion catches.
 */
final class HandoffHeaderParityTest extends TestCase
{
    /** @return \Generator<string, array{0: ArtifactHandoff}> */
    public static function drivers(): \Generator
    {
        yield 'caddy-intercept' => [new CaddyInterceptHandoff];
        yield 'nginx-accel' => [new NginxAccelHandoff];
    }

    /**
     * Every preserved header, present exactly once, on every driver.
     */
    #[DataProvider('drivers')]
    public function test_each_driver_sets_every_preserved_header_exactly_once(ArtifactHandoff $handoff): void
    {
        $response = $handoff->respond('builds/abc/html/index.html', $this->privateHeaders());

        foreach (ArtifactHandoff::PRESERVED_HEADERS as $name) {
            if ($name === 'Cache-Tag') {
                // A private response never carries one (§9.3.2). Asserted as
                // absent below rather than skipped silently here.
                continue;
            }

            $values = $response->headers->all(strtolower($name));

            $this->assertCount(
                1,
                $values,
                "[{$handoff->driver()}] must set [{$name}] exactly once, found ".count($values),
            );
        }
    }

    /**
     * 🛑 §9.3.2: a private response carries `private, no-store` on **both**
     * axes, `Vary: Cookie`, and **never** a cache tag.
     */
    #[DataProvider('drivers')]
    public function test_a_private_response_is_private_on_both_axes(ArtifactHandoff $handoff): void
    {
        $response = $handoff->respond('builds/abc/html/index.html', $this->privateHeaders());

        /*
         * Asserted as a set of directives, not as a string. Symfony's
         * ResponseHeaderBag canonicalises `Cache-Control` and emits its
         * directives in alphabetical order — `no-store, private` — which is
         * semantically identical and not ours to dictate. Asserting the exact
         * string would be asserting the framework's internals, and it would
         * break on a Symfony release for no reason that matters.
         *
         * 🛑 What DOES matter is that both directives are present on both axes.
         * `no-store` without `private`, or either on only one axis, is §9.3.2's
         * failure.
         */
        foreach (['Cache-Control', 'CDN-Cache-Control'] as $axis) {
            $value = (string) $response->headers->get($axis);

            $this->assertStringContainsString('private', $value, "[{$axis}] must be private");
            $this->assertStringContainsString('no-store', $value, "[{$axis}] must be no-store");
            $this->assertStringNotContainsString('public', $value, "[{$axis}] must not be public");
        }

        $this->assertStringContainsString('Cookie', (string) $response->headers->get('Vary'));

        // Never a tag. A tag is a purge handle, and a private response carrying
        // one has told the CDN it is cacheable content worth tracking.
        $this->assertFalse($response->headers->has('Cache-Tag'), 'a private response must carry no cache tag');
    }

    #[DataProvider('drivers')]
    public function test_the_handoff_points_into_the_internal_prefix(ArtifactHandoff $handoff): void
    {
        $response = $handoff->respond('builds/abc/html/index.html', $this->privateHeaders());

        $this->assertSame(
            '/_internal/builds/abc/html/index.html',
            $response->headers->get('X-Accel-Redirect'),
        );
    }

    /**
     * 🛑 The application has not read the bytes, so it must not claim their
     * length.
     *
     * A stale or guessed `Content-Length` either truncates the response or hangs
     * the connection — and §8.9.8's whole point is that PHP never saw the file.
     */
    #[DataProvider('drivers')]
    public function test_no_driver_claims_a_content_length(ArtifactHandoff $handoff): void
    {
        $response = $handoff->respond('builds/abc/html/index.html', $this->privateHeaders());

        $this->assertFalse($response->headers->has('Content-Length'));
        $this->assertSame('', $response->getContent() === false ? '' : $response->getContent());
    }

    /**
     * 🛑 The list in `deploy/nginx.conf` matches
     * {@see ArtifactHandoff::PRESERVED_HEADERS}, exactly and in both directions.
     *
     * This is the drift §18.18 is about. A header added to the constant and not
     * to the config reaches readers on Caddy and not on nginx; one added to the
     * config and not to the constant is dead configuration that reads as
     * protection. Both directions are asserted, because only checking one of
     * them is how a list rots from the other end.
     */
    public function test_the_nginx_config_re_emits_exactly_the_preserved_headers(): void
    {
        $config = (string) file_get_contents(base_path('deploy/nginx.conf'));

        // Only the re-emission block inside the internal location counts. A
        // header set elsewhere in the file is not a re-emission and must not be
        // credited as one.
        $start = strpos($config, 'location /_internal/');
        $this->assertNotFalse($start, 'deploy/nginx.conf must declare the internal handoff location');

        $block = substr($config, $start);
        $end = strpos($block, "\n    location ");
        $block = $end === false ? $block : substr($block, 0, $end);

        preg_match_all('/^\s*add_header\s+(\S+)\s+\$upstream_http_\S+\s+always;/m', $block, $matches);

        $reEmitted = $matches[1];
        sort($reEmitted, SORT_STRING);

        $expected = ArtifactHandoff::PRESERVED_HEADERS;
        sort($expected, SORT_STRING);

        $this->assertSame(
            $expected,
            $reEmitted,
            "deploy/nginx.conf's re-emission list has drifted from ArtifactHandoff::PRESERVED_HEADERS. "
            .'A header in one and not the other is §18.18 happening: present on Caddy, absent on nginx, '
            .'with nothing failing.',
        );
    }

    /**
     * 🛑 Every re-emitted header carries `always`.
     *
     * Without it nginx omits the header on a 304 and on an error — and a 304
     * for a private document with no `private, no-store` is the same leak as a
     * 200 with none. §8.9.9 makes 304 the common case for a repeat reader, so
     * this is the path most responses take.
     */
    public function test_every_re_emitted_header_is_unconditional(): void
    {
        $config = (string) file_get_contents(base_path('deploy/nginx.conf'));

        preg_match_all('/^\s*add_header\s+(\S+)\s+(\S+)\s*(.*);/m', $config, $matches, PREG_SET_ORDER);

        $conditional = [];

        foreach ($matches as $match) {
            if (! str_starts_with($match[2], '$upstream_http_')) {
                continue;
            }

            if (trim($match[3]) !== 'always') {
                $conditional[] = $match[1];
            }
        }

        $this->assertSame([], $conditional, 'these re-emitted headers are omitted on a 304: '
            .implode(', ', $conditional));
    }

    /**
     * 🛑 §8.9.8: the internal location must ignore `X-Accel-*` from the storage
     * upstream.
     *
     * "nginx honours `X-Accel-*` from **any** upstream" — and an artifact tree
     * is attacker-supplied content (§8.8.2). An artifact served with its own
     * `X-Accel-Redirect` could redirect the handoff a second time, to any path
     * nginx can reach.
     */
    public function test_the_internal_location_ignores_upstream_accel_headers(): void
    {
        $config = (string) file_get_contents(base_path('deploy/nginx.conf'));

        foreach (['X-Accel-Redirect', 'X-Accel-Buffering', 'X-Accel-Charset', 'X-Accel-Expires'] as $header) {
            $this->assertMatchesRegularExpression(
                '/proxy_hide_header\s+'.preg_quote($header, '/').'\s*;/',
                $config,
                "deploy/nginx.conf must hide [{$header}] from the storage upstream (§8.9.8)",
            );
        }
    }

    /** 🛑 §9.3.8 and §8.9.8: nginx defaults `disable_symlinks` to off. */
    public function test_the_nginx_config_disables_symlink_resolution(): void
    {
        $config = (string) file_get_contents(base_path('deploy/nginx.conf'));

        $this->assertMatchesRegularExpression(
            '/location \/_internal\/.*?disable_symlinks\s+on\s*;/s',
            $config,
            'the internal handoff location must set disable_symlinks on',
        );
    }

    /**
     * 🛑 §8.9.5: the edge strips inbound `X-Accel-*`, `X-DocUp-*`,
     * `X-Forwarded-Host` and `X-Client-Cert` unconditionally.
     *
     * Corpus cases `header-001` and `header-002`. `X-DocUp-Project` arriving
     * from a reader and acting as a selector is the GHSA-mp38-vprc-7hf5 class
     * §8.9.4 names; the resolver cannot read a header at all, and this is the
     * second line in front of it.
     */
    public function test_the_edge_strips_the_inbound_headers(): void
    {
        $config = (string) file_get_contents(base_path('deploy/nginx.conf'));

        foreach ([
            'HTTP_X_ACCEL_REDIRECT',
            'HTTP_X_DOCUP_PROJECT',
            'HTTP_X_DOCUP_VERSION',
            'HTTP_X_FORWARDED_HOST',
            'HTTP_X_CLIENT_CERT',
        ] as $param) {
            $this->assertMatchesRegularExpression(
                '/fastcgi_param\s+'.preg_quote($param, '/').'\s+""\s*;/',
                $config,
                "deploy/nginx.conf must blank [{$param}] toward the application (§8.9.5)",
            );
        }
    }

    /**
     * A public response carries §9.3.3's tags, and the tags are identifiers.
     *
     * 🛑 Never a slug. A tag reaches the CDN, which is a third party for most
     * installations — and a slug there both leaks project names and strands the
     * tag on a rename, so a purge after a rename would miss exactly the content
     * the rename made wrong.
     */
    #[DataProvider('drivers')]
    public function test_a_public_response_carries_identifier_scoped_cache_tags(ArtifactHandoff $handoff): void
    {
        $directives = CachePolicy::decide(
            projectIsPublic: true,
            versionIsPublic: true,
            rulePubliclyCacheable: true,
            cacheTags: CachePolicy::tagsFor('mount-1', 'project-1', 'version-1', 'build-1'),
        );

        $response = $handoff->respond('builds/abc/html/index.html', $directives->headers());

        $tag = (string) $response->headers->get('Cache-Tag');

        $this->assertStringContainsString('m-mount-1', $tag);
        $this->assertStringContainsString('p-project-1', $tag);
        $this->assertStringContainsString('v-version-1', $tag);
        $this->assertStringContainsString('b-build-1', $tag);
        $this->assertStringStartsWith('public,', (string) $response->headers->get('CDN-Cache-Control'));
    }

    /**
     * 🛑 `config('docup.edge.internal_prefix')` and
     * {@see ArtifactHandoff::INTERNAL_PREFIX} must agree.
     *
     * Phase 01 put the prefix in configuration; Phase 04 made it a constant on
     * the interface, because the two edge configurations — deploy/Caddyfile and
     * deploy/nginx.conf — hardcode it and an operator changing the config value
     * alone would break every handoff with no error anywhere. Rather than
     * delete either, they are asserted equal: the constant is what the code
     * uses, and the config value is what an operator reads, so a drift between
     * them is a documentation lie about a security boundary.
     */
    public function test_the_configured_internal_prefix_matches_the_constant(): void
    {
        $this->assertSame(
            ArtifactHandoff::INTERNAL_PREFIX,
            config('docup.edge.internal_prefix'),
            'the configured internal prefix has drifted from the one the handoff uses',
        );
    }

    /**
     * And both edge configurations use that prefix.
     *
     * A handoff pointing at `/_internal/...` while the edge intercepts
     * something else 404s on every document, with nothing in any log saying
     * why — ADR 0001 records exactly that failure from the Caddy side.
     */
    public function test_both_edge_configurations_use_the_internal_prefix(): void
    {
        $prefix = ArtifactHandoff::INTERNAL_PREFIX;

        foreach (['deploy/Caddyfile', 'deploy/nginx.conf'] as $config) {
            $this->assertStringContainsString(
                $prefix,
                (string) file_get_contents(base_path($config)),
                "{$config} must intercept {$prefix}",
            );
        }
    }

    /** @return array<string, string> */
    private function privateHeaders(): array
    {
        $directives = CachePolicy::decide(
            projectIsPublic: false,
            versionIsPublic: true,
            rulePubliclyCacheable: true,
        );

        return $directives->headers() + [
            'Content-Type' => 'text/html; charset=utf-8',
            'Content-Disposition' => 'inline',
            // §8.9.13's sidecar header. Set in the fixture so the exactly-once
            // assertion covers it: dropped under nginx-accel, a reader gets
            // gzip bytes with no Content-Encoding, which is a binary download
            // where a page should be.
            'Content-Encoding' => 'gzip',
            'Content-Security-Policy' => "default-src 'self'",
            'Link' => '<https://alpha.docs.example.com/en/latest/>; rel="canonical"',
            'X-Robots-Tag' => 'noindex',
            'X-Content-Type-Options' => 'nosniff',
            'ETag' => '"'.str_repeat('a', 64).'"',
            'Last-Modified' => 'Wed, 22 Oct 2026 12:00:00 GMT',
        ];
    }
}
