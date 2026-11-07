<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Auth\Providers;

use Symfony\Component\HttpFoundation\Response;

/**
 * 🛑 §8.12.19's branded 503, as the one place it is built.
 *
 * > "A degraded binding MUST **deny** with a branded 503 naming the binding and
 * > linking to its health page — never fall back to another provider, never to
 * > public, and the UI MUST NOT offer a 'make public' button there."
 *
 * Four things that sentence requires and one it forbids, all of them visible
 * here:
 *
 * - **503, not 404.** The reader may hold a perfectly good credential and the
 *   installation cannot currently tell. 503 says "come back"; 404 says "this
 *   does not exist", which is a lie that sends them to support.
 * - **Naming the binding.** So the reader can tell somebody *which* provider,
 *   which is the difference between a useful report and "the site is broken".
 * - **A link to its health page.** On the dashboard, where an operator can see
 *   the probe output — which the reader never does.
 * - **Never falling back.** There is no "continue as a guest" link and no
 *   public path out of this page, because that is the one thing an operator
 *   under pressure would click.
 *
 * 🛑 **And no "make public" button.** Not because this is the UI, but because
 * this is the page an operator lands on when they hit the problem themselves,
 * and the requirement names that temptation explicitly.
 *
 * 🛑 `Retry-After` is deliberately **absent**. A degraded binding is degraded
 * until a probe passes, and a number here would be a promise the installation
 * cannot keep — a crawler that honoured it would come back to the same 503 and
 * a reader who read it would wait for nothing.
 */
final readonly class DegradedResponse
{
    /**
     * @param  string  $bindingName  the operator's own name for it, which is
     *                               what §8.12.19 means by "naming the
     *                               binding". 🛑 Escaped on the way in: it is
     *                               operator-authored text rendered into HTML.
     */
    public static function for(string $bindingName): Response
    {
        $name = htmlspecialchars($bindingName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $health = htmlspecialchars(
            'https://'.(is_string($host = config('docup.origins.app')) ? $host : '').'/providers',
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8',
        );

        $body = <<<HTML
        <!DOCTYPE html>
        <html lang="en"><head><meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta name="robots" content="noindex, nofollow">
        <title>Sign-in is temporarily unavailable</title>
        <style>
          body{font:16px/1.6 system-ui,sans-serif;margin:0;padding:3rem 1.5rem;max-width:34rem}
          h1{font-size:1.4rem;margin:0 0 1rem}
          .b{background:#fef2f2;border-left:4px solid #dc2626;padding:.75rem 1rem;margin:1.5rem 0}
          code{background:#f4f4f5;padding:.1em .3em;border-radius:3px}
        </style></head><body>
        <h1>Sign-in is temporarily unavailable</h1>
        <div class="b">
          <p>This documentation is protected by <strong>{$name}</strong>, and that
          provider is not currently responding.</p>
        </div>
        <p>Your access has not been removed and nothing has changed about what you
        may read. The site cannot check it right now, so it is refusing rather
        than guessing.</p>
        <p>Trying again shortly is the right thing to do. If it persists, tell
        whoever administers this documentation that the <strong>{$name}</strong>
        provider needs attention.</p>
        <p><a href="{$health}">Provider health</a> &mdash; for administrators.</p>
        </body></html>
        HTML;

        return new Response($body, 503, [
            'Content-Type' => 'text/html; charset=utf-8',
            /*
             * 🛑 Never cached, on either axis. A cached 503 would outlive the
             * outage: §9.3.2's rule about private content applies, and this
             * response is about a specific reader's inability to be checked.
             */
            'Cache-Control' => 'private, no-store',
            'CDN-Cache-Control' => 'private, no-store',
            'Vary' => 'Cookie',
            'X-Robots-Tag' => 'noindex, nofollow',
            'X-Content-Type-Options' => 'nosniff',
            /*
             * 🛑 No `WWW-Authenticate`. §8.12.23 permits a challenge in exactly
             * two cases and neither is this one: the reader has not presented a
             * bad credential and the resource's existence is not the question.
             * Challenging them would invite them to try a credential the
             * installation cannot check.
             */
        ]);
    }
}
