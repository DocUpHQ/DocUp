<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Serving;

use App\Branding\ResolvedFrameAncestors;
use App\Branding\ThemeAssets;

/**
 * 🛑 §8.14.15's documentation Content-Security-Policy, and §8.14.16's
 * `frame-ancestors` finally doing something.
 *
 * > §8.14.15: "Documentation CSP MUST be **permissive by default**, limited to
 * > `frame-ancestors`, `base-uri` and `object-src`, with strict mode opt-in. A
 * > strict CSP breaks Sphinx inline scripts, MathJax and Mermaid; shipping it by
 * > default produces a flood of bug reports and operators who disable CSP
 * > entirely. 🛑 CSP `sandbox` MUST NOT be used on documentation — it creates an
 * > opaque origin that kills the [reader session]."
 *
 * > §8.14.16: "Documentation `frame-ancestors` MUST be a per-project token
 * > defaulting to `'self'`, with an explicit origin allowlist and never `*`."
 *
 * ## Why it ships now and not in Phase 27
 *
 * Phase 27 built and validated the token and emitted nothing, and said so in the
 * token's own `purpose` text: "Stored and validated; not yet enforced … Until
 * then this value protects nothing." The reason recorded there was that emitting
 * it needs the resolved value in the routing snapshot, which it now has
 * ({@see ResolvedFrameAncestors}).
 *
 * The other reason is that there was nothing to protect. §8.15.5 forbids iframed
 * chrome on clickjacking grounds — and the attack it names is the mirror of this
 * one: chrome inside an attacker's frame, with the reader's authentication state
 * and the version switcher under somebody else's cursor. Phase 28 is the phase
 * that puts chrome in the DOM, so it is the phase where `frame-ancestors`
 * defends something real.
 *
 * ## 🛑 Three directives by default, and the fourth that is forbidden
 *
 * `frame-ancestors`, `base-uri` and `object-src` — exactly §8.14.15's list, and
 * the list is short for a stated reason rather than for want of ambition. A
 * `script-src` on documentation breaks Sphinx's inline scripts, MathJax and
 * Mermaid, and §8.14.15's argument is that the bug reports that follow produce
 * "operators who disable CSP entirely", which is strictly worse than a
 * permissive policy nobody disables.
 *
 * 🛑 `sandbox` is **never** emitted, at any setting. §8.14.15 forbids it outright
 * because it creates an opaque origin, and an opaque origin cannot read the
 * `__Host-` cookie §8.12.10's reader session depends on — so a sandboxed
 * documentation page would silently log out every private reader. There is no
 * configuration that turns it on; {@see DocumentationPolicyTest} asserts the
 * absence, because "nobody added it yet" is not a control.
 *
 * ## Strict mode, and what it is for
 *
 * §8.14.10's set — `img-src 'self' data: <asset-host>`, `font-src 'self'`,
 * `connect-src 'self'` — exists to "kill CSS exfiltration by headers, not by
 * parser cleverness". 🛑 The vector it addresses arrives with §8.14.9's
 * per-project custom CSS, which §18.22's pre-decided consequence says not to
 * build and which Phase 27 did not build. So strict mode is **off by default**
 * and is an installation-wide flag rather than a per-project one: the thing it
 * protects against is an installation policy decision, and a per-project opt-in
 * would let one tenant's choice imply a guarantee for another's.
 */
final readonly class DocumentationPolicy
{
    /** The header this class builds. */
    public const string HEADER = 'Content-Security-Policy';

    /**
     * 🛑 The directive §8.14.15 forbids, named so a test can assert its absence.
     *
     * A constant rather than a string in a test, because the point is that no
     * code path may emit it — and a reader of this class should be able to find
     * the reason without leaving the file.
     */
    public const string FORBIDDEN_DIRECTIVE = 'sandbox';

    /**
     * The policy for one project's documentation response.
     *
     * @param  string  $frameAncestors  the resolved token, as the snapshot carries it
     */
    public static function for(string $frameAncestors): string
    {
        $directives = [
            /*
             * 🛑 §8.14.16: "never `*`". The grammar already refuses a wildcard
             * at the point of authoring ({@see \App\Branding\TokenType} and
             * `OriginListValue`), and this is the second half of the same rule:
             * a value that somehow reached the column — a hand-written UPDATE, a
             * restored backup from before the grammar existed — is replaced by
             * the default rather than emitted.
             *
             * Belt and braces across a trust boundary, and the braces matter
             * here: emitting `frame-ancestors *` is indistinguishable from
             * having no policy, so the failure would be silent.
             */
            'frame-ancestors '.self::safeFrameAncestors($frameAncestors),

            /*
             * §8.14.15's other two. `base-uri 'self'` stops injected markup
             * re-pointing every relative URL in the document — which on a
             * documentation page is every asset and every link — and
             * `object-src 'none'` removes a plugin surface no generator emits.
             *
             * Neither breaks anything §8.14.15 names: Sphinx, MathJax and
             * Mermaid are script and style, and no generator writes a `<base>`
             * pointing off-origin.
             */
            "base-uri 'self'",
            "object-src 'none'",
        ];

        if (self::isStrict()) {
            /*
             * §8.14.10's exfiltration set. `data:` is in `img-src` because
             * generators inline small images and removing it would break
             * documentation for no gain — the exfiltration channel is an
             * absolute URL to an attacker's host, which this list is what
             * removes.
             */
            $assetOrigin = ThemeAssets::assetOrigin();

            $directives[] = trim("img-src 'self' data: ".$assetOrigin);
            $directives[] = "font-src 'self'";
            $directives[] = "connect-src 'self'";
        }

        return implode('; ', $directives);
    }

    /**
     * Whether §8.14.10's strict set is switched on for this installation.
     *
     * 🛑 Off unless an operator says otherwise, which is §8.14.15 in terms:
     * "Documentation CSP MUST be **permissive by default** … with strict mode
     * opt-in."
     */
    public static function isStrict(): bool
    {
        return config('docup.csp.documentation_strict') === true;
    }

    /**
     * The frame-ancestors value, or the default when it is not one.
     *
     * Refuses a wildcard in any position, an empty value, and anything carrying
     * a `;` — which would end the directive and let the rest of the stored
     * string become directives of its own.
     */
    private static function safeFrameAncestors(string $value): string
    {
        $value = trim($value);

        if ($value === '' || str_contains($value, '*') || str_contains($value, ';')) {
            return "'self'";
        }

        return $value;
    }
}
