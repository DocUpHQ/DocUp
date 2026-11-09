<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Addons;

use App\Artifacts\ChromeInjector;
use App\Branding\ApiOnlyChrome;

/**
 * 🛑 §8.15.2's `GET /_/addons` payload contract, and its version.
 *
 * > §8.15.2: "All request-scoped data MUST come from `GET /_/addons`, resolved
 * > from the **request's** host and path, authorised identically to the HTML,
 * > with `Vary: Cookie`: branding tokens, version list and sort, flyout
 * > configuration, notifications, search configuration, merged navigation,
 * > cross-reference map, canonical URL and analytics opt-in."
 *
 * Ten things, and the sentence is the field list. {@see AddonsPayload} emits
 * exactly those and nothing else; §8.15.11 adds the offline formats to the same
 * payload, for the reason it gives — "so the flyout can offer downloads without
 * a second resolution round trip".
 *
 * ## 🛑 Why the artifact carries no project identifier
 *
 * §8.15.1 permits the build id in the injected `<meta>` and nothing else,
 * because "baking project or version identifiers into HTML would destroy
 * cross-project build reuse (§8.7.9)". So the runtime cannot tell the server
 * which project it is on — it does not know. The server resolves the project
 * from the **request's own host and path**, exactly as it resolved the document,
 * which is why §8.15.2 says "the request's" rather than "the document's".
 *
 * That is also the mechanism behind §17's Phase 28 exit criterion "changing a
 * branding token changes the rendered chrome with the **same build id**": the
 * build id in the artifact is stable and everything that varies arrives here.
 *
 * ## Versioning
 *
 * {@see self::VERSION} is the number a `chrome_mode: api_only` consumer pins to
 * for the *addons* envelope, and {@see ApiOnlyChrome::VERSION} is the one it
 * pins to for the theme payload nested inside it. 🛑 Two numbers because they
 * change for different reasons: a new notification banner is an addons change
 * and a new branding token is a theme change, and a single version would force
 * every consumer of one to re-verify against the other.
 *
 * The additive rule is §8.1.11's, the same one {@see ApiOnlyChrome} states: a
 * new key is not breaking; removing a key, changing a value's grammar or
 * changing a nested shape is.
 */
final class AddonsContract
{
    /**
     * The addons envelope version.
     *
     * 🛑 Bumped only for a breaking change. A version that moved on every
     * release would teach consumers to ignore it, which is the failure
     * {@see ApiOnlyChrome::VERSION} records in its own docblock.
     */
    public const int VERSION = 1;

    /**
     * Where the payload lives.
     *
     * 🛑 Under §7.3's reserved first segment, beside the loader
     * ({@see ChromeInjector::LOADER_PATH}), so no project can mount a path that
     * shadows either. The runtime resolves this against the document's own
     * origin rather than against a configured host — a reader on a custom domain
     * must reach the payload on that domain or the request would be cross-origin
     * and carry no cookies, and §8.15.2 requires it to be "authorised
     * identically to the HTML".
     */
    public const string PATH = '/_/addons';
}
