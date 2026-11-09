<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * 🛑 §8.14.14's `chrome_mode: api_only` contract.
 *
 * > "A versioned `chrome_mode: api_only` contract with a **reference example
 * > theme** MUST ship, as the first-class answer to 'can we ship our own
 * > chrome?'. 'Tokens only' loses deals."
 *
 * ## What the contract is
 *
 * {@see DeliveredTheme::toPayload()} is the payload and this class is its
 * version. A consumer in `api_only` mode gets no injected chrome
 * (§8.15.7's `api_only`) and reads this payload instead: token values in both
 * colour schemes, asset URLs with dimensions, the structured navigation and
 * footer, the announcement as sanitised inline markup, the scheme default and
 * the version banner.
 *
 * ## 🛑 Versioned, with §8.1.11's deprecation policy
 *
 * The version is in the payload as `contract`, so a consumer pins to it. A
 * breaking change is a new version and the old one keeps its meaning — which is
 * the same rule §8.1.11 applies to the `.docup.yaml` schema and the reason
 * `CachePolicy::forPublishedContract()` can cache a contract for a day.
 *
 * **Additive changes are not breaking.** A new token appears as a new key in
 * `theme.tokens`, and a consumer that iterates the map gets it for free while a
 * consumer that reads named keys is unaffected. What would be breaking: removing
 * a key, changing a value's grammar, or changing the shape of `chrome`.
 *
 * ## The reference example theme
 *
 * `resources/themes/api-only-reference.json` is a complete payload, and
 * `ApiOnlyContractTest` asserts that it matches what DocUp actually emits for
 * the installation default — field for field. 🛑 That assertion is the point of
 * shipping it: a reference example that drifts from the implementation is worse
 * than none, because an integrator builds against it and discovers the
 * difference in production. The file is the documentation; the test is what
 * makes it true.
 */
final class ApiOnlyChrome
{
    /**
     * The contract version.
     *
     * 🛑 Bumped only for a **breaking** change — see the class docblock for
     * which changes are which. A version that moved on every release would
     * teach consumers to ignore it.
     */
    public const int VERSION = 1;

    /** Where the reference example lives, relative to the repository root. */
    public const string REFERENCE_PATH = 'resources/themes/api-only-reference.json';
}
