<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding;

/**
 * Why a token value, an asset or a chrome fragment was refused.
 *
 * 🛑 **A declared vocabulary, so the abuse corpus can name an outcome that
 * either exists or fails CI.** The corpus README's rule 3 wants "a status code
 * or a stable error identifier", and Phase 25 found what `reject` costs: one
 * surviving control keeps every coarse case green while the rest have
 * regressed. §9.4's corpus gate for this phase asserts each case's `expect`
 * against this enum, so a rename breaks the build rather than orphaning a
 * case that still reads as plausible.
 *
 * 🛑 **The reader never sees these.** They go to the operator editing the
 * theme, who is the tenant's own administrator — so unlike §8.12.23's reader
 * surfaces there is no enumeration oracle here, and a precise reason is what
 * makes a rejected colour fixable rather than mysterious.
 */
enum TokenRejection: string
{
    /** §8.14.1: "unknown keys rejected". A key the registry does not define. */
    case UnknownToken = 'unknown_token';

    /** The value is not of the token's declared type at all. */
    case WrongType = 'wrong_type';

    /**
     * 🛑 §8.14.2's named functions: `var()`, `url()`, `env()`, `attr()`,
     * `calc()` — and `expression()`, which §8.14.9 names and which is IE's
     * long-dead script-in-CSS vector that static scanners still look for.
     *
     * Its own case rather than folding into {@see self::WrongType}, because
     * this is the exit criterion: "A token value containing `url(`, `var(`,
     * `calc(` or `expression(` is rejected by the grammar." A test asserting
     * `WrongType` would pass for a value rejected because it was a typo.
     */
    case ForbiddenFunction = 'forbidden_function';

    /** A colour that is syntactically a colour but not in an accepted form. */
    case UnsupportedColourForm = 'unsupported_colour_form';

    /** A numeric component outside the range its function allows. */
    case NumericOutOfRange = 'numeric_out_of_range';

    /** A length with no unit, or a unit outside the allowlist. */
    case DisallowedUnit = 'disallowed_unit';

    /** A font family that is neither in the catalogue nor a self-hosted asset. */
    case UnknownFontFamily = 'unknown_font_family';

    /** 🛑 §8.14.2: "no remote font URL ever" — an injection surface and a third-country transfer. */
    case RemoteFontReference = 'remote_font_reference';

    /** An enumerated token given a value outside its option list. */
    case NotAnOption = 'not_an_option';

    /** Text longer than the token permits, or carrying control characters. */
    case TextRefused = 'text_refused';

    /** An asset reference naming no row this scope may see. */
    case UnknownAsset = 'unknown_asset';

    /** An asset reference naming a row of the wrong kind for the token. */
    case WrongAssetKind = 'wrong_asset_kind';

    /** 🛑 §8.14.16: `frame-ancestors` "never `*`". */
    case WildcardOrigin = 'wildcard_origin';

    /** An origin that is not a scheme-and-host, or carries a path. */
    case MalformedOrigin = 'malformed_origin';

    /**
     * 🛑 §8.14.1's own depth rule, and §8.14.8's for raw HTML.
     *
     * A token set at a level deeper than its registry entry allows. The
     * interesting case is `chrome.head.raw_html`: §8.14.8 makes it
     * installation-scope only, so this rejection is what stops an
     * organisation administrator from writing it.
     */
    case ScopeTooDeep = 'scope_too_deep';

    /** A shallower level locked this path (§8.14.1's per-path locking). */
    case PathLocked = 'path_locked';

    /** A lock naming a token the registry does not define. */
    case UnknownLockPath = 'unknown_lock_path';

    /** 🛑 §8.14.5: a contrast pair below 3:1 refuses publication. */
    case ContrastTooLow = 'contrast_too_low';

    /** §8.14.11: the uploaded bytes are not the media type they claim. */
    case AssetTypeNotSniffed = 'asset_type_not_sniffed';

    /** §8.14.11's byte cap. */
    case AssetTooLarge = 'asset_too_large';

    /** §8.14.11's pixel cap — a decompression bomb is small on disk. */
    case AssetTooManyPixels = 'asset_too_many_pixels';

    /** The raster could not be decoded, or re-encoding produced nothing. */
    case AssetNotDecodable = 'asset_not_decodable';

    /** The SVG is not well-formed XML, or carries a doctype or entity. */
    case SvgNotWellFormed = 'svg_not_well_formed';

    /** 🛑 §8.14.3: chrome content is structured data, "never free HTML". */
    case MarkupRefused = 'markup_refused';

    /** A homepage block naming a type outside the registry (§8.14.3). */
    case UnknownBlockType = 'unknown_block_type';

    /** A link whose target is not a safe URL (§8.14.3). */
    case UnsafeLinkTarget = 'unsafe_link_target';

    /** An email slot the registry does not define (§8.14.13). */
    case UnknownEmailSlot = 'unknown_email_slot';

    /** 🛑 §8.14.8: tenant JavaScript or raw HTML below installation scope. */
    case TenantScriptRefused = 'tenant_script_refused';

    /** Too many entries in a bounded collection — nav links, blocks, locks. */
    case TooManyEntries = 'too_many_entries';
}
