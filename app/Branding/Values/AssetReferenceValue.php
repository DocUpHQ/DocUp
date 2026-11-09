<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\TokenGrammar;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * A reference to a row in `theme_assets` — a logo, a favicon, an OG image.
 *
 * 🛑 **An identifier, never a URL.** The URL is built by the side that serves
 * the asset, from the content hash and the configured asset host, so a token
 * value cannot name a host at all. That closes the hole §8.14.2 names for
 * fonts — "no remote font URL ever" — for every other asset too, and it means
 * moving the asset host is a configuration change rather than a migration over
 * every tenant's stored tokens.
 *
 * 🛑 **Whether the row exists is not this type's question.**
 * {@see TokenGrammar} resolves the id against the rows the
 * writing scope may see and refuses an unknown or wrong-kind one. A value
 * object that queried would be a value object that could not be unit-tested,
 * and the lookup needs the scope — which a value object has no business
 * knowing.
 */
final readonly class AssetReferenceValue implements TokenValue
{
    private function __construct(public string $assetId) {}

    /**
     * @param  string  $path  the token name, for the rejection
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path): self
    {
        $id = strtolower(trim($raw));

        if ($id === '') {
            throw TokenRefused::of(TokenRejection::UnknownAsset, $path, 'empty');
        }

        if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $id) !== 1) {
            throw TokenRefused::of(
                TokenRejection::UnknownAsset,
                $path,
                'an asset token holds an asset id, not a path or a URL',
            );
        }

        return new self($id);
    }

    public function serialise(): string
    {
        return $this->assetId;
    }

    public function toStorage(): string
    {
        return $this->assetId;
    }
}
