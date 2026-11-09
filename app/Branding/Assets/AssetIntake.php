<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

use App\Audit\ActorType;
use App\Audit\Audit;
use App\Branding\CascadeLevel;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;
use App\Models\ThemeAsset;
use App\Support\Uuid;

/**
 * 🛑 §8.14.11's pipeline, and the **only** writer of `theme_assets`.
 *
 * > "Uploaded rasters MUST be content-sniffed and re-encoded server-side to
 * > strip metadata and defeat polyglots, pixel- and byte-capped,
 * > content-addressed with the uploaded filename discarded. SVG MUST be
 * > DOM-sanitised against an element and attribute allowlist, re-serialised,
 * > and rendered **only via `<img src>`** from a dedicated asset host carrying
 * > `default-src 'none'; sandbox`, `nosniff` and no cookies."
 *
 * ## 🛑 The order of the four steps is the design
 *
 * 1. **Cap the bytes**, before anything reads them. A 500 MB upload is refused
 *    while it is still a string nobody has parsed.
 * 2. **Sniff**, never trust. The filename and the client's `Content-Type` are
 *    the uploader's to choose, so neither decides anything — the bytes do.
 * 3. **Transform.** Re-encode the raster, sanitise the SVG, check the font's
 *    signature. This is the step that makes the output DocUp's own bytes.
 * 4. **Hash the output and store it.** The content address is over what DocUp
 *    wrote, not over what arrived — so two uploads that re-encode identically
 *    are one row and one URL, and an address can never refer to bytes a tenant
 *    supplied unaltered.
 *
 * Hashing the *input* would be the natural mistake and would quietly undo step
 * 3's guarantee: the address would identify an attacker's file, and the
 * re-encoded bytes would merely be what happened to be stored beside it.
 *
 * ## 🛑 The uploaded filename is discarded
 *
 * Not sanitised, not stored in a column nobody reads — discarded. A filename is
 * attacker-controlled text that ends up in a `Content-Disposition`, a log line
 * and an operator's UI, and §8.14.11 removes the whole class by keeping none of
 * it. The operator's own `label` is what names the asset instead.
 */
final readonly class AssetIntake
{
    /** 🛑 WOFF2's magic number. The only font container DocUp accepts (§8.14.2). */
    private const WOFF2_SIGNATURE = 'wOF2';

    public function __construct(private AssetStore $store) {}

    public static function make(): self
    {
        return new self(AssetStore::make());
    }

    /**
     * Take one upload through §8.14.11 and record it.
     *
     * @param  string  $bytes  exactly as uploaded
     * @param  string  $label  the operator's own name for it; the filename is discarded
     * @param  CascadeLevel  $scope  installation, organisation or project
     * @param  string|null  $scopeId  null at installation scope
     * @param  string|null  $organisationId  the tenancy key; null at installation scope
     *
     * @throws TokenRefused
     */
    public function accept(
        string $bytes,
        AssetKind $kind,
        string $label,
        CascadeLevel $scope,
        ?string $scopeId = null,
        ?string $organisationId = null,
        ?string $actorId = null,
    ): AcceptedAsset {
        if (! in_array($scope, [CascadeLevel::Installation, CascadeLevel::Organisation, CascadeLevel::Project], true)) {
            throw TokenRefused::of(
                TokenRejection::ScopeTooDeep,
                'asset',
                'an asset is owned at installation, organisation or project scope',
            );
        }

        /* Step 1: the byte cap, before anything parses the bytes. */
        $maxBytes = self::maxBytesFor($kind);

        if (strlen($bytes) > $maxBytes) {
            throw TokenRefused::of(
                TokenRejection::AssetTooLarge,
                'asset',
                sprintf('%d bytes; the limit for a %s is %d', strlen($bytes), $kind->value, $maxBytes),
            );
        }

        if ($bytes === '') {
            throw TokenRefused::of(TokenRejection::AssetTypeNotSniffed, 'asset', 'empty');
        }

        /* Steps 2 and 3. */
        $processed = $this->transform($bytes, $kind);

        /* Step 4: the address is over DocUp's own output. */
        $hash = hash('sha256', $processed['bytes']);
        $extension = $kind->extension($processed['vector']);

        $this->store->put($hash, $extension, $processed['bytes']);

        $existing = ThemeAsset::query()
            ->where('scope_type', $scope->value)
            ->where('content_hash', $hash)
            ->when($scopeId === null, fn ($query) => $query->whereNull('scope_id'))
            ->when($scopeId !== null, fn ($query) => $query->where('scope_id', $scopeId))
            ->first();

        if ($existing instanceof ThemeAsset) {
            /*
             * The same bytes, already in this scope. Returned rather than
             * duplicated, and the label is left as it was: an operator who
             * re-uploads a logo has not asked to rename the one they already
             * had, and two rows with one hash would make `asset.logo` ambiguous
             * in the dashboard for no benefit.
             */
            return new AcceptedAsset($existing, $processed['removed'], true);
        }

        $asset = new ThemeAsset;
        $asset->id = Uuid::v7();
        $asset->organisation_id = $organisationId;
        $asset->scope_type = $scope->value;
        $asset->scope_id = $scopeId;
        $asset->kind = $kind->value;
        $asset->content_hash = $hash;
        $asset->media_type = $kind->outputMediaType($processed['vector']);
        $asset->byte_size = strlen($processed['bytes']);
        $asset->width = $processed['width'];
        $asset->height = $processed['height'];
        $asset->source_media_type = $processed['sourceMediaType'];
        $asset->label = $label;
        $asset->created_by = $actorId;
        $asset->save();

        Audit::record(
            action: 'branding.asset.uploaded',
            actorType: $actorId === null ? ActorType::System : ActorType::User,
            organisationId: $organisationId,
            actorId: $actorId,
            subjectType: 'theme_asset',
            subjectId: (string) $asset->id,
            payload: [
                'kind' => $kind->value,
                'scope' => $scope->value,
                'source_media_type' => $processed['sourceMediaType'],
                'media_type' => $asset->media_type,
                'bytes' => $asset->byte_size,
                /*
                 * 🛑 What the sanitiser removed is in the audit record, not
                 * only in the response. An SVG that arrived with an `onload`
                 * is the one fact about a branding upload that somebody may
                 * need to go back and look for.
                 */
                'removed' => $processed['removed'],
            ],
        );

        return new AcceptedAsset($asset, $processed['removed'], false);
    }

    /**
     * Sniff and transform, per kind.
     *
     * @return array{bytes: string, width: int|null, height: int|null, sourceMediaType: string, vector: bool, removed: list<string>}
     *
     * @throws TokenRefused
     */
    private function transform(string $bytes, AssetKind $kind): array
    {
        if ($kind === AssetKind::Font) {
            /*
             * 🛑 A signature check and nothing else — DocUp does not re-encode
             * a font. There is no safe pure-PHP WOFF2 decoder, and writing one
             * would be adding a font parser to the attack surface in order to
             * reduce it. What makes a font safe to serve is that it is served
             * from DocUp's own origin under §8.14.10's `font-src 'self'`, as
             * bytes the browser's own font engine sandboxes; what the signature
             * check buys is that a PNG or a PHP file cannot be stored as one.
             *
             * Recorded as a known limit in the operator documentation rather
             * than left implicit.
             */
            if (! str_starts_with($bytes, self::WOFF2_SIGNATURE)) {
                throw TokenRefused::of(
                    TokenRejection::AssetTypeNotSniffed,
                    'asset',
                    'a font upload must be WOFF2 (§8.14.2); the wOF2 signature is absent',
                );
            }

            return [
                'bytes' => $bytes,
                'width' => null,
                'height' => null,
                'sourceMediaType' => 'font/woff2',
                'vector' => false,
                'removed' => [],
            ];
        }

        if (self::looksLikeSvg($bytes)) {
            if (! $kind->acceptsSvg()) {
                throw TokenRefused::of(
                    TokenRejection::WrongAssetKind,
                    'asset',
                    sprintf('an SVG may be uploaded as a logo only, not as a %s', $kind->value),
                );
            }

            $sanitised = SvgSanitiser::sanitise($bytes);

            return [
                'bytes' => $sanitised->svg,
                'width' => null,
                'height' => null,
                'sourceMediaType' => 'image/svg+xml',
                'vector' => true,
                'removed' => $sanitised->removed,
            ];
        }

        $reencoded = RasterReencoder::reencode(
            $bytes,
            maxPixels: self::maxPixels(),
            maxEdge: self::maxEdgeFor($kind),
        );

        return [
            'bytes' => $reencoded['bytes'],
            'width' => $reencoded['width'],
            'height' => $reencoded['height'],
            'sourceMediaType' => $reencoded['sourceMediaType'],
            'vector' => false,
            'removed' => [],
        ];
    }

    /**
     * 🛑 Whether the bytes are XML with an `svg` root, by **sniffing**.
     *
     * Deliberately cheap and deliberately not a parse: this only decides which
     * pipeline runs, and {@see SvgSanitiser} refuses anything that is not a
     * well-formed SVG document. A file that looks like XML and is not reaches
     * the sanitiser and is refused there with a reason; a file that is neither
     * XML nor a decodable raster is refused by the re-encoder. Both answers are
     * correct, so this function does not have to be clever — and a clever
     * sniffer here would be a second place the decision about what an SVG is
     * could be wrong.
     */
    private static function looksLikeSvg(string $bytes): bool
    {
        $head = ltrim(substr($bytes, 0, 1024));

        /* A UTF-8 byte-order mark, which design tools do emit. */
        $head = ltrim((string) preg_replace('/^\xEF\xBB\xBF/', '', $head));

        if (! str_starts_with($head, '<')) {
            return false;
        }

        return stripos($head, '<svg') !== false
            || stripos($head, '<?xml') === 0
            || stripos($head, '<!doctype svg') === 0;
    }

    private static function maxBytesFor(AssetKind $kind): int
    {
        $configured = config('branding.assets.max_bytes.'.$kind->value);

        return is_numeric($configured) ? (int) $configured : 512 * 1024;
    }

    private static function maxEdgeFor(AssetKind $kind): int
    {
        $configured = config('branding.assets.max_edge.'.$kind->value);

        return is_numeric($configured) ? (int) $configured : 512;
    }

    private static function maxPixels(): int
    {
        $configured = config('branding.assets.max_pixels');

        return is_numeric($configured) ? (int) $configured : 4_000_000;
    }
}
