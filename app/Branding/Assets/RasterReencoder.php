<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Assets;

use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 §8.14.11's raster half: "Uploaded rasters MUST be content-sniffed and
 * re-encoded server-side to strip metadata and defeat polyglots, pixel- and
 * byte-capped, content-addressed with the uploaded filename discarded."
 *
 * ## Why re-encoding and not stripping
 *
 * A metadata stripper walks the chunks it knows about and leaves the ones it
 * does not. Re-encoding decodes to a pixel buffer and writes a new file from
 * it, so **everything** that was not a pixel is gone: EXIF with its GPS
 * coordinates, an ICC profile, an XMP packet, a trailing ZIP archive, a PHP
 * tag after IEND. There is no list of things to remember.
 *
 * That is also the polyglot defence, and the polyglot is the real threat here.
 * A GIF whose first bytes satisfy the GIF sniffer and whose later bytes are a
 * valid HTML document with a `<script>` in it is a file that an image sniffer
 * calls an image and a content-sniffing browser may call a document. Re-encoded
 * from pixels, the output is a PNG DocUp wrote and the attacker's bytes are not
 * in it — which is a stronger statement than any header can make.
 *
 * ## 🛑 The pixel cap is checked from the header, before any decode
 *
 * A decompression bomb is small on disk and enormous in memory: a 10 KB PNG can
 * declare 50,000 × 50,000 pixels, and GD will try to allocate about 10 GB for
 * it before anything has a chance to object. `getimagesizefromstring` reads the
 * header only, so the cap is enforced while the file is still 10 KB.
 *
 * This is why §8.14.11 names **both** caps. The byte cap alone would pass this
 * file; the pixel cap alone would pass a 100 MB photograph.
 *
 * ## Always PNG out
 *
 * One output format, whatever came in. A branding image is a logo or a card and
 * PNG is lossless, universally supported and the format whose encoder DocUp has
 * one call to. Choosing per input would mean keeping three encoder paths
 * correct for a saving no reader notices, and would put the output format under
 * the uploader's control.
 */
final class RasterReencoder
{
    /**
     * The input types DocUp will decode.
     *
     * 🛑 Determined by **sniffing the bytes**, never by the filename or the
     * client's `Content-Type`. Both of those are the uploader's to choose, and
     * §8.14.11 says "content-sniffed" for that reason.
     *
     * BMP, TGA, XBM and WBMP are absent even though GD reads them: each is a
     * decoder nobody exercises, and a branding upload has no legitimate reason
     * to be any of them.
     *
     * @var array<int, string>
     */
    private const DECODABLE = [
        IMAGETYPE_PNG => 'image/png',
        IMAGETYPE_JPEG => 'image/jpeg',
        IMAGETYPE_GIF => 'image/gif',
        IMAGETYPE_WEBP => 'image/webp',
    ];

    /**
     * Re-encode one upload to PNG.
     *
     * @param  string  $bytes  as uploaded
     * @param  int  $maxPixels  the total pixel cap, checked from the header
     * @param  int  $maxEdge  the longest edge DocUp will emit
     * @return array{bytes: string, width: int, height: int, sourceMediaType: string}
     *
     * @throws TokenRefused
     */
    public static function reencode(string $bytes, int $maxPixels, int $maxEdge): array
    {
        /*
         * 🛑 The header first, and nothing is decoded until it passes. The
         * order is the whole of the decompression-bomb defence.
         */
        $probe = @getimagesizefromstring($bytes);

        /*
         * `false` is the only failure getimagesizefromstring() reports: on
         * success the first three offsets always exist, so an isset() guard on
         * them is dead code that reads as caution.
         */
        if ($probe === false) {
            throw TokenRefused::of(
                TokenRejection::AssetTypeNotSniffed,
                'asset',
                'the bytes are not a PNG, JPEG, GIF or WebP image',
            );
        }

        [$width, $height, $type] = [(int) $probe[0], (int) $probe[1], (int) $probe[2]];

        if (! array_key_exists($type, self::DECODABLE)) {
            throw TokenRefused::of(
                TokenRejection::AssetTypeNotSniffed,
                'asset',
                'the sniffed image type is not one DocUp decodes',
            );
        }

        if ($width < 1 || $height < 1) {
            throw TokenRefused::of(TokenRejection::AssetNotDecodable, 'asset', 'the header declares no pixels');
        }

        if ($width * $height > $maxPixels) {
            throw TokenRefused::of(
                TokenRejection::AssetTooManyPixels,
                'asset',
                sprintf('%d × %d declared; the limit is %d pixels', $width, $height, $maxPixels),
            );
        }

        $source = @imagecreatefromstring($bytes);

        if (! $source instanceof \GdImage) {
            /*
             * The header parsed and the decoder refused. That is a truncated
             * or deliberately malformed file, and it is a different fault from
             * an unrecognised type — so it gets a different identifier, because
             * an operator whose export was interrupted should not be told their
             * PNG is not a PNG.
             */
            throw TokenRefused::of(TokenRejection::AssetNotDecodable, 'asset', 'the image header parsed but the pixels did not');
        }

        try {
            /*
             * 🛑 The DECODED dimensions, not the header's.
             *
             * `$width` and `$height` above are what the header declared, and
             * they exist for the pixel cap — which has to run before any
             * decode, so it has nothing else to go on. They are **not** the
             * size of the image GD produced, and for a malformed file or a GIF
             * whose logical canvas is larger than its frame (which is legal,
             * and what every animated GIF looks like) they differ.
             *
             * Measured: a GIF declaring 256 × 128 whose image descriptor
             * covers 1 × 1 decodes to a 1 × 1 buffer. Scaling that by the
             * header's ratio produced a 64 × 32 output from one pixel and
             * recorded 64 × 32 on the row — so the `<img width height>` the
             * chrome payload emits would have been a lie, and the reader would
             * get the layout shift those attributes exist to prevent. On CI's
             * libgd the same path segfaulted the test process.
             */
            $decodedWidth = imagesx($source);
            $decodedHeight = imagesy($source);

            $target = self::fit($source, $decodedWidth, $decodedHeight, $maxEdge);

            /*
             * 🛑 Alpha is preserved explicitly. GD's default is to composite
             * the alpha channel away on save, which turns a transparent logo
             * into one with a black box behind it — and the operator's remedy
             * would be to give up and use a JPEG.
             */
            imagealphablending($target['image'], false);
            imagesavealpha($target['image'], true);

            ob_start();
            $written = imagepng($target['image'], null, 9);
            $png = (string) ob_get_clean();

            if ($written === false || $png === '') {
                throw TokenRefused::of(TokenRejection::AssetNotDecodable, 'asset', 're-encoding produced no bytes');
            }

            return [
                'bytes' => $png,
                'width' => $target['width'],
                'height' => $target['height'],
                'sourceMediaType' => self::DECODABLE[$type],
            ];
        } finally {
            /*
             * Freed in a `finally` because a 4-megapixel buffer held until the
             * request ends is a 16 MB leak per upload, and §9.2's memory budget
             * is the operator's problem rather than the uploader's.
             */
            if (isset($target) && $target['image'] !== $source) {
                imagedestroy($target['image']);
            }

            imagedestroy($source);
        }
    }

    /**
     * Downscale to fit `$maxEdge`, or return the source untouched.
     *
     * 🛑 Never **up**scales. An 8-pixel logo stays an 8-pixel logo: enlarging
     * it would produce a blurred image the operator did not upload and could
     * not explain, and the point of the cap is a ceiling rather than a size.
     *
     * @return array{image: \GdImage, width: int, height: int}
     *
     * @throws TokenRefused
     */
    private static function fit(\GdImage $source, int $width, int $height, int $maxEdge): array
    {
        $longest = max($width, $height);

        if ($longest <= $maxEdge) {
            return ['image' => $source, 'width' => $width, 'height' => $height];
        }

        $scale = $maxEdge / $longest;
        $targetWidth = max(1, (int) round($width * $scale));
        $targetHeight = max(1, (int) round($height * $scale));

        $scaled = imagescale($source, $targetWidth, $targetHeight, IMG_BICUBIC_FIXED);

        if (! $scaled instanceof \GdImage) {
            throw TokenRefused::of(TokenRejection::AssetNotDecodable, 'asset', 'the image could not be downscaled');
        }

        return ['image' => $scaled, 'width' => $targetWidth, 'height' => $targetHeight];
    }
}
