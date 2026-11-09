<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Support;

/**
 * The hostile inputs §9.4's `addons` corpus cases name by builder.
 *
 * Built in PHP rather than committed, for the reason
 * `tests/Fixtures/AbuseCorpus/README.md` gives about the archives: when the
 * input is bytes rather than a string, the **mutation** is the reviewable
 * artefact and a committed blob is not. A reviewer can read what
 * {@see self::shiftJisDocument()} does; they cannot read a file of Shift-JIS
 * bytes and tell whether it is the case the corpus claims.
 */
final class AddonsHostiles
{
    /** Build the input a case names. */
    public static function build(string $builder): string
    {
        return match ($builder) {
            'shiftJisDocument' => self::shiftJisDocument(),
            'oversizedDocument' => self::oversizedDocument(),
            'oversizedPath' => self::oversizedPath(),
            default => '',
        };
    }

    /**
     * A document that is valid Shift-JIS and **not** valid UTF-8.
     *
     * 🛑 The bytes are the case. `\x93\xfa\x96\x7b` is 日本 in Shift-JIS and is
     * not a valid UTF-8 sequence, which is what §8.15.4 refuses on: "the
     * document's own charset declaration cannot be trusted without parsing and
     * a mis-declared charset is an XSS vector".
     *
     * 🛑 And the declaration here says `utf-8`, deliberately — that is the
     * vector rather than an oversight. A document that declares a charset it is
     * not encoded in is exactly the case where trusting the declaration would
     * be wrong, and the injector does not read it at all.
     */
    private static function shiftJisDocument(): string
    {
        return '<!doctype html><html><head><meta charset="utf-8">'
            ."<title>\x93\xfa\x96\x7b\x8c\xea</title></head>"
            ."<body>\x82\xb1\x82\xf1\x82\xce\x82\xf1\x82\xcd</body></html>";
    }

    /**
     * A document over the injector's byte ceiling.
     *
     * 🛑 The padding is **incompressible**, and that is not an aesthetic
     * choice: §8.3's ingest refuses an upload whose decompression ratio is
     * implausible, so four megabytes of one repeated character is rejected as
     * a ratio bomb before the injector ever sees it — and the case would then
     * pass for the wrong reason. Base64 of random bytes compresses by
     * essentially nothing.
     */
    private static function oversizedDocument(): string
    {
        $ceiling = (int) config('artifacts.chrome.max_html_bytes');
        $padding = '';

        while (strlen($padding) <= $ceiling) {
            $padding .= base64_encode(random_bytes(3_072));
        }

        return '<!doctype html><html><head></head><body>'.$padding.'</body></html>';
    }

    /**
     * A `path` parameter past the addons endpoint's cap.
     *
     * Canonical in shape — every segment is legal — so the only thing that can
     * refuse it is the length check, which is what the case is about.
     */
    private static function oversizedPath(): string
    {
        return '/en/v1/'.str_repeat('a/', 2_048).'index.html';
    }
}
