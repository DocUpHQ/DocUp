<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\ForbiddenFunctions;
use App\Branding\TokenGrammar;
use App\Branding\TokenRefused;
use App\Branding\TokenRejection;

/**
 * 🛑 §8.14.2's font grammar: "catalogue names or self-hosted WOFF2 asset
 * references; **no remote font URL ever**".
 *
 * > "(an injection surface and a third-country transfer)"
 *
 * Both halves of that parenthesis are load-bearing and neither is hypothetical.
 * A remote font URL is a request the reader's browser makes to a third party on
 * every page of a tenant's documentation, which is a GDPR transfer the operator
 * never agreed to — the 2022 Munich judgment on Google Fonts is the case
 * everyone cites. And a `url()` in a font declaration is the one place CSS
 * fetches a binary the browser then parses with a font engine.
 *
 * So there is no notation here for a remote font, not merely a check that
 * rejects one. An entry is a **name** or an **asset handle**, and neither can
 * express a host.
 *
 * ## The three kinds of entry
 *
 * - **Generic** — CSS's own families (`sans-serif`, `ui-monospace`). Always
 *   available, never fetched.
 * - **Catalogue** — a family the *installation* has self-hosted, listed in
 *   `config/branding.php`. Installation scope, because the files are on the
 *   operator's disk and in their image.
 * - **Asset** — `asset:<uuid>`, a WOFF2 a tenant uploaded through §8.14.11's
 *   pipeline. 🛑 This type does **not** check that the row exists; it cannot,
 *   because a value object that reached the database would be a value object
 *   that could not be unit-tested. {@see TokenGrammar} resolves
 *   the handle and refuses an unknown one with
 *   {@see TokenRejection::UnknownAsset}.
 */
final readonly class FontStackValue implements TokenValue
{
    /** CSS's own generic families. Closed, because CSS's list is. @var list<string> */
    public const GENERIC = [
        'serif', 'sans-serif', 'monospace', 'cursive', 'fantasy',
        'system-ui', 'ui-serif', 'ui-sans-serif', 'ui-monospace', 'ui-rounded',
        'math', 'emoji', 'fangsong',
    ];

    /** How many families one stack may name. A fallback chain, not a catalogue dump. */
    private const MAX_ENTRIES = 8;

    /**
     * @param  list<FontEntry>  $entries  in declaration order
     */
    private function __construct(public array $entries) {}

    /**
     * @param  string  $path  the token name, for the rejection
     * @param  list<string>  $catalogue  the installation's self-hosted families
     *
     * @throws TokenRefused
     */
    public static function parse(string $raw, string $path, array $catalogue): self
    {
        ForbiddenFunctions::assertAbsent($raw, $path);

        /*
         * Quotes are stripped rather than required. CSS needs them around a
         * family whose name has a space, design tools emit them inconsistently,
         * and the names that survive this parse are constrained to a closed set
         * — so what the operator typed around the name carries no meaning.
         */
        $parts = array_values(array_filter(
            array_map(
                static fn (string $part): string => trim($part, " \t\n\r\0\x0B\"'"),
                explode(',', $raw),
            ),
            static fn (string $part): bool => $part !== '',
        ));

        if ($parts === []) {
            throw TokenRefused::of(TokenRejection::WrongType, $path, 'a font stack names at least one family');
        }

        if (count($parts) > self::MAX_ENTRIES) {
            throw TokenRefused::of(
                TokenRejection::TooManyEntries,
                $path,
                sprintf('%d families; the limit is %d', count($parts), self::MAX_ENTRIES),
            );
        }

        $entries = [];

        foreach ($parts as $part) {
            $entries[] = self::entry($part, $path, $catalogue);
        }

        return new self($entries);
    }

    /**
     * 🛑 Re-serialised from the parsed entries, and **quoted by DocUp**.
     *
     * A family name is quoted here rather than carried through as the operator
     * typed it, so the output has one shape whatever the input did. The names
     * that reach this point are already constrained to the catalogue or to
     * CSS's generics, so the quoting cannot be escaped out of — but doing it
     * from the parsed name rather than from the raw text is what §8.14.2 asks
     * for, and it is the difference between a grammar and a filter.
     */
    public function serialise(): string
    {
        return implode(', ', array_map(
            static fn (FontEntry $entry): string => $entry->serialise(),
            $this->entries,
        ));
    }

    public function toStorage(): string
    {
        return implode(', ', array_map(
            static fn (FontEntry $entry): string => $entry->toStorage(),
            $this->entries,
        ));
    }

    /**
     * The asset handles this stack names, for the grammar to resolve.
     *
     * @return list<string>
     */
    public function assetHandles(): array
    {
        return array_values(array_map(
            static fn (FontEntry $entry): string => $entry->name,
            array_filter($this->entries, static fn (FontEntry $entry): bool => $entry->kind === FontEntryKind::Asset),
        ));
    }

    /**
     * @param  list<string>  $catalogue
     *
     * @throws TokenRefused
     */
    private static function entry(string $part, string $path, array $catalogue): FontEntry
    {
        if (str_starts_with($part, 'asset:')) {
            $handle = substr($part, 6);

            /*
             * The handle is a UUID's canonical text. Checked by shape here so
             * that a malformed handle is a grammar rejection rather than a
             * database lookup for something that cannot exist.
             */
            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $handle) !== 1) {
                throw TokenRefused::of(TokenRejection::UnknownAsset, $path, 'asset: must be followed by an asset id');
            }

            return new FontEntry(FontEntryKind::Asset, $handle);
        }

        $lower = strtolower($part);

        if (in_array($lower, self::GENERIC, true)) {
            return new FontEntry(FontEntryKind::Generic, $lower);
        }

        /*
         * 🛑 Anything with a scheme or a dot in it lands here and is reported
         * as a remote reference rather than as an unknown family, because the
         * two mistakes have different remedies: an unknown family is a typo,
         * and `https://fonts.example/...` is somebody who needs to be told why
         * DocUp will not do that.
         */
        if (str_contains($lower, '//') || str_contains($lower, ':') || preg_match('/\.[a-z]{2,}/', $lower) === 1) {
            throw TokenRefused::of(
                TokenRejection::RemoteFontReference,
                $path,
                'a font is a catalogue name or asset:<id>; DocUp never fetches a remote font (§8.14.2)',
            );
        }

        foreach ($catalogue as $family) {
            if (strtolower($family) === $lower) {
                return new FontEntry(FontEntryKind::Catalogue, $family);
            }
        }

        throw TokenRefused::of(
            TokenRejection::UnknownFontFamily,
            $path,
            sprintf('%s is not in the installation font catalogue', $part),
        );
    }
}
