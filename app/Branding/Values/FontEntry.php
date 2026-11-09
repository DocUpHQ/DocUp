<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Branding\Values;

use App\Branding\StylesheetCompiler;

/**
 * One family in a {@see FontStackValue}.
 *
 * 🛑 **An uploaded font is named, never addressed.** The CSS a stack
 * serialises to contains a family *name* and no URL — the `@font-face` rule
 * that binds that name to bytes is written by
 * {@see StylesheetCompiler} from the asset row, which is the one
 * place that knows the content hash and the one place §8.14.10's
 * `font-src 'self'` has to hold for. A token value that carried the URL would
 * put the fetch target in tenant-authored data, which is exactly what
 * §8.14.2's "no remote font URL ever" forbids, and it would do so in a way
 * that looked like it had been validated.
 */
final readonly class FontEntry
{
    public function __construct(
        public FontEntryKind $kind,
        /** A family name, or an asset id for {@see FontEntryKind::Asset}. */
        public string $name,
    ) {}

    /**
     * The family name as it appears in CSS.
     *
     * Generic families are bare keywords — quoting `sans-serif` would make it
     * a family name nobody has. Everything else is quoted.
     */
    public function serialise(): string
    {
        return match ($this->kind) {
            FontEntryKind::Generic => $this->name,
            FontEntryKind::Catalogue => '"'.$this->name.'"',
            FontEntryKind::Asset => '"'.self::assetFamily($this->name).'"',
        };
    }

    /** The authored spelling, for storage. */
    public function toStorage(): string
    {
        return $this->kind === FontEntryKind::Asset ? 'asset:'.$this->name : $this->name;
    }

    /**
     * The CSS family name DocUp mints for an uploaded font.
     *
     * 🛑 Derived from the asset id rather than chosen by the tenant, so two
     * tenants who upload fonts cannot collide on a family name — and so a
     * tenant cannot name their font `Instrument Sans` and have the
     * installation's own catalogue entry silently resolve to their bytes.
     */
    public static function assetFamily(string $assetId): string
    {
        return 'docup-font-'.substr(str_replace('-', '', $assetId), 0, 16);
    }
}
