<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Versions;

/**
 * Every way a version operation can be refused, as a stable identifier.
 *
 * The same shape as `ConfigRejection` and for the same reasons: the set is
 * enumerable so a completeness test can assert each one has a sentence, and
 * the identifier is a contract an operator's tooling can match on where the
 * message is prose that gets reworded.
 */
enum VersionRejection: string
{
    /**
     * 🛑 §8.6.6's slug function, applied to an operator's input and REFUSED
     * rather than applied silently.
     *
     * An operator who typed `Release 2.0` and got `release-2.0` without
     * being told has a slug they did not choose in URLs they will quote;
     * one who is told can decide. The automatic path derives its own slug
     * and never reaches this.
     */
    case SlugNotNormalised = 'slug_not_normalised';

    /** 🛑 §8.6.6: a slug may not be a reserved segment or a language code. */
    case SlugReserved = 'slug_reserved';

    /** `project_versions_slug_unique` would refuse it; this says so first. */
    case SlugTaken = 'slug_taken';

    /**
     * 🛑 §8.6.12: two versions of one project in one language cannot be
     * translations of each other — that is what a *version* is. Allowing
     * it would make the language switcher ambiguous.
     */
    case DuplicateLanguageInGroup = 'duplicate_language_in_group';

    /** `version.<reason>`, as §8.5.15 spells an identifier. */
    public function identifier(): string
    {
        return 'version.'.$this->value;
    }

    /** @return list<string> */
    public static function identifiers(): array
    {
        return array_map(static fn (self $case): string => $case->identifier(), self::cases());
    }
}
