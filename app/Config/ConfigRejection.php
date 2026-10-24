<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

use App\Builds\FailureCatalogue;

/**
 * Every way a `.docup.yaml` can be refused, as a stable identifier.
 *
 * §8.5.15 makes `<class>.<reason>` a contract an operator builds alerts on,
 * and Phase 09's exit criterion requires four specific hostile files to fail
 * "with a **documented identifier** in under a second". An enum rather than
 * string literals scattered through the parser, for two reasons that are not
 * style:
 *
 *  - 🛑 **the set is enumerable**, so `CatalogueCompletenessTest` can assert
 *    that every one of them has a sentence in {@see FailureCatalogue};
 *    a refusal with no message is an author looking at a hex string;
 *  - 🛑 **the order of the first four cases is the order they are checked
 *    in**, and that ordering is the defence rather than a detail. A 200 MB
 *    file must be refused on its size before anything opens it, and an alias
 *    bomb must be refused on sight of the `*` before a parser expands it.
 *    §8.4.9's caps are only caps if nothing runs ahead of them.
 */
enum ConfigRejection: string
{
    // ----------------------------------------------------------------- caps
    // §8.4.9, in the order they are applied. Each of these is answered from
    // the bytes alone, with no parser involved, which is why the exit
    // criterion's "under a second" is not a performance target but an
    // arithmetic consequence.

    /** Over §8.4.9's 256 KiB ceiling. Answered from `filesize()`. */
    case TooLarge = 'too_large';

    /**
     * A YAML anchor or alias. §8.4.9: "YAML aliases disabled".
     *
     * 🛑 Refused by **lexical scan, before parsing**, and this is the only
     * defence that works. The billion-laughs bomb is a few hundred bytes of
     * YAML that expands to gigabytes during parse, so a parser-side limit is
     * applied after the memory has already been taken. Symfony's parser has
     * no switch for this; the switch is refusing the document.
     */
    case AliasesForbidden = 'aliases_forbidden';

    /** Over §8.4.9's depth 32. Counted from the indentation, before parsing. */
    case TooDeep = 'too_deep';

    /** §8.4.9: "single document". A `---` separator introducing a second one. */
    case MultipleDocuments = 'multiple_documents';

    /** Not YAML at all, or YAML that is not a mapping. */
    case Unparseable = 'unparseable';

    // ------------------------------------------------------------- contract

    /** 🛑 §8.4.8's `additionalProperties: false`, which is where it lands. */
    case UnknownKey = 'unknown_key';

    /**
     * 🛑 §8.4.8 again, but named separately on purpose.
     *
     * A key naming a project, a domain or a visibility level is rejected by
     * the schema exactly as any other unknown key is — but an author who
     * wrote `project: my-docs` has made a *category* error rather than a
     * typing one, and `unknown key: project` sends them looking for the
     * correct spelling of something that will never exist. This identifier
     * carries the sentence that explains why.
     */
    case ProjectScopedKey = 'project_scoped_key';

    /** A value the schema refuses: a bad enum member, a traversing path. */
    case InvalidValue = 'invalid_value';

    /**
     * A section is present but missing a key it cannot work without.
     *
     * Separate from {@see InvalidValue} because the remedy is the opposite:
     * one says "that value is wrong", this says "there is no value". The
     * author of `conda: {enviroment: x}` needs to be told the correct
     * spelling, not that something is invalid somewhere under `conda`.
     */
    case MissingKey = 'missing_key';

    /** §8.4.4: `build.commands` with `build.apt_packages`. */
    case CommandsWithAptPackages = 'commands_with_apt_packages';

    /** §8.4.14: `conda.environment` is parseable and not runnable in v1. */
    case CondaUnsupported = 'conda_unsupported';

    /** No `.docup.yaml` and no generator could be inferred. */
    case NoToolchain = 'no_toolchain';

    /** A `toolchain:` naming a preset this installation does not ship. */
    case UnknownToolchain = 'unknown_toolchain';

    /** The preset needs a file the repository does not have. */
    case MissingGeneratorConfiguration = 'missing_generator_configuration';

    /** §8.4.11: sparse checkout was asked for and could not be honoured. */
    case SparseCheckoutFailed = 'sparse_checkout_failed';

    /** `<class>.<reason>`, as §8.5.15 spells it. Always the `config` class. */
    public function identifier(): string
    {
        return 'config.'.$this->value;
    }

    /**
     * The caps, stated once.
     *
     * Here rather than in `config/builds.php` because 🛑 these are not
     * operator policy. §8.4.9 fixes them, they are part of the published
     * contract of §8.1.11, and an installation that raised the depth limit
     * would accept a file every other installation refuses — which makes
     * "keep your existing config file" false in the one direction nobody
     * tests.
     */
    public const MAX_BYTES = 262144;      // 256 KiB

    public const MAX_DEPTH = 32;

    /**
     * The identifiers, for the completeness test.
     *
     * @return list<string>
     */
    public static function identifiers(): array
    {
        return array_map(static fn (self $case): string => $case->identifier(), self::cases());
    }
}
