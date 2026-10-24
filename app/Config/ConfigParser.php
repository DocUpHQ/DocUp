<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

use App\Builds\Stage;
use Opis\JsonSchema\Errors\ErrorFormatter;
use Opis\JsonSchema\Errors\ValidationError;
use Opis\JsonSchema\Helper;
use Opis\JsonSchema\Validator;
use Symfony\Component\Yaml\Exception\ParseException;
use Symfony\Component\Yaml\Yaml;

/**
 * §8.4.9's read: outside any sandbox, under hard caps, against the published
 * schema.
 *
 * > "The system MUST parse configuration **outside any sandbox** under hard
 * > caps: ≤256 KiB, nesting depth ≤32, YAML aliases disabled, single
 * > document, validated against a published JSON Schema."
 *
 * 🛑 **Outside the sandbox is a decision, not an omission.** {@see Stage}
 * answers `executesRepositoryCode()` false for `validate_config` for the
 * reason stated there: a YAML parser is not an execution engine, and
 * sandboxing it would cost a container start per build with no reduction in
 * risk — *provided* the caps hold. {@see YamlGate} is what makes that
 * proviso true, which is why it runs on the bytes before this class builds
 * anything.
 *
 * 🛑 **The schema is a file, not a PHP reimplementation of one.** §8.1.11
 * makes `.docup.yaml` a published versioned contract, so an editor offers
 * completion from `resources/schema/docup-yaml-v1.schema.json` and this class
 * validates against the same bytes. Two implementations of one contract
 * diverge; the only question is when. (The same reasoning gave Phase 07 one
 * `egress-allowlist.conf` read by both squid and the application — ADR 0011.)
 */
final class ConfigParser
{
    /** The `$id` in the schema file, and the URI the validator resolves. */
    public const SCHEMA_ID = 'https://docup.dev/schema/docup-yaml/v1.json';

    /**
     * 🛑 §8.4.8's forbidden vocabulary, for a *better message* and nothing
     * else.
     *
     * The schema already rejects every one of these, because
     * `additionalProperties: false` rejects everything it does not name. This
     * list exists so that an author who wrote `project: api-docs` is told
     * **why** no such key will ever exist — "a repository does not name the
     * projects that mount it" — instead of being sent to look for the correct
     * spelling of something that is not a spelling mistake.
     *
     * `ConfigContractTest` asserts that every name here is in fact rejected,
     * so the list cannot quietly become a list of keys that work.
     *
     * @var list<string>
     */
    public const PROJECT_SCOPED_KEYS = [
        'project', 'projects', 'project_slug', 'slug', 'name',
        'mount', 'mount_path', 'mounts', 'path_prefix',
        'domain', 'domains', 'canonical_domain', 'custom_domain', 'base_url',
        'visibility', 'private', 'public', 'auth', 'authentication', 'access',
        'channel', 'stable', 'latest', 'default_version', 'versions',
        'retention', 'retain', 'expires',
        'organisation', 'organization', 'team', 'owner',
    ];

    private static ?Validator $validator = null;

    /**
     * Parse and validate one configuration file's bytes.
     *
     * @param  string  $yaml  the raw file, exactly as it is in the repository
     * @param  string  $filename  which of §8.4.1's names it was found under
     *
     * @throws ConfigRefused on any §8.4.9 cap, any schema violation, or
     *                       §8.4.14's conda limitation
     */
    public static function parse(string $yaml, string $filename): DocupConfig
    {
        YamlGate::admit($yaml);

        try {
            /*
             * `PARSE_EXCEPTION_ON_INVALID_TYPE` turns a PHP object or
             * resource in the document into an exception rather than a
             * silently mangled value. `PARSE_CUSTOM_TAGS` is deliberately
             * NOT set: an unknown `!tag` must be a parse error, because a
             * tag is the other half of YAML's deserialisation surface and
             * accepting one we do not understand is accepting whatever a
             * future parser decides it means.
             */
            $parsed = Yaml::parse($yaml, Yaml::PARSE_EXCEPTION_ON_INVALID_TYPE);
        } catch (ParseException $e) {
            throw ConfigRefused::of(
                ConfigRejection::Unparseable,
                'line '.$e->getParsedLine(),
            );
        }

        if (! is_array($parsed) || $parsed === [] || array_is_list($parsed)) {
            throw ConfigRefused::of(
                ConfigRejection::Unparseable,
                'the file must be a mapping of keys to values',
            );
        }

        /*
         * The exact depth, now that there is a structure to measure. The
         * lexical gate has already refused anything it could not prove was
         * shallow enough; this catches the remainder, where its conservative
         * estimate was lower than the truth.
         */
        $depth = YamlGate::depthOf($parsed);

        if ($depth > ConfigRejection::MAX_DEPTH) {
            throw ConfigRefused::of(
                ConfigRejection::TooDeep,
                'depth '.$depth.', limit '.ConfigRejection::MAX_DEPTH,
            );
        }

        self::validateAgainstSchema($parsed);

        /*
         * §8.4.14: accepted by the schema, refused here, with a sentence that
         * names the limitation and the two alternatives. Checked after the
         * schema so that `conda: {enviroment: x}` is still a typo rather than
         * an unsupported feature.
         */
        if (isset($parsed['conda'])) {
            throw ConfigRefused::of(ConfigRejection::CondaUnsupported, 'conda.environment');
        }

        return new DocupConfig(
            filename: $filename,
            raw: $parsed,
            digest: hash('sha256', $yaml),
        );
    }

    /**
     * @param  array<array-key, mixed>  $parsed
     *
     * @throws ConfigRefused
     */
    private static function validateAgainstSchema(array $parsed): void
    {
        $result = self::validator()->validate(Helper::toJSON($parsed), self::SCHEMA_ID);

        if ($result->isValid()) {
            return;
        }

        $error = $result->error();

        if (! $error instanceof ValidationError) {
            return;
        }

        /*
         * 🛑 §8.4.8 first. An unknown key that happens to be one of the
         * forbidden ones gets the sentence explaining the model; everything
         * else gets the ordinary one. Checked against the top-level keys the
         * author actually wrote rather than against the error tree, because
         * `additionalProperties` reports at the object it fired on and the
         * interesting case is always the root.
         */
        $offending = array_values(array_intersect(
            array_map(strval(...), array_keys($parsed)),
            self::PROJECT_SCOPED_KEYS,
        ));

        if ($offending !== []) {
            throw ConfigRefused::of(ConfigRejection::ProjectScopedKey, '', $offending);
        }

        $unknown = self::unknownProperties($error);

        if ($unknown !== []) {
            throw ConfigRefused::of(ConfigRejection::UnknownKey, '', $unknown);
        }

        /*
         * §8.4.4's `not` fires as a bare `not` at `/build`, which would
         * otherwise reach an author as "the value must not match the schema"
         * — true, and useless.
         */
        if (self::hasKeyword($error, 'not') && isset($parsed['build']) && is_array($parsed['build'])
            && isset($parsed['build']['commands'], $parsed['build']['apt_packages'])) {
            throw ConfigRefused::of(ConfigRejection::CommandsWithAptPackages, 'build');
        }

        $missing = self::missingProperties($error);

        if ($missing !== []) {
            throw ConfigRefused::of(ConfigRejection::MissingKey, '', $missing);
        }

        throw ConfigRefused::of(ConfigRejection::InvalidValue, self::firstPointer($error));
    }

    /**
     * The property names an `additionalProperties: false` rejected.
     *
     * @return list<string>
     */
    private static function unknownProperties(ValidationError $error): array
    {
        $names = [];

        foreach ((new ErrorFormatter)->formatFlat($error, static fn (ValidationError $e): ValidationError => $e) as $flat) {
            if (! $flat instanceof ValidationError || $flat->keyword() !== 'additionalProperties') {
                continue;
            }

            $properties = $flat->args()['properties'] ?? [];

            if (! is_array($properties)) {
                continue;
            }

            $prefix = self::pointer($flat);

            foreach ($properties as $property) {
                if (is_string($property) || is_int($property)) {
                    $names[] = ($prefix === '' ? '' : $prefix.'.').$property;
                }
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * The keys a `required` reported absent, qualified by their section.
     *
     * 🛑 Reported in preference to the generic value message because the two
     * have opposite remedies, and because this is what a typo in a nested
     * key looks like from the schema's side: `conda: {enviroment: …}` is a
     * `required: environment` failure, and telling the author only that
     * something under `conda` is invalid sends them looking at the value.
     *
     * @return list<string>
     */
    private static function missingProperties(ValidationError $error): array
    {
        $names = [];

        foreach ((new ErrorFormatter)->formatFlat($error, static fn (ValidationError $e): ValidationError => $e) as $flat) {
            if (! $flat instanceof ValidationError || $flat->keyword() !== 'required') {
                continue;
            }

            $missing = $flat->args()['missing'] ?? [];

            if (! is_array($missing)) {
                continue;
            }

            $prefix = self::pointer($flat);

            foreach ($missing as $property) {
                if (is_string($property) || is_int($property)) {
                    $names[] = ($prefix === '' ? '' : $prefix.'.').$property;
                }
            }
        }

        return array_values(array_unique($names));
    }

    private static function hasKeyword(ValidationError $error, string $keyword): bool
    {
        foreach ((new ErrorFormatter)->formatFlat($error, static fn (ValidationError $e): ValidationError => $e) as $flat) {
            if ($flat instanceof ValidationError && $flat->keyword() === $keyword) {
                return true;
            }
        }

        return false;
    }

    /** The dotted path of the first leaf error — a key, never a value. */
    private static function firstPointer(ValidationError $error): string
    {
        $subErrors = $error->subErrors();

        if ($subErrors !== []) {
            return self::firstPointer($subErrors[0]);
        }

        $pointer = self::pointer($error);

        return ($pointer === '' ? '(root)' : $pointer).' ('.$error->keyword().')';
    }

    private static function pointer(ValidationError $error): string
    {
        $path = array_map(strval(...), $error->data()->fullPath());

        return implode('.', $path);
    }

    /**
     * One validator, with the schema file registered under its `$id`.
     *
     * Static because compiling the schema is the expensive part and a build
     * worker validates one file per build for the life of the process.
     */
    private static function validator(): Validator
    {
        if (self::$validator instanceof Validator) {
            return self::$validator;
        }

        $validator = new Validator;
        $validator->resolver()?->registerFile(self::SCHEMA_ID, self::schemaPath());

        /*
         * 🛑 Collect several errors rather than stopping at the first, and
         * the reason is the message rather than completeness. `conda:
         * {enviroment: ...}` violates both `required` and
         * `additionalProperties`; stopping at the first reports "environment
         * is required", which sends an author looking for a missing key
         * instead of at the typo three characters away. With both in hand,
         * {@see unknownProperties()} finds the one that names the mistake.
         */
        $validator->setMaxErrors(20);

        return self::$validator = $validator;
    }

    /** Where the published schema lives. One file; see the class comment. */
    public static function schemaPath(): string
    {
        return dirname(__DIR__, 2).'/resources/schema/docup-yaml-v1.schema.json';
    }

    /** Test seam: forget the compiled schema after the file has changed. */
    public static function forgetValidator(): void
    {
        self::$validator = null;
    }
}
