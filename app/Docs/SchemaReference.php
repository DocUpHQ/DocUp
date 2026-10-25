<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Docs;

/**
 * The `.docup.yaml` reference, rendered from the schema that enforces it.
 *
 * 🛑 **Generated, because a hand-written reference is a second contract.**
 * §8.1.11 makes `.docup.yaml` one of three independently versioned public
 * contracts and §8.4.2 makes `resources/schema/docup-yaml-v1.schema.json`
 * **the** statement of it — "the application validates against this exact
 * document rather than against a PHP reimplementation of it, so that the
 * schema an editor offers completion from and the schema a build is refused
 * by cannot drift apart". A reference page maintained by hand would be
 * exactly the third copy that argument rejects, and the one an author
 * actually reads.
 *
 * So the page is rendered from the schema, committed so it is readable
 * without running anything, and re-rendered and compared by a test. Adding a
 * key to the schema and not to the page is a failing build rather than a
 * documentation gap nobody files.
 *
 * The schema's own `description` strings carry the reasoning, which is why
 * they are long: they were written to be read here.
 */
final class SchemaReference
{
    /**
     * Render the whole reference body.
     *
     * @param  array<string, mixed>  $schema  the decoded JSON Schema
     */
    public static function render(array $schema): string
    {
        $properties = is_array($schema['properties'] ?? null) ? $schema['properties'] : [];
        $required = is_array($schema['required'] ?? null) ? $schema['required'] : [];

        $out = [];

        foreach ($properties as $name => $definition) {
            if (! is_string($name) || ! is_array($definition)) {
                continue;
            }

            $out[] = self::key($name, $definition, in_array($name, $required, true));
        }

        return implode("\n", $out);
    }

    /**
     * One top-level key, with its nested object keys as a table.
     *
     * Two levels and no more. Deeper nesting in this schema is always a
     * `oneOf` over shapes — `python.install`'s two forms, `formats`' literal
     * `all` — and rendering those as a tree produces something an author
     * reads past rather than reads. The constraint line below states them
     * instead.
     *
     * @param  array<string, mixed>  $definition
     */
    private static function key(string $name, array $definition, bool $required): string
    {
        $lines = ['## `'.$name.'`', ''];

        $children = is_array($definition['properties'] ?? null) ? $definition['properties'] : [];

        /*
         * The constraint line is dropped where a child table follows it: "an
         * object" above a table of that object's keys is a sentence that
         * tells a reader what they can already see.
         */
        $summary = $children === [] ? self::constraints($definition) : '';
        $opening = trim(($required ? '**Required.** ' : '').($summary === '' ? '' : ucfirst($summary).'.'));

        if ($opening !== '') {
            $lines[] = $opening;
            $lines[] = '';
        }

        $description = $definition['description'] ?? null;

        if (is_string($description) && $description !== '') {
            $lines[] = self::prose($description);
            $lines[] = '';
        }

        if ($children !== []) {
            $childRequired = is_array($definition['required'] ?? null) ? $definition['required'] : [];

            $lines[] = '| Key | Accepts | Notes |';
            $lines[] = '|---|---|---|';

            foreach ($children as $childName => $child) {
                if (! is_string($childName) || ! is_array($child)) {
                    continue;
                }

                /*
                 * The column header is already "Accepts", so the verb the
                 * prose form needs is noise here: "one of `html`, `dirhtml`"
                 * rather than "takes one of".
                 */
                $accepts = (string) preg_replace('/^takes /', '', self::constraints($child));

                $lines[] = '| `'.$childName.'` | '
                    .self::cell($accepts === '' ? 'see below' : $accepts).' | '
                    .self::cell(self::note($child, in_array($childName, $childRequired, true))).' |';
            }

            $lines[] = '';
        }

        return implode("\n", $lines);
    }

    /**
     * What a key accepts, as one phrase.
     *
     * @param  array<string, mixed>  $definition
     */
    private static function constraints(array $definition): string
    {
        if (array_key_exists('const', $definition)) {
            return 'takes the literal `'.self::scalar($definition['const']).'`';
        }

        if (is_array($definition['enum'] ?? null)) {
            return 'takes one of '.implode(', ', array_map(
                static fn (mixed $value): string => '`'.self::scalar($value).'`',
                $definition['enum'],
            ));
        }

        if (isset($definition['$ref']) && $definition['$ref'] === '#/$defs/repositoryPath') {
            return 'a path inside the checkout';
        }

        if (isset($definition['$ref']) && $definition['$ref'] === '#/$defs/commandList') {
            return 'a list of shell commands';
        }

        if (isset($definition['oneOf'])) {
            return 'takes one of several forms';
        }

        $type = $definition['type'] ?? null;

        if (is_array($type)) {
            return implode(' or ', array_map(
                static fn (mixed $one): string => self::article((string) $one),
                $type,
            ));
        }

        if (! is_string($type)) {
            return '';
        }

        if ($type === 'array') {
            $items = is_array($definition['items'] ?? null) ? $definition['items'] : [];

            return 'a list'.self::plural($items);
        }

        return self::article($type);
    }

    /**
     * What a list holds, as ` of …`, or nothing when the items are unconstrained.
     *
     * @param  array<string, mixed>  $items
     */
    private static function plural(array $items): string
    {
        $inner = self::constraints($items);

        if ($inner === '') {
            return '';
        }

        // "a list of a string" is how a generated page announces that it was
        // generated. The three forms the schema actually produces here are an
        // article, an enumeration and a `$defs` phrase; only the first needs
        // pluralising.
        return match (true) {
            str_starts_with($inner, 'a path inside the checkout') => ' of paths inside the checkout',
            str_starts_with($inner, 'a string') => ' of strings',
            str_starts_with($inner, 'an object') => ' of objects',
            str_starts_with($inner, 'takes one of several forms') => ' whose entries take one of several forms',
            str_starts_with($inner, 'takes one of ') => ' of '.substr($inner, strlen('takes one of ')),
            default => ' of '.$inner,
        };
    }

    /** `a` or `an`, so a generated sentence reads like a written one. */
    private static function article(string $noun): string
    {
        return (str_contains('aeiou', substr($noun, 0, 1)) ? 'an ' : 'a ').$noun;
    }

    /**
     * The short note beside a nested key: its default, cap or pattern.
     *
     * The full `description` is deliberately not inlined here — the ones in
     * this schema are paragraphs, and a table cell is the wrong place for a
     * paragraph. They are in the schema, which is the contract.
     *
     * @param  array<string, mixed>  $definition
     */
    private static function note(array $definition, bool $required): string
    {
        $notes = [];

        if ($required) {
            $notes[] = 'required';
        }

        if (array_key_exists('default', $definition)) {
            $notes[] = 'default `'.self::scalar($definition['default']).'`';
        }

        foreach (['maxLength' => 'at most %s characters', 'maxItems' => 'at most %s entries'] as $key => $format) {
            if (isset($definition[$key]) && is_scalar($definition[$key])) {
                $notes[] = sprintf($format, (string) $definition[$key]);
            }
        }

        if (isset($definition['minimum'], $definition['maximum'])) {
            $notes[] = 'from '.self::scalar($definition['minimum']).' to '.self::scalar($definition['maximum']);
        }

        return $notes === [] ? '' : ucfirst(implode(', ', $notes));
    }

    /**
     * A schema description, as Markdown prose.
     *
     * The descriptions cite the specification as `SPEC 8.4.2`, which is right
     * in a JSON file a tool reads and wrong on a page an author reads — the
     * specification is not published. Rewritten to `§8.4.2`, which at least
     * reads as a cross-reference rather than as a dangling link.
     */
    private static function prose(string $description): string
    {
        return trim((string) preg_replace('/\bSPEC (\d)/', '§$1', $description));
    }

    private static function cell(string $text): string
    {
        return str_replace('|', '\\|', $text);
    }

    private static function scalar(mixed $value): string
    {
        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        return is_scalar($value) ? (string) $value : '';
    }
}
