<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace Tests\Unit\Composition;

use App\Composition\SinglePass\SourceSlot;
use App\Models\Component;
use App\Models\ComponentSource;
use App\Models\Repository;
use App\Support\Uuid;

/**
 * Unsaved models for the unit tests of §8.7.12's playbook generator.
 *
 * 🛑 **Unsaved on purpose.** {@see SourceSlot} reads a component key and a
 * source path and nothing else, so a test that needed a database to
 * exercise it would be hiding how little it touches — and the properties
 * under test (where the playbook is written, what is in it, what cannot
 * reach the shell) are true of the values rather than of the rows.
 */
final class SlotFactory
{
    public static function make(string $key, string $sourcePath, bool $isPrimary): SourceSlot
    {
        $component = new Component;
        $component->forceFill(['id' => Uuid::v7(), 'key' => $key, 'name' => ucfirst($key)]);

        $source = new ComponentSource;
        $source->forceFill(['id' => Uuid::v7(), 'source_path' => $sourcePath]);

        $repository = new Repository;
        $repository->forceFill([
            'id' => Uuid::v7(),
            'clone_url' => 'https://github.com/docup/'.$key.'.git',
        ]);

        return SourceSlot::for($component, $source, $repository, $isPrimary);
    }
}
