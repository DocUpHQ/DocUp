<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Console\Commands;

use App\Docs\GeneratedBlocks;
use Illuminate\Console\Command;

/**
 * `docup:docs:render` — fill the generated blocks of DocUp's own manual.
 *
 * 🛑 `--check` is the half that matters, and CI runs it. A generator nobody
 * verifies is a generator somebody forgets to run, and the page it left
 * behind is a stale copy of a contract — §8.7.13's matrix being the worst
 * case, because an operator switches composition modes on it.
 *
 * {@see GeneratedBlocks} says which blocks live where and why each one is
 * generated rather than written.
 */
final class RenderDocsCommand extends Command
{
    protected $signature = 'docup:docs:render
        {--check : Exit non-zero if any generated block is out of date}';

    protected $description = "Render the generated blocks of DocUp's own documentation";

    public function handle(): int
    {
        $stale = [];

        foreach (GeneratedBlocks::all() as $page => $blocks) {
            $path = base_path($page);

            if (! is_file($path)) {
                $this->components->error($page.' does not exist');

                return self::FAILURE;
            }

            $before = (string) file_get_contents($path);
            $after = $before;

            foreach ($blocks as $block => $render) {
                try {
                    $after = GeneratedBlocks::replace($after, $block, $render());
                } catch (\RuntimeException $missing) {
                    $this->components->error($page.': '.$missing->getMessage());

                    return self::FAILURE;
                }
            }

            if ($after === $before) {
                $this->components->twoColumnDetail($page, '<fg=green>up to date</>');

                continue;
            }

            if ($this->option('check')) {
                $stale[] = $page;
                $this->components->twoColumnDetail($page, '<fg=red>out of date</>');

                continue;
            }

            file_put_contents($path, $after);
            $this->components->twoColumnDetail($page, '<fg=yellow>rendered</>');
        }

        if ($stale !== []) {
            $this->newLine();
            $this->components->error(
                'Run `php artisan docup:docs:render` and commit: '.implode(', ', $stale),
            );

            return self::FAILURE;
        }

        return self::SUCCESS;
    }
}
