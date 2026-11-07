<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Seo;

use App\Support\Uuid;
use Illuminate\Support\Facades\Storage;

/**
 * 🛑 §8.11.6's generated-artefact store — and the emphasis in that
 * requirement is on the word **separate**.
 *
 * > "`robots.txt`, `sitemap.xml`, `llms.txt` and `llms-full.txt` MUST be
 * > generated **per domain mount** and written at pointer flip to a
 * > generated-artefact store keyed by domain mount and revision —
 * > `generated/<domain_mount_uuid>/<revision>/…` — which is 🛑 **separate
 * > from the immutable build artifact tree**, so §8.8.1's write-once rule
 * > and §8.8.2's ingest validation are untouched and a rebrand or a new
 * > domain regenerates them without touching a build."
 *
 * **Why these files cannot live in a build.** A build is immutable by
 * construction: §8.8.1 makes `put()` refuse an overwrite and chmod the file
 * read-only, and §8.8.5's rollback depends on the previous build's bytes
 * being exactly what they were. These four files are not properties of a
 * build at all — they are properties of *a build as served at a particular
 * place*:
 *
 *  - the **same build** on two domains needs two different `sitemap.xml`,
 *    because the URLs differ;
 *  - a **rebrand** changes nothing in any build and should change
 *    `robots.txt`;
 *  - a **new domain** needs a whole set for a build that has not changed.
 *
 * Writing them into the build tree would mean either breaking write-once or
 * rebuilding to change a hostname. So this is a different prefix, a
 * different class, and a deliberately **mutable** one — and keeping §8.8.1
 * untouched is the reason it is a separate class rather than a flag on the
 * existing store.
 */
final readonly class GeneratedStore
{
    /** The four files §8.11.6 names, and nothing else. */
    public const array FILES = ['robots.txt', 'sitemap.xml', 'llms.txt', 'llms-full.txt'];

    public function __construct(private string $disk) {}

    public static function fromConfig(): self
    {
        $driver = config('artifacts.driver');
        $disks = config('artifacts.disks');
        $disk = is_array($disks) && is_string($driver) ? ($disks[$driver] ?? null) : null;

        return new self(is_string($disk) ? $disk : 'artifacts');
    }

    /**
     * `generated/<domain_mount_uuid>/<revision>`, exactly as §8.11.6 writes
     * it.
     *
     * 🛑 The revision is in the **path**, not a column pointing at a
     * mutable file, so publishing a new set and switching to it are two
     * steps and a reader never sees a half-written one. The old revision
     * stays until {@see self::sweep()} removes it, which is also what
     * makes the switch reversible.
     *
     * @param  string  $mountId  raw 16 bytes
     */
    public function prefixFor(string $mountId, int $revision): string
    {
        return 'generated/'.Uuid::toText($mountId).'/'.$revision;
    }

    /** @param  string  $mountId  raw 16 bytes */
    public function keyFor(string $mountId, int $revision, string $file): string
    {
        return $this->prefixFor($mountId, $revision).'/'.$file;
    }

    /**
     * Write one generated file.
     *
     * 🛑 No write-once check, and that absence is the point of the class.
     * It is safe here for a reason that does not apply to a build: nothing
     * cites a generated file by digest, no rollback restores one, and
     * §8.8.2's ingest validation never sees it. What protects a reader
     * from a half-written set is the revision in the path, not
     * immutability.
     */
    public function put(string $mountId, int $revision, string $file, string $contents): void
    {
        Storage::disk($this->disk)->put($this->keyFor($mountId, $revision, $file), $contents);
    }

    /** @param  string  $mountId  raw 16 bytes */
    public function get(string $mountId, int $revision, string $file): ?string
    {
        $key = $this->keyFor($mountId, $revision, $file);
        $disk = Storage::disk($this->disk);

        return $disk->exists($key) ? ($disk->get($key) ?? null) : null;
    }

    /**
     * Remove every revision for a mount except the one named.
     *
     * 🛑 Called **after** the mount's `generated_revision` has been moved
     * on, never before. Reversed, a reader arriving between the delete and
     * the update gets a 404 for `robots.txt` — which a crawler reads as
     * "crawl everything".
     *
     * @param  string  $mountId  raw 16 bytes
     */
    public function sweep(string $mountId, int $keep): void
    {
        $disk = Storage::disk($this->disk);
        $root = 'generated/'.Uuid::toText($mountId);
        $keeping = $root.'/'.$keep;

        foreach ($disk->directories($root) as $directory) {
            if ($directory !== $keeping) {
                $disk->deleteDirectory($directory);
            }
        }
    }
}
