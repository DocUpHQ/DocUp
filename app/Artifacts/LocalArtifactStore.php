<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

use Illuminate\Support\Facades\Storage;

/**
 * Artifacts on a local filesystem — the default self-hosted driver (§11.1).
 */
final class LocalArtifactStore extends FilesystemArtifactStore
{
    public function driver(): string
    {
        return 'local';
    }

    /**
     * Drop the write bit.
     *
     * 🛑 Honest about what this is and is not. Clearing write permission stops
     * the application overwriting its own artifacts by accident, which is the
     * realistic failure. It does **not** stop root, it does not stop the owner
     * restoring the bit, and it is not a POSIX immutable flag — `chattr +i`
     * needs CAP_LINUX_IMMUTABLE and is filesystem-specific, so depending on it
     * would make the driver work on ext4 and silently not on overlayfs, which
     * is exactly where a container runs.
     *
     * The real write-once guarantee is the refusal in
     * {@see FilesystemArtifactStore::put()}. This is defence in depth, and
     * saying so matters: a reader who thinks this line makes the bytes
     * tamper-proof would stop looking for the control that does.
     */
    protected function enforceImmutability(string $key): void
    {
        $path = Storage::disk($this->disk)->path($key);

        if (is_file($path)) {
            @chmod($path, 0o444);
        }
    }

    /**
     * Local deletion has to clear the read-only bit first, or the unlink fails
     * on directories whose contents were made read-only above.
     */
    public function deletePrefix(string $prefix): void
    {
        foreach ($this->list($prefix) as $file) {
            $path = Storage::disk($this->disk)->path($file);

            if (is_file($path)) {
                @chmod($path, 0o644);
            }
        }

        parent::deletePrefix($prefix);
    }
}
