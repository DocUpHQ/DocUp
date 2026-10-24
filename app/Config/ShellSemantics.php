<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Config;

/**
 * §8.4.10: how a build's commands are run, and the one documented way out.
 *
 * > "🛑 Build commands MUST run under `set -euo pipefail`. This is a
 * > **deliberate incompatibility** with Read the Docs, which runs
 * > `/bin/sh -c` with no error flags so a failing mid-pipeline command
 * > silently produces a green build. A documented per-project legacy opt-out
 * > MUST exist."
 *
 * §19/24 states the trade plainly: a green build over broken documentation is
 * worse than a red one, because nobody looks at a green build.
 *
 * 🛑 **The opt-out is a stored setting, never a key in `.docup.yaml`**, and
 * that is not a detail. §20.4 requires every per-project or per-component
 * weakening to be "audited on change, surfaced in the project's settings UI
 * as a weakening, and listed in one place in the operator documentation". A
 * YAML key satisfies none of those: any repository could restore Read the
 * Docs' silent-failure semantics by adding one line, the deliberate
 * incompatibility would evaporate on the first migration, and the owner who
 * is accountable for the documentation would never know it had happened.
 *
 * 🛑 **It is per *component*, where §8.4.10 says per *project*.** A build
 * belongs to a component and is reusable by every project that mounts it
 * (§7.2, §8.7.9); a per-project flag would either change the output of a
 * shared build — making one project's setting decide another's documentation
 * — or force the flag into the content key and forfeit the reuse that the
 * whole composition model is built on. Recorded as a divergence in the build
 * log rather than taken silently.
 */
enum ShellSemantics: string
{
    /**
     * The default. `set -euo pipefail`, so a failing command fails the build.
     *
     * - `-e` a command that fails stops the script
     * - `-u` an unset variable is an error, not an empty string
     * - `-o pipefail` a pipeline fails if **any** stage fails, not just the last
     *
     * The third is the one that catches the real cases:
     * `sphinx-build … | tee build.log` exits 0 on Read the Docs however badly
     * `sphinx-build` failed, because `tee` succeeded.
     */
    case Strict = 'strict';

    /**
     * Read the Docs' semantics, for a repository that depends on them.
     *
     * Still `-e`-less rather than silently different: this is exactly
     * `/bin/sh -c`, which is what the author's commands were written
     * against. Offering a half-way mode would be a third set of semantics
     * nobody has ever tested their build under.
     */
    case Legacy = 'legacy';

    /**
     * The prologue prepended to a command script.
     *
     * Returned as a string rather than applied, so that the one place a
     * build script is assembled is the one place this appears, and a test
     * can assert the prologue is present without running a container.
     */
    public function prologue(): string
    {
        return match ($this) {
            self::Strict => "set -euo pipefail\n",
            self::Legacy => "# §8.4.10 legacy shell semantics: no -e, no -u, no pipefail\n",
        };
    }

    /** The interpreter argv. `pipefail` is not POSIX `sh`, so strict needs bash. */
    public function shell(): string
    {
        return match ($this) {
            self::Strict => '/bin/bash',
            self::Legacy => '/bin/sh',
        };
    }

    /** Does this mode weaken a default, for §20.4's "listed in one place"? */
    public function isWeakening(): bool
    {
        return $this === self::Legacy;
    }

    /**
     * Parse a stored value, defaulting to the safe one.
     *
     * 🛑 An unrecognised value yields `Strict`. A component row that somehow
     * holds a value this enum does not know must not silently get the weaker
     * behaviour — the failure direction of a bad read is the whole reason
     * `BuildConfig`'s fallbacks are written the way they are.
     */
    public static function fromStored(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::Strict;
    }
}
