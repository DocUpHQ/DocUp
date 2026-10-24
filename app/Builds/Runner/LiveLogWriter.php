<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Runner;

use App\Builds\Log\BuildLog;
use App\Builds\Log\LogLine;
use App\Credentials\SecretRedactor;
use App\Credentials\SecretRegistry;

/**
 * The runner's end of §8.5.21's line-by-line stream.
 *
 * 🛑 **The runner redacts the one secret it holds, and only that one.**
 * §8.5.21 requires redaction "before persistence or broadcast", and the
 * full list of an installation's secrets lives on the credentialed side of
 * §11.2 — handing it to the process that holds the container-runtime
 * socket would undo the separation Phase 06 and Phase 07 built. So the
 * responsibility splits where the knowledge does: this scrubs the git
 * credential it was given for this stage, and {@see BuildLog}
 * scrubs everything else on the way into the file an API will serve.
 *
 * Neither layer is sufficient alone. Without this one the credential a
 * fetcher echoes on failure would sit in the spool in plaintext; without
 * the other, a component's environment secret would reach an author's
 * browser.
 *
 * 🛑 **Opened lazily and closed once.** A stage that prints nothing leaves
 * no file at all, which is what lets the worker treat "absent" and "empty"
 * as the same thing instead of distinguishing a stage that had no output
 * from one that never ran.
 */
final class LiveLogWriter
{
    /** @var resource|null */
    private $handle = null;

    private int $seq = 0;

    private readonly ?SecretRedactor $redactor;

    /** @var list<string> */
    private array $registered = [];

    public function __construct(
        private readonly string $path,
        ?string $credential = null,
    ) {
        $this->redactor = $credential === null || $credential === '' ? null : new SecretRedactor;

        if ($credential !== null && $credential !== '') {
            $this->remember($credential);
        }
    }

    /**
     * Append one already-sanitised line.
     *
     * The caller has stripped NUL bytes and applied §8.5.21's 8 KiB
     * truncation, because it is the same loop that enforces the per-stage
     * byte cap and splitting those apart would mean reading the line
     * twice.
     */
    public function write(string $text, string $stream): void
    {
        if (! is_resource($this->handle)) {
            $directory = dirname($this->path);

            if (! is_dir($directory)) {
                @mkdir($directory, 0o750, true);
            }

            $handle = @fopen($this->path, 'ab');

            if ($handle === false) {
                return;
            }

            $this->handle = $handle;
        }

        if ($this->redactor instanceof SecretRedactor) {
            $text = $this->redactor->scrub($text);
        }

        $line = new LogLine(++$this->seq, (int) (microtime(true) * 1000), $stream, $text);

        fwrite($this->handle, $line->encode());
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }

        $this->handle = null;

        /*
         * 🛑 Registered secrets are forgotten here, not left for the
         * process to exit with. The runner is long-lived and handles one
         * build after another; a registry that only grew would keep every
         * repository credential it had ever seen in memory, which is
         * exactly what {@see SecretRegistry}'s own docblock warns about.
         */
        foreach ($this->registered as $value) {
            SecretRegistry::forget($value);
        }

        $this->registered = [];
    }

    /**
     * Teach the registry the credential, whole and field by field.
     *
     * 🛑 Both forms matter. A git credential helper body is
     * `username=…\npassword=…\n`, and what a failing fetch echoes is
     * almost never the whole body — it is the password on its own, inside
     * a URL, or quoted in an error. Registering only the body would redact
     * nothing in the case that actually happens.
     */
    private function remember(string $credential): void
    {
        $values = [$credential];

        foreach (preg_split('/\R/', $credential) ?: [] as $field) {
            $value = str_contains($field, '=') ? substr($field, strpos($field, '=') + 1) : $field;

            if ($value !== '') {
                $values[] = $value;
            }
        }

        foreach ($values as $value) {
            SecretRegistry::remember($value);
            $this->registered[] = $value;
        }
    }
}
