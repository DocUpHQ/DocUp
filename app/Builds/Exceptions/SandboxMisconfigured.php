<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds\Exceptions;

/**
 * A sandbox configuration the application refuses to boot with (§8.5.11,
 * §8.5.12).
 *
 * 🛑 An exception rather than a log line, and thrown from a service
 * provider, because §8.5.11 and §8.5.12 both say **refuse** — "The
 * application MUST refuse to boot with `APP_ENV=production`, builds enabled
 * and no explicit isolation declaration" and "**Startup MUST fail** if the
 * self-test fails". A warning would be read once by whoever deployed it and
 * never again, and the installation it warned about would keep running
 * repository code with no isolation anybody had chosen.
 *
 * Every message carries the section, the thing that is wrong and the one
 * action that fixes it, because this is read by an operator at the moment
 * their installation will not start.
 */
final class SandboxMisconfigured extends \RuntimeException {}
