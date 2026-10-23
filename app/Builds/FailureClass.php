<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * §8.5.15's eleven failure classes.
 *
 * > "The system MUST classify every failure into a typed class with a stable
 * > identifier (`contract.multiple_pdf_files`, `resource.oom_killed`) from the
 * > set `rejected, config, source, user, contract, conflict, timeout,
 * > resource, infra, cancelled, gate`."
 *
 * The class is not decoration. Three separate rules read it:
 *
 *  - §8.5.16 retries **only** infrastructure failures;
 *  - 🛑 §8.5.17 counts **only** user-caused classes toward the governor that
 *    disables webhook triggering, and "Infrastructure failures MUST NEVER
 *    disable a tenant";
 *  - §8.5.15 requires the identifier to be stable, because operators build
 *    alerts on these strings.
 *
 * So a misclassification is not a cosmetic error. Classing an infrastructure
 * failure as `user` silently counts it toward disabling a tenant's webhooks
 * for something that was never their fault; classing a user failure as `infra`
 * retries repository code that failed on its merits.
 */
enum FailureClass: string
{
    /** Refused before anything ran — a hostile URL, a closed gate, a quota. */
    case Rejected = 'rejected';

    /** The configuration file is wrong. The author's, and not retryable. */
    case Config = 'config';

    /** The source could not be obtained: a missing ref, a vanished repository. */
    case Source = 'source';

    /** The build commands failed. The ordinary case, and the author's. */
    case User = 'user';

    /** §8.4.5's output contract was violated — two PDFs, no `html/index.html`. */
    case Contract = 'contract';

    /** §8.8.4's compare-and-swap lost, or two builds collided. */
    case Conflict = 'conflict';

    /** A stage exceeded its own clock, or §8.5.18's wall clock. */
    case Timeout = 'timeout';

    /** OOM, disk, PID ceiling. §8.5.15 reads OOM from cgroup `memory.events:oom_kill`. */
    case Resource = 'resource';

    /** Ours: the runner died, the store was unreachable, the image would not pull. */
    case Infra = 'infra';

    /** Asked for. §8.5.15 makes exit code 183 a voluntary cancel. */
    case Cancelled = 'cancelled';

    /** A publish gate refused. */
    case Gate = 'gate';

    /**
     * 🛑 §8.5.16: only infrastructure failures retry.
     *
     * Deliberately narrow. `timeout` is **not** retryable even though it looks
     * transient: a build that exceeded 30 minutes once will exceed it again,
     * and retrying buys a second 30-minute slot for the same answer. A timeout
     * caused by something of ours shows up as `infra` from the runner, which
     * is the path that retries.
     */
    public function isRetryable(): bool
    {
        return $this === self::Infra;
    }

    /**
     * 🛑 §8.5.17: "Only user-caused classes (`user`, `config`, `contract`,
     * `conflict`, `resource`) MUST count toward the consecutive-failure
     * governor ... Infrastructure failures MUST NEVER disable a tenant."
     *
     * The set is quoted from the specification rather than inferred, because
     * the obvious inference is wrong in two places: `resource` counts (a build
     * that OOMs is asking for more than it may have), and `source` does not
     * (a repository that vanished is usually a permissions change at the
     * provider, not a tenant misbehaving).
     */
    public function countsTowardGovernor(): bool
    {
        return match ($this) {
            self::User, self::Config, self::Contract, self::Conflict, self::Resource => true,
            default => false,
        };
    }

    /** True when the tenant can act on this themselves. Drives the UI's wording. */
    public function isAuthorActionable(): bool
    {
        return match ($this) {
            self::Config, self::Source, self::User, self::Contract, self::Resource => true,
            default => false,
        };
    }
}
