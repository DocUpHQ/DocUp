<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * §8.5.6's twelve stages, "each with its own timeout, retry policy and failure
 * class".
 *
 * 🛑 The order is specified, so it is stated once here and derived everywhere
 * else. `sequence()` returns §8.5.6's position rather than the enum's ordinal:
 * an ordinal is an implementation detail of whoever last edited the case list,
 * and the one thing a build's step rows must never do is disagree with the
 * specification about what runs before what.
 *
 * 🛑 **`fetch` and `build` are different trust zones, not different steps.**
 * §8.5.7 is categorical: `fetch` runs in a DocUp-authored image with no
 * repository code and the credentials; `build` runs repository code with no
 * credentials. Read the Docs runs `post_checkout` in the credentialed context,
 * "doing so voids the entire credential separation". Keeping them as separate
 * stages with separate images is what makes that separation checkable rather
 * than asserted.
 */
enum Stage: string
{
    /** Admission control (§8.5.5). Decides whether this build may start now. */
    case Admit = 'admit';

    /**
     * §8.5.1: pin every contributing ref to an immutable commit SHA by
     * `git ls-remote`, **before any repository code executes**. The ordering
     * is the requirement: a plan resolved after the first line of repository
     * code has run is a plan that code could have influenced.
     */
    case Plan = 'plan';

    /** §8.5.7: the credential-free fetcher. The only stage that sees a credential. */
    case Fetch = 'fetch';

    /** §8.4.9: parse configuration **outside any sandbox** under hard caps. */
    case ValidateConfig = 'validate_config';

    /** Prepare the toolchain. The first stage that runs repository-influenced input. */
    case Environment = 'environment';

    /** The generator. Repository code, no credentials, no route to anything. */
    case Build = 'build';

    /** §8.4.5: read `$DOCUP_OUTPUT` and enforce the output contract. */
    case Collect = 'collect';

    /** Assemble the component's tree as it will be served. */
    case Compose = 'compose';

    /** §8.8.1: write-once into the artifact store, keyed by build id alone. */
    case Store = 'store';

    /** §8.8.4: the compare-and-swap pointer flip, which is allowed to lose. */
    case Publish = 'publish';

    /** §8.16: search indexing. */
    case Index = 'index';

    /** Provenance, accounting and terminal state. */
    case Finalise = 'finalise';

    /** §8.5.6's position, 1-based. */
    public function sequence(): int
    {
        return match ($this) {
            self::Admit => 1,
            self::Plan => 2,
            self::Fetch => 3,
            self::ValidateConfig => 4,
            self::Environment => 5,
            self::Build => 6,
            self::Collect => 7,
            self::Compose => 8,
            self::Store => 9,
            self::Publish => 10,
            self::Index => 11,
            self::Finalise => 12,
        };
    }

    /**
     * The stage's own timeout.
     *
     * Separate per stage because a single build-wide clock cannot distinguish
     * "the generator is slow" from "the fetch is hanging on a dead remote",
     * and those need different answers. §8.5.18's 30-minute wall clock is the
     * ceiling over all of them, not a substitute for them.
     */
    public function timeoutSeconds(): int
    {
        return match ($this) {
            self::Admit => 30,
            self::Plan => 60,          // ls-remote against every contributing source
            self::Fetch => 600,
            self::ValidateConfig => 30,
            self::Environment => 900,  // dependency installation, the slowest honest case
            self::Build => 1800,       // §8.5.18's default wall clock
            self::Collect => 300,
            self::Compose => 300,
            self::Store => 600,
            self::Publish => 60,
            self::Index => 600,
            self::Finalise => 60,
        };
    }

    /**
     * 🛑 §8.5.16: "Repository-content and configuration failures MUST NOT be
     * retried automatically. Only infrastructure-classified stages MUST
     * retry."
     *
     * This answers the *stage* half — whether a stage is one whose failures
     * can be infrastructural at all. {@see FailureClass::isRetryable()}
     * answers the other half, and both must agree before anything is retried.
     * Retrying a failed `build` would re-run repository code that has already
     * failed on its own merits, which wastes a slot and tells the author
     * nothing new.
     */
    public function mayRetry(): bool
    {
        return match ($this) {
            self::Fetch, self::Store, self::Index => true,
            default => false,
        };
    }

    /** Maximum attempts, where the stage may retry at all. */
    public function maxAttempts(): int
    {
        return $this->mayRetry() ? 3 : 1;
    }

    /**
     * 🛑 Does this stage execute repository-supplied code?
     *
     * The question §8.5.7 turns on. A stage answering true must run in the
     * build sandbox with no credentials; a stage answering false may hold a
     * credential. `ValidateConfig` answers **false** deliberately — §8.4.9
     * requires configuration to be parsed "outside any sandbox under hard
     * caps", because a YAML parser is not an execution engine and sandboxing
     * it would cost a container start per build for no reduction in risk.
     */
    public function executesRepositoryCode(): bool
    {
        return match ($this) {
            self::Environment, self::Build => true,
            default => false,
        };
    }

    /**
     * 🛑 Does this stage receive repository credentials?
     *
     * Exactly one stage does. §8.5.7: credentials reach `fetch` "only through
     * a git credential helper reading a **file descriptor** — never argv,
     * never the remote URL, never the environment".
     */
    public function receivesCredentials(): bool
    {
        return $this === self::Fetch;
    }

    /**
     * The twelve, in §8.5.6's order.
     *
     * @return list<self>
     */
    public static function pipeline(): array
    {
        $stages = self::cases();
        usort($stages, static fn (self $a, self $b): int => $a->sequence() <=> $b->sequence());

        return $stages;
    }
}
