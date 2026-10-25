<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Webhooks;

use App\Source\Provider;
use App\Versions\RefKind;

/**
 * One push, in the shape the rest of DocUp understands.
 *
 * 🛑 §8.5.3's normalisation, one layer earlier than {@see
 * \App\Builds\BuildTrigger}. Five providers describe the same event five
 * ways — GitHub nests the ref under `ref` and the files under
 * `commits[].added|removed|modified`, GitLab adds `total_commits_count`,
 * Bitbucket sends `push.changes[]` with `old`/`new` and no file list at all
 * — and a skip rule that had to know which provider it was reading would be
 * four skip rules.
 *
 * Everything here is **untrusted input** that happened to arrive over an
 * authenticated channel. The signature proves the provider sent it; it
 * proves nothing about whether `changedPaths` is complete, whether
 * `commitSha` is reachable, or whether a 40-character string is a SHA. Each
 * consumer re-validates what it depends on, and §8.5.1 re-pins every ref
 * with `ls-remote` before a build rather than trusting the SHA in here.
 */
final readonly class PushEvent
{
    /**
     * @param  string|null  $repositoryIdentifier  canonicalised per {@see Provider}
     * @param  string  $refName  short name: `main`, not `refs/heads/main`
     * @param  list<string>  $changedPaths  empty when the provider sends none
     * @param  list<string>  $commitMessages  newest first where the provider orders them
     * @param  list<string>  $labels  pull-request labels, for §8.5.4's fourth filter
     * @param  bool  $payloadTruncated  🛑 §8.5.4: treat as "everything changed"
     * @param  bool  $refDeleted  the push removed the ref; §8.6.15 governs what follows
     */
    public function __construct(
        public ?string $deliveryId,
        public ?string $event,
        public ?string $repositoryIdentifier,
        public string $refName,
        public RefKind $refKind,
        public string $commitSha,
        public array $changedPaths = [],
        public array $commitMessages = [],
        public array $labels = [],
        public bool $payloadTruncated = false,
        public bool $refDeleted = false,
    ) {}

    /**
     * Whether a changed-path rule may be applied to this payload.
     *
     * 🛑 §8.5.4: "A changed-path skip rule MUST NOT be applied to a payload
     * detected as truncated." Expressed as a question the rule evaluator asks
     * rather than as a check the evaluator is trusted to remember, because
     * the consequence of forgetting is silent: a monorepo whose pushes exceed
     * the provider's ceiling stops rebuilding the components that changed,
     * and nothing anywhere reports an error.
     *
     * An **empty** list is also untrustworthy, and for the same reason
     * §8.5.4 gives: "(c) absence of the changed-file arrays altogether". A
     * provider that sends no file list at all (Bitbucket) is not telling us
     * that nothing changed.
     */
    public function changedPathsAreTrustworthy(): bool
    {
        return ! $this->payloadTruncated && $this->changedPaths !== [];
    }

    /** The commit messages as one blob, for a `commit_message_regex` rule. */
    public function commitMessageBlob(): string
    {
        return implode("\n", $this->commitMessages);
    }
}
