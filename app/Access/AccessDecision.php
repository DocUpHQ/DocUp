<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Access;

use App\Auth\AccessLevel;

/**
 * The answer {@see EffectiveAccess} returns, and the only thing a caller may
 * act on.
 *
 * 🛑 **A decision carries its own status code.** §8.12.23's rules about 404 and
 * 403 and §8.12.24's about 401 are *part of the decision*, not a presentation
 * choice a controller makes afterwards — because the requirement says so in as
 * many words: "The denial outcome is decided by the request's **authorisation
 * state**, never by its `Accept` or `Sec-Fetch-*` headers; those choose only
 * the *representation* of an already-decided outcome."
 *
 * So the controller asks "what status" and never "should this be a 403", and
 * the one thing a header may change is which body shape carries the already
 * decided status (§8.12.24's problem document versus a redirect).
 */
final class AccessDecision
{
    /**
     * @param  AccessLevel  $required  the strongest level any applicable
     *                                 conjunct demanded (§12.3)
     * @param  AccessLevel  $established  the reader's context, after §12.3's
     *                                    `restricted` elevation
     * @param  PolicyRule|null  $rule  the first-match rule, when one matched
     * @param  AccessLeaf|null  $satisfiedBy  §8.12.25's "satisfied by binding X"
     * @param  bool  $rulePubliclyCacheable  §9.3.2's third input. 🛑 Never true on a
     *                                       denial, and never true unless the
     *                                       satisfying rule said so.
     * @param  bool  $challenge  §8.12.23's two permitted 401 cases
     * @param  PolicyRule|null  $shadowRule  a shadow rule that would have
     *                                       matched — recorded, never enforced
     */
    public function __construct(
        public readonly bool $allowed,
        public readonly AccessReason $reason,
        public readonly int $status,
        public readonly AccessLevel $required,
        public readonly AccessLevel $established,
        public readonly ?PolicyRule $rule = null,
        public readonly ?AccessLeaf $satisfiedBy = null,
        public readonly bool $rulePubliclyCacheable = false,
        public readonly bool $challenge = false,
        public readonly ?PolicyRule $shadowRule = null,
    ) {}

    /**
     * 🛑 Whether a `WWW-Authenticate` header is permitted (§8.12.23).
     *
     * > "In every other case, including an anonymous non-interactive request
     * > for a resource whose existence is private, the response is the
     * > project's `deny_status` with **no** `WWW-Authenticate` header."
     *
     * The header is the disclosure: it tells a crawler that something is there
     * to authenticate *for*. A 404 with a challenge on it is a 404 that answers
     * the question it was supposed to refuse.
     */
    public function mayChallenge(): bool
    {
        return $this->challenge && $this->status === 401;
    }

    /**
     * The decision header's value — §17's "the decision header".
     *
     * 🛑 A **reason code and a rule position**, never a reason in prose and
     * never the reader's identity. It rides on the `X-DocUp-` family §7.4
     * strips from every inbound request, so a reader cannot forge one and
     * nothing downstream can mistake theirs for DocUp's.
     *
     * 🛑 **Why emit it at all on a denial**, when §8.2.2 wants a refusal
     * indistinguishable from absence: because §8.12.22 requires "a `doctor`
     * probe for cached private content" and §8.12.25 requires a simulator, and
     * both need to see *why* from outside the process. The codes are stable
     * identifiers from a fixed vocabulary ({@see AccessReason}) — they name
     * which conjunct refused, never what exists. `project_visibility` is true
     * of every path on a guarded project, including the thousands that do not
     * exist, so it distinguishes nothing.
     */
    public function header(): string
    {
        $value = ($this->allowed ? 'allow' : ($this->challenge ? 'challenge' : 'deny')).':'.$this->reason->value;

        if ($this->rule !== null) {
            $value .= ';rule='.$this->rule->position;
        }

        if ($this->satisfiedBy !== null) {
            $value .= ';by='.$this->satisfiedBy->value;
        }

        return $value;
    }
}
