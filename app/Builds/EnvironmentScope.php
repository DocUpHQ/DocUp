<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Builds;

/**
 * §8.4.6's three scopes, which exist because two requirements would otherwise
 * contradict each other in silence.
 *
 * > "🛑 The system MUST classify every injected environment variable into one
 * > of three scopes, because §8.7.10 forbids project-scoped input from
 * > entering a build container and §8.7.9 excludes it from the content key —
 * > so 'inject the Read the Docs variables' and 'builds are project-agnostic'
 * > cannot both be true unspecified."
 *
 * That sentence is the whole design. Read the Docs injects `READTHEDOCS_PROJECT`
 * and `READTHEDOCS_CANONICAL_URL` because on Read the Docs a build belongs to
 * exactly one project. Here a build is shared by every project that mounts the
 * component, so those two variables have no single correct value — and
 * injecting *a* value would silently bake one project's identity into an
 * artifact served under another's.
 */
enum EnvironmentScope: string
{
    /** About the installation. Never varies, so never enters any key. */
    case Installation = 'installation';

    /**
     * About the component and the ref.
     *
     * Already in the content key through `commit_sha` and the config digest,
     * so injecting these adds nothing to the key and costs no reuse.
     */
    case Component = 'component';

    /**
     * 🛑 About the consuming **project**, and forbidden in the default mode.
     *
     * §8.4.12's `build_context_mode: project_bound` is the opt-in that admits
     * them, and it "forfeits cross-project reuse" — which the dashboard must
     * state when it is selected. That mode arrives with the rest of the §8.4
     * contract in Phase 09; Phase 06 implements `agnostic` only, which means
     * these variables are **withheld**, not given an empty value.
     *
     * Withheld rather than emptied on purpose: `conf.py` files branch on
     * `os.environ.get("READTHEDOCS_PROJECT")`, and an empty string is a value
     * that passes a truthiness check in some languages and fails it in
     * others. Absent is unambiguous.
     */
    case Project = 'project';

    /** May this scope enter a build container in the default `agnostic` mode? */
    public function permittedInAgnosticMode(): bool
    {
        return $this !== self::Project;
    }

    /** Does a variable in this scope contribute to the §8.7.9 content key? */
    public function entersContentKey(): bool
    {
        // Installation values never vary; component values are already in the
        // key via commit_sha and the config digest. Neither adds anything.
        return false;
    }
}
