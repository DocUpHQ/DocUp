<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Artifacts;

/**
 * What happened to one HTML document at ingest (§8.15.3, §8.15.4).
 *
 * 🛑 Five outcomes, and the distinction between "skipped" and "refused" is the
 * one §8.15.3 insists on: "The **warning** MUST exclude *navigational stubs* — a
 * document with no `<head>` element whose body is only a meta-refresh or a
 * `location=` assignment, which is what Antora emits at a site root and which no
 * reader ever sees. They stay in the audit record but must not raise a warning,
 * or every Antora site warns on every build forever and operators learn to
 * ignore injection warnings (ADR 0002)."
 *
 * An operator who has learned to ignore a warning is worse off than one who
 * never saw it, so the taxonomy exists to keep the warning meaningful.
 */
enum InjectionOutcome: string
{
    /** The two tags were inserted before the first `</head>`. */
    case Injected = 'injected';

    /**
     * A navigational stub: no `<head>`, body is only a redirect.
     *
     * Recorded, never warned about. ADR 0002 measured 51 of 52 files injected
     * across seven generators, and the single miss was exactly this.
     */
    case SkippedStub = 'skipped_stub';

    /** §8.15.4: no `</head>` element at all, and not a stub. */
    case RefusedNoHead = 'refused_no_head';

    /**
     * §8.15.4: not valid UTF-8.
     *
     * 🛑 "Non-UTF-8 is **refused rather than injected** even though inserting
     * ASCII bytes would appear to work, because the document's own charset
     * declaration cannot be trusted without parsing and a mis-declared charset
     * is an XSS vector." Inserting ASCII into a Shift-JIS document produces
     * bytes that a browser guessing the encoding may read as something else
     * entirely.
     */
    case RefusedNonUtf8 = 'refused_non_utf8';

    /** §8.15.4: over the configured byte ceiling. */
    case RefusedTooLarge = 'refused_too_large';

    /**
     * Whether this outcome contributes to the per-project warning (§8.15.3).
     *
     * Asked of the outcome rather than decided at the call site, so an outcome
     * added later cannot default to silence.
     */
    public function raisesWarning(): bool
    {
        return match ($this) {
            self::Injected, self::SkippedStub => false,
            self::RefusedNoHead, self::RefusedNonUtf8, self::RefusedTooLarge => true,
        };
    }

    /**
     * Whether this outcome forces §8.15.4's `api_only` fallback for the build.
     *
     * §8.15.4: "An artifact that cannot be injected MUST fall back to
     * `chrome_mode: api_only` for that build." A stub does not force it — the
     * document carries no chrome because no reader ever sees it, not because
     * injection failed.
     */
    public function forcesApiOnly(): bool
    {
        return $this->raisesWarning();
    }
}
