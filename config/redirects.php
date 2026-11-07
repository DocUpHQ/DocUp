<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

/*
|------------------------------------------------------------------------------
| Redirects (SPEC 8.11.2 – 8.11.4)
|------------------------------------------------------------------------------
| 🛑 SPEC 8.11.4 contains regular-expression rules with six controls, and five
| of them are constants in `App\Redirects\RegexGuard` rather than settings:
| the 255-byte cap, the nested-quantifier linter, the compile check, the
| backtrack limit and the per-request evaluation cap of 20. They are not
| configurable because the requirement is explicit that the cap must be
| "a **fixed deterministic** per-request evaluation cap" — a number an
| operator could raise under pressure is not fixed, and one that differs
| between replicas is not deterministic.
|
| The sixth control, the kill switch, is here.
*/

return [

    /*
     * SPEC 8.11.4's "installation-wide kill switch".
     *
     * 🛑 Defaults **on**, which is the one control in this area that does
     * not default closed — and deliberately. SPEC 20.4's invariant is that
     * no **security control** sits behind a flag that defaults open; this
     * switch is the opposite shape. Turning it off removes a feature, not a
     * protection: an installation that disables regex rules still has the
     * other five controls applied to the rules it no longer runs.
     *
     * It exists for the operator who has decided that no amount of
     * containment makes an operator-supplied regular expression on the
     * serving path worth having. That is a defensible position and this is
     * how they take it, without a fork.
     *
     * 🛑 An existing regex rule is **not deleted** when this is off — it is
     * skipped. Deleting would make the switch destructive and one-way; the
     * rules come back when it is turned on, and `docup:doctor` reports how
     * many are dormant.
     */
    'regex_enabled' => env('DOCUP_REDIRECT_REGEX', true),

];
