<?php

// SPDX-FileCopyrightText: 2026 The DocUp contributors
// SPDX-License-Identifier: Apache-2.0

declare(strict_types=1);

namespace App\Http\Controllers;

use App\Access\BreakGlass;
use App\Access\BreakGlassRefused;
use App\Auth\ApiTokens;
use App\Models\BreakGlassGrant;
use App\Models\Project;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

/**
 * 🛑 §8.12.20's break-glass read override, opened and closed.
 *
 * ## 🛑 This controller enforces nothing
 *
 * Every one of §8.12.20's preconditions — installation owner, MFA enrolled,
 * step-up within five minutes, a reason of substance, three an hour — lives in
 * {@see BreakGlass}, and this class only turns a refusal into a response. The
 * route additionally carries `stepup`, which is defence in depth and better
 * UX: the middleware redirects to the confirmation page, where the service can
 * only refuse.
 *
 * The reason that split matters is the one {@see ApiTokens} gives for
 * minting: a second activation path — a command, a job, a future API
 * controller — would be a second place to forget a precondition. There is
 * nothing to forget here.
 *
 * 🛑 **A POST and not a GET**, even though the override only ever *reads*
 * documentation. It writes a grant, raises an alert and consumes one of three
 * hourly activations, so it is a mutation by every measure that matters — and a
 * GET would make it reachable from a link, which is the one shape this
 * particular button must never have.
 */
final class BreakGlassController extends Controller
{
    public function __construct(private readonly BreakGlass $breakGlass) {}

    /** Open a window on one project. */
    public function store(Request $request, Project $project): JsonResponse|RedirectResponse
    {
        $actor = Auth::user();

        if (! $actor instanceof User) {
            abort(403);
        }

        /*
         * 🛑 Validated for shape only — a string, present, within the column.
         * Whether it is a *reason* is {@see BreakGlass}'s judgement, because
         * "mandatory" in §8.12.20 means more than "not empty" and the rule
         * belongs beside the audit record it justifies rather than in a
         * validator a second endpoint would not share.
         */
        $validated = $request->validate([
            'reason' => ['required', 'string', 'max:'.BreakGlass::MAX_REASON],
        ]);

        $reason = is_string($validated['reason'] ?? null) ? $validated['reason'] : '';

        try {
            $grant = $this->breakGlass->open($actor, $project, $reason);
        } catch (BreakGlassRefused $refused) {
            /*
             * 🛑 The refusal is **shown**, which is the opposite of every
             * reader-facing refusal in this system. §8.12.23's silence protects
             * a reader from learning that a private resource exists; this
             * person is an installation owner who already knows, and who needs
             * to be told which precondition they have not met. Being vague here
             * would produce an owner clicking the button repeatedly during an
             * incident, which is also how the rate limit gets spent.
             */
            if ($request->expectsJson()) {
                return response()->json([
                    'message' => $refused->getMessage(),
                    'reason' => $refused->rejection->value,
                ], 422);
            }

            return back()->withErrors(['reason' => $refused->getMessage()]);
        }

        if ($request->expectsJson()) {
            return response()->json([
                'grant' => bin2hex($grant->id),
                'expires_at' => $grant->expires_at->toIso8601String(),
                'window_minutes' => BreakGlass::WINDOW_MINUTES,
            ], 201);
        }

        return back()->with('status', 'break-glass-opened');
    }

    /**
     * Close a window early.
     *
     * 🛑 No step-up and no preconditions, deliberately. Closing an override
     * **narrows** access, and a control that is harder to turn off than on is a
     * control nobody turns off — the asymmetry is the same one §8.12.19 applies
     * to a degraded binding's UI, where there is no "make public" button.
     *
     * Any installation owner may close any window, not only the one who opened
     * it: §8.12.20's alert goes to the role precisely so that somebody other
     * than the actor can act on it, and an alert you cannot act on is a
     * notification.
     */
    public function destroy(Request $request, BreakGlassGrant $grant): JsonResponse|RedirectResponse
    {
        $actor = Auth::user();

        if (! $actor instanceof User) {
            abort(403);
        }

        $this->breakGlass->close($grant, $actor);

        if ($request->expectsJson()) {
            return response()->json(['closed' => true]);
        }

        return back()->with('status', 'break-glass-closed');
    }
}
