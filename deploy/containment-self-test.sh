#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# 🛑 SPEC 8.12.22's containment proof, as the thing that actually fetches.
#
#   "The system MUST ship automated proof of its own containment: a boot-time
#    **and** CI check that fetches a known-private asset through the real edge
#    with no credentials and **fails on any 200**."
#
# This is that check. It runs at start-up and in CI against both edge drivers,
# and it is a shell script rather than PHP for a reason worth stating: SPEC
# 8.3.9 routes every outbound request from the application through the one
# HardenedEgressClient, which denies private and loopback addresses by design —
# every address the edge has. Letting PHP curl the edge would mean adding a
# second entry to an allowlist whose own architecture test says that an
# allowlist growing by one legitimate case per phase stops being a gate.
#
# So the application plans and records (`docup:containment`) and this fetches.
#
# 🛑 TWO halves, and the second is what Phase 22 adds to Phase 21's.
#
#   positive: the asset, with NO credentials  -> must not be 200
#   negative: the same asset, WITH a session  -> must be 200
#
# Without the negative control a probe cannot tell containment from an outage.
# An installation whose documentation host is misconfigured refuses
# *everything*, and the positive half passes on it forever — so the refusal
# proves nothing until something proves the asset was reachable at all.
#
# The negative half needs a reader session, which only exists once SPEC 8.12.10's
# handoff has run, so it is OPTIONAL here: pass a session handle in
# DOCUP_CONTAINMENT_SESSION and it is exercised. A production boot has none, and
# the positive half alone is still SPEC 8.12.22's own sentence.
#
# 🛑 The handle MUST be a session for the asset the plan chose — the application
# picks what to probe (the oldest non-public published project), not the caller,
# so a handle for some other project is refused and reported as a failed
# control. That is correct rather than inconvenient: a session that does not
# open the probed asset is indistinguishable from one that cannot.
#
# CI therefore runs the two halves in two places: deploy/verify-edge.sh carries
# both against its own seeded fixture, where plan and session are the same
# project by construction, and this script runs the positive half against
# whatever the installation actually holds.
#
# Usage:
#   deploy/containment-self-test.sh                  # uses https://<host>
#   DOCUP_CONTAINMENT_SCHEME=http  ...               # a laptop without TLS
#   DOCUP_CONTAINMENT_BASE=http://127.0.0.1:8080 ... # a fixed edge address,
#                                                    # Host header from the plan
#   ARTISAN="docker compose exec -T app php artisan" ...

set -eu

ARTISAN="${ARTISAN:-php artisan}"
SCHEME="${DOCUP_CONTAINMENT_SCHEME:-https}"
CURL_OPTS="${DOCUP_CONTAINMENT_CURL_OPTS:--sS -o /dev/null -k --max-time 10}"

fail() { printf 'containment: FAIL %s\n' "$1" >&2; }
pass() { printf 'containment: ok   %s\n' "$1"; }

# ---------------------------------------------------------------- the plan
PLAN="$($ARTISAN docup:containment --plan 2>/dev/null | tr -d '\r')"

field() { printf '%s\n' "$PLAN" | sed -n "s/^$1=//p"; }

STATE="$(field state)"

if [ "$STATE" = "not_applicable" ]; then
    # 🛑 Not a pass and not a failure. An installation serving only public
    # documentation has no known-private asset, and saying so is honest where
    # claiming a pass would be a green light nobody earned.
    pass 'nothing private is published; SPEC 8.12.22 has nothing to probe'
    exit 0
fi

HOST="$(field host)"
PATH_UNDER_TEST="$(field path)"

if [ -z "$HOST" ] || [ -z "$PATH_UNDER_TEST" ]; then
    fail 'the application printed no usable plan'
    printf '%s\n' "$PLAN" >&2
    exit 1
fi

# 🛑 The Host header is always the planned host, even when the request goes to
# a fixed address. SPEC 8.9.4 resolves a project from the host and the path and
# from nothing else, so probing an IP without the Host header would exercise
# SPEC 8.9.3's unknown-host 404 and pass for entirely the wrong reason.
if [ -n "${DOCUP_CONTAINMENT_BASE:-}" ]; then
    URL="${DOCUP_CONTAINMENT_BASE}${PATH_UNDER_TEST}"
    HOST_HEADER="-H Host:${HOST}"
else
    URL="${SCHEME}://${HOST}${PATH_UNDER_TEST}"
    HOST_HEADER=""
fi

printf 'containment: probing %s (host %s)\n' "$URL" "$HOST"

# ------------------------------------------- the positive half: no credentials
# shellcheck disable=SC2086
STATUS="$(curl $CURL_OPTS $HOST_HEADER -w '%{http_code}' "$URL" || printf '000')"

if [ "$STATUS" = "000" ]; then
    # Unreachable is a failure, not a skip. SPEC 8.12.22 is proof of
    # containment; an unreachable edge proves nothing and must not look green.
    fail "the edge was unreachable at ${URL}"
    $ARTISAN docup:containment --record --status=0 --host="$HOST" >/dev/null 2>&1 || true
    exit 1
fi

# ------------------------------------------ the negative half: with a session
NEGATIVE_ARG=""

if [ -n "${DOCUP_CONTAINMENT_SESSION:-}" ]; then
    # shellcheck disable=SC2086
    CREDENTIALLED="$(curl $CURL_OPTS $HOST_HEADER \
        -H "Cookie: __Host-docup_rsess=${DOCUP_CONTAINMENT_SESSION}" \
        -w '%{http_code}' "$URL" || printf '000')"

    printf 'containment: credentialed read answered %s\n' "$CREDENTIALLED"
    NEGATIVE_ARG="--negative=${CREDENTIALLED}"
else
    printf 'containment: no DOCUP_CONTAINMENT_SESSION; the negative control is skipped\n'
fi

# 🛑 The verdict is the APPLICATION's, not this script's. `docup:containment
# --record` holds SPEC 8.12.22's rule ("fails on any 200") and exits non-zero
# on a failure, so there is one place that decides and this script's exit
# status is that decision.
# shellcheck disable=SC2086
if $ARTISAN docup:containment --record --status="$STATUS" --host="$HOST" $NEGATIVE_ARG; then
    pass "SPEC 8.12.22: anonymous request for a known-private asset answered ${STATUS}"
    exit 0
fi

fail "SPEC 8.12.22: containment is not proven (anonymous status ${STATUS})"
exit 1
