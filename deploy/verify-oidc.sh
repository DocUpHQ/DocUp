#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# ------------------------------------------------------------------------------
# §17's Phase 24 exit criterion, against a real Keycloak.
# ------------------------------------------------------------------------------
#
# > "Two projects on one installation authenticate readers against two different
# > Keycloak realms in one browser session."
#
# 🛑 **This script is the browser.** `tests/Feature/Oidc` drives the same flow
# against a stubbed transport and proves everything that is DocUp's; what it
# cannot prove is that a real provider agrees. So this plays the reader's part
# end to end: it follows every redirect, submits Keycloak's own login form, and
# carries cookies the way a browser would.
#
# A shell script rather than a test, for the reason `containment-self-test.sh`
# is one: §8.3.9 routes every outbound request from the application through one
# `HardenedEgressClient` that denies private and loopback addresses — every
# address this stack listens on. Letting PHP drive the browser's half would mean
# adding an entry to an allowlist whose own architecture test says an allowlist
# growing by one legitimate case per phase stops being a gate.
#
# 🛑 **One cookie jar for the whole run**, which is what "in one browser
# session" means and where the interesting failures live: a `__Host-` cookie set
# by one flow and clobbered by the other, a verifier lost on the second sign-in,
# a session on one origin honoured on another.
#
# Usage:
#   bash deploy/oidc-test-setup.sh
#   docker compose -f compose.yaml -f compose.oidc.yaml up -d
#   docker compose ... exec app php artisan docup:oidc:fixture   # seeds projects
#   bash deploy/verify-oidc.sh
#
# Environment:
#   DOCUP_OIDC_EDGE   where the DocUp edge answers (default http://127.0.0.1:8080)
#   DOCUP_OIDC_KC     where Keycloak answers on the host (default 127.0.0.1:8444)

set -euo pipefail

cd "$(dirname "$0")/.."

# The edge's published TLS address. HTTPS, because §12.4's cookies are
# `Secure` and curl keeps a `Secure` cookie only for an https URL.
EDGE="${DOCUP_OIDC_EDGE:-http://127.0.0.1:8080}"
KC_HOST_PORT="${DOCUP_OIDC_KC:-127.0.0.1:8444}"
CA="deploy/keycloak-tls/keycloak.crt"

# 🛑 `--connect-to`, not `--resolve`. Keycloak's issuer — and therefore every
# URL it emits — names `keycloak:8443`, which is its address *inside* the compose
# network. On the host it is published elsewhere, and `--connect-to` is the one
# option that redirects the connection while leaving SNI, the `Host` header and
# certificate verification pointed at the original name. `--resolve` keeps the
# port, and `-k` would be teaching this script to skip the verification the
# thing under test depends on.
KC_CONNECT=(--connect-to "keycloak:8443:${KC_HOST_PORT}" --cacert "$CA")

WORK="$(mktemp -d -t docup-oidc.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

PASSES=0
FAILURES=0

pass() { printf '  \033[32mok\033[0m   %s\n' "$1"; PASSES=$((PASSES + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1" >&2; FAILURES=$((FAILURES + 1)); }
note() { printf '       %s\n' "$1"; }

# ---------------------------------------------------------------- one hop

# 🛑 The cookie jar, **implemented here rather than delegated to curl**.
#
# Two reasons, and the first is forced:
#
# 1. **The development edge serves no usable TLS on the host.** The shipped
#    compose file publishes the app's 443 but the proxy that terminates TLS has
#    no published port, so every hop from the host is plain HTTP — and curl
#    stores a `Secure` cookie only for an `https` URL. §12.4 marks every reader
#    cookie `Secure`, so curl's jar silently kept none of them: the state cookie
#    never came back and the handoff answered `409 cookiesBlocked`, which is the
#    application correctly reporting a browser that discards cookies. It was
#    right; the driver was wrong.
#
# 2. **Per-origin scoping is the thing under test.** §12.4 gives every cookie the
#    `__Host-` prefix and no `Domain`, so a browser scopes each to exactly the
#    origin that set it — and "two realms in one browser session" is a question
#    about whether those scopes stay separate. Implementing the rule explicitly
#    is better than relying on a library's defaults for the one behaviour the
#    criterion is about. The fixture test learned the same lesson from the other
#    side, with a host-blind jar that failed a correct product.
#
# So: one entry per (origin, name), sent only to that origin, and an empty value
# deletes — which is how §12.4's cookies are cleared.
declare -A COOKIES

remember_cookies() {
    local host="$1" line name value

    while IFS= read -r line; do
        line="${line%$'\r'}"

        case "$line" in
            [Ss]et-[Cc]ookie:*) : ;;
            *) continue ;;
        esac

        # `name=value` up to the first `;`, which is all a jar needs: the
        # attributes that matter here are modelled by this function's own
        # policy rather than parsed.
        line="${line#*: }"
        name="${line%%=*}"
        value="${line#*=}"
        value="${value%%;*}"

        if [ -z "$value" ]; then
            unset "COOKIES[${host}|${name}]"
        else
            COOKIES["${host}|${name}"]="$value"
        fi
    done < "$WORK/headers"
}

cookie_header() {
    local host="$1" key pairs=''

    for key in "${!COOKIES[@]}"; do
        case "$key" in
            "${host}|"*) pairs="${pairs}${pairs:+; }${key#*|}=${COOKIES[$key]}" ;;
        esac
    done

    printf '%s' "$pairs"
}

# Fetch an absolute URL, routing DocUp's own hosts through the edge.
#
# 🛑 DocUp's hosts are `*.localhost` names that do not resolve, so each hop is
# re-issued against the published edge with an explicit `Host:` header — the
# technique `deploy/verify-edge.sh` uses. Keycloak is reached by its own name
# over TLS, with its certificate verified: §8.12.18's exchange is the thing
# under test, and a script that skipped verification there would be teaching
# itself the habit the requirement exists to prevent.
#
# Writes the response headers to $WORK/headers and the body to $WORK/body.
hop() {
    local url="$1" method="${2:-GET}" data="${3:-}"
    local host path cookies

    host="$(printf '%s' "$url" | sed -E 's#^https?://([^/]+).*#\1#')"
    path="$(printf '%s' "$url" | sed -E 's#^https?://[^/]+##')"
    [ -n "$path" ] || path='/'

    cookies="$(cookie_header "$host")"

    local -a args=(-sS -o "$WORK/body" -D "$WORK/headers" --max-time 30)

    [ -z "$cookies" ] || args+=(-H "Cookie: ${cookies}")

    if [ "$method" = POST ]; then
        args+=(-X POST --data "$data" -H 'Content-Type: application/x-www-form-urlencoded')
    fi

    if [ "$host" = "keycloak:8443" ]; then
        curl "${args[@]}" "${KC_CONNECT[@]}" "$url" || true
    else
        # 🛑 `X-Forwarded-Proto: https`, because the reader's half of this flow
        # is https in every real deployment and §12.4's cookies are `Secure`.
        # The edge is reached over plain HTTP from the host (see above), so
        # without this the application would be right to decline to set them.
        curl "${args[@]}" \
            -H "Host: ${host}" \
            -H 'X-Forwarded-Proto: https' \
            "${EDGE}${path}" || true
    fi

    remember_cookies "$host"
}

status() { sed -n '1s#^HTTP/[0-9.]* \([0-9]*\).*#\1#p' "$WORK/headers" | tail -1; }
location() { tr -d '\r' < "$WORK/headers" | sed -n 's/^[Ll]ocation: //p' | tail -1; }

# ------------------------------------------------------------- the flow

# Sign a reader in at one realm and read that realm's private page.
sign_in() {
    local realm="$1" docs_host="$2" user="$3" password="$4"

    note "realm ${realm}: starting at https://${docs_host}/en/v1/"

    # 1. The documentation origin's start leg.
    hop "https://${docs_host}/_/auth/start?return=%2Fen%2Fv1%2F"

    [ "$(status)" = 302 ] || { fail "${realm}: /_/auth/start answered $(status), not 302"; return 1; }

    local next
    next="$(location)"

    case "$next" in
        */_/auth/oidc/start*) : ;;
        *) fail "${realm}: a guarded project did not route to the OIDC leg (${next})"; return 1 ;;
    esac

    # 2. The dashboard's start leg, which redirects to Keycloak.
    hop "$next"

    [ "$(status)" = 302 ] || { fail "${realm}: the OIDC start leg answered $(status)"; return 1; }

    local authorise
    authorise="$(location)"

    case "$authorise" in
        "https://keycloak:8443/realms/${realm}/protocol/openid-connect/auth"*) : ;;
        *) fail "${realm}: expected a Keycloak authorisation URL, got ${authorise}"; return 1 ;;
    esac

    # 🛑 The parameters §8.12.18 makes mandatory, asserted on what DocUp
    # actually sent rather than on what it intended to send.
    printf '%s' "$authorise" | grep -q 'code_challenge_method=S256' \
        || { fail "${realm}: the authorisation request carries no S256 challenge"; return 1; }
    printf '%s' "$authorise" | grep -q 'response_type=code' \
        || { fail "${realm}: the authorisation request is not the code flow"; return 1; }
    printf '%s' "$authorise" | grep -qv 'scope=[^&]*email' \
        || { fail "${realm}: the authorisation request asks for email (§8.12.1)"; return 1; }

    pass "${realm}: DocUp sent a code+S256 request to the right realm"

    # 3. Keycloak's login page.
    hop "$authorise"

    [ "$(status)" = 200 ] || { fail "${realm}: Keycloak's login page answered $(status)"; return 1; }

    # The form's action carries the session code. Extracted rather than
    # constructed, because it is Keycloak's to choose.
    local action
    action="$(
        tr -d '\n' < "$WORK/body" \
            | sed -E 's#.*<form[^>]*action="([^"]*login-actions/authenticate[^"]*)".*#\1#' \
            | sed 's/&amp;/\&/g'
    )"

    case "$action" in
        https://keycloak:8443/*) : ;;
        *) fail "${realm}: could not find Keycloak's login form"; return 1 ;;
    esac

    # 4. Submit the credentials.
    hop "$action" POST "username=${user}&password=${password}&credentialId="

    local callback
    callback="$(location)"

    if [ "$(status)" != 302 ]; then
        # 🛑 ADR 0008's recorded trap, reported by name. "Keycloak 26 enables a
        # Verify Profile required action by default, and a user without
        # firstName/lastName is intercepted at login-actions/required-action
        # BEFORE the code is issued. That presents almost identically to a
        # redirect_uri rejection and produced a false FAIL on the first run."
        if grep -q 'required-action\|Update Account Information' "$WORK/body"; then
            fail "${realm}: Keycloak interrupted with a required action — see ADR 0008; the realm fixture's user needs a complete profile"
        else
            fail "${realm}: the login POST answered $(status), not a redirect to the callback"
        fi

        return 1
    fi

    case "$callback" in
        "https://docup.localhost/_/auth/oidc/callback?"*) : ;;
        *) fail "${realm}: Keycloak redirected to ${callback}, not DocUp's one fixed callback"; return 1 ;;
    esac

    # 🛑 ADR 0008's measurement, re-made: one registered `redirect_uri` served a
    # reader who began on this documentation host. The assertion is that the
    # callback is the **dashboard's**, not this realm's project's host.
    pass "${realm}: one fixed redirect_uri served a reader from ${docs_host}"

    # 5. DocUp's callback: verify, provision, mint a handoff code.
    hop "$callback"

    [ "$(status)" = 302 ] || { fail "${realm}: the callback answered $(status); the token was refused"; return 1; }

    local handoff
    handoff="$(location)"

    case "$handoff" in
        "https://${docs_host}/_/auth/callback?code="*) : ;;
        *) fail "${realm}: the callback redirected to ${handoff}, not back to ${docs_host}"; return 1 ;;
    esac

    pass "${realm}: Keycloak's id_token passed §8.12.18's checks"

    # 6. The documentation origin redeems the handoff code.
    hop "$handoff"

    [ "$(status)" = 200 ] || { fail "${realm}: the handoff answered $(status)"; return 1; }

    # 7. And the private page reads.
    hop "https://${docs_host}/en/v1/"

    if [ "$(status)" = 200 ]; then
        pass "${realm}: the reader reads their own private version"
    else
        fail "${realm}: the private version answered $(status) after a successful sign-in"
        return 1
    fi

    return 0
}

# Assert a host is refused for this jar.
refuses() {
    local label="$1" docs_host="$2"

    hop "https://${docs_host}/en/v1/"

    if [ "$(status)" = 404 ]; then
        pass "$label"
    else
        fail "${label} — answered $(status), not 404"
    fi
}

# --------------------------------------------------------------------- run

printf '\nSPEC 17 Phase 24 — two Keycloak realms, one browser session\n'
printf 'edge=%s keycloak=%s\n\n' "$EDGE" "$KC_HOST_PORT"

[ -f "$CA" ] || { printf 'verify-oidc: FAIL no certificate at %s; run deploy/oidc-test-setup.sh\n' "$CA" >&2; exit 1; }

# 🛑 No apostrophe in either message, and that is not a style choice.
#
# The word in `${var:?word}` is parsed inside the braces, where a `'` opens a
# quoted section even though the whole expansion sits in double quotes. The
# first version read "the acme project's documentation host" and the quote ran
# on to the apostrophe on the NEXT line — so the second assignment was swallowed
# and `GLOBEX_HOST` was never set, which surfaced thirty lines later as an
# `unbound variable` at its first use. `bash -n` accepts it, because it is
# syntactically valid and semantically not what anybody meant.
ACME_HOST="${DOCUP_OIDC_HOST_ACME:?set DOCUP_OIDC_HOST_ACME to the acme documentation host}"
GLOBEX_HOST="${DOCUP_OIDC_HOST_GLOBEX:?set DOCUP_OIDC_HOST_GLOBEX to the globex documentation host}"

sign_in acme "$ACME_HOST" reader-at-acme acme-reader-password-for-tests-only || true

# 🛑 Before the second sign-in: realm A's reader must not read realm B's
# project. Two independent reasons it must fail — the session is per origin and
# the rule names a binding — and asserting it here, between the two sign-ins, is
# what makes it about isolation rather than about order.
refuses 'acme reader cannot read globex (before globex signs in)' "$GLOBEX_HOST"

sign_in globex "$GLOBEX_HOST" reader-at-globex globex-reader-password-for-tests-only || true

# 🛑 And the cross-talk assertion: realm A still reads after realm B signed in,
# in the same jar. A `__Host-` cookie clobbered by the second flow shows up here
# and only here.
hop "https://${ACME_HOST}/en/v1/"

if [ "$(status)" = 200 ]; then
    pass 'acme still reads after globex signed in, in one jar'
else
    fail "acme answered $(status) after globex signed in — the second sign-in broke the first"
fi

printf '\n  %d passed, %d failed\n\n' "$PASSES" "$FAILURES"

[ "$FAILURES" -eq 0 ] || exit 1
