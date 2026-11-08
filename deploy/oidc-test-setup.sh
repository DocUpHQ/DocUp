#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# ------------------------------------------------------------------------------
# Give the OIDC integration suite a Keycloak it can reach over TLS.
# ------------------------------------------------------------------------------
#
# §17's Phase 24 exit criterion needs a real provider, and §8.12.18's own rules
# mean that provider has to speak HTTPS: `OidcDriver::validate()` refuses an
# issuer that is not an absolute `https` URL, and `EgressOptions` allows no
# other scheme on the wire. Neither is relaxed for a test — a gate that is
# turned off to make an integration pass is a gate that is not there.
#
# So Keycloak gets a certificate, and the application is taught to trust it.
# The same two-step `deploy/tls-test-setup.sh` performs for Pebble, and the
# comment there is worth reading for why neither step reaches for `-k`.
#
# 🛑 ONE certificate here, not two. Pebble needed both its own server
# certificate and its issuance root, because it signs things. Keycloak signs
# nothing in this stack: it presents a server certificate and that is all, so a
# self-signed certificate IS its own trust anchor.
#
# Run BEFORE the stack comes up — the certificate is a bind mount, so Keycloak
# needs it to exist at start-up:
#
#   bash deploy/oidc-test-setup.sh
#   docker compose -f compose.yaml -f compose.oidc.yaml up -d
#   bash deploy/oidc-test-setup.sh --trust    # after the app is running
#
# Idempotent: an existing, still-valid certificate is left alone, so repeated
# runs do not invalidate a trust store the stack has already loaded.

set -euo pipefail

cd "$(dirname "$0")/.."

TLS_DIR="deploy/keycloak-tls"
CRT="$TLS_DIR/keycloak.crt"
KEY="$TLS_DIR/keycloak.key"

COMPOSE="${DOCUP_COMPOSE:-docker compose -f compose.yaml -f compose.oidc.yaml}"

log() { printf 'oidc-setup: %s\n' "$1"; }
fail() { printf 'oidc-setup: FAIL %s\n' "$1" >&2; exit 1; }

# ------------------------------------------------------------------ certificate

generate() {
  mkdir -p "$TLS_DIR"

  if [ -f "$CRT" ] && [ -f "$KEY" ]; then
    # 🛑 `-checkend` against a month rather than against now. A certificate that
    # expires mid-run would fail with a TLS error naming neither the expiry nor
    # this script, which is a bad afternoon.
    if openssl x509 -in "$CRT" -noout -checkend 2592000 >/dev/null 2>&1; then
      log "certificate is present and valid for at least 30 days"
      return 0
    fi

    log 'certificate is missing or near expiry; regenerating'
  fi

  # 🛑 `keycloak` is the name DocUp resolves it by — the compose network alias,
  # and the host in KC_HOSTNAME and in both issuers. A certificate for anything
  # else would fail verification with CURLOPT_SSL_VERIFYPEER still on, which is
  # exactly what it should do.
  #
  # `localhost` is in the SAN list too, because the test driver reaches Keycloak
  # through the published port from the host side.
  # 🛑 `MSYS_NO_PATHCONV=1` for Git Bash on Windows, where a leading-slash
  # argument is rewritten as a path: `-subj /CN=keycloak` arrives as
  # `C:/Program Files/Git/CN=keycloak` and openssl refuses it with a message
  # about name format that never mentions paths. Harmless everywhere else — an
  # unused variable on Linux, which is where CI runs this.
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CRT" -days 365 \
    -subj '/CN=keycloak' \
    -addext 'subjectAltName=DNS:keycloak,DNS:localhost,IP:127.0.0.1' \
    >/dev/null 2>&1 || fail 'openssl could not generate a certificate'

  # Keycloak runs as uid 1000 and reads these read-only; world-readable is
  # correct for a fixture key that exists only in a working copy.
  chmod 0644 "$KEY" "$CRT"

  log "generated a self-signed certificate for keycloak (365 days)"

  # 🛑 Said out loud, because a key in a working copy is a key somebody could
  # commit. .gitignore's construction section excludes this directory.
  log 'NOTE: deploy/keycloak-tls/ holds a private key and is git-ignored'
}

# ----------------------------------------------------------------------- trust

trust() {
  $COMPOSE ps --status running --services 2>/dev/null | grep -qx app \
    || fail 'the app container is not running; bring the stack up first'

  [ -f "$CRT" ] || fail "no certificate at $CRT; run this script without --trust first"

  # The application container's CA bundle. Debian layout, which is what the
  # image is built on.
  $COMPOSE cp "$CRT" app:/usr/local/share/ca-certificates/docup-keycloak-test.crt \
    || fail 'could not copy the certificate into the app container'

  $COMPOSE exec -T -u root app update-ca-certificates >/dev/null 2>&1 \
    || fail 'update-ca-certificates failed in the app container'

  # 🛑 Proved rather than assumed, and through the application's own egress
  # client — not with curl. §8.3.9 routes every outbound request through one
  # `HardenedEgressClient` with `CURLOPT_SSL_VERIFYPEER` on, so the only check
  # worth making is whether *that* client can reach the discovery document. A
  # curl from the shell would verify a different trust store.
  local probe
  probe="$(
    $COMPOSE exec -T app php artisan docup:auth:probe --json 2>&1 || true
  )"

  log 'trusted the certificate in the app container'

  if printf '%s' "$probe" | grep -q 'no bindings to probe'; then
    log 'no oidc binding is configured yet, so the probe had nothing to reach'
    return 0
  fi

  if printf '%s' "$probe" | grep -q '"passed": *true'; then
    log 'ok   an oidc binding probed cleanly through the hardened egress client'
    return 0
  fi

  printf '%s\n' "$probe" >&2
  fail 'an oidc binding failed its probe after the certificate was trusted'
}

case "${1:-}" in
  --trust) trust ;;
  '') generate ;;
  *) fail "unknown argument: $1" ;;
esac
