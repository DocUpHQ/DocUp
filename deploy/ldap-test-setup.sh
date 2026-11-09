#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# ------------------------------------------------------------------------------
# Give the LDAP integration suite a directory it can reach over StartTLS.
# ------------------------------------------------------------------------------
#
# §17's Phase 26b exit criterion needs a real directory, and §8.12.18's own
# rules mean that directory has to speak TLS: `LdapConnection::open()` sets
# `LDAP_OPT_X_TLS_REQUIRE_CERT` to `LDAP_OPT_X_TLS_HARD` before the handshake
# and **refuses** an `ldap://` URI whose StartTLS fails, rather than falling
# through to cleartext. Neither is relaxed for a test — a gate turned off to
# make an integration pass is a gate that is not there.
#
# So slapd gets a certificate, and the application is taught to trust it. The
# same two-step `deploy/oidc-test-setup.sh` performs for Keycloak; read that
# file's comment for why neither step reaches for an insecure option.
#
# 🛑 **Where libldap looks for trust anchors, measured rather than assumed.**
# `/etc/ldap/ldap.conf` in the application image carries NO `TLS_CACERT` — every
# line is commented out. OpenLDAP's OpenSSL backend falls back to
# `SSL_CTX_set_default_verify_paths()` when neither `TLS_CACERT` nor
# `TLS_CACERTDIR` is set, which is the system bundle at `/etc/ssl/certs` — so
# `update-ca-certificates` is enough and no `ldap.conf` edit is needed. That
# fallback is what `--trust` proves below, through DocUp's own driver rather
# than with `ldapsearch`: a CLI would read the same store but not the same
# code path, and the thing under test is the code path.
#
# Run BEFORE the stack comes up — the certificate is a bind mount, so slapd
# needs it to exist at start-up:
#
#   bash deploy/ldap-test-setup.sh
#   docker compose -f compose.yaml -f compose.ldap.yaml up -d --build
#   bash deploy/ldap-test-setup.sh --trust    # after the app is running
#
# Idempotent: an existing, still-valid certificate is left alone, so repeated
# runs do not invalidate a trust store the stack has already loaded.

set -euo pipefail

cd "$(dirname "$0")/.."

TLS_DIR='deploy/openldap-tls'
CRT="$TLS_DIR/openldap.crt"
KEY="$TLS_DIR/openldap.key"

COMPOSE="${DOCUP_COMPOSE:-docker compose -f compose.yaml -f compose.ldap.yaml}"

log() { printf 'ldap-setup: %s\n' "$1"; }
fail() { printf 'ldap-setup: FAIL %s\n' "$1" >&2; exit 1; }

# ------------------------------------------------------------------ certificate

generate() {
  mkdir -p "$TLS_DIR"

  if [ -f "$CRT" ] && [ -f "$KEY" ]; then
    # 🛑 `-checkend` against a month rather than against now, for the reason
    # the OIDC script gives: a certificate expiring mid-run fails with a TLS
    # error naming neither the expiry nor this script.
    if openssl x509 -in "$CRT" -noout -checkend 2592000 >/dev/null 2>&1; then
      log 'certificate is present and valid for at least 30 days'
      return 0
    fi

    log 'certificate is missing or near expiry; regenerating'
  fi

  # 🛑 `openldap` is the name DocUp resolves it by — the compose network alias
  # and the host in the binding's `uri`. `LDAP_OPT_X_TLS_HARD` requires a
  # matching name as well as a valid chain, so a certificate for anything else
  # fails verification, which is exactly what it should do.
  #
  # 🛑 `MSYS_NO_PATHCONV=1` for Git Bash on Windows, where `-subj /CN=openldap`
  # arrives as a rewritten path and openssl refuses it with a message that
  # never mentions paths. Harmless on Linux, which is where CI runs this.
  MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$KEY" -out "$CRT" -days 365 \
    -subj '/CN=openldap' \
    -addext 'subjectAltName=DNS:openldap,DNS:localhost,IP:127.0.0.1' \
    >/dev/null 2>&1 || fail 'openssl could not generate a certificate'

  # 🛑 slapd drops to the `openldap` user and reads the KEY, so it has to be
  # readable by a uid this script cannot know. World-readable is correct for a
  # fixture key that exists only in a working copy — and `0640` with a guessed
  # group is the version of this line that fails on somebody else's machine.
  chmod 0644 "$CRT"
  chmod 0644 "$KEY"

  log 'generated a self-signed certificate for openldap (365 days)'

  # 🛑 Said out loud, because a key in a working copy is a key somebody could
  # commit. .gitignore's construction section excludes this directory.
  log 'NOTE: deploy/openldap-tls/ holds a private key and is git-ignored'
}

# ----------------------------------------------------------------------- trust

trust() {
  $COMPOSE ps --status running --services 2>/dev/null | grep -qx app \
    || fail 'the app container is not running; bring the stack up first'

  [ -f "$CRT" ] || fail "no certificate at $CRT; run this script without --trust first"

  # The application container's CA bundle. Debian layout, which is what the
  # image is built on.
  $COMPOSE cp "$CRT" app:/usr/local/share/ca-certificates/docup-openldap-test.crt \
    || fail 'could not copy the certificate into the app container'

  $COMPOSE exec -T -u root app update-ca-certificates >/dev/null 2>&1 \
    || fail 'update-ca-certificates failed in the app container'

  log 'trusted the certificate in the app container'

  # 🛑 Proved through DocUp's own connection class, with every §8.12.18 option
  # in force, rather than with `ldapsearch`. The question is not "is the
  # certificate valid" — openssl could answer that — but "does the code that
  # refuses an unverifiable directory accept this one", and only this code path
  # answers it.
  local probe
  probe="$(
    $COMPOSE exec -T app php -r '
      require "/app/vendor/autoload.php";
      $app = require "/app/bootstrap/app.php";
      $app->make(Illuminate\Contracts\Console\Kernel::class)->bootstrap();
      try {
          App\Auth\Providers\Ldap\LdapConnection::open(
              "ldap://openldap:389",
              "cn=svc-docup,dc=docup,dc=test",
              getenv("DOCUP_LDAP_BIND_PASSWORD") ?: "",
          )->close();
          echo "STARTTLS_OK";
      } catch (Throwable $e) {
          echo "STARTTLS_FAIL: ", $e->getMessage();
      }
    ' 2>&1 || true
  )"

  if printf '%s' "$probe" | grep -q 'STARTTLS_OK'; then
    log 'ok   StartTLS verified through LdapConnection with LDAP_OPT_X_TLS_HARD set'
    return 0
  fi

  printf '%s\n' "$probe" >&2
  fail 'LdapConnection could not verify the directory after the certificate was trusted'
}

case "${1:-}" in
  --trust) trust ;;
  '') generate ;;
  *) fail "unknown argument: $1" ;;
esac
