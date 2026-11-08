#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# ------------------------------------------------------------------------------
# Build the fixture directory from nothing, every start.
# ------------------------------------------------------------------------------
#
# 🛑 Deterministic by construction. `slapd`'s own postinst derives the suffix
# from the container's hostname and keeps a database across restarts; a fixture
# that did that would differ between the first run and every later one, and the
# §17 exit criterion it serves removes a group member — so the next run has to
# start from a directory where that member is back.
#
# 🛑 The config database is assembled in four pieces, and the ORDER is the whole
# of what makes it work. Each one was measured by watching `slapadd` refuse:
#
#  1. `cn=config` itself, carrying the TLS material — which must be in the
#     config before slapd starts, because `olcTLSCertificateFile` is read at
#     start-up and a later `ldapmodify` would leave the first handshake
#     unprotected.
#  2. the MODULES, before any database entry. `back_mdb` is a module in
#     Debian's slapd, not a built-in: without it `olcDbIndex` is an undefined
#     attribute type and the database entry is refused with a message that
#     names the attribute and never the cause.
#  3. the SCHEMA, as Debian's own `cn=schema,cn=config` LDIF files concatenated
#     verbatim. 🛑 **Not an `include:` directive** — that is slapd.conf syntax,
#     and `slapadd` reading it as an LDIF attribute accepts the line and loads
#     nothing, so the first entry needing `inetOrgPerson` fails instead.
#  4. the DATABASES and the overlay, which depend on all three above.

set -euo pipefail

SUFFIX="${LDAP_SUFFIX:-dc=docup,dc=test}"
ADMIN_DN="cn=admin,${SUFFIX}"
ADMIN_PASSWORD="${LDAP_ADMIN_PASSWORD:?LDAP_ADMIN_PASSWORD is required}"
CERT='/opt/docup/tls/openldap.crt'
KEY='/opt/docup/tls/openldap.key'
CONFIG_LDIF='/tmp/config.ldif'

log() { printf 'openldap: %s\n' "$1"; }
fail() { printf 'openldap: FAIL %s\n' "$1" >&2; exit 1; }

[ -r "$CERT" ] || fail "no certificate at $CERT; run deploy/ldap-test-setup.sh before the stack"
[ -r "$KEY" ] || fail "no key at $KEY; run deploy/ldap-test-setup.sh before the stack"

# ----------------------------------------------------------------- 1. config

# 🛑 `slappasswd` rather than the plaintext in the LDIF. Not because the
# fixture's password is a secret — it is in a committed file — but because
# `olcRootPW` in cleartext makes slapd log a warning on every start, and a
# warning that is always there is a warning nobody reads.
HASH="$(slappasswd -s "$ADMIN_PASSWORD")"

rm -rf /etc/ldap/slapd.d/* /var/lib/ldap/*

# 🛑 The ldapi:/// socket's directory, which the Dockerfile's `rm -rf` of
# the package state takes with it. Without it slapd prints
# "slap_open_listener: failed on ldapi:///" and exits 1 AFTER this script has
# already logged that the directory was built — so the container looks like
# it started and the only symptom is an exit code.
mkdir -p /var/run/slapd
chown openldap:openldap /var/run/slapd

# 🛑 Every heredoc below is UNQUOTED, because the variables have to expand.
# That also makes them places where backticks run commands and `$` is live, so
# the comments inside them carry no backticks. Measured the hard way: slapd
# reported "never: command not found" from a word inside an LDIF comment.
cat >"$CONFIG_LDIF" <<CONFIG
dn: cn=config
objectClass: olcGlobal
cn: config
olcLogLevel: none
#
# The TLS material, in force for the first handshake. 8.12.18's "certificate
# verification" is the CLIENT's half; this is the half that gives it something
# to verify.
olcTLSCertificateFile: ${CERT}
olcTLSCertificateKeyFile: ${KEY}
#
# never - the SERVER does not ask the client for a certificate. DocUp
# authenticates with a simple bind over the TLS channel, and a fixture that
# demanded mutual TLS would be testing 8.12.4's mtls driver, which has its own
# tests, while making this requirement unreachable.
olcTLSVerifyClient: never
#
# DELIBERATELY PERMISSIVE, and the only setting here that is.
#
# bind_anon_dn allows a simple bind carrying a DN and an EMPTY password,
# which RFC 4511 4.2 defines as an anonymous bind. slapd refuses it by
# default; Active Directory and several others accept it, and that is the
# condition LdapConnection::verifyPassword() guards against - without the
# guard a reader who submits no password authenticates as nobody and DocUp
# reads it as success.
#
# So the fixture turns it ON, because a directory that refused it would make
# the guard's test pass over a risk that was not there. The test asserts both
# halves: that DocUp refuses the empty password, and that this directory
# would have accepted it.
olcAllows: bind_anon_dn

dn: cn=module{0},cn=config
objectClass: olcModuleList
cn: module{0}
olcModulePath: /usr/lib/ldap
#
# back_mdb FIRST. It is a module in Debian's slapd, and without it the
# olcDbIndex lines below are an undefined attribute type.
olcModuleLoad: back_mdb.la
#
# And memberof, WITHOUT WHICH THIS FIXTURE PROVES NOTHING.
#
# The driver reads groups as an attribute of the USER entry - whichever
# attribute the operator names - because that is the shape Active Directory and
# every directory imitating it present. A groupOfNames tree on its own carries
# membership the other way round, as member DNs on the GROUP, so a user entry
# would come back with no groups at all and 17's exit criterion would pass over
# an empty set in both directions. The overlay maintains memberOf on the user
# as the group's member list changes, which is what makes one ldapmodify a
# group removal the next bind can see.
olcModuleLoad: memberof.la

dn: cn=schema,cn=config
objectClass: olcSchemaConfig
cn: schema
CONFIG

# 🛑 Four schema files and no more: core and cosine for the basics,
# inetorgperson for `uid`, `cn` and `userPassword`, nis for `posixAccount`. A
# fixture that loaded everything would be taking a position on schema it does
# not need, and a missing file is a hard failure rather than a directory that
# refuses its own seed later.
for schema in core cosine inetorgperson nis; do
  [ -r "/etc/ldap/schema/${schema}.ldif" ] || fail "missing schema: ${schema}.ldif"
  printf '\n' >>"$CONFIG_LDIF"
  cat "/etc/ldap/schema/${schema}.ldif" >>"$CONFIG_LDIF"
done

cat >>"$CONFIG_LDIF" <<DATABASES

dn: olcDatabase={0}config,cn=config
objectClass: olcDatabaseConfig
olcDatabase: {0}config
olcRootDN: cn=admin,cn=config
olcRootPW: ${HASH}

dn: olcDatabase={1}mdb,cn=config
objectClass: olcDatabaseConfig
objectClass: olcMdbConfig
olcDatabase: {1}mdb
olcDbDirectory: /var/lib/ldap
olcSuffix: ${SUFFIX}
olcRootDN: ${ADMIN_DN}
olcRootPW: ${HASH}
olcDbIndex: objectClass eq
olcDbIndex: uid eq
olcDbIndex: cn eq
olcDbIndex: member eq
olcDbIndex: memberOf eq
#
# An ACL that lets the service account search, and nobody read a password.
#
# "by anonymous auth" on userPassword is what makes a simple bind work while
# keeping the hash unreadable - and it is the directory's half of why
# LdapConnection::verifyPassword() binds as the reader rather than comparing a
# hash it fetched. A fixture that let the service account read passwords would
# let a wrong implementation pass.
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by * none
olcAccess: {1}to * by dn.exact="${ADMIN_DN}" write by users read by * none

dn: olcOverlay={0}memberof,olcDatabase={1}mdb,cn=config
objectClass: olcOverlayConfig
objectClass: olcMemberOf
olcOverlay: {0}memberof
olcMemberOfRefInt: TRUE
DATABASES

slapadd -F /etc/ldap/slapd.d -b cn=config -l "$CONFIG_LDIF" \
  || fail 'slapadd could not build the config database (its own message is above)'

# ------------------------------------------------------------------- 2. data

# Loaded offline rather than over the wire, so the server is never up with an
# empty directory — which a healthcheck would see as ready.
slapadd -F /etc/ldap/slapd.d -b "$SUFFIX" -l /opt/docup/seed.ldif \
  || fail 'slapadd could not load the seed (its own message is above)'

chown -R openldap:openldap /etc/ldap/slapd.d /var/lib/ldap
rm -f "$CONFIG_LDIF"

# --------------------------------------------------------- 3. the groups

# 🛑 Over the wire, and `deploy/openldap/groups.ldif` says why at length:
# the memberof overlay reacts to writes it SEES, and `slapadd` writes with no
# server in the path -- so groups seeded offline leave every user entry with
# no `memberOf` at all. Measured: the directory answered a search for dana
# with `uid` and `cn` and nothing else.
#
# A short-lived slapd on the LOCAL SOCKET only. Not the real listeners: a
# server answering 389 while its groups are half-loaded is a server a
# healthcheck can see, and the first run would be the flaky one.
slapd -h ldapi:/// -u openldap -g openldap -F /etc/ldap/slapd.d

for _ in $(seq 1 50); do
  ldapwhoami -x -H ldapi:/// >/dev/null 2>&1 && break
  sleep 0.1
done

ldapadd -x -H ldapi:/// -D "$ADMIN_DN" -w "$ADMIN_PASSWORD" -f /opt/docup/groups.ldif \
  || fail 'ldapadd could not load the groups (its own message is above)'

# 🛑 Proved, not assumed. The overlay is the one piece of this fixture
# whose absence makes the group tests pass over an empty set rather than
# fail, so the fixture refuses to start without it.
ldapsearch -x -H ldapi:/// -D "$ADMIN_DN" -w "$ADMIN_PASSWORD" \
  -b "$SUFFIX" "(uid=dana)" memberOf 2>/dev/null | grep -q "^memberOf:" \
  || fail 'the memberof overlay did not populate memberOf; the group tests would prove nothing'

# Stopped before the real server starts, and WAITED FOR: two slapd processes
# on one database is a corrupted database.
pkill -x slapd || true
for _ in $(seq 1 50); do
  pgrep -x slapd >/dev/null 2>&1 || break
  sleep 0.1
done

log "built ${SUFFIX} with StartTLS on 389"

# ----------------------------------------------------------------- 4. slapd

# 🛑 `exec`, so slapd is the process compose signals. Without it the shell
# stays PID 1, `docker compose down` reaches the shell and slapd is killed by
# the timeout instead of shutting down — which corrupts nothing here, but
# teaches a wrong habit in a file somebody will copy.
#
# `ldap:///` only. No `ldaps:///`, for the reason Dockerfile.openldap gives.
exec slapd -h 'ldap:/// ldapi:///' -u openldap -g openldap -F /etc/ldap/slapd.d -d 0
