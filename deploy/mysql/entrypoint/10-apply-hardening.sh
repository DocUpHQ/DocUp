#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# Apply SPEC 8.22.1's hardening at first database initialisation.
#
# 🛑 **Why a wrapper, and not the `.sql` files mounted directly.** They were,
# and it could never have worked: the MySQL image runs
# `/docker-entrypoint-initdb.d` while the schema is EMPTY — before anything has
# migrated — and both scripts name tables that do not exist yet. MySQL accepts
# a table-level GRANT on a missing table only when the privilege list includes
# `CREATE`, so
#
#     GRANT SELECT, INSERT, CREATE, ALTER, DROP ON `audit_events` …   -- accepted
#     GRANT SELECT, DELETE                      ON `audit_anchors` …  -- ERROR 1146
#
# and the `mysql` client aborts a batch on the first error, so nothing after
# that line ever ran. Measured on 8.4.11 and 8.4.13 alike.
#
# 🛑 What changed in 8.4.13 is the consequence, not the error: the image's
# entrypoint now **fails the container** when an init script exits non-zero, so
# a long-latent defect — SPEC 8.22.1's triggers silently never installed on a
# fresh volume — became `container docup-db-1 is unhealthy` and took the CI
# edge-driver job with it. Found by Phase 16's pull request, present since
# Phase 02.
#
# So: `--force`, which reports every error and keeps going. The grant and the
# triggers that need migrated tables still cannot be applied here, and nothing
# pretends otherwise — `docup:doctor` FAILS until they are, naming the script,
# which is the signal SPEC 8.22.1 already relies on for an existing
# installation. The difference is that the stack now starts, and the operator
# is told what is missing rather than left with a database that will not boot.
#
# Apply them for real once the schema exists:
#
#     mysql -u root -p docup < deploy/mysql/init/10-audit-append-only.sql
#
# The files are mounted read-only at /opt/docup/mysql so that the directory the
# image auto-runs holds only this wrapper. They are otherwise unchanged: the
# script an operator runs by hand is byte-for-byte the script CI applies and
# tests/Feature/AuditAppendOnlyTest.php asserts against.
#
# 🛑 No `set -e`, no `set -u` and no `exit`. The image runs a non-executable
# `.sh` in this directory by **sourcing** it (`. "$f"`), so any of the three
# would act on the entrypoint's own shell — and an `exit` there aborts
# initialisation, which is the failure this file exists to remove. It is
# committed with the executable bit set and is written to be safe either way.

for docup_script in /opt/docup/mysql/*.sql; do
    [ -f "$docup_script" ] || continue

    printf 'docup: applying %s (errors below are expected before migration)\n' "$docup_script"

    # --protocol=socket, because at this point the server is the entrypoint's
    # temporary instance with no TCP port. --force so a statement naming a
    # table that does not exist yet reports and does not abort the rest.
    MYSQL_PWD="${MYSQL_ROOT_PASSWORD:-}" mysql \
        --force --protocol=socket -u root "${MYSQL_DATABASE:-}" \
        < "$docup_script" || true
done

unset docup_script
