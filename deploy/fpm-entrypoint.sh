#!/bin/sh
# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# Make the bind-mounted tree writable by the user php-fpm actually runs as.
#
# 🛑 php-fpm drops privileges to www-data, and the source tree is bind-mounted
# from the host, so the writable directories arrive owned by whoever owns the
# checkout — root on a Docker Desktop 9p mount, the runner's uid in CI. Neither
# is www-data.
#
# The primary image never meets this because FrankenPHP serves as root; a SAPI
# that drops privileges has to be told where it may write. It is fixed at start
# rather than at build time because the mount replaces whatever the image did
# to /app.
#
# The symptom is worth naming, because it is not where anyone would look: the
# first request 500s with `UnexpectedValueException` from Monolog's
# StreamHandler saying laravel.log "could not be opened in append mode". That
# reads as a logging misconfiguration and is really mount ownership — nothing in
# the message mentions the mount, the uid, or the SAPI.

set -eu

# The two trees Laravel writes, and only those: a `chown -R` across the whole
# mount is slow over 9p and would rewrite the ownership of the developer's own
# checkout on the host.
#
# 🛑 `storage` whole, not a list of its subdirectories. The first version of
# this enumerated storage/{app,framework/*,logs} and got a SECOND 500 from
# Inertia DevTools creating storage/inertia-devtools — a directory no list would
# have predicted, because any package may write under storage and several do.
# The writable unit here is the tree, and naming its members just moves the
# failure to whichever member gets added next.
for dir in storage bootstrap/cache; do
    mkdir -p "/app/${dir}"
    chown -R www-data:www-data "/app/${dir}" 2>/dev/null || true
done

# 🛑 Verified, not assumed. A chown that failed silently reappears later as the
# Monolog 500 above, and the whole value of doing this here is that the failure
# names the real cause at start-up instead of on the first request.
if ! su -s /bin/sh www-data -c 'test -w /app/storage/logs && test -w /app/bootstrap/cache'; then
    echo "docup: /app/storage is not writable by www-data." >&2
    echo "docup: php-fpm would 500 on its first log write. Refusing to start." >&2
    exit 1
fi

exec "$@"
