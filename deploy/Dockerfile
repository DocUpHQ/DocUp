# SPDX-FileCopyrightText: 2026 The DocUp contributors
# SPDX-License-Identifier: Apache-2.0
#
# The DocUp application image (SPEC 8.1.12: published OCI images with a
# documented environment contract and stateless-app guarantees).
#
# FrankenPHP because caddy-intercept is the default edge driver (SPEC 11.3,
# ADR 0001): the application authorises and the edge moves the artifact bytes,
# and Caddy preserves the application's response headers through that handoff
# natively where nginx replaces the whole set.

FROM dunglas/frankenphp:latest

# PHP 8.4.1 is the floor (SPEC 11.1, ADR 0007): Dom\HTMLDocument is a
# language-level requirement of the SPEC 8.16.3 section extractor and is absent
# in 8.3, symfony/process 8.1.9 requires >=8.4.1, and Pest 5 requires >=8.4.
# The base image currently ships 8.5.x, which satisfies the floor.

# `install-php-extensions` ships in the FrankenPHP image.
#
# Each extension is here because something in the specification needs it, and
# nothing is here speculatively - an unused extension is attack surface:
#   pdo_mysql  MySQL 8.4 is the datastore (SPEC 11.1)
#   intl       locale-aware comparison and IDNA for SPEC 8.10.7 hostnames
#   zip        artifact ingestion (SPEC 8.8.2) and offline formats (SPEC 8.4.5)
#   gd         server-side raster re-encoding to strip metadata (SPEC 8.14.11)
#   bcmath     arbitrary-precision arithmetic for quota accounting
#   sodium     Ed25519 grant tokens (SPEC 8.12.11)
#   pcntl      queue workers and the build runner (SPEC 8.5.13)
#   opcache    production throughput
#   redis      Valkey is mandatory (SPEC 11.1)
#   pcov       coverage measurement (SPEC 8.9.1, SPEC 9.4)
RUN install-php-extensions \
        pdo_mysql \
        intl \
        zip \
        gd \
        bcmath \
        sodium \
        pcntl \
        opcache \
        redis \
        pcov \
    && rm -rf /var/lib/apt/lists/*

# 🛑 pcov is INSTALLED and DISABLED (SPEC 8.9.1, SPEC 9.4).
#
# SPEC 8.9.1 requires the resolver to sustain >=95% branch coverage and >=80%
# mutation score, and neither can be claimed without a coverage driver. Phase 04
# could not measure its own exit criterion until this line existed.
#
# Disabled by default because it is instrumentation: it costs nothing when off,
# and it must not be on for a normal test run or a production boot. Pest enables
# it per run with --coverage.
#
# pcov rather than Xdebug on purpose: far faster, and enough for line coverage.
# 🛑 It does NOT measure BRANCH coverage, which is what SPEC 8.9.1 asks for —
# that needs Xdebug. The gap is recorded in the build log rather than papered
# over by reporting line coverage as though it were branch coverage.
RUN echo "pcov.enabled=0" > /usr/local/etc/php/conf.d/20-pcov.ini


# 🛑 SPEC 8.12.16: Laravel's ArgonHasher default is m=1024 KiB, roughly 19x
# below the OWASP floor. config/hashing.php overrides it; this ensures the
# extension that implements it is actually present, because a missing argon2
# would silently fall back to bcrypt.
RUN php -r 'exit(defined("PASSWORD_ARGON2ID") ? 0 : 1);' \
    || (echo "argon2id unavailable in this PHP build" && exit 1)

WORKDIR /app

# Composer is used at build time for a release image and is intentionally not
# left in the runtime image.
COPY --from=composer:2 /usr/bin/composer /usr/local/bin/composer

# The storage and cache directories must be writable; everything else is
# read-only in production, which keeps a compromised request handler from
# rewriting application code.
RUN mkdir -p /var/lib/docup/artifacts \
    && chown -R www-data:www-data /var/lib/docup

ENV SERVER_NAME=":80"
