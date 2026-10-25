# Installing

The shipped stack is `docker compose`. It brings up the application, a MySQL
8.4 database, Valkey, a queue worker, a scheduler and the build runner.

```
cp .env.example .env
# set APP_KEY, DOCUP_AUDIT_KEY, and the two origins
docker compose up -d
docker compose exec app php artisan migrate --force
```

## The one manual step

!!! warning "The audit log is not append-only until you say so"

    Run this once, as a database administrator, **after** the first
    migration:

    ```
    docker compose exec -T -e MYSQL_PWD="$DB_ROOT_PASSWORD" db \
        mysql -u root docup < deploy/mysql/init/10-audit-append-only.sql
    ```

It cannot be done for you, and it cannot be done by the application. Both
available mechanisms need privileges the application must never hold:

- a table-level `REVOKE` needs a table-level `GRANT` to subtract from, and
  MySQL 8's partial revokes work at schema level, so "everything on `docup.*`
  except `UPDATE` on `audit_events`" cannot be expressed;
- `CREATE TRIGGER` requires `SUPER` while binary logging is enabled.

It also cannot run at first database initialisation, although the stack tries:
the image runs `/docker-entrypoint-initdb.d` against an empty schema, before
anything has migrated, so every statement naming `audit_events` or
`audit_anchors` fails there. The stack starts anyway — that is all the
entrypoint wrapper is for — and `docup:doctor` fails until you have run the
script yourself.

Be honest with yourself about what it buys: it stops `UPDATE` and `DELETE`,
which is how a log gets quietly rewritten. It does not stop `DROP TABLE`, and
whoever can drop the trigger can remove the protection. It is strictly
stronger than the application holding every privilege, and weaker than a grant
MySQL cannot express.

## `docup:doctor`

```
docker compose exec app php artisan docup:doctor
```

It checks the things that are wrong in a way nothing else notices: the two
origins, the audit hardening above, the queue and scheduler actually running,
the build sandbox's network isolation, and the edge driver's configuration. A
failure names the remedy rather than the symptom.

Run it after installing, after upgrading, and when something is strange.

## Upgrading

Migrations are forward-only and the application is safe to run while they
apply. Published documentation keeps serving throughout: an artifact is
immutable and a version manifest is a pointer, so an upgrade never rewrites
what a reader is reading.
