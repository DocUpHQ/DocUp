# Running it

## The services that must actually be running

| Service | What stops if it is not running |
|---|---|
| `worker` | builds never start; the queue grows silently |
| `scheduler` | the daily signed audit anchor and the retention purge never run |
| `runner` | builds are admitted and never execute |

The scheduler is easy to forget and expensive to forget: the audit chain's
daily anchor is what makes the log verifiable after the fact, and nothing
reports its absence except `docup:doctor`.

## The build sandbox

Every build runs in a container with no route to the database, no route to
another build, and egress only through an allowlisting proxy. The runner
refuses to start if the sandbox can reach the database — that check is a real
connection attempt from inside a sandbox, not a configuration read, because a
network policy that fails to apply looks exactly like one that works.

A build gets:

- a checkout performed by DocUp, with no repository code running during it,
  and the credential passed by file descriptor so it is never in an argument
  list or an environment variable;
- a fixed command template, so a repository's configuration contributes
  values and never argv;
- hard caps on time, memory, disk and log size.

🛑 **No project-scoped input reaches a build container** in the default mode:
no project environment variable, no secret, no branding value, no canonical
URL and no mount path. That is what lets three projects share one build of one
component, and it is enforced by an architecture test rather than by review.

## Backups

Back up three things, and they are independent:

1. **the database** — projects, versions, manifests, audit events. The
   manifest is the pointer; losing it loses which build was being served.
2. **the artifact store** — the built documentation itself. Write-once, so an
   incremental backup is cheap and a restored artifact is byte-identical.
3. **`.env`** — specifically `APP_KEY` and `DOCUP_AUDIT_KEY`. Envelope-
   encrypted secrets are unreadable without the first; the audit chain cannot
   be verified without the second.

Restoring the database without the artifact store gives you a site that
resolves every URL and serves nothing. Restoring the artifact store without
the database gives you bytes nobody can find.

## Retention

Build logs, audit events and swept artifacts each have their own retention,
and the purge runs from the scheduler. Audit events are purged by dropping a
partition rather than deleting rows, which is why the append-only trigger does
not get in its way.

Garbage collection is two-phase: a terminal build older than 24 hours is
marked, swept to a quarantine prefix, and deleted 14 days later. A **failed**
build skips both — it can never have been published, so the age floor and the
quarantine buy nothing.

## When DocUp is down

This manual builds with plain `mkdocs build` and no DocUp involved. That is
deliberate: a documentation portal whose own manual is only readable when the
portal is up has chosen the wrong failure mode.

```
mkdocs build -f mkdocs.yml
```

from the repository root produces the same three guides as one site.
