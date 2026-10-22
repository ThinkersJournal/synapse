# Choosing the mailbox store

The mailbox (every message a role has not yet acknowledged) lives in a store that PersistAnt provides.
Synapse names no backend: it states what the mailbox needs, PersistAnt lists the providers that meet
every need, and the operator picks one.

## See the choices

    synapse storage list

Prints each provider that meets the mailbox's needs, best first, with PersistAnt's reasons for the
ranking. A provider already recorded in this home is marked `(recorded)`. Nothing is changed.

## Record a choice

    synapse storage use sqlite-full                       # a file under the home (mailbox.<id>)
    synapse storage use sqlite-full --file mailbox.sqlite # keep an existing file's mail
    synapse storage use postgres --url-env SYNAPSE_DB_URL # a server

The choice is written to `<home>/mailbox-store.json` and taken at the daemon's **next start**. The id is
checked against the mailbox's needs first, and a mismatch is refused: a file store given `--url-env`, or a
server given no `--url-env`, is an error.

The daemon picks its store in this order: `SYNAPSE_MAILBOX_STORE` (deprecated; the daemon says so), the
recorded choice, on a fresh home the first *file* store PersistAnt lists (recorded, so the next start opens
the same one), else redb. A home that already holds `mailbox.redb` or `mailbox.sqlite` and records no
choice opens it as before.

## Server stores (PostgreSQL, MySQL, MariaDB)

`--url-env` names an **environment variable**; its value is the connection URL. The URL is read when the
store opens and is never written to the home, printed or logged, so only the variable name is recorded.

- **The variable must be set in the daemon's own environment.** A lane's environment does not reach a
  daemon started by the task scheduler: set it in the wrapper that starts `synapsed`, or the daemon
  refuses to start.
- **One daemon per database.** A server has no file to lock, so the daemon takes a lease in the database
  (key `<namespace>/lease`, 20 s time-to-live, renewed every 5 s, deleted on a clean stop). A second
  daemon on the same database exits 2 with `another process holds this mail store`. After a hard kill the
  lease lapses by itself, so a restart can be refused for up to 20 s; wait and retry. If the daemon cannot
  renew for 20 s it treats the lease as lost and fails writes rather than risk two writers.
- **A fresh database** is created on first open. Daemons opening an empty database at the same moment can
  hit PostgreSQL's catalog race (`unique violation (pg_type_typname_nsp_index)`); the open retries it,
  and exactly one daemon wins the lease.
- **Not covered:** TLS URLs, moving an existing store's mail onto a server, redb migration on this path
  (only the pinned `SYNAPSE_MAILBOX_STORE=sqlite` path migrates), and MariaDB in CI (PostgreSQL and MySQL
  run as hosted service containers; set `SYNAPSE_TEST_MYSQL_FLAVOR` to run the MySQL tests against
  MariaDB).

Switching stores never moves mail: the old store's file or database is left untouched.
