Added: `synapse storage inspect <file> [--against <file>]`, read-only counts of a mailbox file

Prints a `.redb` or `.sqlite` mailbox file's sequence, role count (retired ones apart), rooms, acked history, queued messages and, per queue, leased count and oldest enqueue time (a `dead:<role>` queue is a role's dead letters). With `--against`, it lists roles and epochs that differ, queued message ids on one side only, and acked-history counts. Never a message body. For a home that holds both `mailbox.redb` and `mailbox.sqlite` with no `mailbox.sqlite.migrated` marker: it shows what each holds before the operator chooses which to keep (the daemon refuses to start there and never merges). Inspect a COPY: opening a redb file creates its tables, and the running daemon holds the live one locked.

— lane: synapse
