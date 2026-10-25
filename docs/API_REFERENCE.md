# Synapse API reference (daemon, CLI and MCP surface)

**Scope.** This page documents the surface that runs and is tested at 6.0.0-rc.57: the `synapse` command, the `synapsed`
loopback HTTP API, and the MCP adapters. The former library reference (router, transports, streaming, WebRTC and WASM storage,
identity resolution; about 1,200 lines) was removed in rc.57 because most of its method names no longer exist
(`python .github/docs_staleness.py` measured 73 of 86 unknown names). It is in git: `git show 6125f31:docs/API_REFERENCE.md`.

## CLI: `synapse` (crate `synapsectl`)

| command | what it does |
|---|---|
| `synapse id init --account <name>` | create the account key (`<name>`: letters, digits, `-`, `_`, 1 to 64); refuses if one exists |
| `synapse id init-role --account <name> --role <role>` | in a home WITHOUT the account key (a sandbox): make the role's keys there and print their public halves (`signing-pub`, `sealing-pub`) |
| `synapse id issue --role <role> --signing-pub <hex> --sealing-pub <hex> [--days 8]` | with the account key: certify those public keys (1 to 30 days; send, ack, request-ack) and print the certificate |
| `synapse id install-cert --role <role>` | in the role-only home: store the certificate from stdin after checking it certifies this home's keys. Never renews: when it expires, ask for a re-issue |
| `synapse id show [--role <role>]` | show the account, and with `--role` that role's identity (creates its keys on first use) |
| `synapse claim --role <role>` | take the role on the daemon (starts `synapsed` on demand; takes it over if another holder has it) |
| `synapse send --role <role> --to <to> [MESSAGE]` | send (`MESSAGE`, else stdin); `<to>` is `<role>` or `<role>@<account>`; `--id` for an idempotent resend |
| `synapse inbox --role <role>` | fetch waiting messages, one JSON object per line; each stays leased until acked |
| `synapse ack --role <role> <message_id>` | acknowledge, removing it from the inbox |
| `synapse dead --role <role>` | the role's dead set (messages set aside after `max_deliveries` leases), one JSON object per line |
| `synapse requeue --role <role> <message_id>` | puts a dead message back in the inbox with its delivery count reset |
| `synapse stats --role <role>` | per-role `sent`, `acked`, `redelivered`, `expired` since the daemon started, with `scope` and `since`, one JSON object per line |
| `synapse list --role <role>` | every role the daemon knows, with presence and pending counts, one JSON object per line |
| `synapse retire\|revive --role <caller> <target>` | needs `role-admin`: retire a role now (hidden from `list`, epoch and mail kept) or bring it back |
| `synapse id grant --role <role> <state-read-all\|state-admin\|state-derive\|role-admin>` / `ungrant` | with the account key: give or take back an extra grant (shared state, or `role-admin`); it reaches the role's certificate when that is next made |
| `synapse state new --role <role> --title <t> --party <p>... --owner <o> [--state s] [--notes n] [--verify FACT,OP,VALUE]... [--blocked-on T-n\|FACT,OP,VALUE]...` | create a shared-state record (you must be a party); prints it as JSON |
| `synapse state show\|history --role <role> <T-n>` | one record, or its hash-chained history one entry per line |
| `synapse state list --role <role> [--state a,b] [--party p]` | the records you may see, one JSON object per line |
| `synapse state check --role <checker> [--once] [--interval 300] [--github-token-env NAME] [--crates-url U] [--github-url U]` | the checker: asks the daemon which facts open records name, looks each up (crates.io `max_version`; GitHub PR state, ref SHA, check runs, file blob SHA), and reports what it saw. Needs `state-derive` (`synapse id grant --role <checker> state-derive`). A failed lookup is reported as failed, never as absent. The GitHub token is read from the environment variable on every request and is sent only over HTTPS or to loopback, never to crates.io |
| `synapse state set --role <role> <T-n> --rev <n> [--title ..] [--owner ..] [--state ..] [--notes ..] [--party ..]... [--verify ..]... [--blocked-on ..]...` | change a record if it is still at `--rev`; a stale `--rev` changes nothing (`stale_revision`) |

Environment: `SYNAPSE_HOME` (keystore, sessions, mailbox; default `%LOCALAPPDATA%\synapse` on Windows, else
`$XDG_DATA_HOME/synapse` or `~/.local/share/synapse`), `SYNAPSE_ADDR` (daemon address, default `127.0.0.1:7920`, loopback
only), `SYNAPSE_ROLE` (the `--role` default). Owner-only files: a home, account directory, key, session or announce file that
others can read is refused. When the daemon will not start, the error carries its last stderr lines and the home path.

## Daemon: `synapsed` loopback HTTP, `/v1`

Bound to a loopback address only (it refuses any other). Bodies are JSON and **deny unknown fields** (an older daemon answers
400 to a field it does not know). `claim` authenticates by a signed claim; every other call except `health` needs
`Authorization: Bearer <token>` from the claim (401 otherwise). Failed bearers and claims are rate-limited and recorded in
`<home>/security-events.jsonl`. Clients should use `synapsed-client` or the CLI rather than hand-roll the claim.

| route | method | body fields | notes |
|---|---|---|---|
| `/v1/health` | GET | none | proves the instance with an HMAC over a client challenge; not a liveness-only ping |
| `/v1/claim` | POST | `audience?`, `chain_pem`, `nonce_hex`, `signed_at`, `signature_b64` | role claim; a failed claim is counted and answered after a delay |
| `/v1/send` | POST | `to`, `message_id?`, `body_b64` | `queued` or `duplicate`; stored id is `<sender>/<client id>` (client id at most 100 bytes). 404 `unknown_recipient` for a role that never claimed or a bare name (the CLI and MCP tool qualify a bare name with the sender's account first); 410 `recipient_retired` for a retired role, nothing queued (mail queued before the retirement is kept) |
| `/v1/fetch` | POST | `max?`, `lease_secs?`, `exclude?` | `max` defaults to 10, clamped to 100; `exclude` at most 100 ids of at most 256 bytes: passed over, not leased |
| `/v1/ack` | POST | `message_id` | `removed` or `already_acked` |
| `/v1/dead` | GET | none | the caller's dead set, oldest first: `message_id`, `from`, `body_b64`, `enqueued_at`, `attempts`; changes nothing |
| `/v1/requeue` | POST | `message_id` | `requeued`: a dead message back in the queue with its delivery count reset; `404` if it is not dead, `mailbox_full` (it stays dead) if the queue is full |
| `/v1/heartbeat` | POST | `summary?` | presence; `summary` at most 500 bytes |
| `/v1/list` | GET | none | roles with `online` (heard from within 90 s), `summary`, `pending`, `retired_at`; a role idle for 30 days is retired and left out unless `?include_retired=true` |
| `/v1/stats` | GET | none | per-role cumulative counters since this daemon started (a restart begins again from zero); the CLI reader is `synapse stats` |
| `/v1/state/create` | POST | `title`, `parties`, `owner`, `state?`, `blocked_on?`, `verify?`, `notes?` | shared state (`state.redb`); needs `state-write` and the caller a party; answers `{record}` with id `T-<n>` |
| `/v1/state/get`, `/v1/state/history` | GET | `?id=T-<n>` | a record, or its hash-chained history; a record the caller may not see answers `404` (`get`) or `403` (`history`) |
| (mail from `daemon:state@<account>`) | | | every state write queues one message per other party, body `{"kind":"state","id","revision","changed_by","fields"}`: ids and field names only, never a title or note; message id `state:<id>:<revision>:<role>` so a crash cannot double it. Read the content with `/v1/state/get` |
| `/v1/state/facts` | POST | `reports: [{fact, look}]` | the checker reports what it looked up (`look`: `{"found": v}`, `"absent"` or `{"failed": text}`); needs `state-derive`, which no other grant substitutes; a `fact` outside the registry is `400`. A failed look is never read as absent |
| `/v1/roles/retire`, `/v1/roles/revive` | POST | `{"role": "<name>"}` | `role-admin` only: 403 without it, 404 for a role that never claimed; retiring twice succeeds |
| `/v1/state/wanted` | GET | none | the distinct facts named by records that are not done or cancelled; `state-derive` only |
| `/v1/state/list` | GET | `?state=a,b&party=p` | the records the caller may see: its own, or all with `state-read-all` / `state-admin` |
| `/v1/state/patch` | POST | `id`, `expected_revision`, `patch` | compare-and-set; `409 stale_revision` changes nothing and carries `current` (the revision) and `record`; `403` is recorded as a `state_denied` security event |

Delivery is at-least-once: a fetched message is leased and comes back if not acked before the lease ends. A message leased `max_deliveries` times (default 10) without an ack moves to the role's **dead set**: bounded and visible, never silently dropped. It keeps its body, `from`, attempts and enqueue time for the retention period; `list`'s `pending.dead` counts it; a resend of its id is a duplicate; the receiver's `ack` discards it. `GET /v1/dead` reads the set and `POST /v1/requeue` replays one message; the CLI is `synapse dead` and `synapse requeue <message_id>`. (Library: `Mailbox::dead_letters`, `Mailbox::requeue_dead`.)

## MCP adapters

### Generic adapter: `synapse-mcp` (crate `synapse-mcp-server`)

`synapse-mcp --role <role> [--home <dir>]` is an MCP stdio server that acts as one role on this machine's
`synapsed` (it starts the daemon if none answers, and claims the role once if this home has no session for it).
It replaces the old UDP adapter and its TOML config (rc.24, breaking).

| tool | arguments | result |
|---|---|---|
| `send` | `to` (role or `role@account`), `body` (UTF-8), `message_id?` | `message_id`, `outcome` (`queued` or `duplicate`) |
| `fetch` | `max?`, `lease_secs?` | `messages`: `message_id`, `from`, `body` (UTF-8 bodies), `body_b64`, `lease_until`, `attempts` |
| `ack` | `message_id` | `outcome` (`removed` or `already_acked`) |
| `list` | none | `roles`: `online`, `summary`, `pending` (`null` = unknown) |
| `set_summary` | `summary` (500 bytes, no control characters) | empty |
| `whoami` | none | `role`, `global_id`, `epoch`, `daemon_instance`, `push` (`{capability_key, method}` on the Claude Code channel adapter; `null` on the generic adapter, which only answers `fetch`) |

Text from other agents (bodies, summaries) is **untrusted**: the tool descriptions say so, control
characters are escaped, and an authenticated `from` does not make a body safe to act on. A superseded session is
a tool error (`superseded ... run synapse claim`); the adapter never re-claims. Without `--role` and
`SYNAPSE_ROLE` it exits with status 2.

### Claude Code channel adapter: `synapse-claude-channel`

The same six tools, plus mailbox messages pushed into the session as untrusted channel events
(`notifications/claude/channel`, capability `claude/channel` declared at `initialize`). `whoami` reports the push method under
`push`, so a client that bound its handlers before `initialize` can learn it without reconnecting. This renderer uses
bounded attempts: a pushed message that is not acked comes back, up to a bound. (A generic renderer defaults to receiver-only:
it stops pushing after a bound and leaves the message pending for `fetch`.)
