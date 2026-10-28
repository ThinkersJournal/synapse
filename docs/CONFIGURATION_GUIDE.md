# Synapse configuration

**Scope.** What can be configured on the daemon-era surface (`synapsed`, `synapse`, `synapse-mcp`,
`synapse-claude-channel`) at 6.0.0-rc.99, read from `crates/synapsed/src/main.rs`, `src/keystore.rs`,
`src/mailbox.rs` and `docs/API_REFERENCE.md`. The former library configuration guide (builders, TLS and
cipher options, discovery settings; about 550 lines) was replaced in rc.100 because most of the types it
documented no longer exist (`python .github/docs_staleness.py` measured 112 of 113 method names unknown). It is
in git: `git show 519bd52:docs/CONFIGURATION_GUIDE.md`.

`synapsed` has **no configuration file and no command-line flags.** Everything below is an environment
variable or a compiled-in default.

## Environment

| variable | read by | meaning | default |
|---|---|---|---|
| `SYNAPSE_HOME` | `synapse`, `synapsed`, both adapters | the home: keystore, sessions, mailbox, security log | Windows `%LOCALAPPDATA%\synapse`; else `$XDG_DATA_HOME/synapse`; else `~/.local/share/synapse` |
| `SYNAPSE_ADDR` | `synapse`, `synapsed` | the daemon's address; **loopback only** (the daemon refuses any other) | `127.0.0.1:7920` |
| `SYNAPSE_ROLE` | `synapse`, both adapters | the default for `--role` | none; an adapter without `--role` or `SYNAPSE_ROLE` exits with status 2 |
| `SYNAPSE_LAUNCHER_ROLES` | `synapsed` | comma-separated roles allowed to read the launch signals (`GET /v1/waiting`); empty means lane launch on message is off | empty (off) |
| `SYNAPSE_LAUNCH_SENDERS` | `synapsed` | comma-separated authenticated senders (`role` for this account, or `role@account`) whose pending mail may raise a launch signal; **empty means no signal at all, even with launcher roles set**. Also `[launch] senders` in `synapsed.toml`, re-read every 5 s. `GET /v1/stats` shows `launch_senders_set` | empty (no signals) |
| `SYNAPSE_ALERT_ROLES` | `synapsed` | comma-separated roles that receive security alerts as mail from `daemon:alerts@<account>` (a threshold of 10 events in 5 minutes for one kind, surface and subject; digests of held alerts, at most one alert per kind and surface per 15 minutes). A role that has not claimed yet gets them when it does; a body is untrusted text like any other | empty (off: nothing changes) |

An unparsable `SYNAPSE_ADDR` or a bad role name in `SYNAPSE_LAUNCHER_ROLES` or `SYNAPSE_ALERT_ROLES` makes `synapsed` exit with
status 2 and say which. A port already in use also exits 2 (`cannot listen on <addr>`).

Names (accounts and roles) are 1 to 64 characters: letters, digits, `-` and `_`.

**The adapters' `--home` flag does not reach a daemon the adapter starts on demand**; set `SYNAPSE_HOME` in
the adapter's environment instead (for Claude Code, the `env` block of its `.mcp.json` entry; see
`docs/PILOT_T0_RUNBOOK.md` section 3a).

## `synapsed.toml` (since rc.161)

The four `synapsed` settings above can also be set in `<home>/synapsed.toml`; the environment wins over the file,
the file over the defaults. `SYNAPSE_HOME` is not in the file (the file lives in the home). Read through ConfigurAnt
0.2.34; the schema is `crates/synapsed/synapsed.schema.toml`.

```toml
[listen]
addr = "127.0.0.1:7920"      # SYNAPSE_ADDR
[launch]
roles = ["agentlife-launcher"] # SYNAPSE_LAUNCHER_ROLES
senders = ["agentlife"]        # SYNAPSE_LAUNCH_SENDERS
[alert]
roles = ["pm"]                 # SYNAPSE_ALERT_ROLES
[storage]
id = "sqlite"                  # SYNAPSE_MAILBOX_STORE (deprecated; prefer `synapse storage use`)
[liveness]
role_ttl_days = 30             # a role idle this long is retired; file only, at least 1
[session]
ttl_hours = 24                 # a session unused this long expires (401 session_expired); every call renews it; file only, at least 1
```

An unknown key, a file that does not parse, an address that is not one, or a bad role name makes `synapsed` exit 2
naming the key. An absent file changes nothing.

## Mailbox limits (compiled in)

`synapsed` opens its mailbox with `MailConfig::default()`; there is no runtime setting for any of these.
Changing one means changing the code.

| limit | value |
|---|---|
| default lease (`fetch` without `lease_secs`) | 60 s |
| shortest / longest lease accepted | 5 s / 15 min (a lease outside the range is refused) |
| acked history kept (and with it, dedupe of resends) | 7 days |
| queued messages per role | 10,000 |
| queued body bytes per role | 64 MiB |
| leases before a message goes to the dead set | 10 (`0` would mean no cap) |
| sweep of acked history | every hour |

A full queue refuses the send with `mailbox_full`; nothing is dropped.

## What is in the home

All of it owner-only: a home, account directory, key, session or announce file that others can read is
refused, and the refusal is recorded as `permissions_too_open`.

| file | what |
|---|---|
| `mailbox.redb` | the daemon's mailbox (queued, leased, acked, dead, role epochs) |
| `security-events.jsonl` | the daemon's security log: failed bearers and claims, over-budget requests, file refusals. Never carries a token, nonce or signature |
| `cli-security-events.jsonl` | the CLI's side of the same log |
| `synapsed.json` | the announce file; removed on a clean stop, and clients trust the health proof, not the file |
| `synapsed-start.err` | stderr of a daemon the CLI or an adapter started on demand |
| `account.key.pem`, `signing.key.pem`, `sealing.key.pem`, `cert.pem` | the account key, and the per-role signing key, sealing key and certificate, in the keystore directories |

Do not `curl` the daemon port without a session: an unauthenticated call writes a line to
`security-events.jsonl`.

## Cargo features (library users)

The library crate `synapse` builds with the default feature `native`. Two features matter to a consumer of the
mailbox: `mailbox-redb` (the durable `RedbStore`) and `mailbox-conformance` (off by default; exposes
`synapse::mailbox::conformance`, the cases any `MailStore` must pass). The daemon and CLI need none of this;
they are installed with `cargo install synapsed synapsectl synapse-claude-channel`.
