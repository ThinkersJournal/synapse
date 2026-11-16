Added: `synapsectl waiting` and `synapsectl launch-result` (ROADMAP row 49, cutover spec section 7 item 3)

Thin CLIs over the existing `GET /v1/waiting` and `POST /v1/launch-result` routes and their client methods, for operators and for the launcher's tests. `waiting [--wait N]` prints the daemon's JSON reply; `launch-result <target> --signal-id --epoch --attempt --outcome [--reason]` answers one signal (outcome: started, already-running, refused, failed). Only the configured launcher role may call either; a signal no longer open answers `stale_signal`. With `launch-clear` (#369) the whole launcher surface is on the CLI.

— lane: synapse
