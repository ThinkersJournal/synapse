Added: `synapsectl launch-clear <target> --role <launcher>` (ROADMAP row 49)

A thin CLI over the existing `POST /v1/launch-clear` route and `Daemon::launch_clear`: it forgets the target role's launch state (a `refused` or `unreachable` verdict included), starts a new epoch and prints it. Only the configured launcher role may call it; any other role gets the daemon's refusal. Until now only AgentLife's `launcher --clear` could do this.

— lane: synapse
