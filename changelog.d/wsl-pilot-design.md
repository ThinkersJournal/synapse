Docs: WSL2 pilot design note, the Hyper-V socket relay spike, and the two-daemons-over-email feasibility note

Docs and a spike under `tools/wsl-relay/`; no daemon, crate or manifest change.

`docs/WSL-PILOT-DESIGN.md` designs running lanes inside WSL2 against the Windows pilot daemon: the relay over a Hyper-V
socket (the WSL VM id is found by the relay itself), the certificate problem (P1/P2), and how a lane is launched
there (the prompt goes before the variadic channels flag). `tools/wsl-relay/` holds the spike code, the lane usage
doc, an MCP config and `proxies-up.sh`. `docs/EMAIL_BRIDGE_DESIGN.md` is a feasibility note on two Synapse daemons
exchanging mail over email. Nothing here is wired into the build or CI; the spike is not a supported feature.
