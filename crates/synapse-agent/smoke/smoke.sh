#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Smoke test for synapse-agent. Usage: [SMOKE_MODEL=<model>] smoke.sh <bin-dir> gemini|mock
#   <bin-dir> holds synapse-agent, synapsed and synapse (the CLI, from synapsectl).
#   gemini: needs GEMINI_API_KEY in this process's environment (the PM maps it; never printed here).
#   mock:   no key; serves a local PONG endpoint instead. Same agent, same mail path.
# Prints PASS or FAIL as the last line. Exit 0 on PASS.
set -u
BIN="$1"; MODE="$2"
HOME_DIR="$(mktemp -d)"
export SYNAPSE_HOME="$HOME_DIR" SYNAPSE_ADDR=127.0.0.1:0
BIN="$(cygpath -u "$BIN" 2>/dev/null || echo "$BIN")"   # a C:/... path would split PATH at the colon
export PATH="$BIN:$PATH"
PIDS=()
# Kills only what this script started: the daemon is found by the pid in THIS home's announce file,
# never by image name (other synapsed processes on the box, the pilot's included, are not ours).
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
  DPID="$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['pid'])" "$HOME_DIR/synapsed.json" 2>/dev/null)"
  [ -n "$DPID" ] && taskkill //F //PID "$DPID" >/dev/null 2>&1
  rm -rf "$HOME_DIR"
}
trap cleanup EXIT

synapse id init --account acct >/dev/null || { echo "FAIL: id init"; exit 1; }

if [ "$MODE" = mock ]; then
  python "$(dirname "$0")/mock_openai.py" 18765 & PIDS+=($!)
  sleep 1
  export SMOKE_MOCK_KEY=unused
  ARGS=(--model mock-model --endpoint http://127.0.0.1:18765/v1/ --key-env SMOKE_MOCK_KEY)
else
  [ -n "${GEMINI_API_KEY:-}" ] || { echo "FAIL: GEMINI_API_KEY not set"; exit 1; }
  # Providers retire models (gemini-2.5-flash 404s for new users, 2026-10-20); override as needed.
  ARGS=(--model "${SMOKE_MODEL:-gemini-3.8-flash}")
fi

# The agent claims role `gem`; `boss` is the asker.
synapse claim --role boss >/dev/null || { echo "FAIL: claim boss"; exit 1; }
synapse-agent --role gem "${ARGS[@]}" --every 2 2>"$HOME_DIR/agent.log" & PIDS+=($!)
sleep 3
synapse send --role boss --to gem "Reply with exactly the single word PONG." >/dev/null || { echo "FAIL: send"; exit 1; }

for i in $(seq 1 30); do
  OUT="$(synapse inbox --role boss --lease-secs 5 2>/dev/null || true)"
  if echo "$OUT" | grep -q '"from":"gem@'; then
    echo "reply: $(echo "$OUT" | head -c 400)"
    if echo "$OUT" | grep -qi pong; then echo "PASS"; exit 0; fi
    echo "FAIL: reply arrived but does not contain PONG"; exit 1
  fi
  sleep 2
done
echo "FAIL: no reply from gem in 60 s"; echo "--- agent log:"; sed 's/\(key\|token\)=[^ ]*/\1=<redacted>/Ig' "$HOME_DIR/agent.log" | head -20
exit 1
