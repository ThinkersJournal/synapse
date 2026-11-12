#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# Smoke test for synapse-agent.
#   Usage: [SMOKE_MODEL=<model>] smoke.sh <bin-dir> mock|gemini|mock-tools|gemini-tools
#   <bin-dir> holds synapse-agent, synapsed and synapse (the CLI, from synapsectl).
#   mock:         no key; a local endpoint answers PONG. Same agent, same mail path.
#   gemini:       needs GEMINI_API_KEY in this process's environment (never printed here).
#   *-tools:      the agent also gets `--allow-send ops`; the asker tells it to send TOOLOK to the
#                 role `ops`. PASS needs TOOLOK in ops's inbox from gem AND a reply to the asker.
# Prints PASS or FAIL as the last line. Exit 0 on PASS.
set -u
BIN="$1"; MODE="$2"
case "$MODE" in
  mock|gemini) TOOLS=0 ;;
  mock-tools|gemini-tools) TOOLS=1 ;;
  *) echo "FAIL: mode must be mock|gemini|mock-tools|gemini-tools"; exit 1 ;;
esac
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

if [ "${MODE%-tools}" = mock ]; then
  python "$(dirname "$0")/mock_openai.py" 18765 & PIDS+=($!)
  sleep 1
  export SMOKE_MOCK_KEY=unused
  ARGS=(--model mock-model --endpoint http://127.0.0.1:18765/v1/ --key-env SMOKE_MOCK_KEY)
else
  [ -n "${GEMINI_API_KEY:-}" ] || { echo "FAIL: GEMINI_API_KEY not set"; exit 1; }
  # Providers retire models (gemini-2.5-flash 404s for new users, 2026-10-20); override as needed.
  ARGS=(--model "${SMOKE_MODEL:-gemini-3.8-flash}")
fi
[ "$TOOLS" = 1 ] && ARGS+=(--allow-send ops)

# The agent claims role `gem`; `boss` is the asker; `ops` only receives.
# A new role is visible only to its creator and the account holder (A2a); the asker must see `gem`,
# so it holds role-admin (the account-holder bridge) before it first claims.
synapse id grant --role boss role-admin >/dev/null || { echo "FAIL: grant boss"; exit 1; }
synapse claim --role boss >/dev/null || { echo "FAIL: claim boss"; exit 1; }
[ "$TOOLS" = 1 ] && { synapse claim --role ops >/dev/null || { echo "FAIL: claim ops"; exit 1; }; }
# gem may see and message the roles it answers and sends to (A2a: nothing is visible by default).
OBJ=(--object agent:boss@acct); [ "$TOOLS" = 1 ] && OBJ+=(--object agent:ops@acct)
synapse access grant --role boss --to gem@acct --action see --action send "${OBJ[@]}" >/dev/null || { echo "FAIL: grant gem"; exit 1; }
synapse-agent --role gem "${ARGS[@]}" --every 2 2>"$HOME_DIR/agent.log" & PIDS+=($!)
sleep 3
if [ "$TOOLS" = 1 ]; then
  ASK="Use your send_message tool to send the exact text TOOLOK to the role ops, then reply with the single word DONE."
else
  ASK="Reply with exactly the single word PONG."
fi
synapse send --role boss --to gem "$ASK" >/dev/null || { echo "FAIL: send"; exit 1; }

fail_log() {
  echo "--- agent log:"; sed 's/\(key\|token\)=[^ ]*/\1=<redacted>/Ig' "$HOME_DIR/agent.log" | head -20
}

REPLY=""; OPS=""
for i in $(seq 1 30); do
  if [ -z "$REPLY" ]; then
    OUT="$(synapse inbox --role boss --lease-secs 5 2>/dev/null || true)"
    echo "$OUT" | grep -q '"from":"gem@' && REPLY="$OUT"
  fi
  if [ "$TOOLS" = 1 ] && [ -z "$OPS" ]; then
    OUT="$(synapse inbox --role ops --lease-secs 5 2>/dev/null || true)"
    echo "$OUT" | grep -q '"from":"gem@' && OPS="$OUT"
  fi
  [ -n "$REPLY" ] && { [ "$TOOLS" = 0 ] || [ -n "$OPS" ]; } && break
  sleep 2
done

[ -n "$REPLY" ] && echo "reply to boss: $(echo "$REPLY" | head -c 400)"
[ -n "$OPS" ] && echo "mail to ops:   $(echo "$OPS" | head -c 400)"
if [ -z "$REPLY" ]; then echo "FAIL: no reply from gem in 60 s"; fail_log; exit 1; fi
if [ "$TOOLS" = 1 ]; then
  if [ -z "$OPS" ]; then echo "FAIL: gem replied but never sent to ops (the model did not call the tool, or the call was refused)"; fail_log; exit 1; fi
  echo "$OPS" | grep -qi toolok || { echo "FAIL: ops got mail from gem but not TOOLOK"; exit 1; }
  echo "PASS"; exit 0
fi
echo "$REPLY" | grep -qi pong || { echo "FAIL: reply arrived but does not contain PONG"; exit 1; }
echo "PASS"; exit 0
