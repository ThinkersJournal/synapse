#!/bin/sh
# Start the lane's two Synapse proxies if not running (idempotent). Run as lane-commysdk, OUTSIDE the sandbox.
H=/home/lane-commysdk/synapse-home
pgrep -f "guest_proxy.py unix" >/dev/null || setsid nohup python3 $H/guest_proxy.py unix $H/relay.sock 0x53590001 >$H/proxy-unix.log 2>&1 &
sleep 1
pgrep -f "guest_proxy.py tcp" >/dev/null || setsid nohup /usr/local/bin/lane-sandbox -- python3 $H/guest_proxy.py tcp $H/relay.sock >$H/proxy-tcp.log 2>&1 &
sleep 1; echo proxies up
