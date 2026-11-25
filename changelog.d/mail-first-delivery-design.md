Fixed: the push loop writes a leased message again at +10 s and +30 s, plus a fetch-lease debug line (ROADMAP row 56)

The first channel notification of a mail-started session was lost (the client was not listening yet) and the message
surfaced only at the daemon's redelivery gap, about 120 s later. The adapter now keeps the first write of each message
and writes the same notification again 10 s and 30 s after it while the message is still unacked
(`PushConfig::repush_after`, empty turns it off). A re-write takes no new lease and does not count as a push, so the
daemon's `attempts`, its 2/4/8/16 minute schedule and `should_ack` are unchanged; a receiver tells a repeat by its
`message_id`. A message the model acked or declined is not re-sent.

Added: `synapsed` writes one debug line per leased message to its stderr when `SYNAPSE_FETCH_LOG=1` (off by default):
`synapsed: fetch-lease role=<id> message_id=<id> attempts=<n> leased_at=<time> lease_until=<time>`, never the body.

Design and numbers: `docs/MAIL-FIRST-DELIVERY-DESIGN.md`. Tests: `a_first_write_is_repeated_at_the_offsets_until_acked`
(sabotaged by disabling the plan: fails 1 write against 3) and `the_fetch_line_appears_only_when_on_and_never_carries_the_body`.
