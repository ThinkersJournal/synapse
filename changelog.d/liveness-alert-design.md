Docs: role liveness part 2, a stall alert for queued mail and default grants for a new lane (ROADMAP row 31)

Design only (`docs/ROLE_LIVENESS_ALERT_DESIGN.md`), no code. Covers the silent queue to an offline role (a `[STALLED]` notice and a `recipient.online` field on send), the deny-all finding for lanes claimed after the access migration (default grants applied at provision time), and a lapsing admin grant. Four slices and four open calls for the PM.
