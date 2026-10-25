# Patent sweep: Synapse 6.0.0 release-candidate line (6.0.0-rc.173) @ e657ecd

Date: 2026-10-25
Run by: synapse lane, Claude Sonnet 5.5
Method: AI-assisted search and read; NOT legal advice; NOT a freedom-to-operate opinion.

Covers: the `6.0.0-rc.N` line, swept at `main` e657ecd (`6.0.0-rc.173`). Anything added after
that commit, or any `6.0.0` final that differs materially, needs its own sweep.
Ordered by CireSnave (board 286): "Ensure a patent sweep has been done of every one of our projects before release."

## Ideas swept

Each is a mechanism, stated as a claim-like sentence. I1-I15, I18 are in shipped code; I17 and I19
are design documents only and are marked so.

1. **I1** A mailbox lease is fenced by an epoch: when a newer-epoch holder takes over a role, every lease taken under an older epoch is void, and delivery is at-least-once.
2. **I2** A role claim is signed, domain-separated and bound to the daemon's audience; a replay guard rejects reuse; the newest claim wins with a strictly increasing epoch, and the superseded session is told (HTTP 409).
3. **I3** A session expires on a sliding TTL, and "superseded" outranks "expired" when both apply.
4. **I4** A role idle past a TTL is retired (hidden from `list`, epoch and mail kept), revived on a new claim, and sends to it are refused with a typed error (HTTP 410).
5. **I5** A message delivered N times without acknowledgement moves to a dead-letter set; requeueing it resets its delivery count.
6. **I6** A local daemon proves its identity to a client by an HMAC challenge keyed by its announced instance id, so liveness is not judged by pid or image name.
7. **I7** An account key signs agent certificates that form a chain narrowing permissions at each link, with nested validity, and revocations relayed in metadata are accepted only when signed by the pinned account key.
8. **I8** A type-level split ensures an application cannot receive an unverified message: transports write to a write-only raw inbox that only the manager drains, paired with a sender verdict.
9. **I9** Replay suppression keeps a sliding freshness window of message ids; when capacity forces eviction it raises a horizon below which messages are rejected.
10. **I11** Agents share records with compare-and-set revisions and hash-chained history, and changes are announced by id-only notices sent through mail.
11. **I12** Facts are derived by a checker role from an external code forge, marked stale when old, and used to unblock waiting tasks automatically.
12. **I13** A message is pushed into an LLM client session with bounded delivery attempts then acknowledgement, a parked list after a refused acknowledgement, untrusted-data framing, and control/bidi character escaping.
13. **I14** A signal on message arrival launches or wakes a stopped agent session, with epoch and attempt outcomes recorded.
14. **I15** A mailbox store is chosen by declared needs and durability class, and the choice is recorded.
15. **I17** (design only, not built) Agents negotiate a mode stack for agent-to-agent traffic: L0 natural language, L1 compact schema with a deterministic decoder, L2 latent; any negotiated language needs a filed spec and an independent auditor per mode.
16. **I18** Security alerts travel as internal mail with failure budgets that delay rather than lock out.
17. **I19** (design only, not built) A QUIC connection pool evicts a peer's connection when the application layer reports a verification failure for that source, with a per-address cooldown.

## Queries (source, query, date)

All 2026-10-25, source Google Patents (via web search restricted to `patents.google.com`, plus its public result pages for full claims) unless stated. Search covered granted and published documents, US and EP/WO/CN family members that Google Patents surfaces, no date cut-off.

| Idea | Query |
|---|---|
| I1 | message queue lease, session-locked queue, epoch / fencing token invalidating older consumer leases |
| I1 | fencing token epoch number newer consumer supersedes older consumer message queue leases invalidated |
| I2, I3 | session claim signed by role key, monotonically increasing epoch, newest claim wins, stale session rejected |
| I5 | dead letter queue message exceeds maximum delivery count moved to dead letter set requeue resets delivery count |
| I4 | software agent identity retire inactive after time-to-live hidden from directory revived when agent reconnects messages retained |
| I7 | agent certificate chain narrowing permissions delegated signed by account key revocation list accepted only if signed by pinned key |
| I9 | replay suppression sliding freshness window message identifiers capacity eviction horizon reject older than horizon |
| I17 | large language model agents negotiate communication mode compact schema deterministic decoder natural language fallback between AI agents (this one also returned arXiv papers, listed under Limitations) |
| I13 | push message into large language model client session notification untrusted data framing escape control characters bounded delivery attempts acknowledgement |
| I11 | shared state record between software agents compare-and-set revision hash-chained history change notice by message |
| I14 | wake stopped AI agent session on incoming message launch process signal agent coding assistant message arrival |
| I6 | local daemon identity proof challenge response HMAC keyed by instance identifier client verifies local server is the expected instance not by process id |
| I8 | message transport application cannot receive unverified message type system inbox only manager drains verification sender authentication before delivery to application |

Not searched separately: I10 (not an idea we kept), I12, I15, I18, I19. I12 and I15 are ordinary
configuration and polling, and I18 is ordinary rate limiting; no mechanism beyond their prior art
was claimed. I19 is a design only; it is covered by the fencing and connection-pool results above.
This is a gap, listed in Limitations.

## Hits

Claims were read in full for the independent claims with the PM tool's Google Patents fetch
(`ic.py`, a trimmed variant of `tools/patent-claims.py`). Text there is machine-converted.
Legal status was not confirmed against an official register for any hit.

| Number | Title | Assignee | Status | Claims read | Overlap | Our difference | Verdict |
|---|---|---|---|---|---|---|---|
| US9015303B2 | Message queue behavior optimizations | Microsoft | not confirmed | independent | queues keyed by topic/session; group sent in one transaction | no epoch; no takeover voiding older leases | clear (I1) |
| US7330910B2 | Fencing of resources allocated to non-cooperative client computers | IBM / now Airbnb | not confirmed | claim 1 (only claim) | fences blocks held by a client whose I/O did not finish in time | block storage with a timestamp, not a mailbox lease with a monotone epoch | clear (I1) |
| US6243814B1 | Reliable disk fencing in a multicomputer system | Sun Microsystems | filed 1998, likely expired (not confirmed) | claim 1 | new membership generates a unique value that fences failed nodes' access | disk controller and membership list; not messaging or role claims | clear (I1, I2) |
| WO2013122977A1 | Connection leasing for hosted services | Citrix | not confirmed | claim 1 | cryptographically signed lease token authorising a session | lease authorises resource access; ours is a mailbox delivery lease invalidated by epoch | clear (I1) |
| US8959530B1 | Messaging middleware processing thread count based events | Sprint | not confirmed | all 3 independent claims | poison/back-out handling of messages in a queue system (description) | claims are thread-count monitoring; no delivery-count dead-letter set | clear (I5) |
| US9210114B1 | Automated delayed message redelivery | USAA | not confirmed | all 3 independent claims | micro and macro retry counters, back-out after N tries | counters are per redelivery manager; ours is a per-message delivery count in the store with reset on requeue | design-around (I5) |
| US7543140B2 | Revocation of a certificate and exclusion of other principals in a DRM system... | Microsoft | not confirmed | both independent claims | a certificate names delegated revocation authorities whose signed lists revoke it | claims require at least two delegated authorities and per-authority lists in a DRM setting; ours is one pinned account key | clear (I7) |
| US8438641B2 | Security protocol processing for anti-replay protection | LSI / now Intel | not confirmed | all 3 independent claims | sliding anti-replay window of sequence numbers | claims a wrapping N-bit window in security-processor memory words; ours is a message-id set with a capacity-raised horizon | clear (I9) |
| US12711207B1 | Agent-to-agent communication security protocol for AI agents with translation layer enforcement | Intuit | filed 2026-02-12, newly published | all 3 independent claims (1, 9, 15) | schema established for two AI agents; a translation component turns agent A's prompt into a secure version delivered to agent B | I17 is design only and its decoder expands a compact message, it does not rewrite a prompt into a "secure version"; but the claim is broad | **needs-review (I17 only)** |
| US20130066977A1, US10951572B1, EP1299799A2 | session-locked queues / watermark queue redelivery / message-based leasing | Microsoft / not recorded / not recorded | not confirmed | **unread** (titles and summaries only) | queue and lease topics adjacent to I1 | not assessed | **unread** (I1) |
| US20140245026A1, US9673984B2, US20170085553A1 | storage envelope epochs / signed session keys / revoking sessions | not recorded | not confirmed | **unread** (summaries only) | epoch as staleness check; signed session tokens; revoke older sessions | not assessed | **unread** (I2, I3) |
| US20020152214A1, US20140081927A1, US6708175B2 | lease enforcement in a distributed file system / data node fencing / disk fencing in a shared disk file system | not recorded | not confirmed | **unread** | fencing and lease topics adjacent to I1 | not assessed | **unread** (I1) |
| EP1643406A2, US20030188195A1, WO2005036857A1 | registration identifier reuse / automatic re-authentication / reconnection across sessions | not recorded | not confirmed | **unread** | identifier persistence and reconnection, adjacent to I4 | not assessed | **unread** (I4) |
| US7571343B1, CN101800989A | anti-replay window after failover / industrial wireless anti-replay (timestamp window) | not recorded | not confirmed | **unread** | window and horizon adjacency to I9 | not assessed | **unread** (I9) |

Nothing here is marked `clear` unless every independent claim of that patent was read. The
`unread` rows are the limitation of the exercise, not an all-clear.

Non-patent results (arXiv papers on Agora-style agent protocols, agent-communication surveys, prompt
injection and terminal-escape papers) were found for I17 and I13. They are prior art for novelty
purposes, not infringement risks, and are not tabulated.

## Needs review (to the PM)

- **US12711207B1 (Intuit, filed 2026-02-12), idea I17 only.** Independent claims 1, 9 and 15 cover establishing a schema for two AI agents and a translation component that produces a secure version of one agent's prompt as input to the other. Nothing shipped in Synapse does this. The plan in `docs/AI_TO_AI_COMMUNICATION_PLAN_2026-10-25.md` (L1 compact schema with a deterministic decoder) sits near it. Sent to the PM as a [FINDING] on 2026-10-25. The element that makes it relevant (claims 9 and 15, verbatim from the full independent claims read with `tools/patent-claims.py`): "configuring a translation component to interface between the first AI agent and the second AI agent based on the schema; using the configured translation component to generate a secure version of a prompt generated by the first AI agent; and providing the secure version of the prompt as input to the second AI agent." A compact-schema mode with a decoder between two agents would sit in the same place. On board 296 item D, the PM holds I17 until CireSnave answers. Recommendation: do not build L1 or the decoder until CireSnave decides, which matches the PM's earlier ruling that the decoder is low value.

## Limitations

- AI-assisted, Google Patents only. USPTO, Espacenet and WIPO were not queried directly, and Google Patents' own indexing and machine-converted claim text are known to be imperfect.
- One query per idea (two for I1). Search engines return ten results a query; closer hits may exist beyond them. Terms such as "tombstone", "dormant", "optimistic concurrency" and "macaroon" were suggested by the search but not run.
- Of the hits, the independent claims of 9 patents were read; 14 more were located but **not read**, and are `unread`, not `clear`.
- Legal status (in force, expired, assigned) was not confirmed against an official register for any hit.
- Ideas I12, I15, I18 and I19 were not searched on their own, and I10 was dropped.
- Dependent claims were not examined. An independent claim that does not read on us can have no dependent that does, but the point was not separately checked.
- The ideas were written from the code and design notes by the same lane that wrote them, so a mechanism may be missing from the list.
- This is due diligence, not a freedom-to-operate opinion. Anything that matters should go to a patent attorney.
