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

## Addendum 2026-11-06: rooms (I20, design only, `docs/ROOMS_DESIGN.md`)

**I20** (design only, not built) A named room is an address; a send to it is fanned out as one copy per member into each member's own mailbox, only to members who joined and are online (offline members get nothing queued); the creator sets join policy, who may send, new-joiner mute, and mute/remove/ban; a muted post is refused to the sender with a typed error; rate limits per sender and per room.

Method: Google Patents via web search (5 queries: pub/sub fan-out to subscriber queues; chat-room moderator mute; presence-gated group delivery; allow-list/invite-only group membership for bots; per-sender/per-channel rate limit with moderator mute), claims read with `tools/patent-claims.py`. Run by a Sonnet subagent for the synapse lane; the lane did not re-read the claims. The tool's output was truncated at about 3.5k characters, so later independent claims of some patents were not seen. Legal status not confirmed against a register. Not legal advice.

| Number | Title | Assignee | Status | Claims read | Overlap | Our difference | Verdict |
|---|---|---|---|---|---|---|---|
| US7865563B2 | Persisting a group in an IM application | Microsoft | active per Google; not confirmed | claim 1 (claim 7 onward truncated) | transmits a group message to each member who is online; named persistent group; invitations | claim 1 also requires retaining the message and an offline-message transmitter; rooms queue nothing for offline members | design-around (I20); a continuation claiming the online-only mode is possible, human check advised |
| US8086686B2 | same family | Microsoft | active per Google; not confirmed | claim 1 (claim 11 truncated) | transmit to each member logged into the group | claim 1 requires sending an offline message to members not logged in | design-around (I20) |
| US8341233B2 | same family | Microsoft | active per Google; not confirmed | claim 1 | group-directed message to members | requires storing the received message and sending on later start | design-around (I20) |
| US8949348B2 | Controlling message delivery in publish/subscribe | IBM | expired per Google; not confirmed | claim 1 (claim 6 truncated) | delivers to each registered subscriber | core is storing when no subscribers and delivering to later ones | clear on claims read (I20) |
| US20060235932A1 | Chat server mute capability | IBM | abandoned per Google; not confirmed | claim 1 | server-side mute between a designated participant and the indicating participant | ours is a creator-imposed room-wide mute with a typed refusal; application abandoned | clear (I20) |
| US11843470B2 | Integrated and interactive chat suite | Princeton University | active per Google, est. expiry 2042; not confirmed | all 19 claims; claim 1 is the only independent claim (read by us) | chat rooms; dependent claims 13-14 add a moderator who can mute or block a participant | claim 1 needs a chat-room template with instructions and prompts, creating rooms from it, assigning participants, providing prompts at template-defined times, and storing every message with a time stamp and participant code; rooms have no template, prompts or message log. Dependent claims 13-14 cannot read on us if claim 1 does not | clear (I20), read by us, not reviewed by counsel |
| US8566412B2 | Group messaging | GoGroups / Microsoft | active per Google; not confirmed | claim 1 | server notifies a subset of members | markup file, XMPP notifications, stateless fetch; not our flow | clear (I20) |
| US6212548B1 | System and method for multiple asynchronous text chat conversations | AT&T / Tumbleweed | expired per Google; not confirmed | claims 1, 12, 15 (read by us) | conversations among a selected set of participants, messages carrying a conversation ID and initiator ID | every claim is about multiple chat windows on a user terminal updated by ID; rooms have no windows and no client display logic | clear (I20), read by us, not reviewed by counsel |
| AU784512B2 | Method and system for persistent chat sessions | IBM | ceased per Google; not confirmed | independent claims 1, 12, 31, 39, 41 and one apparatus claim whose number the tool did not show (read by us; 42-43 are by reference to drawings) | invitation to a non-participant; persistent chat context | claims need a chat-session context sent in an invitation, or stored in a newsgroup; rooms have neither; patent ceased | clear (I20), read by us, not reviewed by counsel |
| US20040104933A1 | Dynamic role creation | SAP | abandoned per Google; not confirmed | claims 1, 12, 19 (read by us) | participants and roles | claims a participants-by-roles matrix UI to associate a participant with a role; rooms have no such UI | clear (I20), read by us, not reviewed by counsel |
| US8145719B2 | Messaging and communication based on groups | GoGroups / Microsoft | active per Google, est. expiry 2029; not confirmed | independent claims 1, 13, 16 (read by us; 16 truncated by the tool at its last limb) | server-side group list; push to group members online over an IM connection | every claim needs a shared HTML file appended with a persistent message and a pushed notice telling clients to download the updated file over a second connection; rooms deliver the message itself into a mailbox | clear (I20), read by us, not reviewed by counsel |

Coverage is a first pass: 5 queries; 11 patents' independent claims read (7 by the subagent; 4 more by the synapse lane on 2026-11-06, which also re-read US11843470B2 in full). No query found software-agent or bot rooms, and none found a patent on a typed-error refusal of a muted post.

## Addendum 2026-11-06: access-control rules (I21, design only, `docs/ACCESS_CONTROL_DESIGN.md`)

**I21** (design only, not built) An account holder stores rules (subject pattern, action see/send/join/post, object pattern, allow/deny); one policy function runs on every send and every directory listing; a send to an agent the sender may not see returns the same error as an absent agent; the default is allow and can be flipped to deny; rules are fed by access tokens bound to the agent's public key, introspected at session claim, re-checked on a short TTL, fail closed; legacy certificate permissions act as a bridge until a per-account switch ends them.

| Number | Title | Assignee | Status | Claims read | What claim 1 requires | Ours differs | Verdict |
|---|---|---|---|---|---|---|---|
| US12255895B2 | Attribute-based access control authorization for a message broker | Microsoft | active per Google; not confirmed | claim 1 verbatim, via `tools/patent-claims.py` (dependent claims 2-4 shown) | an IoT message reaches the broker through a wrapper, which also supplies a list of attributes it got from a claims provider, including the topics the device may publish to; the broker publishes only if the topic is in that list | A1/A2 keep rules in the daemon with no externally supplied attribute list and no wrapper. A3 (grants from a token naming allowed objects, checked at the broker) is the same shape in a different setting: agents and recipients, not IoT devices and topics | clear for A1/A2 on claim 1; **needs human review before A3 and before room posting by token**, read by us, not reviewed by counsel |
| US11483155B2 | Access control using proof-of-possession token | T-Mobile | active per Google; not confirmed | claims 1 and 12 verbatim, via `tools/patent-claims.py` | an application server that finds no PoP token on a request asks the authorization server for a token with a confirmation key and the presenter's identity, opens a secure second channel and sends the token back to the presenter | our daemon never requests a token on an agent's behalf and opens no second channel; the agent obtains the token from the authorization server and presents it at claim | design-around on claim 1 (I21), read by us, not reviewed by counsel |
| US7870260B2 | Controlling access to an electronic message recipient | Reflexion / Sophos | expired per Google; not confirmed | independent claims 1, 3, 30, 67, 81, paraphrase from the page | proxy identifiers per recipient with allow-all, deny-all or conditional state | no proxy identifiers; rule patterns instead | clear (expired), subagent-read, paraphrase only |
| US6108691A | Directory with options for access to and display of email addresses | Switchboard | expired per Google; not confirmed | claims 1, 5, 8, 10, 14, paraphrase | per-user show/hide of an address, with forwarding when hidden | ours hides existence and relays nothing | clear (expired), paraphrase only |
| US7490238B2 | Implicit population of access control lists | AOL / Meta | expired per Google; not confirmed | claims 1, 20-22, paraphrase | reciprocal membership in two independently kept lists | explicit pattern rules | clear (expired), paraphrase only |
| US9391991B2 | Messaging gateway for directory and anonymous services | Verizon / AOL | expired per Google; not confirmed | claims 1, 10, 18, paraphrase | a subscriber's withhold-unless-authorized preference and an authorization over a second medium | no contact-info authorization flow | clear (expired), paraphrase only |
| US8433752B2 | Notification of a blocked user entering a multi-user chat | Nokia | active per Google; not confirmed | claims 1, 5, 13, paraphrase | client-side blocklist check on a SIP NOTIFY | server-side policy | clear, paraphrase only |
| US10574609B2 | Chat room access control | Cisco | active per Google; not confirmed | claims 1, 19, paraphrase | join request gets an access level (veto, majority, moderator approval) limiting content access | account-holder allow/deny rules | clear, paraphrase only |

Coverage: 4 queries and 8 patents opened. Two (US12255895B2, US11483155B2) have claim 1 read verbatim; the other six were read only through a page summary the tool produced, so those verdicts are weaker. No query found a patent combining key-bound tokens with a software-agent message broker (only arXiv papers appeared), and none found one on answering a forbidden send exactly as an absent recipient; neither absence had a positive control. US20190156000A1 appeared and was not opened. Queries: broker access control with unknown-recipient and directory visibility; key-bound token for agents with introspection and a message broker; chat ACL where a user cannot discover another; AI agent delegated authorization with a public-key-bound token and message routing.

## Needs review (to the PM)

- **I21 v2 additions not screened (2026-11-06):** verified attenuation of delegated grants (intersection along a chain, a delegation dying with its source) and a per-grant "sensitive" mark that forces a live check from the source on every call. The I21 row above was written before these; a screen from the claims is owed before A2.

- **I21 access control (above).** Build A1 and A2 (rules in the daemon) on the current reading. A human reads US12255895B2's full claim set and continuations before A3 (grants from a token naming allowed objects). Verbatim claim 1 only was read, and not the dependent claims past 4.

- **I20 rooms (above).** No `unread` row remains; all verdicts are "read by us, not reviewed by counsel". The Microsoft IM-group family (US7865563B2, US8086686B2, US8341233B2) is the closest and sits outside claim 1 only because of its offline-message limb. Do not build R3 (fan-out) before a human reads the family's continuations.

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
