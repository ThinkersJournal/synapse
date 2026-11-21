<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->
# Patent reading: nack, delivery failure and outcome-to-sender (messaging steps 2a-2c)

Date: 2026-11-20. Run by the synapse lane (Sonnet 5.5) on pm-platform's task. **A model reading, not legal advice and
not a freedom-to-operate opinion; there is no attorney.** Claims were fetched with `tools/patent-claims.py` (Google
Patents page text, not the official USPTO record). Verdicts are "outside as read" or "inside as read" per claim element,
never "clear". Format follows AlarmAnt's `PATENT-SYNAPSE-READING.md` (alert-rate-limit@50f9c23c, board 478).

## What was read

| Patent | Holder; status (Google, not official) | Read |
|---|---|---|
| US8050281B2 "Alert gateway, systems and methods" | Qwest; Active, est. exp. 2028-04-17 | independents 1, 3, 7, 26, 27 in full; dependents 13-25 (the tool cut claims 5, 12, 29, 30 short, so those are not read) |
| US9542830B2 (same family) | Qwest; shown "Expired - Lifetime" with est. exp. 2028-04-17: the two fields disagree, treat it as live | claim 1 in full; dependents 2-8 partly |
| US9881475B2 "Alert management utilizing mobile devices" | Cerner; Active, est. exp. 2033-11-07 | both independents (1, 6) and dependents 2-5, 7-12 in full |

Not done: file histories, USPTO full text, Espacenet, the other family members (US10121346, US9805573), case law
on claim construction. The reading stays incomplete.

## Synapse features read against them

- **Nack (built, 2a, `POST /v1/nack`)**: a receiver agent declines a message it holds; the daemon removes it and mails
  the sender `[DECLINED] to= id= reason=` (`docs/MESSAGING_SEMANTICS_DESIGN.md` section 2).
- **Delivery failure (built: `[UNACKED]`; planned: expiry and refusal reports, 2b)**: after the redelivery schedule runs
  out, the daemon sets the message aside and mails the sender `[UNACKED] to= id= age= attempts=`.
- **Outcome to sender (planned, 2c)**: for a room post, one mail saying who acked, declined or did not.
- **Modes (planned, 2b)**: fire-and-forget, reliable, room broadcast, any-of (one ack), all-of (every member).

## US8050281 (Qwest)

Every independent claim (1, 3, 7, 26, 27) needs **all** of: (a) an alert gateway device **at a subscriber premises**;
(b) receiving an **alert message** (from an alert provider, in 7/26/27 via a **first, external interface**, with a
**second, internal interface** to the subscriber's devices); (c) **determining which one or more of a plurality of
subscriber devices should receive the alert message**; (d) **formatting the alert into an electronic message that
one of the subscriber devices can receive**; (e) providing/acting on it. Claim 3 adds the plurality of subscriber
devices on a communication medium.

| Element | Synapse | Reading |
|---|---|---|
| (a) gateway at a subscriber premises, two interfaces (external to the provider, internal to the subscriber's devices) | `synapsed` is a mailbox daemon with one local API for the roles of one account; it is not placed at a subscriber's premises as a gateway between a provider network and in-premises devices | outside as read; weakest-held element, since a daemon on a person's own machine is not obviously "not a premises" |
| (b) an **alert** message from an **alert provider** | a message between agent roles; an alert exists only as the `SYNAPSE_ALERT_ROLES` mail (row 9) | outside as read for nack, `[UNACKED]` and outcome mail (they are replies about a message, not an alert from a provider); **not settled** for the daemon's own alert mail |
| (c) determining which of a plurality of **subscriber devices** receives it | the recipient is named by the sender; the failover chain and receiver-policy caps are step 3 and are not built | nack, `[UNACKED]`, modes and outcome: outside as read (no choice among a subscriber's devices). **Step 3 failover ("forward to the next receiver after a settable time") and the urgency routing to a terminal or to AlarmAnt would pick among destinations for one human: flag for a person before step 3 is built** |
| (d) format the alert into a message a subscriber device can receive | bodies pass through unchanged; no per-device formatting | outside as read |

Dependents that look like our features. A dependent claim is infringed only if its independent claim is, so these
move the reading only if an independent element above is found inside:

- **claim 17** (anticipate an acknowledgement that the subscriber received the alert), **claim 20-21** (if no
  acknowledgement, retransmit, to a second device in 21): this is the shape of redelivery and of step 3 failover.
- **claim 18-19** (an ack on one device retracts the alert from the other devices): this is the shape of room
  `any-of`, if later we cancel the other members' copies after the first ack. Not planned; do not add a retraction
  mail to the rest of the room without the flag below.
- **claim 22** (no acknowledgement in a certain period: notify the alert provider that the alert was not received):
  this is the shape of `[UNACKED]`, already built (row 41), and of the planned expiry and outcome reports. It
  depends on claim 17, and so on claim 7's gateway-at-the-premises elements.

## US9542830 (Qwest, same family)

Claim 1 adds hardware: external and internal network interfaces **inside the network area and the consumer area of a
housing of a network interface device affixed to an exterior wall**, the network area physically separate and not
accessible to the subscriber, with a processor and storage in that housing. **Outside as read** (no such housing or
device in any Synapse surface). The reading of dependents 2-8 (urgent public information, Amber alerts) found nothing
that changes it.

## US9881475 (Cerner)

Claim 1 is a medium with instructions executable **by a mobile device** for an **alert user interface** comprising an
alert identifier area, an alert area presenting critical or noncritical, an alert response area with **accept, reject
and message** options, **and** a selectable area of **additional caregivers to whom the alert can be forwarded**.
Claim 6 needs a description, status, patient identification, and accept, reject, message and additional-information
options with the stated behaviours.

| Element | Synapse | Reading |
|---|---|---|
| mobile-device alert user interface with those areas | `nack` is an API call and an MCP tool; there is no UI, no mobile client and no alert areas | outside as read (nack is the "reject" function, but claim 1 and 6 claim the interface, not the function) |
| accept + reject + message + forward-to-caregiver options together | ack (accept), nack (reject) and send exist as separate tools; nothing presents them with a forward-to-caregiver list | outside as read |

**Flag for step 5**: the planned human terminal client for low-urgency mail must not become one interface offering
accept, reject, a reply message and a forward-to-colleague list on an alert (claim 1) or accept, reject, message and
more-information (claim 6) on a mobile device. A terminal is not a mobile device, but I have not read how a court would
construe that.

## Constraints this reading adds (design guards, not a clearance)

P1. Keep nack, `[UNACKED]`, expiry and outcome mail as **replies to the sender about a message it sent**; do not
    present them as an alert pushed to a person's devices.
P2. No Synapse component takes a **provider's alert and chooses among one person's devices**. Step 3 (failover chains,
    urgency to a human) is read again before it is built (Qwest element c, claims 17, 20-22).
P3. No retraction of other members' copies after a first ack (`any-of` stays "needs one ack", the rest are not
    recalled) until a person has looked at Qwest claim 18-19.
P4. The human terminal client (step 5) shows ack and nack as two commands, not one panel of accept, reject, message
    and forward (Cerner claims 1 and 6).

## Open

A person should confirm this reading, and in particular (a) whether a daemon on the user's own machine could be a
"gateway at a subscriber premises", and (b) whether the daemon's `SYNAPSE_ALERT_ROLES` alert mail (row 9) is an "alert
message from an alert provider". The unread claims and families above are owed. Nothing in this note changes what is
built; it constrains steps 3 and 5.
