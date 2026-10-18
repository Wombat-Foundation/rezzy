# h64 prefix grinding and collisions (2026-10-12)

Status: **local no-amplification policy implemented.** Placement remains
predictable; the retry path now bounds defender work by node population and
depth without salt, epochs, or wire changes. The caller handles terminal
failed prefixes with its node-scoped bounded ID fallback.

## What the integrity checks do and don't give us

- The level-0 accumulator (`algebraic.rs`, `digest ^= hash.h128`) covers each
  side's whole population. XOR cancels events present on both sides, so
  `XOR(local) ^ XOR(remote)` equals the XOR of the symmetric difference.
- `verify_global_residual` (`client.rs`) XORs the decoded `h128` values and
  compares them with that residual. It checks that the decode is complete and
  correct. It adds no collision evidence beyond what the decoded identifiers
  already show.
- `h128` is the trailing half of the digest, disjoint from `h64` (test
  `h128_comes_from_the_trailing_half_disjoint_from_h64`). So an `h64` alias
  between distinct events is caught unless their `h128` also collides (~2^-128).
- Phase 2 (`verify_follow_up`) handles opposite-sided `h64` pairs, which cancel
  in the sketch and balance the counts, via the `h64 -> h128` map.

## Threat model

- Accidental `h64` collisions: ~n^2 / 2^65 expected pairs. Rare, detected, and
  handled by splitting and falling back to direct ID exchange.
- Adversarial prefix grinding: `h64` is unkeyed and fixed once the event exists.
  An author who controls content can grind a shared prefix of ~20+ bits cheaply.
  The old one-bit ladder made the give-up path disproportionate to the
  attacker's work. The revised client avoids that growth curve.
- Precondition: the ground events must be in the symmetric difference (selective
  federation, or a withholding attacker-run homeserver). Events that replicate
  normally cancel out. The result is a liveness and bandwidth cost on the
  attacked prefixes, not a correctness failure.

## Why the obvious fixes don't work

- **Per-session salt on `h64`:** breaks `ResidentKernel` (`resident.rs`), which
  is built once, maintained incrementally and shared across peers. The bucket
  geometry would become session-specific, needing a resident structure per peer
  or a rebuild per session.
- **Static room-scoped key:** known to every member, so a member can grind
  against it. What defeats grinding is unpredictability at authoring time, not
  secrecy.
- **Epoch-rotated room key:** defeats precomputation and keeps amortization
  within an epoch, but needs an epoch boundary that every server agrees on. That
  boundary can't come from timestamps or arrival time. It has to be a checkpoint
  event (or set of checkpoint extremities) in the DAG, with each event assigned
  to the epoch containing it. Late events descending from the old checkpoint
  stay in the old epoch. The hard part is concurrent branches where servers
  disagree on the current checkpoint. That needs a deterministic finalization
  rule and a rule (probably "stay in the old epoch or force fallback") for
  events that don't descend from it. This is protocol-level coordination with
  checkpoint finality. See the next section for why this is likely impossible,
  not merely complex.

## Why structurally-derived epochs are plausibly impossible

An epoch key only defeats grinding if the key does not exist (is unpredictable)
when the attacker authors the event. A DAG-derived epoch breaks that premise:

1. **The author chooses the epoch.** An event's epoch is determined by its
   position in the DAG, i.e. by the `prev_events` / auth chain the author picks.
   An attacker can author against an old checkpoint, whose key has been public
   since that epoch began, and grind freely. Rotation only helps if events are
   forced into the _current_ epoch, which needs agreement on what "current" is.
2. **"Current" needs consensus the DAG doesn't have.** Under partition or
   concurrent branches there is no global current checkpoint. Any rule that
   forces new events onto the latest checkpoint requires finality, which
   Matrix's eventually-consistent DAG deliberately lacks. The withholding
   attacker from our threat model is exactly the party who can exploit this:
   they deliver old-epoch events late and they remain valid.
3. **Time-based epochs don't help either.** Timestamps are author-supplied
   within clock-skew tolerance, and arrival time differs per server. Neither is
   a boundary both sides agree on.
4. **Reconciliation needs the key for events one side hasn't seen.** To put a
   remote-only event into a sketch, both sides must compute its `h64`. If the
   key depends on the event's DAG position, a peer that lacks the event doesn't
   know its epoch, so cannot know the key, so cannot place it. Placement would
   have to be keyed by something both sides already agree on, which is back to a
   global epoch.

Conclusion: a structurally-derived epoch hands the attacker the choice of key
(point 1) or requires finality the DAG lacks (point 2). Non-structural epochs
(clock or out-of-band) need agreed time or external coordination. So any scheme
that is both unpredictable at authoring time and agreed by all peers without
extra consensus appears not to exist. What remains is bounding the damage
(mitigations below), not preventing it.

## No-amplification policy

This policy describes the verified `BucketExchange::advance_verified` path.

1. **Overflow decode small residuals.** If the sum of both sides' node counts
   is at most 256, request one capacity-256 overflow sketch. The residual
   population is bounded by that capacity, giving the decoder one attempt
   without a capacity ladder.
2. **Fan out stalled nodes.** A failed node too large for overflow uses the
   available 128-request budget to descend up to seven prefix bits in one round.
   Nodes with population above 256 are split immediately based on the summaries
   already returned for each node.
3. **Keep terminal fallback local.** `ladder_failed` reports the failed node
   only. Its caller performs bounded ID fallback for that node, so transferred
   IDs are limited to the population in the attacked region.

Each additional constrained digest bit doubles the expected hashes per attacker
element. The responder's fallback cost is proportional to the node population,
whose elements must cross the symmetric difference regardless. A fully
exhausted 32-bit prefix therefore costs about 2^32 hashes per element to
construct and causes only a node-local transfer. This is a complete
no-amplification answer; unpredictability still requires entropy, but is not
needed to make grinding economically unattractive.

## Scope

This does not make placement unpredictable. Per-session salts, keyed
re-placement, and epoch keys remain protocol-level options if unpredictability
is ever required. They are unnecessary for the economic objective here and
would add coordination or change node-membership semantics.
