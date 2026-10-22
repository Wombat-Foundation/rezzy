# h64 prefix grinding and collisions (2026-10-12)

Status: **local no-amplification policy implemented.** Placement remains
predictable; the retry path now bounds defender work by node population and
depth without salt, epochs, or wire changes. Terminal failed prefixes are
exposed to the caller, which must apply node-scoped bounded ID fallback.

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

### One-sided chains and the population cutoff

A one-sided poisoned prefix does not advance `no_progress_rounds`: each split
has one failing child and one successfully decoded empty sibling. The retry
therefore remains a one-bit split per round, and the default 20-round budget
limits its depth. A node small enough for one overflow sketch first spends a
round on that retry, and a larger failure may fan out by up to seven bits, so
the budget is not exactly 20 one-bit advances. Taking 20 one-bit advances from
an initial request at depth `d` as an upper estimate, constraining `d + 20`
`h64` bits costs about `2^(d + 20)` event hashes per candidate event, and about
33 candidate events are needed, so roughly `33 * 2^(d + 20)` hashes in total.
For initial depths 0 through 6, that is about `33 * 2^20` to `33 * 2^26` hashes.
The exact work depends on the starting depth and how candidate events are
constructed; this is a grinding estimate, not a protocol guarantee.

The stop rule is population-based, not a short no-progress timer. After a failed
overflow decode, if the larger of the local and remote node populations is at
most `COLLISION_GIVE_UP_POPULATION` (64, or twice the normal bucket capacity),
the exchange marks that prefix `ladder_failed` for caller-applied fallback. A
larger failed node continues splitting. Thus an empty sibling does not trigger a
shallow fallback: an attacker must keep the poisoned population concentrated
until it is small enough to meet the cutoff. The 20-round and depth limits
remain terminal safety bounds; if either is reached first, the caller may still
need to fall back on a larger prefix.

1. **Overflow decode small residuals.** For an undecodable normal bucket that
   was not rejected by phase-1 verification, if the sum of both sides' node
   counts is at most 256 and the aggregate budget admits it, request one
   capacity-256 overflow sketch. The residual population is bounded by that
   capacity, giving the decoder one attempt without a capacity ladder. Phase-1
   verification failures are split instead; they do not take this overflow
   retry.
2. **Fan out stalled nodes.** A failed node too large for overflow, or whose
   overflow request does not fit the configured aggregate budget, is split
   immediately, based on the summaries already returned for each node, by up to
   seven prefix bits. The children are queued; up to 128 requests per round are
   sent, bounded by the aggregate capacity, and the remainder go out in later
   rounds.
3. **Keep terminal fallback local.** `ClientAction::ResolveRoots` exposes
   terminal failures through `ladder_failed`; it does not perform ID fallback.
   The caller must apply ID fallback to each failed node. Population-triggered
   give-up is limited to nodes with at most 64 events on either side; depth or
   round exhaustion can still expose a larger prefix, so callers must also bound
   fallback work.

Each additional constrained digest bit doubles the expected hashes per attacker
element. Prefix grinding remains possible, but ordinary population-triggered
fallback is delayed until the affected node is small. Unpredictability still
requires entropy; the client policy bounds routine fallback size rather than
preventing an attacker from choosing predictable prefixes.

## Scope

This does not make placement unpredictable. Per-session salts, keyed
re-placement, and epoch keys remain protocol-level options if unpredictability
is ever required. They are unnecessary for the economic objective here and would
add coordination or change node-membership semantics.
