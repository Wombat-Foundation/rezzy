# h64 prefix grinding and collisions (2026-10-12)

Status: **open, possibly unsolvable in full.** Nothing here is implemented or
validated. See also the `TODO(prefix-grinding)` comment in
`rezzy-recon/src/algebraic.rs` and the MSC4511-C notes in
`docs/msc4511_compressed_trie.md`.

## What the integrity checks do and don't give us

- The level-0 accumulator (`algebraic.rs`, `digest ^= hash.h128`) covers each
  side's whole population. XOR cancels events present on both sides, so
  `XOR(local) ^ XOR(remote)` equals the XOR of the symmetric difference.
- `verify_global_residual` (`client.rs`) XORs the decoded `h128` values and
  compares them with that residual. It checks that the decode is complete and
  correct. It adds no collision evidence beyond what the decoded identifiers
  already show.
- `h128` is the trailing half of the digest, disjoint from `h64`
  (test `h128_comes_from_the_trailing_half_disjoint_from_h64`). So an `h64`
  alias between distinct events is caught unless their `h128` also collides
  (~2^-128).
- Phase 2 (`verify_follow_up`) handles opposite-sided `h64` pairs, which
  cancel in the sketch and balance the counts, via the `h64 -> h128` map.

## Threat model

- Accidental `h64` collisions: ~n^2 / 2^65 expected pairs. Rare, detected,
  and handled by splitting and falling back to direct ID exchange.
- Adversarial prefix grinding: `h64` is unkeyed and fixed once the event
  exists. An author who controls content can grind a shared prefix of ~20+
  bits cheaply. The splitter descends one bit per round over
  `MAX_RECONCILIATION_ROUNDS` (20), so such a bucket exhausts the budget and
  falls to `ClientAction::ExtremityDiff`.
- Precondition: the ground events must be in the symmetric difference
  (selective federation, or a withholding attacker-run homeserver). Events
  that replicate normally cancel out. The result is a liveness and bandwidth
  cost on the attacked prefixes, not a correctness failure.

## Why the obvious fixes don't work

- **Per-session salt on `h64`:** breaks `ResidentKernel` (`resident.rs`),
  which is built once, maintained incrementally and shared across peers. The
  bucket geometry would become session-specific, needing a resident structure
  per peer or a rebuild per session.
- **Static room-scoped key:** known to every member, so a member can grind
  against it. What defeats grinding is unpredictability at authoring time,
  not secrecy.
- **Epoch-rotated room key:** defeats precomputation and keeps amortization
  within an epoch, but needs an epoch boundary that every server agrees on.
  That boundary can't come from timestamps or arrival time. It has to be a
  checkpoint event (or set of checkpoint extremities) in the DAG, with each
  event assigned to the epoch containing it. Late events descending from the
  old checkpoint stay in the old epoch. The hard part is concurrent branches
  where servers disagree on the current checkpoint. That needs a
  deterministic finalization rule and a rule (probably "stay in the old epoch
  or force fallback") for events that don't descend from it. This is
  protocol-level coordination with checkpoint finality, and is judged too
  complex for now.

## Mitigations considered (unprototyped)

1. **Salt only on escalation.** Keep the resident index unkeyed. When a
   bucket exhausts its split budget, re-place just that bucket's elements with
   a per-session nonce or the independent `h128`. A grinder who fixed an
   `h64` prefix can't also control the second placement. Cost is O(bucket
   size), bounded by the attacker's own grinding. Builds on the existing
   per-prefix fallback (`ladder_fail`, `force_split`). Not yet checked against
   how those functions re-place a bucket.
2. **Wider fan-out per round.** Split 2^k ways per round so a 20-bit prefix
   costs 20/k rounds instead of 20. Constant-factor, also helps accidental
   skew, but makes per-round sketches larger.
3. **Early skew detection.** If a prefix is implausibly crowded for its depth,
   send its IDs directly instead of burning rounds.
4. **Accept and document.** The attack is liveness-only and needs withholding.

## Open questions

- Is the grinding problem fully solvable without a DAG-level epoch? Current
  view: probably not, only boundable.
- Do `ladder_fail` / `force_split` allow re-placing a failing bucket by
  `h128` without protocol changes?
- Is `h64` persisted or cached anywhere outside `rezzy-recon`? A grep of
  `src/` found no `h64` references, but `resident.rs` was only skimmed.
