// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Requester-side MSC0501 reconciliation decisions and verification over MSC4521 digests.

use super::resident::{ResidentKernel, STRATA_COUNT, STRATUM_CAPACITY};
use super::triage::{
    bucket_range_start, BucketDecodeBatch, BucketRequest, NodeSummary,
    MAX_BUCKETED_SKETCH_CAPACITY, MAX_BUCKET_SKETCH_CAPACITY, SATURATED_DELTA_ESTIMATE,
};
use super::verify::Classified;
use super::{AlgebraicError, ElementHash, SyndromeSketch, MAX_LOCAL_SKETCH_DECODE_CAPACITY};
use alloc::collections::VecDeque;

/// Baseline policy limit for maximum reconciliation rounds in a single exchange.
///
/// Paired with [`MAX_BUCKETED_SKETCH_CAPACITY`], the default 20-round limit yields a
/// default operating point of ~82,000 differing elements before falling back to
/// extremity-based frame diffing under default client policy. This is a default,
/// not a protocol ceiling: [`ReconciliationClient::with_max_aggregate_capacity`]
/// raises the per-round capacity (and, through [`derive_gate_threshold`], the
/// derived round-budget gate) for two implementations that agree out of band to
/// attempt larger single-exchange deltas.
// TODO(prefix-grinding): this round budget is also the thing an attacker
// who can get ground events into the symmetric difference (see
// `ElementHash::from_digest32`'s doc comment in algebraic.rs for the
// precondition and the placement-key fix under consideration for
// 4511-C) could otherwise exhaust on a crafted bucket, forcing
// `ClientAction::ExtremityDiff` for that region every time two servers
// reconcile it -- bounded (falls back rather than hanging), but not free,
// and the cost recurs across sessions, not just the one under attack.
//
// `BucketExchange::advance`'s no-progress detection (see its doc comment,
// `MAX_NO_PROGRESS_ROUNDS`) now closes the round-budget half of this: it
// caps the damage from riding out all 20 rounds down to ~3, purely
// client-side, no wire change, no MSC. It does not fix the exposure
// itself -- the underlying bucket can still be found and re-targeted on
// the next reconciliation, since placement is still predictable -- only
// the placement-key redesign above (still open, tracked against 4511-C)
// closes that.
pub const MAX_RECONCILIATION_ROUNDS: usize = 20;
/// Maximum number of bucket requests emitted in one reconciliation round.
pub const MAX_BUCKETS_PER_ROUND: usize = 128;
/// Maximum split depth implied by `MAX_BUCKETS_PER_ROUND`.
pub const MAX_BUCKET_ROUND_DEPTH: u8 = bucket_round_depth(MAX_BUCKETS_PER_ROUND);

const MIN_BUCKET_SKETCH_CAPACITY: usize = 4;

const fn bucket_round_depth(bucket_count: usize) -> u8 {
    let mut count = bucket_count;
    let mut depth: u8 = 0;
    while count > 1 {
        count >>= 1;
        depth = match depth.checked_add(1) {
            Some(next) => next,
            None => panic!("MAX_BUCKETS_PER_ROUND depth must fit in u8"),
        };
    }
    depth
}

/// MSC4521 requester-side provisioning: `ceil(1.5 * delta) + 4`, plus headroom.
fn provision_capacity(delta: u64, headroom: u64) -> Option<u64> {
    delta
        .checked_add(delta / 2)
        .and_then(|capacity| capacity.checked_add(delta % 2))
        .and_then(|capacity| capacity.checked_add(4))
        .and_then(|capacity| capacity.checked_add(headroom))
}

/// Derives the round-budget gate threshold from a round count and a
/// per-round aggregate capacity. Defaults to [`MAX_BUCKETED_SKETCH_CAPACITY`]
/// for the capacity, but a client that raises its aggregate capacity via
/// [`ReconciliationClient::with_max_aggregate_capacity`] gets a
/// correspondingly higher default gate.
const fn derive_gate_threshold(max_rounds: usize, max_aggregate_capacity: usize) -> u64 {
    // Widen to u64 before multiplying: on 32-bit targets, saturating_mul in
    // usize would silently cap at usize::MAX well below the real threshold
    // for large max_rounds, weakening the configured reconciliation limit.
    (max_rounds as u64).saturating_mul(max_aggregate_capacity as u64)
}

/// Requester policy for one MSC0501 reconciliation exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationClient {
    max_sketch_capacity: usize,
    max_rounds: usize,
    gate_threshold: Option<u64>,
    /// Maximum aggregate bucket capacity provisioned for one reconciliation
    /// exchange. Defaults to [`MAX_BUCKETED_SKETCH_CAPACITY`]; raising it
    /// (via [`Self::with_max_aggregate_capacity`]) lets two servers that
    /// agree out of band attempt larger single-exchange deltas than the
    /// MSC4521 default operating point.
    max_aggregate_capacity: usize,
    requested_aggregate_capacity: usize,
}

/// Information learned from the responder's room digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteDigest {
    /// The responder's frame digest.
    pub digest: u128,
    /// Number of events the responder reports.
    pub known_event_count: u64,
    /// The responder's per-stratum sketch coordinates.
    pub strata: [[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    /// Whether both digests cover the same frame anchors.
    pub frame_matches: bool,
    /// Whether the responder advertised an extremity unknown to the requester.
    pub has_unknown_extremity: bool,
}

/// The next request selected by the reconciliation client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientAction {
    /// The frame digest and count agree; no request is needed.
    Synchronized,
    /// Locate a common DAG anchor before attempting set extraction.
    ExtremityDiff,

    /// Retry independently decoded bucket sketches.
    BucketSketches {
        /// Buckets to request next.
        requests: alloc::vec::Vec<BucketRequest>,
        /// Roots already recovered from earlier rounds.
        accumulated_roots: alloc::vec::Vec<u64>,
    },
    /// All requested buckets decoded and are ready for host-side resolution.
    ResolveRoots {
        /// Roots resolved by the reconciliation exchange.
        roots: alloc::vec::Vec<u64>,
        /// Nodes `(depth, prefix)` the exchange gave up on, classified as a
        /// collision or responder inconsistency that no retry can fix. The
        /// result is **partial**: the caller MUST apply its per-prefix
        /// fallback (with a bounded TTL) for each of these. Empty when the
        /// result is complete.
        ladder_failed: alloc::vec::Vec<(u8, u64)>,
    },
}

/// Consecutive no-progress rounds (see `BucketExchange::advance`'s doc
/// comment) tolerated before bailing to `ClientAction::ExtremityDiff`
/// early, instead of riding out the full `max_rounds` budget. Small and
/// fixed rather than configurable: this is a cheap circuit breaker, not a
/// policy knob, and a caller that wants a different threshold can still
/// reach it via `max_rounds` itself.
const MAX_NO_PROGRESS_ROUNDS: usize = 3;

/// Population (the larger side's node count) at or below which a known
/// collision is given up on instead of split further. Each extra level costs
/// one round, but siblings verify in parallel, so the loss shrinks from the
/// whole population to about this many elements in `log2(n / T)` rounds. A
/// starting point, to be tuned with the benches.
///
/// The count compared is the larger of the two sides', so it includes the
/// peer's claim. A lying peer can make a node keep splitting (bounded by the
/// depth cap and round budget) or give up early; either way the outcome stays
/// within the baseline invariant, so no extra check is needed.
const COLLISION_GIVE_UP_POPULATION: u64 = 2 * (MAX_BUCKET_SKETCH_CAPACITY as u64);

/// Whether a node whose phase 2 failed is worth narrowing with
/// [`BucketExchange::narrow`], under the same limits as a phase-1 known
/// collision: its population is above the give-up threshold, it can still be
/// split, and at least one round is left in the caller's budget. Otherwise the
/// node goes straight to the caller's per-prefix fallback.
#[must_use]
pub fn should_narrow(classified: &Classified, rounds_left: usize) -> bool {
    classified.population() > COLLISION_GIVE_UP_POPULATION
        && classified.node().0 < crate::MAX_DEPTH
        && rounds_left > 1
}

/// Stateful bucket exchange planner that carries deferred frontier nodes across rounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketExchange {
    pending: VecDeque<BucketRequest>,
    accumulated_roots: alloc::vec::Vec<u64>,
    rounds_emitted: usize,
    max_rounds: usize,
    max_buckets_per_round: usize,
    max_aggregate_capacity: usize,
    max_pending_requests: usize,
    /// Consecutive rounds in which every split-child failure came back
    /// without its sibling succeeding -- i.e. neither branch of the split
    /// could be resolved (persistently stalled). Reset to 0 whenever any split
    /// narrows (its sibling succeeds) or any bucket resolves a root.
    /// See `advance`'s doc comment.
    no_progress_rounds: usize,
    /// Nodes that passed phase-1 verification via [`Self::advance_verified`].
    classified: alloc::vec::Vec<Classified>,
    /// Phase-1 verification failures seen so far, for collision detection.
    failures: alloc::vec::Vec<Phase1Failure>,
    /// Prefixes given up on as collisions or responder inconsistency.
    ladder_failed: alloc::vec::Vec<(u8, u64)>,
    /// Responder summaries of failed nodes that may yet be split, kept until
    /// both children have arrived (possibly in different rounds).
    parents: alloc::vec::Vec<(u8, u64, NodeSummary)>,
    /// Responder summaries of children still waiting for their sibling.
    awaiting: alloc::vec::Vec<(u8, u64, NodeSummary)>,
    /// Nodes that failed phase 1 and must be split, never given a bigger
    /// capacity: more syndromes cannot help a collision, and a split helps a
    /// spurious decode as reliably as a bump does.
    force_split: alloc::vec::Vec<(u8, u64)>,
}

/// One phase-1 verification failure, recorded for collision detection.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Phase1Failure {
    depth: u8,
    prefix: u64,
    capacity: usize,
    roots: alloc::vec::Vec<u64>,
}

/// Whether `ancestor` is `node` or one of its ancestors.
fn covers(ancestor: (u8, u64), node: (u8, u64)) -> bool {
    let Some(shift) = node.0.checked_sub(ancestor.0) else {
        return false;
    };
    u128::from(node.1).checked_shr(u32::from(shift)) == Some(u128::from(ancestor.1))
}

/// Whether `h64` falls inside `node`.
fn in_node(h64: u64, node: (u8, u64)) -> bool {
    crate::server::H64Index::bounds_unchecked(&BucketRequest::new(node.0, node.1, 1))
        .contains(&u128::from(h64))
}

/// The roots of `roots` (sorted) that fall inside `node`.
fn restrict(roots: &[u64], node: (u8, u64)) -> alloc::vec::Vec<u64> {
    roots
        .iter()
        .copied()
        .filter(|&root| in_node(root, node))
        .collect()
}

impl BucketExchange {
    /// Creates a new pending-queue planner with the default round and wire caps.
    #[must_use]
    pub const fn new(
        accumulated_roots: alloc::vec::Vec<u64>,
        max_rounds: usize,
        max_buckets_per_round: usize,
        max_aggregate_capacity: usize,
    ) -> Self {
        Self {
            pending: VecDeque::new(),
            accumulated_roots,
            rounds_emitted: 0,
            max_rounds,
            max_buckets_per_round,
            max_aggregate_capacity,
            max_pending_requests: max_rounds.saturating_mul(max_buckets_per_round),
            no_progress_rounds: 0,
            classified: alloc::vec::Vec::new(),
            failures: alloc::vec::Vec::new(),
            ladder_failed: alloc::vec::Vec::new(),
            parents: alloc::vec::Vec::new(),
            awaiting: alloc::vec::Vec::new(),
            force_split: alloc::vec::Vec::new(),
        }
    }

    /// Starts an exchange that re-runs only the children of `nodes`, for
    /// example nodes whose phase 2 failed, so a loss is narrowed the way a
    /// phase-1 failure is. Each [`Classified`] carries the responder summary it
    /// was verified against, which seeds the split-consistency check on its
    /// children.
    ///
    /// `max_rounds` should be the caller's remaining budget, shared across
    /// passes: subtract [`Self::rounds_emitted`] from it after each pass.
    ///
    /// Returns the exchange (one round already counted) and the first round's
    /// requests; children that do not fit the per-round caps are queued in the
    /// pending frontier, as in a normal exchange.
    ///
    /// Call [`should_narrow`] first: below its threshold the node belongs to
    /// the caller's per-prefix fallback.
    ///
    /// # Errors
    /// Returns an error if a node cannot be split (already at the depth cap),
    /// the nodes are not an antichain, or a single request exceeds the caps.
    pub fn narrow(
        nodes: &[Classified],
        max_rounds: usize,
        max_buckets_per_round: usize,
        max_aggregate_capacity: usize,
    ) -> Result<(Self, alloc::vec::Vec<BucketRequest>), AlgebraicError> {
        let mut all = alloc::vec::Vec::new();
        for node in nodes {
            let (depth, prefix) = node.node();
            let parent = BucketRequest::new(depth, prefix, MAX_BUCKET_SKETCH_CAPACITY);
            let children = retry_or_split_bucket(&parent, 0, true)
                .map_err(|_| AlgebraicError::InvalidBucketIndex)?;
            all.extend(children);
        }
        all.sort_unstable_by_key(bucket_range_start);
        crate::triage::validate_bucket_requests(&all)?;
        let mut exchange = Self::new(
            alloc::vec::Vec::new(),
            max_rounds,
            max_buckets_per_round,
            max_aggregate_capacity,
        );
        exchange.parents = nodes
            .iter()
            .map(|c| (c.node().0, c.node().1, c.remote_summary()))
            .collect();
        exchange.pending = all.into();
        let first = exchange
            .drain_pending_round()
            .map_err(|_| AlgebraicError::InvalidSketchCapacity)?;
        Ok((exchange, first.into()))
    }

    /// Prefixes the exchange gave up on. The same list is returned in
    /// [`ClientAction::ResolveRoots`], where the type forces the caller to
    /// handle it; this accessor is for inspection.
    #[must_use]
    pub fn ladder_failed(&self) -> &[(u8, u64)] {
        &self.ladder_failed
    }

    /// Gives up on `region`: no retry or split can fix it, so it is removed
    /// from every piece of exchange state and recorded as ladder-failed.
    fn ladder_fail(&mut self, region: (u8, u64), batch: &mut BucketDecodeBatch) {
        if !self.ladder_failed.contains(&region) {
            self.ladder_failed.push(region);
        }
        let inside = |depth: u8, prefix: u64| covers(region, (depth, prefix));
        self.classified.retain(|c| !covers(region, c.node()));
        self.accumulated_roots
            .retain(|&root| !in_node(root, region));
        self.pending
            .retain(|request| !inside(request.depth, request.prefix));
        self.failures.retain(|f| !inside(f.depth, f.prefix));
        self.force_split.retain(|&(d, p)| !inside(d, p));
        self.parents.retain(|&(d, p, _)| !inside(d, p));
        self.awaiting.retain(|&(d, p, _)| !inside(d, p));
        batch
            .successful_buckets
            .retain(|s| !inside(s.depth, s.prefix));
        batch.failed_buckets.retain(|&(d, p)| !inside(d, p));
    }

    /// Checks that each split's two children, as reported by the responder,
    /// XOR and sum to the parent's summary. The children may arrive in
    /// different rounds, so the parent's summary is kept until both are in.
    /// A violation is responder inconsistency, which no capacity bump or split
    /// can fix, so the parent goes straight to ladder-failed.
    ///
    /// Only the responder's summaries are checked: that is what catches peer
    /// inconsistency. The local summaries come from our own population and are
    /// trusted.
    fn check_split_consistency(
        &mut self,
        requests: &[BucketRequest],
        remote: &[NodeSummary],
        batch: &mut BucketDecodeBatch,
    ) {
        for (request, &summary) in requests.iter().zip(remote) {
            let (depth, prefix) = (request.depth, request.prefix);
            let Some(parent_depth) = depth.checked_sub(1) else {
                continue;
            };
            let parent = (parent_depth, prefix >> 1);
            let Some(slot) = self.parents.iter().position(|&(d, p, _)| (d, p) == parent) else {
                continue;
            };
            let sibling = (depth, prefix ^ 1);
            let from_round = requests
                .iter()
                .zip(remote)
                .find(|(r, _)| (r.depth, r.prefix) == sibling)
                .map(|(_, &s)| s);
            let from_earlier = self
                .awaiting
                .iter()
                .position(|&(d, p, _)| (d, p) == sibling);
            let sibling_summary = from_round.or_else(|| from_earlier.map(|i| self.awaiting[i].2));
            let Some(sibling_summary) = sibling_summary else {
                if !self
                    .awaiting
                    .iter()
                    .any(|&(d, p, _)| (d, p) == (depth, prefix))
                {
                    self.awaiting.push((depth, prefix, summary));
                }
                continue;
            };
            let (_, _, parent_summary) = self.parents.remove(slot);
            self.awaiting
                .retain(|&(d, p, _)| (d, p) != sibling && (d, p) != (depth, prefix));
            let consistent = parent_summary.digest == summary.digest ^ sibling_summary.digest
                && summary.count.checked_add(sibling_summary.count) == Some(parent_summary.count);
            if !consistent {
                self.ladder_fail(parent, batch);
            }
        }
    }

    /// Whether a phase-1 failure of `node` repeats an earlier one: same
    /// restricted root set, from an ancestor-or-equal node, under a different
    /// sketch (`(depth, capacity)` differs). Decoding the same sketch twice is
    /// deterministic and proves nothing; a spurious decode does not survive a
    /// capacity bump or a narrower node, but a collision does. Empty root sets
    /// count: an opposite-sided pair with `M` empty repeats `[]`.
    fn repeats_earlier_failure(&self, node: (u8, u64), capacity: usize, roots: &[u64]) -> bool {
        let here = restrict(roots, node);
        self.failures.iter().any(|f| {
            covers((f.depth, f.prefix), node)
                && (f.depth, f.capacity) != (node.0, capacity)
                && restrict(&f.roots, node) == here
        })
    }

    /// Nodes admitted so far by [`Self::advance_verified`], each carrying the
    /// roots the caller must still fetch (`M`) for phase 2.
    #[must_use]
    pub fn classified(&self) -> &[Classified] {
        &self.classified
    }

    /// Like [`Self::advance`], but verifies each decoded node first.
    ///
    /// This is phase 1 only. Phase 2 ([`crate::verify_follow_up`]) needs the
    /// identifiers the peer returns for each node's `M`, so it runs *after*
    /// the exchange ends in [`ClientAction::ResolveRoots`] and the exchange can
    /// neither split nor retry on it. A phase-2 failure (for example an
    /// opposite-sided `h64` pair, which cancels in the sketch and balances the
    /// counts) is the caller's fallback for that node's prefix; the node's
    /// siblings are unaffected.
    ///
    /// `requests`, `local` and `remote` are the round's requests and the two
    /// sides' per-node summaries, index-aligned. A node that fails phase 1 is
    /// treated as a failed bucket, so it is retried or split on its own while
    /// its siblings are admitted. `local_candidates` is the multi-valued
    /// `h64 -> h128` map over the local population.
    ///
    /// # Errors
    /// Returns an error if the inputs are misaligned or a decoded node was
    /// never requested.
    pub fn advance_verified<F>(
        &mut self,
        batch: BucketDecodeBatch,
        requests: &[BucketRequest],
        local: &[NodeSummary],
        remote: &[NodeSummary],
        global_estimate: Option<u64>,
        local_candidates: F,
    ) -> Result<ClientAction, AlgebraicError>
    where
        F: FnMut(u64) -> alloc::vec::Vec<u128>,
    {
        let (mut batch, verified, rejected) =
            crate::verify::verify_batch(batch, requests, local, remote, local_candidates)?;

        // Responder inconsistency first: it invalidates whole regions.
        self.check_split_consistency(requests, remote, &mut batch);

        // A phase-1 failure is not a capacity problem, so the node is split,
        // never given a bigger capacity. A repeat under a different sketch is
        // a *known* collision, which only narrowing can help: keep splitting
        // it, and give up on the prefix only once it is small or no split is
        // possible (depth cap or round budget).
        for (depth, prefix, roots) in rejected {
            let node = (depth, prefix);
            if self
                .ladder_failed
                .iter()
                .any(|&region| covers(region, node))
            {
                continue;
            }
            let Some(slot) = requests.iter().position(|r| (r.depth, r.prefix) == node) else {
                continue;
            };
            let capacity = requests[slot].capacity;
            let repeats = self.repeats_earlier_failure(node, capacity, &roots);
            let population = local[slot].count.max(remote[slot].count);
            let cannot_narrow = depth >= crate::MAX_DEPTH
                || self.rounds_emitted.saturating_add(1) >= self.max_rounds;
            if cannot_narrow || (repeats && population <= COLLISION_GIVE_UP_POPULATION) {
                self.ladder_fail(node, &mut batch);
            } else {
                self.failures.push(Phase1Failure {
                    depth,
                    prefix,
                    capacity,
                    roots,
                });
                self.force_split.push(node);
            }
        }

        // Remember surviving failed nodes' responder summaries: they may be
        // split next, and their children are checked against them.
        for &(depth, prefix) in &batch.failed_buckets {
            let summary = requests
                .iter()
                .zip(remote)
                .find(|(r, _)| (r.depth, r.prefix) == (depth, prefix))
                .map(|(_, &s)| s);
            if let Some(summary) = summary {
                if !self
                    .parents
                    .iter()
                    .any(|&(d, p, _)| (d, p) == (depth, prefix))
                {
                    self.parents.push((depth, prefix, summary));
                }
            }
        }

        let verified: alloc::vec::Vec<Classified> = verified
            .into_iter()
            .filter(|c| {
                !self
                    .ladder_failed
                    .iter()
                    .any(|&region| covers(region, c.node()))
            })
            .collect();
        self.classified.extend(verified);
        Ok(self.advance(batch, requests, global_estimate))
    }

    /// Returns the accumulated roots carried through the exchange so far.
    #[must_use]
    pub fn accumulated_roots(&self) -> &[u64] {
        &self.accumulated_roots
    }

    /// Returns the number of request rounds emitted from the pending frontier.
    #[must_use]
    pub const fn rounds_emitted(&self) -> usize {
        self.rounds_emitted
    }

    /// Returns the number of deferred frontier nodes waiting to be scheduled.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn drain_pending_round(&mut self) -> Result<VecDeque<BucketRequest>, ClientAction> {
        if self.rounds_emitted.saturating_add(1) >= self.max_rounds {
            return Err(ClientAction::ExtremityDiff);
        }

        let mut total = 0_usize;
        let mut requests = VecDeque::with_capacity(self.max_buckets_per_round);
        while let Some(candidate) = self.pending.front().copied() {
            if requests.len() >= self.max_buckets_per_round {
                break;
            }
            let Some(next_total) = total.checked_add(candidate.capacity) else {
                return Err(ClientAction::ExtremityDiff);
            };
            if next_total > self.max_aggregate_capacity {
                break;
            }
            total = next_total;
            self.pending.pop_front();
            requests.push_back(candidate);
        }

        if requests.is_empty() {
            return Err(ClientAction::ExtremityDiff);
        }

        self.rounds_emitted = self.rounds_emitted.saturating_add(1);
        Ok(requests)
    }

    /// Advances the exchange by ingesting one decoded bucket batch and emitting the next round.
    ///
    /// The planner keeps deferred children in a pending frontier rather than aborting when a
    /// single round hits the per-round bucket cap.
    ///
    /// Detects lack of progress and bails to [`ClientAction::ExtremityDiff`]
    /// after a few consecutive rounds of it (an internal, unexported
    /// constant), rather than
    /// always riding out the full `max_rounds` budget. `retry_or_split_bucket`
    /// always emits a failed bucket's two split children together (same
    /// depth, prefixes `p<<1` and `(p<<1)|1`). A failed bucket whose
    /// sibling (found via `previous_requests`, this round's submission) also
    /// failed means the split failed to resolve either branch (persistently
    /// stalled), and further splits without progress are unlikely to help.
    /// Conversely, if a sibling succeeds (even if empty with zero roots), the
    /// split has narrowed the unresolved range and progress is being made.
    /// This is a global signal, not per split-chain: coarser than tracking each
    /// lineage individually, but enough to cap the cost of an adversary who can
    /// keep a crafted difference on both sides of every split (see
    /// `ElementHash::from_digest32`'s doc comment in algebraic.rs, and the TODO
    /// on `MAX_RECONCILIATION_ROUNDS` above, for that scenario). Any split narrowing
    /// or bucket resolving a nonzero root resets the counter.
    #[must_use]
    pub fn advance(
        &mut self,
        batch: BucketDecodeBatch,
        previous_requests: &[BucketRequest],
        global_estimate: Option<u64>,
    ) -> ClientAction {
        let BucketDecodeBatch {
            successful_buckets,
            failed_buckets,
        } = batch;

        let had_failures = !failed_buckets.is_empty();

        let any_nonempty_success = successful_buckets.iter().any(|s| !s.roots.is_empty());
        let is_split_sibling_of = |depth: u8, prefix: u64| {
            previous_requests
                .iter()
                .any(|r| r.depth == depth && r.prefix == (prefix ^ 1))
        };
        let mut saw_split_failure = false;
        let all_split_failures_stalled = failed_buckets.iter().all(|&(depth, prefix)| {
            if !is_split_sibling_of(depth, prefix) {
                // Not a split child this round (a solo capacity retry, or a
                // first-round request) -- has no sibling to compare against,
                // so it neither confirms nor denies stall.
                return true;
            }
            saw_split_failure = true;
            let sibling_prefix = prefix ^ 1;
            !successful_buckets
                .iter()
                .any(|s| s.depth == depth && s.prefix == sibling_prefix)
        });
        if saw_split_failure && all_split_failures_stalled && !any_nonempty_success {
            self.no_progress_rounds = self.no_progress_rounds.saturating_add(1);
        } else {
            self.no_progress_rounds = 0;
        }
        if self.no_progress_rounds >= MAX_NO_PROGRESS_ROUNDS {
            return ClientAction::ExtremityDiff;
        }

        for success in successful_buckets {
            self.accumulated_roots.extend(success.roots);
        }

        let Ok(resolved_count) = u64::try_from(self.accumulated_roots.len()) else {
            return ClientAction::ExtremityDiff;
        };
        let unaccounted = global_estimate.unwrap_or(0).saturating_sub(resolved_count);
        let Ok(failed_count) = u64::try_from(failed_buckets.len()) else {
            return ClientAction::ExtremityDiff;
        };
        let share = if failed_count == 0 {
            0
        } else {
            unaccounted.checked_div(failed_count).unwrap_or(0)
        };

        for (depth, prefix) in failed_buckets {
            let force_split = self.force_split.contains(&(depth, prefix));
            self.force_split.retain(|&node| node != (depth, prefix));
            let Ok(next_requests) =
                retry_failed_bucket(previous_requests, depth, prefix, share, force_split)
            else {
                return ClientAction::ExtremityDiff;
            };
            self.pending.extend(next_requests);
            if self.pending.len() > self.max_pending_requests {
                return ClientAction::ExtremityDiff;
            }
        }

        self.pending
            .make_contiguous()
            .sort_unstable_by_key(bucket_range_start);

        if !had_failures && self.pending.is_empty() {
            return ClientAction::ResolveRoots {
                roots: self.accumulated_roots.clone(),
                ladder_failed: self.ladder_failed.clone(),
            };
        }

        let Ok(requests) = self.drain_pending_round() else {
            return ClientAction::ExtremityDiff;
        };

        ClientAction::BucketSketches {
            requests: requests.into_iter().collect(),
            accumulated_roots: self.accumulated_roots.clone(),
        }
    }
}

/// Finds the request a failed bucket was submitted under, then retries or
/// splits it. Shared by [`BucketExchange::advance`] and
/// [`ReconciliationClient::transition_bucket_batch`].
fn retry_failed_bucket(
    previous_requests: &[BucketRequest],
    depth: u8,
    prefix: u64,
    share: u64,
    force_split: bool,
) -> Result<VecDeque<BucketRequest>, ClientAction> {
    let previous = previous_requests
        .iter()
        .find(|request| request.prefix == prefix && request.depth == depth)
        .ok_or(ClientAction::ExtremityDiff)?;
    retry_or_split_bucket(previous, share, force_split)
}

/// Provisions a bucket sketch capacity for `target`, clamped to
/// `[floor, MAX_BUCKET_SKETCH_CAPACITY]`.
fn provision_bucket_capacity(target: u64, floor: usize) -> Option<usize> {
    target
        .checked_add(target / 2)
        .and_then(|value| value.checked_add(target % 2))
        .and_then(|value| value.checked_add(4))
        .and_then(|value| usize::try_from(value).ok())
        .map(|value| value.clamp(floor, MAX_BUCKET_SKETCH_CAPACITY))
}

/// Retries a failed bucket at a larger capacity, or splits it once it is at
/// the capacity ceiling. `force_split` skips the capacity step: it is for
/// phase-1 verification failures, which are not capacity problems.
fn retry_or_split_bucket(
    previous: &BucketRequest,
    share: u64,
    force_split: bool,
) -> Result<VecDeque<BucketRequest>, ClientAction> {
    let mut requests = VecDeque::new();

    if previous.capacity < MAX_BUCKET_SKETCH_CAPACITY && !force_split {
        let Some(floor) = previous.capacity.checked_add(1) else {
            return Err(ClientAction::ExtremityDiff);
        };
        let Ok(floor_u64) = u64::try_from(floor) else {
            return Err(ClientAction::ExtremityDiff);
        };
        let target = share.max(floor_u64);
        let Some(capacity) = provision_bucket_capacity(target, floor) else {
            return Err(ClientAction::ExtremityDiff);
        };
        requests.push_back(BucketRequest::new(
            previous.depth,
            previous.prefix,
            capacity,
        ));
        return Ok(requests);
    }

    if previous.depth >= super::MAX_DEPTH {
        return Err(ClientAction::ExtremityDiff);
    }

    let floor = MIN_BUCKET_SKETCH_CAPACITY;
    let Ok(floor_u64) = u64::try_from(floor) else {
        return Err(ClientAction::ExtremityDiff);
    };
    let target = (share / 2).max(floor_u64);
    let Some(capacity) = provision_bucket_capacity(target, floor) else {
        return Err(ClientAction::ExtremityDiff);
    };

    let Some(next_depth) = previous.depth.checked_add(1) else {
        return Err(ClientAction::ExtremityDiff);
    };

    requests.push_back(BucketRequest::new(
        next_depth,
        previous.prefix << 1,
        capacity,
    ));
    requests.push_back(BucketRequest::new(
        next_depth,
        (previous.prefix << 1) | 1,
        capacity,
    ));

    Ok(requests)
}
impl Default for ReconciliationClient {
    fn default() -> Self {
        Self {
            max_sketch_capacity: MAX_LOCAL_SKETCH_DECODE_CAPACITY,
            max_rounds: MAX_RECONCILIATION_ROUNDS,
            gate_threshold: Some(derive_gate_threshold(
                MAX_RECONCILIATION_ROUNDS,
                MAX_BUCKETED_SKETCH_CAPACITY,
            )),
            max_aggregate_capacity: MAX_BUCKETED_SKETCH_CAPACITY,
            requested_aggregate_capacity: MAX_BUCKETED_SKETCH_CAPACITY,
        }
    }
}

impl ReconciliationClient {
    /// Creates a requester with an explicit local unbucketed decode limit.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::InvalidSketchCapacity`] for a zero limit or a
    /// limit above the implementation's local decode policy.
    pub const fn new(max_sketch_capacity: usize) -> Result<Self, AlgebraicError> {
        if max_sketch_capacity == 0 || max_sketch_capacity > MAX_LOCAL_SKETCH_DECODE_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(Self {
            max_sketch_capacity,
            max_rounds: MAX_RECONCILIATION_ROUNDS,
            gate_threshold: Some(derive_gate_threshold(
                MAX_RECONCILIATION_ROUNDS,
                MAX_BUCKETED_SKETCH_CAPACITY,
            )),
            max_aggregate_capacity: MAX_BUCKETED_SKETCH_CAPACITY,
            requested_aggregate_capacity: MAX_BUCKETED_SKETCH_CAPACITY,
        })
    }

    /// Sets a custom maximum round count and recalculates the gate threshold.
    ///
    /// This overwrites a threshold configured earlier with
    /// [`Self::with_gate_threshold`], so builder call order is significant.
    #[must_use]
    pub const fn with_max_rounds(mut self, max_rounds: usize) -> Self {
        self.max_rounds = max_rounds;
        self.gate_threshold = Some(derive_gate_threshold(
            max_rounds,
            self.requested_aggregate_capacity,
        ));
        self
    }

    /// Sets a custom maximum aggregate bucket capacity for one reconciliation
    /// exchange and recalculates the gate threshold.
    ///
    /// Defaults to [`MAX_BUCKETED_SKETCH_CAPACITY`] (the MSC4521 default
    /// operating point, ~82,000 differing elements at the default round
    /// count). Raising this is a client-side policy choice: both servers
    /// must independently configure a matching-or-higher capacity, or the
    /// side with the lower ceiling still bails to `ExtremityDiff` once its
    /// own gate is exceeded. This overwrites a threshold configured earlier
    /// with [`Self::with_gate_threshold`], so builder call order is
    /// significant.
    #[must_use]
    pub fn with_max_aggregate_capacity(mut self, max_aggregate_capacity: usize) -> Self {
        self.requested_aggregate_capacity = max_aggregate_capacity;
        self.max_aggregate_capacity = max_aggregate_capacity.min(MAX_BUCKETED_SKETCH_CAPACITY);
        // Derive gate from the requested capacity (not clamped) to reflect the total
        // aggregate budget across all rounds, while keeping per-round requests clamped.
        self.gate_threshold = Some(derive_gate_threshold(
            self.max_rounds,
            max_aggregate_capacity,
        ));
        self
    }

    /// Sets an explicit gate threshold on the maximum estimated delta.
    /// Pass `None` to disable delta gating entirely for large syncs.
    #[must_use]
    pub const fn with_gate_threshold(mut self, threshold: Option<u64>) -> Self {
        self.gate_threshold = threshold;
        self
    }

    /// Disables the delta gate threshold entirely, allowing set reconciliation to proceed
    /// for arbitrarily large set differences.
    #[must_use]
    pub const fn allow_unlimited_delta(mut self) -> Self {
        self.gate_threshold = None;
        self
    }

    /// Returns the maximum allowed rounds.
    #[must_use]
    pub const fn max_rounds(self) -> usize {
        self.max_rounds
    }

    /// Returns the gate threshold, if active.
    #[must_use]
    pub const fn gate_threshold(self) -> Option<u64> {
        self.gate_threshold
    }

    /// Selects the next protocol action from local and remote level-0 state.
    ///
    /// `concurrency_headroom` accounts for events expected to arrive during
    /// the exchange. Sketch provisioning follows the MSC rule
    /// `ceil(1.5 * estimate) + 4`, with `concurrency_headroom` added on top.
    /// Requests that exceed local policy are capped and ask for a bucket
    /// summary so the next exchange can localize the difference.
    #[must_use]
    pub fn select_action(
        self,
        local: &ResidentKernel,
        remote: RemoteDigest,
        concurrency_headroom: usize,
    ) -> ClientAction {
        if !remote.frame_matches || remote.has_unknown_extremity {
            return ClientAction::ExtremityDiff;
        }
        if local.accumulator().digest() == remote.digest
            && local.accumulator().known_event_count() == remote.known_event_count
        {
            return ClientAction::Synchronized;
        }

        let count_delta = local
            .accumulator()
            .known_event_count()
            .abs_diff(remote.known_event_count);
        let estimated_delta = match crate::triage::estimate_strata(
            local.strata(),
            &remote.strata,
            crate::triage::MAX_STRATA_FACTOR_WORK,
        ) {
            Ok(estimate) => estimate.delta.max(count_delta),
            Err(_) => return ClientAction::ExtremityDiff,
        };

        if estimated_delta >= SATURATED_DELTA_ESTIMATE {
            return ClientAction::ExtremityDiff;
        }

        if let Some(threshold) = self.gate_threshold {
            if estimated_delta > threshold {
                return ClientAction::ExtremityDiff;
            }
        }

        let provisioned = u64::try_from(concurrency_headroom)
            .ok()
            .and_then(|headroom| provision_capacity(estimated_delta, headroom));
        // Clamp before the `usize` conversion: on 32-bit targets a large
        // provisioned `u64` can exceed `usize::MAX` even though it's far
        // above `MAX_BUCKETED_SKETCH_CAPACITY`, which the value is capped to
        // right below anyway. Converting first would reject those cases as
        // `ExtremityDiff` instead of just clamping.
        let capped = provisioned.map(|value| value.min(self.max_aggregate_capacity as u64));
        let Some(target_capacity) = capped.and_then(|value| usize::try_from(value).ok()) else {
            return ClientAction::ExtremityDiff;
        };

        let mut depth = 0_u8;
        let mut buckets = 1_usize;

        while buckets.saturating_mul(MAX_BUCKET_SKETCH_CAPACITY) < target_capacity
            && depth < MAX_BUCKET_ROUND_DEPTH
        {
            depth = depth.saturating_add(1);
            buckets = buckets.saturating_mul(2);
        }

        let per_bucket = target_capacity
            .div_ceil(buckets)
            .clamp(MIN_BUCKET_SKETCH_CAPACITY, MAX_BUCKET_SKETCH_CAPACITY);
        let total_capacity = buckets.saturating_mul(per_bucket);

        // `buckets` is structurally bounded by MAX_BUCKET_ROUND_DEPTH (itself
        // derived from MAX_BUCKETS_PER_ROUND), so the first clause never
        // trips. The second is live for any max_aggregate_capacity below the
        // default MAX_BUCKETED_SKETCH_CAPACITY: an operator who configures a
        // ceiling lower than one round's worst-case provisioning should have
        // it enforced here, not silently ignored.
        if buckets > MAX_BUCKETS_PER_ROUND || total_capacity > self.max_aggregate_capacity {
            return ClientAction::ExtremityDiff;
        }

        let mut requests = alloc::vec::Vec::with_capacity(buckets);
        let Ok(max_prefix) = u64::try_from(buckets) else {
            return ClientAction::ExtremityDiff;
        };
        for prefix in 0..max_prefix {
            requests.push(BucketRequest::new(depth, prefix, per_bucket));
        }

        ClientAction::BucketSketches {
            requests,
            accumulated_roots: alloc::vec![],
        }
    }

    /// Builds the requester's unbucketed sketch over the negotiated frame.
    ///
    /// # Errors
    /// Returns an error for an invalid capacity or a zero short identifier.
    pub fn build_sketch(
        self,
        capacity: usize,
        hashes: impl IntoIterator<Item = ElementHash>,
    ) -> Result<SyndromeSketch, AlgebraicError> {
        if capacity == 0 || capacity > self.max_sketch_capacity {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        let mut sketch = SyndromeSketch::new(capacity)?;
        for hash in hashes {
            sketch.toggle(hash.h64)?;
        }
        Ok(sketch)
    }

    /// Advances the bucket-decoding exchange without discarding prior roots.
    ///
    /// Normal decode failures are retried at a strictly larger capacity. A
    /// missing prior request, a failed maximum-capacity bucket, or an aggregate
    /// retry above the wire cap falls back to bounded extremity discovery.
    ///
    /// `aggregate_cap` is trusted as-is, not clamped to
    /// [`MAX_BUCKETED_SKETCH_CAPACITY`] -- unlike [`ReconciliationClient`]'s
    /// `select_action`/`BucketExchange` path, this static method has no
    /// `self` and so no [`ReconciliationClient::with_max_aggregate_capacity`]
    /// to read; a caller invoking it directly is responsible for passing a
    /// sane value.
    #[must_use]
    pub fn transition_bucket_batch(
        batch: BucketDecodeBatch,
        previous_requests: &[BucketRequest],
        mut accumulated_roots: alloc::vec::Vec<u64>,
        global_estimate: Option<u64>,
        aggregate_cap: usize,
    ) -> ClientAction {
        for success in batch.successful_buckets {
            accumulated_roots.extend(success.roots);
        }
        if batch.failed_buckets.is_empty() {
            return ClientAction::ResolveRoots {
                roots: accumulated_roots,
                ladder_failed: alloc::vec::Vec::new(),
            };
        }

        let Ok(resolved_count) = u64::try_from(accumulated_roots.len()) else {
            return ClientAction::ExtremityDiff;
        };
        let unaccounted = global_estimate.unwrap_or(0).saturating_sub(resolved_count);
        let failed_count = match u64::try_from(batch.failed_buckets.len()) {
            Ok(count) if count != 0 => count,
            _ => return ClientAction::ExtremityDiff,
        };
        let share = unaccounted.checked_div(failed_count).unwrap_or(0);
        let aggregate_limit = aggregate_cap;
        let mut total = 0_usize;
        let mut requests = alloc::vec::Vec::with_capacity(batch.failed_buckets.len());

        for (depth, prefix) in batch.failed_buckets {
            let Ok(next_requests) =
                retry_failed_bucket(previous_requests, depth, prefix, share, false)
            else {
                return ClientAction::ExtremityDiff;
            };
            for request in next_requests {
                total = match total.checked_add(request.capacity) {
                    Some(total) if total <= aggregate_limit => total,
                    _ => return ClientAction::ExtremityDiff,
                };
                if requests.len() >= MAX_BUCKETS_PER_ROUND {
                    return ClientAction::ExtremityDiff;
                }
                requests.push(request);
            }
        }
        requests.sort_unstable_by_key(bucket_range_start);
        ClientAction::BucketSketches {
            requests,
            accumulated_roots,
        }
    }

    /// Final step of [`crate::verify::verify_follow_up`]: checks the global
    /// 128-bit residual once roots are resolved to hashes.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::DecodeFailure`] when the supplied roots do not
    /// reproduce the residual.
    pub(crate) fn verify_global_residual(
        expected_residual: u128,
        local_roots: &[u128],
        remote_roots: &[u128],
    ) -> Result<(), AlgebraicError> {
        let actual = local_roots
            .iter()
            .chain(remote_roots)
            .fold(0, |residual, hash| residual ^ hash);
        (actual == expected_residual)
            .then_some(())
            .ok_or(AlgebraicError::DecodeFailure)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::vec;

    use super::*;

    fn hash(wide: u128, short: u64) -> ElementHash {
        ElementHash {
            h128: wide,
            h64: short,
        }
    }

    fn accumulator(hashes: &[ElementHash]) -> ResidentKernel {
        let mut kernel = ResidentKernel::new();
        for hash in hashes {
            kernel.insert(*hash).unwrap();
        }
        kernel
    }

    /// Remote kernel holding the odd values 1..=17, whose strata produce the
    /// sparse-tail estimator scenario exercised below.
    fn odd_element_kernel() -> ResidentKernel {
        let mut remote = ResidentKernel::new();
        for value in (1_u64..=17).step_by(2) {
            remote
                .insert(ElementHash {
                    h128: u128::from(value),
                    h64: value,
                })
                .unwrap();
        }
        remote
    }

    fn assert_sparse_tail_bucket_sketches(client: ReconciliationClient) {
        let local = ResidentKernel::new();
        let remote = odd_element_kernel();
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 1,
                    known_event_count: 9,
                    strata: *remote.strata(),
                    frame_matches: true,
                    has_unknown_extremity: false,
                },
                0,
            ),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest::new(0, 0, 31)],
                accumulated_roots: vec![],
            }
        );
    }

    /// Builds `count` max-capacity failed buckets at depth 7 together with the
    /// requests they were submitted under.
    fn failed_bucket_fanout(
        count: usize,
    ) -> (alloc::vec::Vec<(u8, u64)>, alloc::vec::Vec<BucketRequest>) {
        let mut failed_buckets = alloc::vec::Vec::with_capacity(count);
        let mut previous_requests = alloc::vec::Vec::with_capacity(count);
        for prefix in 0..count {
            let prefix = u64::try_from(prefix).expect("bucket fanout prefix fits in u64");
            failed_buckets.push((7, prefix));
            previous_requests.push(BucketRequest::new(7, prefix, MAX_BUCKET_SKETCH_CAPACITY));
        }
        (failed_buckets, previous_requests)
    }

    #[test]
    fn tests_client_builder_methods_and_accessors() {
        let client = ReconciliationClient::default()
            .with_max_rounds(42)
            .with_gate_threshold(Some(999));
        assert_eq!(client.max_rounds(), 42);
        assert_eq!(client.gate_threshold(), Some(999));

        let client = client.allow_unlimited_delta();
        assert_eq!(client.gate_threshold(), None);
    }

    #[test]
    fn raised_aggregate_capacity_scales_gate_threshold() {
        let client = ReconciliationClient::default().with_max_aggregate_capacity(8_192);
        assert_eq!(
            client.gate_threshold(),
            Some((MAX_RECONCILIATION_ROUNDS as u64) * 8_192)
        );
    }

    /// A delta past the default ~82k gate bails to `ExtremityDiff` under
    /// default policy, but proceeds to bucketed sketches once
    /// `with_max_aggregate_capacity` raises the round-budget gate past it.
    /// The first round's own provisioning is still bounded by
    /// `MAX_BUCKETS_PER_ROUND * MAX_BUCKET_SKETCH_CAPACITY` regardless --
    /// raising the aggregate capacity widens how many *rounds* of that fixed
    /// per-round ceiling the exchange is allowed to spend, via the gate.
    #[test]
    fn raised_aggregate_capacity_admits_deltas_past_the_default_gate() {
        let local = ResidentKernel::new();
        let remote_digest = RemoteDigest {
            digest: 1,
            known_event_count: 100_000,
            strata: [[0; STRATUM_CAPACITY]; STRATA_COUNT],
            frame_matches: true,
            has_unknown_extremity: false,
        };

        let default_client = ReconciliationClient::default();
        assert_eq!(
            default_client.select_action(&local, remote_digest, 0),
            ClientAction::ExtremityDiff,
            "100k-element delta should exceed the default ~82k gate"
        );

        let raised_client = ReconciliationClient::default().with_max_aggregate_capacity(8_192);
        let action = raised_client.select_action(&local, remote_digest, 0);
        let ClientAction::BucketSketches { requests, .. } = action else {
            panic!("expected bucket requests once the gate is raised past 100k, got {action:?}");
        };
        assert!(!requests.is_empty(), "expected at least one bucket request");
    }

    #[test]
    fn client_new_rejects_invalid_sketch_capacity() {
        assert_eq!(
            ReconciliationClient::new(0),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
    }

    #[test]
    fn selects_short_circuit_extremity_and_sketch_paths() {
        let local = accumulator(&[hash(1, 1), hash(2, 2)]);
        let client = ReconciliationClient::default();
        let matching = RemoteDigest {
            digest: local.accumulator().digest(),
            known_event_count: 2,
            strata: [[0; STRATUM_CAPACITY]; STRATA_COUNT],
            frame_matches: true,
            has_unknown_extremity: false,
        };
        assert_eq!(
            client.select_action(&local, matching, 0),
            ClientAction::Synchronized
        );
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    frame_matches: false,
                    ..matching
                },
                0,
            ),
            ClientAction::ExtremityDiff
        );
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 7,
                    known_event_count: 6,
                    ..matching
                },
                2,
            ),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest::new(0, 0, 12)],
                accumulated_roots: vec![],
            }
        );
    }

    #[test]
    fn provision_capacity_rounds_up_odd_deltas() {
        assert_eq!(provision_capacity(5, 2), Some(14));
        assert_eq!(provision_capacity(18, 0), Some(31));
    }

    #[test]
    fn caps_large_and_two_sided_differences_for_localization() {
        let client = ReconciliationClient::new(16).unwrap();
        let local = accumulator(&[hash(1, 1)]);
        let expected_requests = (0..64)
            .map(|prefix| BucketRequest::new(6, prefix, 24))
            .collect();
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 2,
                    known_event_count: 1_000,
                    strata: *local.strata(),
                    frame_matches: true,
                    has_unknown_extremity: false,
                },
                0,
            ),
            ClientAction::BucketSketches {
                requests: expected_requests,
                accumulated_roots: vec![],
            }
        );
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 2,
                    known_event_count: 1,
                    strata: *local.strata(),
                    frame_matches: true,
                    has_unknown_extremity: false,
                },
                0,
            ),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest::new(0, 0, 4)],
                accumulated_roots: vec![],
            }
        );
    }

    #[test]
    fn capacity_overflow_falls_back_to_extremity_diff() {
        let client = ReconciliationClient::default();
        assert_eq!(
            client.select_action(
                &ResidentKernel::new(),
                RemoteDigest {
                    digest: 1,
                    known_event_count: u64::MAX,
                    strata: [[0; STRATUM_CAPACITY]; STRATA_COUNT],
                    frame_matches: true,
                    has_unknown_extremity: false,
                },
                usize::MAX,
            ),
            ClientAction::ExtremityDiff
        );
    }

    #[test]
    fn sparse_tail_estimator_failure_proceeds_with_bucket_sketches() {
        assert_sparse_tail_bucket_sketches(ReconciliationClient::default());
    }

    #[test]
    fn sparse_tail_estimator_failure_proceeds_with_bucket_sketches_even_without_gate() {
        assert_sparse_tail_bucket_sketches(ReconciliationClient::default().allow_unlimited_delta());
    }

    #[test]
    fn select_action_rejects_unknown_extremity_and_gated_estimates() {
        let local = ResidentKernel::new();
        let remote = odd_element_kernel();

        let client = ReconciliationClient::default().with_gate_threshold(Some(10));
        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 1,
                    known_event_count: 9,
                    strata: *remote.strata(),
                    frame_matches: true,
                    has_unknown_extremity: true,
                },
                0,
            ),
            ClientAction::ExtremityDiff
        );

        assert_eq!(
            client.select_action(
                &local,
                RemoteDigest {
                    digest: 1,
                    known_event_count: 9,
                    strata: *remote.strata(),
                    frame_matches: true,
                    has_unknown_extremity: false,
                },
                0,
            ),
            ClientAction::ExtremityDiff
        );
    }

    #[test]
    fn bucket_transition_resolves_and_preserves_roots() {
        let batch = BucketDecodeBatch {
            successful_buckets: vec![super::super::triage::BucketDecodeSuccess {
                depth: 8,
                prefix: 1,
                roots: vec![42],
            }],
            failed_buckets: vec![],
        };
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(batch, &[], vec![99], None, 4096),
            ClientAction::ResolveRoots {
                roots: vec![99, 42],
                ladder_failed: vec![],
            }
        );
    }

    #[test]
    fn bucket_transition_retries_and_preserves_partial_successes() {
        let batch = BucketDecodeBatch {
            successful_buckets: vec![super::super::triage::BucketDecodeSuccess {
                depth: 8,
                prefix: 1,
                roots: vec![42],
            }],
            failed_buckets: vec![(8, 2)],
        };
        let previous = [BucketRequest::new(8, 2, 8)];
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(batch, &previous, vec![99], None, 4096,),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest::new(8, 2, 18)],
                accumulated_roots: vec![99, 42],
            }
        );
    }

    #[test]
    fn retry_or_split_bucket_retries_small_capacity_buckets() {
        let next_requests = retry_or_split_bucket(&BucketRequest::new(8, 2, 8), 10, false)
            .expect("small-capacity buckets should retry");

        assert_eq!(
            next_requests.into_iter().collect::<alloc::vec::Vec<_>>(),
            vec![BucketRequest::new(8, 2, 19)]
        );
    }

    #[test]
    fn retry_or_split_bucket_falls_back_on_small_capacity_overflow() {
        assert_eq!(
            retry_or_split_bucket(&BucketRequest::new(8, 2, 8), u64::MAX, false),
            Err(ClientAction::ExtremityDiff)
        );
    }

    #[test]
    fn bucket_transition_falls_back_without_panicking() {
        let batch = BucketDecodeBatch {
            successful_buckets: vec![],
            failed_buckets: vec![(8, 3)],
        };
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(
                batch.clone(),
                &[BucketRequest::new(8, 3, MAX_BUCKET_SKETCH_CAPACITY)],
                vec![],
                None,
                4096,
            ),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest::new(9, 6, 10), BucketRequest::new(9, 7, 10),],
                accumulated_roots: vec![],
            }
        );
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(
                batch,
                &[BucketRequest::new(8, 1, 8)],
                vec![],
                None,
                4096,
            ),
            ClientAction::ExtremityDiff
        );
    }

    #[test]
    fn bucket_transition_falls_back_when_retry_fanout_exceeds_round_cap() {
        let (failed_buckets, previous_requests) = failed_bucket_fanout(65);

        let batch = BucketDecodeBatch {
            successful_buckets: vec![],
            failed_buckets,
        };

        assert_eq!(
            ReconciliationClient::transition_bucket_batch(
                batch,
                &previous_requests,
                vec![],
                None,
                MAX_BUCKETED_SKETCH_CAPACITY,
            ),
            ClientAction::ExtremityDiff
        );
    }

    #[test]
    fn bucket_exchange_carries_pending_frontier_across_rounds() {
        let mut exchange = BucketExchange::new(
            vec![99],
            MAX_RECONCILIATION_ROUNDS,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        );
        assert_eq!(exchange.accumulated_roots(), &[99]);

        let (failed_buckets, previous_requests) = failed_bucket_fanout(65);

        let first = exchange.advance(
            BucketDecodeBatch {
                successful_buckets: vec![super::super::triage::BucketDecodeSuccess {
                    depth: 0,
                    prefix: 0,
                    roots: vec![42],
                }],
                failed_buckets,
            },
            &previous_requests,
            Some(10_000),
        );
        let ClientAction::BucketSketches {
            requests: second_requests,
            accumulated_roots,
        } = first
        else {
            panic!("expected queued bucket requests");
        };
        assert_eq!(accumulated_roots, vec![99, 42]);
        assert_eq!(second_requests.len(), MAX_BUCKETS_PER_ROUND);
        assert_eq!(exchange.pending_len(), 2);
        assert_eq!(exchange.rounds_emitted(), 1);

        let second = exchange.advance(
            BucketDecodeBatch {
                successful_buckets: vec![],
                failed_buckets: vec![],
            },
            &second_requests,
            Some(10_000),
        );
        let ClientAction::BucketSketches {
            requests: third_requests,
            accumulated_roots,
        } = second
        else {
            panic!("expected pending frontier to drain on next round");
        };
        assert_eq!(accumulated_roots, vec![99, 42]);
        assert_eq!(third_requests.len(), 2);
        assert_eq!(exchange.pending_len(), 0);
        assert_eq!(exchange.rounds_emitted(), 2);

        let final_action = exchange.advance(
            BucketDecodeBatch {
                successful_buckets: vec![],
                failed_buckets: vec![],
            },
            &third_requests,
            Some(10_000),
        );
        assert_eq!(
            final_action,
            ClientAction::ResolveRoots {
                roots: vec![99, 42],
                ladder_failed: vec![],
            }
        );
    }

    /// Round 1 for the no-progress/narrowing tests: one max-capacity bucket
    /// fails outright, forcing an immediate depth split (no sibling exists
    /// yet this round).
    fn advance_failed_root_bucket(exchange: &mut BucketExchange) -> ClientAction {
        exchange.advance(
            BucketDecodeBatch {
                successful_buckets: vec![],
                failed_buckets: vec![(7, 0)],
            },
            &[BucketRequest::new(7, 0, MAX_BUCKET_SKETCH_CAPACITY)],
            Some(u64::MAX / 2),
        )
    }

    /// Coverage: `BucketExchange::advance`'s no-progress detection. A
    /// bucket that keeps splitting with both split children failing
    /// (neither sibling succeeds) must bail to `ExtremityDiff` after
    /// `MAX_NO_PROGRESS_ROUNDS`, well before `max_rounds` -- the scenario
    /// an attacker who can predict h64 placement (see
    /// `ElementHash::from_digest32`'s doc comment in algebraic.rs) can
    /// otherwise force.
    #[test]
    fn bucket_exchange_bails_after_consecutive_no_progress_splits() {
        let mut exchange = BucketExchange::new(
            vec![],
            MAX_RECONCILIATION_ROUNDS,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        );

        // Round 1: a single bucket at max capacity fails outright, forcing
        // an immediate depth split (no sibling exists yet this round).
        let mut action = advance_failed_root_bucket(&mut exchange);

        // Rounds 2..: every split's children BOTH keep failing -- neither
        // sibling succeeds, nothing separates out or narrows.
        let mut rounds = 1;
        while let ClientAction::BucketSketches { requests, .. } = &action {
            let failed_buckets = requests.iter().map(|r| (r.depth, r.prefix)).collect();
            let previous_requests = requests.clone();
            action = exchange.advance(
                BucketDecodeBatch {
                    successful_buckets: vec![],
                    failed_buckets,
                },
                &previous_requests,
                Some(u64::MAX / 2),
            );
            rounds += 1;
            assert!(
                rounds < MAX_RECONCILIATION_ROUNDS,
                "no-progress detection should bail well before max_rounds \
                 ({MAX_RECONCILIATION_ROUNDS}); still going at round {rounds}: {action:?}"
            );
        }

        assert_eq!(
            action,
            ClientAction::ExtremityDiff,
            "a persistently stalled split must bail to ExtremityDiff, not keep splitting: \
             stopped after {rounds} rounds"
        );
        assert!(
            rounds <= MAX_NO_PROGRESS_ROUNDS.saturating_add(2),
            "should bail within a couple rounds of the {MAX_NO_PROGRESS_ROUNDS}-round \
             threshold, not ride out most of max_rounds; took {rounds} rounds"
        );
    }

    /// Coverage: narrowing splits (where one child succeeds, even with zero roots)
    /// must NOT count as stalled, allowing the client to continue splitting the
    /// dense child to decode the difference.
    #[test]
    fn bucket_exchange_continues_on_narrowing_splits() {
        let mut exchange = BucketExchange::new(
            vec![],
            MAX_RECONCILIATION_ROUNDS,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        );

        let mut action = advance_failed_root_bucket(&mut exchange);

        // Run 5 narrowing split rounds (more than MAX_NO_PROGRESS_ROUNDS).
        // Each round, left fails and right succeeds with 0 roots.
        for _ in 0..5 {
            let ClientAction::BucketSketches { requests, .. } = &action else {
                panic!("expected BucketSketches action on narrowing split");
            };
            let left = requests[0];
            let right = requests[1];
            let previous_requests = requests.clone();
            action = exchange.advance(
                BucketDecodeBatch {
                    successful_buckets: vec![super::super::triage::BucketDecodeSuccess {
                        depth: right.depth,
                        prefix: right.prefix,
                        roots: vec![],
                    }],
                    failed_buckets: vec![(left.depth, left.prefix)],
                },
                &previous_requests,
                Some(u64::MAX / 2),
            );
        }

        assert!(
            matches!(action, ClientAction::BucketSketches { .. }),
            "narrowing splits must continue splitting without bailing early: got {action:?}"
        );
    }

    #[test]
    fn bucket_exchange_stops_round_when_aggregate_cap_would_be_exceeded() {
        let mut exchange =
            BucketExchange::new(vec![], MAX_RECONCILIATION_ROUNDS, MAX_BUCKETS_PER_ROUND, 25);

        let previous_requests = [BucketRequest::new(0, 0, 8), BucketRequest::new(0, 1, 8)];

        let action = exchange.advance(
            BucketDecodeBatch {
                successful_buckets: vec![],
                failed_buckets: vec![(0, 0), (0, 1)],
            },
            &previous_requests,
            Some(18),
        );

        let ClientAction::BucketSketches {
            requests,
            accumulated_roots,
        } = action
        else {
            panic!("expected a partially drained request round");
        };

        assert!(accumulated_roots.is_empty());
        assert_eq!(requests, vec![BucketRequest::new(0, 0, 18)]);
        assert_eq!(exchange.pending_len(), 1);
        assert_eq!(exchange.rounds_emitted(), 1);
    }

    #[test]
    fn builds_a_decodable_local_sketch() {
        let hashes = [hash(1, 3), hash(2, 5)];
        let sketch = ReconciliationClient::default()
            .build_sketch(4, hashes)
            .unwrap();
        assert_eq!(sketch.decode_elements(4).unwrap().as_slice(), &[3, 5]);
    }

    #[test]
    fn verifies_global_residual_before_admission() {
        assert_eq!(
            ReconciliationClient::verify_global_residual(0x3333, &[0x1111], &[0x2222]),
            Ok(())
        );
        assert_eq!(
            ReconciliationClient::verify_global_residual(0x7777, &[0x1111], &[0x2222]),
            Err(AlgebraicError::DecodeFailure)
        );
        assert_eq!(
            ReconciliationClient::verify_global_residual(0xaaaa, &[0x1111], &[0x2222]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    /// A 64-bit collision cannot be derived from real event IDs, so it is
    /// mocked: two distinct elements (different `h128`) forced to one `h64`.
    /// The sketch layer sees the pair cancel, the roots resolve to nothing,
    /// and the 128-bit residual -- which is not truncated -- refuses to
    /// admit the result, sending the caller down the fallback ladder.
    #[test]
    fn colliding_h64_decodes_clean_but_fails_the_global_residual() {
        let colliding_local = hash(0xAAAA, 0x1234);
        let colliding_remote = hash(0xBBBB, 0x1234);
        let shared = hash(0xCCCC, 0x9999);

        let client = ReconciliationClient::default();
        let local = client.build_sketch(4, [colliding_local, shared]).unwrap();
        let remote = client.build_sketch(4, [colliding_remote, shared]).unwrap();
        let roots = local.subtract(&remote).unwrap().decode_elements(4).unwrap();
        assert!(roots.is_empty(), "equal h64 values must cancel");

        let local_digest = accumulator(&[colliding_local, shared])
            .accumulator()
            .digest();
        let remote_digest = accumulator(&[colliding_remote, shared])
            .accumulator()
            .digest();
        let residual = local_digest ^ remote_digest;
        assert_eq!(residual, 0xAAAA ^ 0xBBBB);

        // No roots resolved, so nothing accounts for the non-zero residual.
        assert_eq!(
            ReconciliationClient::verify_global_residual(residual, &[], &[]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn collision_alongside_a_real_difference_still_fails_the_residual() {
        let colliding_local = hash(0xAAAA, 0x1234);
        let colliding_remote = hash(0xBBBB, 0x1234);
        let only_remote = hash(0xDDDD, 0x5555);

        let client = ReconciliationClient::default();
        let local = client.build_sketch(4, [colliding_local]).unwrap();
        let remote = client
            .build_sketch(4, [colliding_remote, only_remote])
            .unwrap();
        let roots = local.subtract(&remote).unwrap().decode_elements(4).unwrap();
        assert_eq!(roots, vec![only_remote.h64]);

        let residual = 0xAAAA ^ 0xBBBB ^ 0xDDDD;
        // Resolving the one decoded root explains only its own h128.
        assert_eq!(
            ReconciliationClient::verify_global_residual(residual, &[], &[only_remote.h128]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn collision_free_difference_passes_the_residual() {
        let local_only = hash(0xAAAA, 0x1234);
        let remote_only = hash(0xBBBB, 0x4321);
        let residual = 0xAAAA ^ 0xBBBB;
        assert_eq!(
            ReconciliationClient::verify_global_residual(
                residual,
                &[local_only.h128],
                &[remote_only.h128]
            ),
            Ok(())
        );
    }

    fn fresh_exchange() -> BucketExchange {
        BucketExchange::new(
            vec![],
            MAX_RECONCILIATION_ROUNDS,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        )
    }

    fn summary(count: u64, digest: u128) -> NodeSummary {
        NodeSummary { count, digest }
    }

    fn success(depth: u8, prefix: u64, roots: &[u64]) -> BucketDecodeBatch {
        BucketDecodeBatch {
            successful_buckets: vec![crate::triage::BucketDecodeSuccess {
                depth,
                prefix,
                roots: roots.to_vec(),
            }],
            failed_buckets: vec![],
        }
    }

    fn undecodable(depth: u8, prefix: u64) -> BucketDecodeBatch {
        BucketDecodeBatch {
            successful_buckets: vec![],
            failed_buckets: vec![(depth, prefix)],
        }
    }

    /// A phase-1 failure is not a capacity problem: the node is split, never
    /// re-requested at a bigger capacity.
    #[test]
    fn phase_one_failure_splits_instead_of_bumping_capacity() {
        let mut exchange = fresh_exchange();
        let action = exchange
            .advance_verified(
                success(0, 0, &[5]),
                &[BucketRequest::new(0, 0, 8)],
                &[summary(0, 0)],
                &[summary(0, 0)],
                None,
                |_| vec![],
            )
            .unwrap();
        let ClientAction::BucketSketches { requests, .. } = action else {
            panic!("expected a retry round, got {action:?}");
        };
        assert_eq!(
            requests
                .iter()
                .map(|r| (r.depth, r.prefix))
                .collect::<alloc::vec::Vec<_>>(),
            vec![(1, 0), (1, 1)],
            "children, not the same node at a larger capacity"
        );
    }

    /// At the depth cap no split is possible: give up on that prefix instead
    /// of escalating the whole exchange.
    #[test]
    fn phase_one_failure_at_the_depth_cap_ladder_fails_that_prefix() {
        let mut exchange = fresh_exchange();
        let action = exchange
            .advance_verified(
                success(crate::MAX_DEPTH, 0, &[5]),
                &[BucketRequest::new(crate::MAX_DEPTH, 0, 8)],
                &[summary(0, 0)],
                &[summary(0, 0)],
                None,
                |_| vec![],
            )
            .unwrap();
        assert_eq!(
            action,
            ClientAction::ResolveRoots {
                roots: vec![],
                ladder_failed: vec![(crate::MAX_DEPTH, 0)],
            }
        );
    }

    /// With no round left to split in, the prefix is given up on, not the
    /// exchange.
    #[test]
    fn phase_one_failure_without_round_budget_ladder_fails_that_prefix() {
        let mut exchange = BucketExchange::new(
            vec![],
            1,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        );
        let action = exchange
            .advance_verified(
                success(0, 0, &[5]),
                &[BucketRequest::new(0, 0, 8)],
                &[summary(0, 0)],
                &[summary(0, 0)],
                None,
                |_| vec![],
            )
            .unwrap();
        assert_eq!(
            action,
            ClientAction::ResolveRoots {
                roots: vec![],
                ladder_failed: vec![(0, 0)],
            }
        );
    }

    /// A known collision in a large node keeps being split rather than given
    /// up on; it is only given up on once its population is small.
    #[test]
    fn known_collision_in_a_large_node_keeps_splitting() {
        let mut exchange = fresh_exchange();
        let big = summary(1_000, 0);
        for capacity in [8_usize, 16] {
            let action = exchange
                .advance_verified(
                    success(0, 0, &[5]),
                    &[BucketRequest::new(0, 0, capacity)],
                    &[big],
                    &[big],
                    None,
                    |_| vec![],
                )
                .unwrap();
            assert!(matches!(action, ClientAction::BucketSketches { .. }));
        }
        assert!(exchange.ladder_failed().is_empty());
    }

    /// A node verified with equal summaries on both sides and no roots.
    fn classify(depth: u8, prefix: u64, s: NodeSummary) -> Classified {
        let request = BucketRequest::new(depth, prefix, 8);
        crate::verify::verify_decode(&request, s, s, &[], |_| vec![]).unwrap()
    }

    /// `narrow` re-runs just the children of the given nodes.
    #[test]
    fn narrow_requests_the_children_of_each_node() {
        let (exchange, requests) = BucketExchange::narrow(
            &[classify(2, 1, summary(100, 7))],
            MAX_RECONCILIATION_ROUNDS,
            MAX_BUCKETS_PER_ROUND,
            MAX_BUCKETED_SKETCH_CAPACITY,
        )
        .unwrap();
        assert_eq!(
            requests
                .iter()
                .map(|r| (r.depth, r.prefix))
                .collect::<alloc::vec::Vec<_>>(),
            vec![(3, 2), (3, 3)]
        );
        assert_eq!(exchange.rounds_emitted(), 1);
        // A node at the depth cap cannot be narrowed, and overlapping nodes
        // are not an antichain.
        let s = summary(1, 1);
        let at_cap = classify(crate::MAX_DEPTH, 0, s);
        assert!(BucketExchange::narrow(&[at_cap], 20, 8, 4096).is_err());
        let overlapping = [classify(1, 0, s), classify(2, 0, s)];
        assert!(BucketExchange::narrow(&overlapping, 20, 8, 4096).is_err());
    }

    /// Children beyond the per-round cap are queued, not an error.
    #[test]
    fn narrow_queues_children_beyond_the_round_cap() {
        let s = summary(100, 7);
        let (exchange, requests) = BucketExchange::narrow(
            &[classify(2, 0, s), classify(2, 1, s), classify(2, 2, s)],
            20,
            2,
            4096,
        )
        .unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(exchange.pending_len(), 4);
    }

    /// The parent summaries seed split consistency, so a peer whose children
    /// do not add up to the node being narrowed is caught on this path too.
    #[test]
    fn narrow_checks_split_consistency_of_its_children() {
        let (mut exchange, requests) =
            BucketExchange::narrow(&[classify(2, 1, summary(10, 0xff))], 20, 8, 4096).unwrap();
        let (a, b) = (summary(5, 1), summary(5, 2));
        let mut batch = success(3, 2, &[]);
        batch
            .successful_buckets
            .extend(success(3, 3, &[]).successful_buckets);
        exchange
            .advance_verified(batch, &requests, &[a, b], &[a, b], None, |_| vec![])
            .unwrap();
        assert_eq!(exchange.ladder_failed(), &[(2, 1)]);
    }

    /// The phase-2 stop rule mirrors phase 1's: large, splittable, budget left.
    #[test]
    fn should_narrow_follows_the_phase_one_limits() {
        let classify = |depth: u8, count: u64| classify(depth, 0, summary(count, 0));
        assert!(should_narrow(&classify(2, 1_000), 10));
        assert!(!should_narrow(
            &classify(2, COLLISION_GIVE_UP_POPULATION),
            10
        ));
        assert!(!should_narrow(&classify(crate::MAX_DEPTH, 1_000), 10));
        assert!(!should_narrow(&classify(2, 1_000), 1));
    }

    /// Decoding the same sketch twice is deterministic, so a repeat of the
    /// same `(depth, capacity)` proves nothing; only a different sketch
    /// returning the same restricted roots identifies a collision.
    #[test]
    fn same_sketch_repeat_is_not_a_collision_but_a_different_sketch_is() {
        let mut exchange = fresh_exchange();
        let remote = [summary(0, 0)];
        let local = [summary(0, 0)];
        // Root 5 is remote-only but the counts say nothing differs: phase 1
        // rejects it.
        let attempt = |exchange: &mut BucketExchange, capacity: usize| {
            exchange
                .advance_verified(
                    success(0, 0, &[5]),
                    &[BucketRequest::new(0, 0, capacity)],
                    &local,
                    &remote,
                    None,
                    |_| vec![],
                )
                .unwrap()
        };
        let _ = attempt(&mut exchange, 8);
        let _ = attempt(&mut exchange, 8);
        assert!(
            exchange.ladder_failed().is_empty(),
            "same sketch twice must not classify a collision"
        );
        let _ = attempt(&mut exchange, 16);
        assert_eq!(exchange.ladder_failed(), &[(0, 0)]);
    }

    /// Different roots under a different sketch is a spurious decode, not a
    /// collision, and keeps escalating normally.
    #[test]
    fn different_roots_under_a_new_sketch_are_not_a_collision() {
        let mut exchange = fresh_exchange();
        let remote = [summary(0, 0)];
        let local = [summary(0, 0)];
        for (capacity, root) in [(8, 5_u64), (16, 9)] {
            let _ = exchange
                .advance_verified(
                    success(0, 0, &[root]),
                    &[BucketRequest::new(0, 0, capacity)],
                    &local,
                    &remote,
                    None,
                    |_| vec![],
                )
                .unwrap();
        }
        assert!(exchange.ladder_failed().is_empty());
    }

    /// The children of a split may arrive in different rounds. When they do not
    /// add up to the parent the responder is inconsistent, which no capacity
    /// bump or split can fix: the parent goes straight to ladder-failed, and
    /// the child already admitted is withdrawn.
    #[test]
    fn inconsistent_split_children_across_rounds_ladder_fail_the_parent() {
        let mut exchange = fresh_exchange();
        let max = MAX_BUCKET_SKETCH_CAPACITY;
        // Round 1: the parent cannot be decoded; remember its summary.
        let _ = exchange
            .advance_verified(
                undecodable(0, 0),
                &[BucketRequest::new(0, 0, max)],
                &[summary(4, 0xF)],
                &[summary(4, 0xF)],
                None,
                |_| vec![],
            )
            .unwrap();
        // Round 2: one child verifies and is admitted.
        let _ = exchange
            .advance_verified(
                success(1, 0, &[]),
                &[BucketRequest::new(1, 0, 8)],
                &[summary(2, 0x3)],
                &[summary(2, 0x3)],
                None,
                |_| vec![],
            )
            .unwrap();
        assert_eq!(exchange.classified().len(), 1);
        assert!(exchange.ladder_failed().is_empty());
        // Round 3: the sibling arrives and the pair no longer sums to the parent.
        let action = exchange
            .advance_verified(
                success(1, 1, &[]),
                &[BucketRequest::new(1, 1, 8)],
                &[summary(3, 0xC)],
                &[summary(3, 0xC)],
                None,
                |_| vec![],
            )
            .unwrap();
        assert_eq!(exchange.ladder_failed(), &[(0, 0)]);
        assert!(exchange.classified().is_empty(), "admitted child withdrawn");
        assert_eq!(
            action,
            ClientAction::ResolveRoots {
                roots: vec![],
                ladder_failed: vec![(0, 0)],
            }
        );
    }

    #[test]
    fn consistent_split_children_across_rounds_are_admitted() {
        let mut exchange = fresh_exchange();
        let max = MAX_BUCKET_SKETCH_CAPACITY;
        let _ = exchange
            .advance_verified(
                undecodable(0, 0),
                &[BucketRequest::new(0, 0, max)],
                &[summary(4, 0xF)],
                &[summary(4, 0xF)],
                None,
                |_| vec![],
            )
            .unwrap();
        for (prefix, count, digest) in [(0_u64, 2_u64, 0x3_u128), (1, 2, 0xC)] {
            let _ = exchange
                .advance_verified(
                    success(1, prefix, &[]),
                    &[BucketRequest::new(1, prefix, 8)],
                    &[summary(count, digest)],
                    &[summary(count, digest)],
                    None,
                    |_| vec![],
                )
                .unwrap();
        }
        assert!(exchange.ladder_failed().is_empty());
        assert_eq!(exchange.classified().len(), 2);
    }

    #[test]
    fn test_bucket_round_depth() {
        assert_eq!(bucket_round_depth(1), 0);
        assert_eq!(bucket_round_depth(2), 1);
        assert_eq!(bucket_round_depth(3), 1);
        assert_eq!(bucket_round_depth(4), 2);
        assert_eq!(bucket_round_depth(5), 2);
        assert_eq!(bucket_round_depth(127), 6);
        assert_eq!(bucket_round_depth(128), 7);
        assert_eq!(bucket_round_depth(255), 7);
        assert_eq!(bucket_round_depth(256), 8);
    }
}
