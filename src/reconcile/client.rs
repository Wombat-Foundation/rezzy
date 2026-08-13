// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Requester-side MSC0501 reconciliation decisions and verification over MSC4521 digests.

use super::resident::{ResidentKernel, STRATA_COUNT, STRATUM_CAPACITY};
use super::triage::{
    bucket_range_start, BucketDecodeBatch, BucketRequest, MAX_BUCKETED_SKETCH_CAPACITY,
    MAX_BUCKET_SKETCH_CAPACITY, SATURATED_DELTA_ESTIMATE,
};
use super::{AlgebraicError, ElementHash, SyndromeSketch, MAX_LOCAL_SKETCH_DECODE_CAPACITY};
use alloc::collections::VecDeque;

/// Baseline policy limit for maximum reconciliation rounds in a single exchange.
///
/// Paired with [`MAX_BUCKETED_SKETCH_CAPACITY`], the default 20-round limit yields a
/// default operating point of ~82,000 differing elements before falling back to
/// extremity-based frame diffing under default client policy.
pub const MAX_RECONCILIATION_ROUNDS: usize = 20;
/// Maximum number of bucket requests emitted in one reconciliation round.
pub const MAX_BUCKETS_PER_ROUND: usize = 128;
/// Maximum split depth implied by `MAX_BUCKETS_PER_ROUND`.
pub const MAX_BUCKET_ROUND_DEPTH: u8 = bucket_round_depth(MAX_BUCKETS_PER_ROUND);

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

/// Requester policy for one MSC0501 reconciliation exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationClient {
    max_sketch_capacity: usize,
    max_rounds: usize,
    gate_threshold: Option<u64>,
}

/// Information learned from the responder's room digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteDigest {
    pub digest: u128,
    pub known_event_count: u64,
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
        requests: alloc::vec::Vec<BucketRequest>,
        accumulated_roots: alloc::vec::Vec<u64>,
    },
    /// All requested buckets decoded and are ready for host-side resolution.
    ResolveRoots { roots: alloc::vec::Vec<u64> },
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
}

impl BucketExchange {
    /// Creates a new pending-queue planner with the default round and wire caps.
    #[must_use]
    pub fn new(
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
            max_aggregate_capacity: max_aggregate_capacity.min(MAX_BUCKETED_SKETCH_CAPACITY),
            max_pending_requests: max_rounds.saturating_mul(max_buckets_per_round),
        }
    }

    /// Returns the accumulated roots carried through the exchange so far.
    #[must_use]
    pub fn accumulated_roots(&self) -> &[u64] {
        &self.accumulated_roots
    }

    /// Returns the number of request rounds emitted from the pending frontier.
    #[must_use]
    pub fn rounds_emitted(&self) -> usize {
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
            let Some(previous) = previous_requests
                .iter()
                .find(|request| request.prefix == prefix && request.depth == depth)
            else {
                return ClientAction::ExtremityDiff;
            };
            let Ok(next_requests) = retry_or_split_bucket(previous, share) else {
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

fn retry_or_split_bucket(
    previous: &BucketRequest,
    share: u64,
) -> Result<VecDeque<BucketRequest>, ClientAction> {
    let mut requests = VecDeque::new();

    if previous.capacity < MAX_BUCKET_SKETCH_CAPACITY {
        let Some(floor) = previous.capacity.checked_add(1) else {
            return Err(ClientAction::ExtremityDiff);
        };
        let Ok(floor_u64) = u64::try_from(floor) else {
            return Err(ClientAction::ExtremityDiff);
        };
        let target = share.max(floor_u64);
        let provisioned = target
            .checked_add(target / 2)
            .and_then(|value| value.checked_add(target % 2))
            .and_then(|value| value.checked_add(4));
        let capacity = provisioned
            .and_then(|value| usize::try_from(value).ok())
            .map(|value| value.clamp(floor, MAX_BUCKET_SKETCH_CAPACITY));
        let Some(capacity) = capacity else {
            return Err(ClientAction::ExtremityDiff);
        };
        requests.push_back(BucketRequest {
            depth: previous.depth,
            prefix: previous.prefix,
            capacity,
        });
        return Ok(requests);
    }

    if previous.depth >= 31 {
        return Err(ClientAction::ExtremityDiff);
    }

    let floor = 4_usize;
    let Ok(floor_u64) = u64::try_from(floor) else {
        return Err(ClientAction::ExtremityDiff);
    };
    let target = (share / 2).max(floor_u64);
    let provisioned = target
        .checked_add(target / 2)
        .and_then(|value| value.checked_add(target % 2))
        .and_then(|value| value.checked_add(4));
    let capacity = provisioned
        .and_then(|value| usize::try_from(value).ok())
        .map(|value| value.clamp(floor, MAX_BUCKET_SKETCH_CAPACITY));
    let Some(capacity) = capacity else {
        return Err(ClientAction::ExtremityDiff);
    };

    let Some(next_depth) = previous.depth.checked_add(1) else {
        return Err(ClientAction::ExtremityDiff);
    };

    requests.push_back(BucketRequest {
        depth: next_depth,
        prefix: previous.prefix << 1,
        capacity,
    });
    requests.push_back(BucketRequest {
        depth: next_depth,
        prefix: (previous.prefix << 1) | 1,
        capacity,
    });

    Ok(requests)
}
impl Default for ReconciliationClient {
    fn default() -> Self {
        Self {
            max_sketch_capacity: MAX_LOCAL_SKETCH_DECODE_CAPACITY,
            max_rounds: MAX_RECONCILIATION_ROUNDS,
            gate_threshold: u64::try_from(
                MAX_RECONCILIATION_ROUNDS.saturating_mul(MAX_BUCKETED_SKETCH_CAPACITY),
            )
            .ok(),
        }
    }
}

impl ReconciliationClient {
    /// Creates a requester with an explicit local unbucketed decode limit.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::InvalidSketchCapacity`] for a zero limit or a
    /// limit above the implementation's local decode policy.
    pub fn new(max_sketch_capacity: usize) -> Result<Self, AlgebraicError> {
        if max_sketch_capacity == 0 || max_sketch_capacity > MAX_LOCAL_SKETCH_DECODE_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(Self {
            max_sketch_capacity,
            max_rounds: MAX_RECONCILIATION_ROUNDS,
            gate_threshold: u64::try_from(
                MAX_RECONCILIATION_ROUNDS.saturating_mul(MAX_BUCKETED_SKETCH_CAPACITY),
            )
            .ok(),
        })
    }

    /// Sets a custom maximum round count for the reconciliation client,
    /// adjusting the gate threshold accordingly.
    #[must_use]
    pub fn with_max_rounds(mut self, max_rounds: usize) -> Self {
        self.max_rounds = max_rounds;
        self.gate_threshold =
            u64::try_from(max_rounds.saturating_mul(MAX_BUCKETED_SKETCH_CAPACITY)).ok();
        self
    }

    /// Sets an explicit gate threshold on the maximum estimated delta.
    /// Pass `None` to disable delta gating entirely for large syncs.
    #[must_use]
    pub fn with_gate_threshold(mut self, threshold: Option<u64>) -> Self {
        self.gate_threshold = threshold;
        self
    }

    /// Disables the delta gate threshold entirely, allowing set reconciliation to proceed
    /// for arbitrarily large set differences.
    #[must_use]
    pub fn allow_unlimited_delta(mut self) -> Self {
        self.gate_threshold = None;
        self
    }

    /// Returns the maximum allowed rounds.
    #[must_use]
    pub fn max_rounds(self) -> usize {
        self.max_rounds
    }

    /// Returns the gate threshold, if active.
    #[must_use]
    pub fn gate_threshold(self) -> Option<u64> {
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
        let estimated_delta =
            match crate::reconcile::triage::estimate_strata(local.strata(), &remote.strata) {
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
        let target_capacity = provisioned
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(crate::reconcile::triage::MAX_BUCKETED_SKETCH_CAPACITY)
            .min(crate::reconcile::triage::MAX_BUCKETED_SKETCH_CAPACITY);

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
            .clamp(4, MAX_BUCKET_SKETCH_CAPACITY);
        let total_capacity = buckets.saturating_mul(per_bucket);

        if buckets > MAX_BUCKETS_PER_ROUND
            || total_capacity > crate::reconcile::triage::MAX_BUCKETED_SKETCH_CAPACITY
        {
            return ClientAction::ExtremityDiff;
        }

        let mut requests = alloc::vec::Vec::with_capacity(buckets);
        let max_prefix = u32::try_from(buckets).unwrap_or(0);
        for prefix in 0..max_prefix {
            requests.push(BucketRequest {
                depth,
                prefix,
                capacity: per_bucket,
            });
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
        let aggregate_limit = aggregate_cap.min(MAX_BUCKETED_SKETCH_CAPACITY);
        let mut total = 0_usize;
        let mut requests = alloc::vec::Vec::with_capacity(batch.failed_buckets.len());

        for (depth, prefix) in batch.failed_buckets {
            let Some(previous) = previous_requests
                .iter()
                .find(|request| request.prefix == prefix && request.depth == depth)
            else {
                return ClientAction::ExtremityDiff;
            };

            let Ok(next_requests) = retry_or_split_bucket(previous, share) else {
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

    /// Verifies the global 128-bit residual after roots are resolved to hashes.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::DecodeFailure`] when the supplied roots do not
    /// reproduce the residual.
    pub fn verify_global_residual(
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
                requests: vec![BucketRequest {
                    depth: 0,
                    prefix: 0,
                    capacity: 12,
                }],
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
            .map(|prefix| BucketRequest {
                depth: 6,
                prefix,
                capacity: 24,
            })
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
                requests: vec![BucketRequest {
                    depth: 0,
                    prefix: 0,
                    capacity: 4,
                }],
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
        let local = ResidentKernel::new();
        let mut remote = ResidentKernel::new();
        for value in (1_u64..=17).step_by(2) {
            remote
                .insert(ElementHash {
                    h128: u128::from(value),
                    h64: value,
                })
                .unwrap();
        }

        let client = ReconciliationClient::default();
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
                requests: vec![BucketRequest {
                    depth: 0,
                    prefix: 0,
                    capacity: 31,
                }],
                accumulated_roots: vec![],
            }
        );
    }

    #[test]
    fn sparse_tail_estimator_failure_proceeds_with_bucket_sketches_even_without_gate() {
        let local = ResidentKernel::new();
        let mut remote = ResidentKernel::new();
        for value in (1_u64..=17).step_by(2) {
            remote
                .insert(ElementHash {
                    h128: u128::from(value),
                    h64: value,
                })
                .unwrap();
        }

        let client = ReconciliationClient::default().allow_unlimited_delta();
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
                requests: vec![BucketRequest {
                    depth: 0,
                    prefix: 0,
                    capacity: 31,
                }],
                accumulated_roots: vec![],
            }
        );
    }

    #[test]
    fn select_action_rejects_unknown_extremity_and_gated_estimates() {
        let local = ResidentKernel::new();
        let mut remote = ResidentKernel::new();
        for value in (1_u64..=17).step_by(2) {
            remote
                .insert(ElementHash {
                    h128: u128::from(value),
                    h64: value,
                })
                .unwrap();
        }

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
                roots: vec![99, 42]
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
        let previous = [BucketRequest {
            depth: 8,
            prefix: 2,
            capacity: 8,
        }];
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(batch, &previous, vec![99], None, 4096,),
            ClientAction::BucketSketches {
                requests: vec![BucketRequest {
                    depth: 8,
                    prefix: 2,
                    capacity: 18,
                }],
                accumulated_roots: vec![99, 42],
            }
        );
    }

    #[test]
    fn retry_or_split_bucket_retries_small_capacity_buckets() {
        let next_requests = retry_or_split_bucket(
            &BucketRequest {
                depth: 8,
                prefix: 2,
                capacity: 8,
            },
            10,
        )
        .expect("small-capacity buckets should retry");

        assert_eq!(
            next_requests.into_iter().collect::<alloc::vec::Vec<_>>(),
            vec![BucketRequest {
                depth: 8,
                prefix: 2,
                capacity: 19,
            }]
        );
    }

    #[test]
    fn retry_or_split_bucket_falls_back_on_small_capacity_overflow() {
        assert_eq!(
            retry_or_split_bucket(
                &BucketRequest {
                    depth: 8,
                    prefix: 2,
                    capacity: 8,
                },
                u64::MAX,
            ),
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
                &[BucketRequest {
                    depth: 8,
                    prefix: 3,
                    capacity: MAX_BUCKET_SKETCH_CAPACITY,
                }],
                vec![],
                None,
                4096,
            ),
            ClientAction::BucketSketches {
                requests: vec![
                    BucketRequest {
                        depth: 9,
                        prefix: 6,
                        capacity: 10,
                    },
                    BucketRequest {
                        depth: 9,
                        prefix: 7,
                        capacity: 10,
                    },
                ],
                accumulated_roots: vec![],
            }
        );
        assert_eq!(
            ReconciliationClient::transition_bucket_batch(
                batch,
                &[BucketRequest {
                    depth: 8,
                    prefix: 1,
                    capacity: 8,
                }],
                vec![],
                None,
                4096,
            ),
            ClientAction::ExtremityDiff
        );
    }

    #[test]
    fn bucket_transition_falls_back_when_retry_fanout_exceeds_round_cap() {
        let mut failed_buckets = alloc::vec::Vec::with_capacity(65);
        let mut previous_requests = alloc::vec::Vec::with_capacity(65);
        for prefix in 0..65_u32 {
            failed_buckets.push((7, prefix));
            previous_requests.push(BucketRequest {
                depth: 7,
                prefix,
                capacity: MAX_BUCKET_SKETCH_CAPACITY,
            });
        }

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

        let mut previous_requests = alloc::vec::Vec::with_capacity(65);
        let mut failed_buckets = alloc::vec::Vec::with_capacity(65);
        for prefix in 0..65_u32 {
            failed_buckets.push((7, prefix));
            previous_requests.push(BucketRequest {
                depth: 7,
                prefix,
                capacity: MAX_BUCKET_SKETCH_CAPACITY,
            });
        }

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
                roots: vec![99, 42]
            }
        );
    }

    #[test]
    fn bucket_exchange_stops_round_when_aggregate_cap_would_be_exceeded() {
        let mut exchange =
            BucketExchange::new(vec![], MAX_RECONCILIATION_ROUNDS, MAX_BUCKETS_PER_ROUND, 25);

        let previous_requests = [
            BucketRequest {
                depth: 0,
                prefix: 0,
                capacity: 8,
            },
            BucketRequest {
                depth: 0,
                prefix: 1,
                capacity: 8,
            },
        ];

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
        assert_eq!(
            requests,
            vec![BucketRequest {
                depth: 0,
                prefix: 0,
                capacity: 18,
            }]
        );
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
