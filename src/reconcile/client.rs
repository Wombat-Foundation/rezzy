// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Requester-side MSC0501 reconciliation decisions and verification over MSC0500 digests.

use super::resident::{ResidentKernel, STRATA_COUNT, STRATUM_CAPACITY};
use super::triage::{
    BucketDecodeBatch, BucketRequest, MAX_BUCKETED_SKETCH_CAPACITY, MAX_BUCKET_SKETCH_CAPACITY,
};
use super::{AlgebraicError, ElementHash, SyndromeSketch, MAX_LOCAL_SKETCH_DECODE_CAPACITY};

/// Baseline policy limit for maximum reconciliation rounds in a single exchange.
///
/// Paired with [`MAX_BUCKETED_SKETCH_CAPACITY`], the default 20-round limit yields a
/// default operating point of ~82,000 differing elements before falling back to
/// extremity-based frame diffing under default client policy.
pub const MAX_RECONCILIATION_ROUNDS: usize = 20;

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
    /// the exchange. Capacity follows the MSC's `ceil(1.5 * count_delta) + 4`
    /// rule. Requests that exceed local policy are capped and ask for a bucket
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
            match crate::reconcile::triage::estimate_delta(local.strata(), &remote.strata) {
                Ok(Some(value)) => value.max(count_delta),
                Ok(None) => count_delta,
                Err(_) => return ClientAction::ExtremityDiff,
            };

        if let Some(threshold) = self.gate_threshold {
            if estimated_delta > threshold {
                return ClientAction::ExtremityDiff;
            }
        }

        let provisioned = u64::try_from(concurrency_headroom)
            .ok()
            .and_then(|headroom| {
                estimated_delta
                    .checked_add(estimated_delta / 2)
                    .and_then(|capacity| capacity.checked_add(estimated_delta % 2))
                    .and_then(|capacity| capacity.checked_add(4))
                    .and_then(|capacity| capacity.checked_add(headroom))
            });
        let target_capacity = provisioned
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(usize::MAX);

        let mut depth = 0_u8;
        let mut buckets = 1_usize;

        while buckets.saturating_mul(32) < target_capacity && depth < 6 {
            depth = depth.saturating_add(1);
            buckets = buckets.saturating_mul(2);
        }

        let per_bucket = target_capacity
            .div_ceil(buckets)
            .clamp(4, MAX_BUCKET_SKETCH_CAPACITY);
        let total_capacity = buckets.saturating_mul(per_bucket);

        if buckets > 64 || total_capacity > crate::reconcile::triage::MAX_BUCKETED_SKETCH_CAPACITY {
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

            if previous.capacity < MAX_BUCKET_SKETCH_CAPACITY {
                let Some(floor) = previous.capacity.checked_add(1) else {
                    return ClientAction::ExtremityDiff;
                };
                let Ok(floor_u64) = u64::try_from(floor) else {
                    return ClientAction::ExtremityDiff;
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
                    return ClientAction::ExtremityDiff;
                };
                total = match total.checked_add(capacity) {
                    Some(total) if total <= aggregate_limit => total,
                    _ => return ClientAction::ExtremityDiff,
                };
                requests.push(BucketRequest {
                    depth: previous.depth,
                    prefix,
                    capacity,
                });
            } else {
                if previous.depth >= 31 {
                    return ClientAction::ExtremityDiff;
                }

                let floor = 4_usize;
                let Ok(floor_u64) = u64::try_from(floor) else {
                    return ClientAction::ExtremityDiff;
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
                    return ClientAction::ExtremityDiff;
                };

                let Some(next_depth) = previous.depth.checked_add(1) else {
                    return ClientAction::ExtremityDiff;
                };

                for sub in 0..2 {
                    total = match total.checked_add(capacity) {
                        Some(total) if total <= aggregate_limit => total,
                        _ => return ClientAction::ExtremityDiff,
                    };
                    requests.push(BucketRequest {
                        depth: next_depth,
                        prefix: (previous.prefix << 1) | sub,
                        capacity,
                    });
                }
            }
        }
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
}
