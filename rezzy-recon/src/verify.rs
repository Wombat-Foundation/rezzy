if request.depth > crate::MAX_DEPTH
        || request.prefix >= (1_u64 << request.depth)
    {
        return Err(AlgebraicError::InvalidBucketIndex);
    }
    let bounds = H64Index::bounds_unchecked(request);
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Per-node two-phase MSC4521 verification of a decoded symmetric difference.
//!
//! Every sketch node travels with a [`NodeSummary`] (count and `h128` XOR), so
//! each node is verified on its own: a failed node is split or discarded while
//! its siblings are admitted.
//!
//! Phase 1 ([`verify_decode`], or [`verify_batch`] over a round) runs at
//! decode time: it checks every root lies in the node, classifies roots as
//! local-only (`L`) or remote-only (`M`), and enforces the count identity.
//! Phase 2 ([`verify_follow_up`]) runs once the peer has returned the
//! identifiers for `M`: it checks them structurally and then against the
//! node's residual.
//!
//! Every failure is [`AlgebraicError::DecodeFailure`]. There is deliberately
//! no variant that blames the peer: a colliding or ambiguous root is
//! indistinguishable from misbehavior, and the caller's response is the same
//! either way -- discard the node's result and use the baseline.

use alloc::vec::Vec;

use super::client::ReconciliationClient;
use super::server::H64Index;
use super::triage::{BucketDecodeBatch, BucketRequest, NodeSummary};
use super::{AlgebraicError, ElementHash};

/// One node's decoded roots, classified by local `h64` presence.
///
/// Keyed by the node's `(depth, prefix)`, and [`verify_follow_up`] refuses a
/// follow-up for any other node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    depth: u8,
    prefix: u64,
    l_roots: Vec<u64>,
    m_roots: Vec<u64>,
    /// XOR of every local `h128` candidate under an `L` root.
    local_accumulated: u128,
    /// The summaries this node was verified against. The remote one is what
    /// the peer claimed, and seeds split consistency if the node is narrowed.
    local: NodeSummary,
    remote: NodeSummary,
}

impl Classified {
    /// The responder's summary of this node, as claimed in the exchange.
    #[must_use]
    pub const fn remote_summary(&self) -> NodeSummary {
        self.remote
    }

    /// `D_A xor D_B` for this node.
    #[must_use]
    pub const fn residual(&self) -> u128 {
        self.local.digest ^ self.remote.digest
    }

    /// The larger side's element count for the node.
    #[must_use]
    pub fn population(&self) -> u64 {
        self.local.count.max(self.remote.count)
    }

    /// The node's `(depth, prefix)`.
    #[must_use]
    pub const fn node(&self) -> (u8, u64) {
        (self.depth, self.prefix)
    }

    /// Roots present locally (the remote lacks them).
    #[must_use]
    pub fn l_roots(&self) -> &[u64] {
        &self.l_roots
    }

    /// Roots absent locally; their identifiers must come from the peer.
    #[must_use]
    pub fn m_roots(&self) -> &[u64] {
        &self.m_roots
    }
}

/// Phase 1 for one node: classify `roots` and enforce
/// `count_A - count_B = |L| - |M|`.
///
/// `local` and `remote` are the two sides' summaries of this node.
/// `local_candidates(root)` returns the `h128` of every local element whose
/// `h64` is `root` (the multi-valued map; empty means absent). When `M` is
/// empty the residual is checked immediately, provided no `L` root is
/// ambiguous. Roots must be distinct and fall inside the node.
///
/// # Errors
/// [`AlgebraicError::DecodeFailure`] on any failed check.
pub fn verify_decode<F>(
    request: &BucketRequest,
    local: NodeSummary,
    remote: NodeSummary,
    roots: &[u64],
    mut local_candidates: F,
) -> Result<Classified, AlgebraicError>
where
    F: FnMut(u64) -> Vec<u128>,
{
    // The decoder yields distinct roots; reject a caller that does not, since
    // a repeated root would be masked by the length check in phase 2.
    let mut distinct = roots.to_vec();
    distinct.sort_unstable();
    if distinct.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(AlgebraicError::DecodeFailure);
    }
    let bounds = H64Index::bounds_unchecked(request);
    if roots
        .iter()
        .any(|&root| !bounds.contains(&u128::from(root)))
    {
        return Err(AlgebraicError::DecodeFailure);
    }

    let mut l_roots = Vec::new();
    let mut m_roots = Vec::new();
    let mut local_accumulated = 0_u128;
    let mut ambiguous = false;
    for &root in roots {
        let candidates = local_candidates(root);
        if candidates.is_empty() {
            m_roots.push(root);
        } else {
            ambiguous |= candidates.len() > 1;
            local_accumulated = candidates.iter().fold(local_accumulated, |acc, h| acc ^ h);
            l_roots.push(root);
        }
    }
    m_roots.sort_unstable();

    // Widened to i128, so these subtractions cannot overflow; `checked_sub`
    // only satisfies the arithmetic lint and the `else` arm is dead code.
    let lhs = i128::from(local.count).checked_sub(i128::from(remote.count));
    let rhs = (l_roots.len() as i128).checked_sub(m_roots.len() as i128);
    let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
        return Err(AlgebraicError::DecodeFailure);
    };
    if lhs != rhs {
        return Err(AlgebraicError::DecodeFailure);
    }

    let residual = local.digest ^ remote.digest;
    if m_roots.is_empty() && !ambiguous {
        ReconciliationClient::verify_global_residual(residual, &[local_accumulated], &[])?;
    }
    Ok(Classified {
        depth: request.depth,
        prefix: request.prefix,
        l_roots,
        m_roots,
        local_accumulated,
        local,
        remote,
    })
}

/// Phase 1 over one decoded round.
///
/// `requests`, `local` and `remote` are index-aligned. Each successfully
/// decoded node is verified; a node that fails verification is moved into
/// `failed_buckets`, so the exchange splits or retries it while its siblings
/// are admitted. Returns the batch to feed the exchange, the classified nodes
/// that passed, and each phase-1-rejected node as `(depth, prefix, roots)` so
/// the exchange can tell a repeated collision from a spurious decode.
///
/// # Errors
/// [`AlgebraicError::InvalidSketchLength`] if the slices are not aligned, and
/// [`AlgebraicError::InvalidBucketIndex`] if a decoded node was never
/// requested.
pub fn verify_batch<F>(
    batch: BucketDecodeBatch,
    requests: &[BucketRequest],
    local: &[NodeSummary],
    remote: &[NodeSummary],
    mut local_candidates: F,
) -> Result<VerifiedBatch, AlgebraicError>
where
    F: FnMut(u64) -> Vec<u128>,
{
    if requests.len() != local.len() || requests.len() != remote.len() {
        return Err(AlgebraicError::InvalidSketchLength);
    }
    let BucketDecodeBatch {
        successful_buckets,
        mut failed_buckets,
    } = batch;
    let mut admitted = Vec::with_capacity(successful_buckets.len());
    let mut verified = Vec::with_capacity(successful_buckets.len());
    let mut rejected = Vec::new();
    for success in successful_buckets {
        let slot = requests
            .iter()
            .position(|r| r.depth == success.depth && r.prefix == success.prefix)
            .ok_or(AlgebraicError::InvalidBucketIndex)?;
        let (Some(request), Some(&l), Some(&r)) =
            (requests.get(slot), local.get(slot), remote.get(slot))
        else {
            return Err(AlgebraicError::InvalidBucketIndex);
        };
        match verify_decode(request, l, r, &success.roots, &mut local_candidates) {
            Ok(classified) => {
                verified.push(classified);
                admitted.push(success);
            }
            Err(AlgebraicError::DecodeFailure) => {
                failed_buckets.push((success.depth, success.prefix));
                let mut roots = success.roots;
                roots.sort_unstable();
                rejected.push((success.depth, success.prefix, roots));
            }
            Err(error) => return Err(error),
        }
    }
    Ok((
        BucketDecodeBatch {
            successful_buckets: admitted,
            failed_buckets,
        },
        verified,
        rejected,
    ))
}

/// Result of [`verify_batch`]: the batch to feed the exchange, the nodes that
/// passed phase 1, and the nodes rejected by it with their decoded roots.
pub type VerifiedBatch = (BucketDecodeBatch, Vec<Classified>, Vec<(u8, u64, Vec<u64>)>);

/// Phase 2 for one node: check the identifiers the peer returned for `M`.
///
/// `returned` holds the canonical 32-byte digests `D(e)` computed locally from
/// the returned identifiers. This function derives `h64` and `h128` itself, so
/// peer-supplied hashes can never be passed in. Each must re-derive to a root
/// in `M`, each root in `M` must be covered exactly once, and the node's full
/// residual `D_A xor D_B = A(L) xor A(M)` must hold. A root with several local
/// candidates is resolved here by that residual, or the result is discarded.
///
/// # Errors
/// [`AlgebraicError::DecodeFailure`] on any failure, including a `request`
/// for a different `node` than `classified`; the caller must discard the node's
/// result and fall back.
pub fn verify_follow_up(
    classified: &Classified,
    node: (u8, u64),
    returned: &[[u8; 32]],
) -> Result<(), AlgebraicError> {
    if classified.node() != node || returned.len() != classified.m_roots.len() {
        return Err(AlgebraicError::DecodeFailure);
    }
    let returned: Vec<ElementHash> = returned
        .iter()
        .map(|digest| ElementHash::from_digest32(*digest))
        .collect();
    let mut covered = alloc::vec![false; classified.m_roots.len()];
    for element in &returned {
        let slot = classified
            .m_roots
            .binary_search(&element.h64)
            .map_err(|_| AlgebraicError::DecodeFailure)?;
        let seen = covered.get_mut(slot).ok_or(AlgebraicError::DecodeFailure)?;
        if core::mem::replace(seen, true) {
            return Err(AlgebraicError::DecodeFailure);
        }
    }
    // Equal lengths plus no repeat means every root is covered exactly once.
    let remote_hashes: Vec<u128> = returned.iter().map(|e| e.h128).collect();
    ReconciliationClient::verify_global_residual(
        classified.residual(),
        &[classified.local_accumulated],
        &remote_hashes,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::triage::BucketDecodeSuccess;

    fn el(h128: u128, h64: u64) -> ElementHash {
        ElementHash { h128, h64 }
    }

    /// A digest whose derived `h64`/`h128` are exactly the given values
    /// (`h64` must be non-zero).
    fn dig(e: ElementHash) -> [u8; 32] {
        let mut d = [0_u8; 32];
        d[..8].copy_from_slice(&e.h64.to_be_bytes());
        d[16..].copy_from_slice(&e.h128.to_be_bytes());
        d
    }

    fn fu(c: &Classified, returned: &[ElementHash]) -> Result<(), AlgebraicError> {
        let digests: Vec<[u8; 32]> = returned.iter().map(|e| dig(*e)).collect();
        verify_follow_up(c, (0, 0), &digests)
    }

    fn remote(digest: u128, count: u64) -> NodeSummary {
        NodeSummary { count, digest }
    }

    fn vd<F: FnMut(u64) -> Vec<u128>>(
        local_digest: u128,
        local_count: u64,
        remote: &NodeSummary,
        roots: &[u64],
        lookup: F,
    ) -> Result<Classified, AlgebraicError> {
        verify_decode(
            &BucketRequest::new(0, 0, 8),
            NodeSummary {
                count: local_count,
                digest: local_digest,
            },
            *remote,
            roots,
            lookup,
        )
    }

    /// Local multi-valued map over a fixed element list.
    fn lookup(local: &[ElementHash]) -> impl FnMut(u64) -> Vec<u128> + '_ {
        move |root| {
            local
                .iter()
                .filter(|e| e.h64 == root)
                .map(|e| e.h128)
                .collect()
        }
    }

    fn digest(set: &[ElementHash]) -> u128 {
        set.iter().fold(0, |acc, e| acc ^ e.h128)
    }

    #[test]
    fn honest_difference_passes_both_phases() {
        let shared = el(0x10, 1);
        let l = el(0x20, 2);
        let m = el(0x40, 3);
        let local = [shared, l];
        let far = [shared, m];
        let c = vd(
            digest(&local),
            2,
            &remote(digest(&far), 2),
            &[2, 3],
            lookup(&local),
        )
        .unwrap();
        assert_eq!(c.l_roots(), &[2]);
        assert_eq!(c.m_roots(), &[3]);
        assert_eq!(fu(&c, &[m]), Ok(()));
    }

    #[test]
    fn empty_m_checks_the_residual_immediately() {
        let l = el(0x20, 2);
        let ok = vd(0x20, 1, &remote(0, 0), &[2], lookup(&[l]));
        assert!(ok.is_ok());
        // Residual disagrees with A(L): rejected in phase 1, before any fetch.
        let bad = vd(0x21, 1, &remote(0, 0), &[2], lookup(&[l]));
        assert_eq!(bad, Err(AlgebraicError::DecodeFailure));
    }

    /// A shared element whose h64 collides with a remote-only one: the root
    /// survives the sketch (remote holds it twice, local once), is present
    /// locally so lands in `L`, but truly belongs to `M`. The count identity
    /// rejects it in phase 1, before any fetch.
    #[test]
    fn shared_element_collision_misclassifies_and_fails_the_count_identity() {
        let shared = el(0xA, 7);
        let remote_only = el(0xB, 7);
        let local = [shared];
        let far = [shared, remote_only];
        let r = vd(
            digest(&local),
            1,
            &remote(digest(&far), 2),
            &[7],
            lookup(&local),
        );
        // count_A - count_B = -1, but |L| - |M| = 1.
        assert_eq!(r, Err(AlgebraicError::DecodeFailure));
    }

    fn honest() -> (Classified, ElementHash, ElementHash) {
        let l = el(0x20, 2);
        let m1 = el(0x40, 3);
        let m2 = el(0x80, 4);
        let local = [l];
        let far = [m1, m2];
        let c = vd(
            digest(&local),
            1,
            &remote(digest(&far), 2),
            &[2, 3, 4],
            lookup(&local),
        )
        .unwrap();
        (c, m1, m2)
    }

    #[test]
    fn l_root_substituted_into_the_follow_up_is_rejected() {
        let (c, m1, _) = honest();
        assert_eq!(
            fu(&c, &[m1, el(0x20, 2)]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn root_covered_twice_is_rejected() {
        let (c, m1, _) = honest();
        assert_eq!(fu(&c, &[m1, m1]), Err(AlgebraicError::DecodeFailure));
    }

    #[test]
    fn extra_returned_id_is_rejected() {
        let (c, m1, m2) = honest();
        assert_eq!(
            fu(&c, &[m1, m2, el(0x1, 3)]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn missing_m_root_is_rejected() {
        let (c, m1, _) = honest();
        assert_eq!(fu(&c, &[m1]), Err(AlgebraicError::DecodeFailure));
    }

    #[test]
    fn right_roots_wrong_h128_fails_the_residual() {
        let (c, _, m2) = honest();
        assert_eq!(
            fu(&c, &[el(0x41, 3), m2]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    /// Local holds two elements under one h64 (they cancel locally), remote
    /// holds a third. The root is ambiguous: phase 1 defers the residual, and
    /// phase 2 discards the result via the same error as any other failure.
    #[test]
    fn ambiguous_local_root_is_discarded_without_a_misbehavior_variant() {
        let x1 = el(0x1, 5);
        let x2 = el(0x2, 5);
        let y = el(0x4, 5);
        let local = [x1, x2];
        let far = [y];
        let c = vd(
            digest(&local),
            2,
            &remote(digest(&far), 1),
            &[5],
            lookup(&local),
        )
        .expect("phase 1 defers an ambiguous root");
        assert_eq!(c.l_roots(), &[5]);
        assert_eq!(fu(&c, &[]), Err(AlgebraicError::DecodeFailure));
    }

    #[test]
    fn duplicate_roots_are_rejected() {
        let l = el(0x20, 2);
        let r = vd(0x20, 1, &remote(0, 0), &[2, 2], lookup(&[l]));
        assert_eq!(r, Err(AlgebraicError::DecodeFailure));
    }

    #[test]
    fn root_outside_the_node_is_rejected() {
        // Depth-1 node with prefix 0 covers h64 < 2^63.
        let request = BucketRequest::new(1, 0, 8);
        let inside = verify_decode(
            &request,
            NodeSummary::default(),
            NodeSummary {
                count: 1,
                digest: 0x4,
            },
            &[5],
            |_| Vec::new(),
        );
        assert!(inside.is_ok());
        let outside = verify_decode(
            &request,
            NodeSummary::default(),
            NodeSummary {
                count: 1,
                digest: 0x4,
            },
            &[u64::MAX],
            |_| Vec::new(),
        );
        assert_eq!(outside, Err(AlgebraicError::DecodeFailure));
    }

    #[test]
    fn follow_up_for_another_node_is_rejected() {
        let (c, m1, m2) = honest();
        let digests = [dig(m1), dig(m2)];
        assert_eq!(
            verify_follow_up(&c, (1, 1), &digests),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    /// One node fails its count identity and is moved to `failed_buckets`
    /// (so the exchange splits it) while its sibling is admitted.
    #[test]
    fn failed_node_is_split_while_sibling_is_admitted() {
        let requests = [BucketRequest::new(1, 0, 8), BucketRequest::new(1, 1, 8)];
        let high = 1_u64 << 63;
        // Node 0: honest remote-only root 5. Node 1: same shape but the remote
        // reports an extra element no root accounts for.
        let local = [NodeSummary::default(), NodeSummary::default()];
        let far = [
            NodeSummary {
                count: 1,
                digest: 0x4,
            },
            NodeSummary {
                count: 2,
                digest: 0x8,
            },
        ];
        let batch = BucketDecodeBatch {
            successful_buckets: vec![
                BucketDecodeSuccess {
                    depth: 1,
                    prefix: 0,
                    roots: vec![5],
                },
                BucketDecodeSuccess {
                    depth: 1,
                    prefix: 1,
                    roots: vec![high | 5],
                },
            ],
            failed_buckets: Vec::new(),
        };
        let (batch, classified, rejected) =
            verify_batch(batch, &requests, &local, &far, |_| Vec::new()).unwrap();
        assert_eq!(batch.successful_buckets.len(), 1);
        assert_eq!(batch.successful_buckets[0].prefix, 0);
        assert_eq!(batch.failed_buckets, vec![(1, 1)]);
        assert_eq!(rejected, vec![(1, 1, vec![high | 5])]);
        assert_eq!(classified.len(), 1);
        assert_eq!(classified[0].node(), (1, 0));
    }

    #[test]
    fn batch_rejects_misaligned_inputs_and_unrequested_nodes() {
        let requests = [BucketRequest::new(1, 0, 8)];
        let ok = |roots_prefix: u64| BucketDecodeBatch {
            successful_buckets: vec![BucketDecodeSuccess {
                depth: 1,
                prefix: roots_prefix,
                roots: Vec::new(),
            }],
            failed_buckets: Vec::new(),
        };
        assert_eq!(
            verify_batch(ok(0), &requests, &[], &[], |_| Vec::new()).unwrap_err(),
            AlgebraicError::InvalidSketchLength
        );
        let one = [NodeSummary::default()];
        assert_eq!(
            verify_batch(ok(1), &requests, &one, &one, |_| Vec::new()).unwrap_err(),
            AlgebraicError::InvalidBucketIndex
        );
    }

    /// Pins the MSC4521 "Node summary" test vector.
    #[test]
    fn node_summary_matches_the_spec_vector() {
        let summary = NodeSummary {
            count: 3,
            digest: 1,
        };
        let mut expected = [0_u8; 24];
        expected[15] = 1;
        expected[23] = 3;
        assert_eq!(summary.to_bytes(), expected);
    }

    #[test]
    fn node_summary_round_trips_and_rejects_bad_length() {
        let summary = NodeSummary::from_h128s(&[0x1, 0x2, 0x4]).unwrap();
        assert_eq!(
            summary,
            NodeSummary {
                count: 3,
                digest: 0x7
            }
        );
        assert_eq!(NodeSummary::from_bytes(&summary.to_bytes()), Ok(summary));
        assert_eq!(
            NodeSummary::from_bytes(&[0; 23]),
            Err(AlgebraicError::InvalidSketchLength)
        );
    }
}
