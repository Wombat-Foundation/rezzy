// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Two-phase MSC4521 verification of a decoded symmetric difference.
//!
//! Phase 1 ([`verify_decode`]) runs at decode time, before any fetch: it
//! classifies each decoded root as local-only (`L`) or remote-only (`M`) and
//! enforces the count identity. Phase 2 ([`verify_follow_up`]) runs once the
//! peer has returned the identifiers for `M`: it checks them structurally and
//! then against the global 128-bit residual.
//!
//! Every failure is [`AlgebraicError::DecodeFailure`]. There is deliberately
//! no variant that blames the peer: a colliding or ambiguous root is
//! indistinguishable from misbehavior, and the caller's response is the same
//! either way -- discard the result and use the non-reconciliation baseline.

use alloc::vec::Vec;

use super::client::{ReconciliationClient, RemoteDigest};
use super::{AlgebraicError, ElementHash};

/// Decoded roots classified by local `h64` presence.
///
/// Bound to one exchange only: it carries nothing tying it to a frame, so the
/// caller must not apply it to another exchange's follow-up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Classified {
    l_roots: Vec<u64>,
    m_roots: Vec<u64>,
    /// `D_A xor D_B`.
    residual: u128,
    /// XOR of every local `h128` candidate under an `L` root.
    local_accumulated: u128,
}

impl Classified {
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

/// Phase 1: classify `roots` and enforce `count_A - count_B = |L| - |M|`.
///
/// `local_candidates(root)` returns the `h128` of every local element whose
/// `h64` is `root` (the multi-valued map; empty means absent). `local_digest`
/// and `local_count` describe the verifying peer's frame. When `M` is empty
/// the residual is checked immediately, provided no `L` root is ambiguous.
///
/// # Errors
/// [`AlgebraicError::DecodeFailure`] when the count identity or the early
/// residual fails.
pub fn verify_decode<F>(
    local_digest: u128,
    local_count: u64,
    remote: &RemoteDigest,
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
    let lhs = i128::from(local_count).checked_sub(i128::from(remote.known_event_count));
    let rhs = (l_roots.len() as i128).checked_sub(m_roots.len() as i128);
    let (Some(lhs), Some(rhs)) = (lhs, rhs) else {
        return Err(AlgebraicError::DecodeFailure);
    };
    if lhs != rhs {
        return Err(AlgebraicError::DecodeFailure);
    }

    let residual = local_digest ^ remote.digest;
    if m_roots.is_empty() && !ambiguous {
        ReconciliationClient::verify_global_residual(residual, &[local_accumulated], &[])?;
    }
    Ok(Classified {
        l_roots,
        m_roots,
        residual,
        local_accumulated,
    })
}

/// Phase 2: check the identifiers the peer returned for `M`.
///
/// `returned` holds the canonical 32-byte digests `D(e)` computed locally from
/// the returned identifiers. This function derives `h64` and `h128` itself, so
/// peer-supplied hashes can never be passed in. Each must re-derive to a root in `M`, each root in `M` must be covered exactly
/// once, and the full residual `D_A xor D_B = A(L) xor A(M)` must hold. A
/// root with several local candidates is resolved here by that residual, or
/// the result is discarded.
///
/// # Errors
/// [`AlgebraicError::DecodeFailure`] on any failure; the caller must discard
/// the result and fall back.
pub fn verify_follow_up(
    classified: &Classified,
    returned: &[[u8; 32]],
) -> Result<(), AlgebraicError> {
    if returned.len() != classified.m_roots.len() {
        return Err(AlgebraicError::DecodeFailure);
    }
    let mut covered = alloc::vec![false; classified.m_roots.len()];
    let returned: Vec<ElementHash> = returned
        .iter()
        .map(|digest| ElementHash::from_digest32(*digest))
        .collect();
    for element in &returned {
        let slot = classified
            .m_roots
            .binary_search(&element.h64)
            .map_err(|_| AlgebraicError::DecodeFailure)?;
        // Index is in range: it came from a search over `m_roots`.
        let seen = covered.get_mut(slot).ok_or(AlgebraicError::DecodeFailure)?;
        if core::mem::replace(seen, true) {
            return Err(AlgebraicError::DecodeFailure);
        }
    }
    // Equal lengths plus no repeat means every root is covered exactly once.
    let remote_hashes: Vec<u128> = returned.iter().map(|e| e.h128).collect();
    ReconciliationClient::verify_global_residual(
        classified.residual,
        &[classified.local_accumulated],
        &remote_hashes,
    )
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::resident::{STRATA_COUNT, STRATUM_CAPACITY};

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
        verify_follow_up(c, &digests)
    }

    fn remote(digest: u128, count: u64) -> RemoteDigest {
        RemoteDigest {
            digest,
            known_event_count: count,
            strata: [[0; STRATUM_CAPACITY]; STRATA_COUNT],
            frame_matches: true,
            has_unknown_extremity: false,
        }
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
        let c = verify_decode(
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
        let ok = verify_decode(0x20, 1, &remote(0, 0), &[2], lookup(&[l]));
        assert!(ok.is_ok());
        // Residual disagrees with A(L): rejected in phase 1, before any fetch.
        let bad = verify_decode(0x21, 1, &remote(0, 0), &[2], lookup(&[l]));
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
        let r = verify_decode(
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
        let c = verify_decode(
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
        let c = verify_decode(
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
        let r = verify_decode(0x20, 1, &remote(0, 0), &[2, 2], lookup(&[l]));
        assert_eq!(r, Err(AlgebraicError::DecodeFailure));
    }
}
