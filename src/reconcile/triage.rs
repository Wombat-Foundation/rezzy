// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Phase 0 difference estimation and bucket localization for MSC4521.

use alloc::vec::Vec;

use super::{pinsketch, AlgebraicError, SyndromeSketch, MAX_DEPTH, STRATA_COUNT, STRATUM_CAPACITY};

/// Maximum sum of capacities in one bucketed sketch request.
pub const MAX_BUCKETED_SKETCH_CAPACITY: usize = 4_096;
/// Maximum extraction capacity assigned to one bucket.
pub const MAX_BUCKET_SKETCH_CAPACITY: usize = 32;
/// Maximum capacity permitted only through the local overflow request path.
///
/// This is not a negotiated protocol capability. Normal bucket requests remain
/// limited to [`MAX_BUCKET_SKETCH_CAPACITY`].
pub const MAX_OVERFLOW_BUCKET_CAPACITY: usize = 256;
/// Client-side sketch-mode cutoff for estimates in the saturated regime.
pub const SATURATED_DELTA_ESTIMATE: u64 = 8 * (1_u64 << 31);
/// Minimum cardinality implied by an over-capacity stratum-0 decode failure.
const OVER_CAPACITY_DELTA_FLOOR: u64 = (STRATUM_CAPACITY as u64) + 1;

/// One localized sketch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketRequest {
    pub depth: u8,
    pub prefix: u64,
    pub capacity: usize,
    /// Explicit overflow marker. Must be set to `true` only after the overflow
    /// request validation path passes. Never infer from `capacity` alone.
    pub overflow: bool,
}

impl BucketRequest {
    /// Standard bucket request (overflow = false).
    #[must_use]
    pub fn new(depth: u8, prefix: u64, capacity: usize) -> Self {
        Self {
            depth,
            prefix,
            capacity,
            overflow: false,
        }
    }

    /// Overflow bucket request (overflow = true).
    #[must_use]
    pub fn with_overflow(depth: u8, prefix: u64, capacity: usize) -> Self {
        Self {
            depth,
            prefix,
            capacity,
            overflow: true,
        }
    }
}

/// Roots recovered from one independently decoded bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDecodeSuccess {
    pub depth: u8,
    pub prefix: u64,
    pub roots: Vec<u64>,
}

/// Partial result of decoding a concatenated bucket sketch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDecodeBatch {
    pub successful_buckets: Vec<BucketDecodeSuccess>,
    /// Each entry is `(depth, prefix)` — the full bucket identifier, not prefix alone.
    pub failed_buckets: Vec<(u8, u64)>,
}

/// Returns the canonical start of a bucket's key-space range.
///
/// This is shared between bucket ordering and request validation so the two
/// paths stay aligned if the bucket geometry changes.
#[must_use]
pub(crate) fn bucket_range_start(request: &BucketRequest) -> u128 {
    let shift = u32::from(MAX_DEPTH.saturating_sub(request.depth));
    u128::from(request.prefix) << shift
}

/// Estimated symmetric-difference cardinality derived from the strata sketches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrataEstimate {
    /// Estimated symmetric-difference cardinality.
    pub delta: u64,
    /// Whether the estimate is provisional because decoding stopped at an
    /// over-capacity stratum and had to extrapolate from the decoded tail.
    pub low_confidence: bool,
}

/// Estimates the symmetric difference from corresponding strata sketches.
///
/// This helper stays test-only so production callers use the structured
/// [`StrataEstimate`] API rather than a bare scalar estimate.
///
/// # Errors
/// Returns an error when root finding exceeds its work budget.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
fn estimate_delta(
    local: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    remote: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
) -> Result<u64, AlgebraicError> {
    Ok(estimate_delta_internal(local, remote)?.0)
}

/// Estimates the symmetric difference and whether that estimate is provisional.
///
/// Starting at the sparsest stratum, this decodes the longest consecutive tail.
/// If `r` is the lowest decoded stratum and `T` is the decoded tail cardinality,
/// `T * 2^r` estimates the complete difference. Decoding every stratum yields
/// the exact cardinality.
///
/// If even the sparsest residual stratum overflows, this returns a saturated
/// estimate in [`StrataEstimate::delta`] and marks it
/// [`StrataEstimate::low_confidence`] so the caller can route away from sketch
/// mode.
///
/// # Errors
/// Returns an error when root finding exceeds its work budget.
pub fn estimate_strata(
    local: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    remote: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
) -> Result<StrataEstimate, AlgebraicError> {
    let (delta, low_confidence) = estimate_delta_internal(local, remote)?;
    Ok(StrataEstimate {
        delta,
        low_confidence,
    })
}

fn estimate_delta_internal(
    local: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    remote: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
) -> Result<(u64, bool), AlgebraicError> {
    let mut decoded_tail = 0_u64;
    let mut lowest_decoded = None;

    for stratum in (0..STRATA_COUNT).rev() {
        let residual: [u64; STRATUM_CAPACITY] =
            core::array::from_fn(|index| local[stratum][index] ^ remote[stratum][index]);

        match pinsketch::decode(&residual, STRATUM_CAPACITY) {
            Ok(roots) => {
                let cardinality =
                    u64::try_from(roots.len()).map_err(|_| AlgebraicError::CountOverflow)?;
                decoded_tail = decoded_tail
                    .checked_add(cardinality)
                    .ok_or(AlgebraicError::CountOverflow)?;
                lowest_decoded = Some(stratum);
            }

            Err(AlgebraicError::DecodeFailure) => {
                if lowest_decoded.is_none() && stratum == STRATA_COUNT - 1 {
                    return Ok((SATURATED_DELTA_ESTIMATE, true));
                }

                let scaled_stratum = lowest_decoded.unwrap_or(stratum);
                let shift =
                    u32::try_from(scaled_stratum).map_err(|_| AlgebraicError::CountOverflow)?;
                let estimate = decoded_tail
                    .max(OVER_CAPACITY_DELTA_FLOOR)
                    .saturating_mul(1_u64 << shift);

                return Ok((estimate, true));
            }
            Err(error) => return Err(error),
        }
    }

    let stratum = lowest_decoded.expect("all strata decoded implies stratum 0 decoded");
    let shift = u32::try_from(stratum).map_err(|_| AlgebraicError::CountOverflow)?;
    // saturating_mul overflows to u64::MAX rather than silently collapsing to 0
    // (which the old checked_shl(shift).unwrap_or(0) scale factor could do).
    Ok((decoded_tail.saturating_mul(1_u64 << shift), false))
}

/// Parses and independently decodes concatenated residual bucket sketches.
///
/// Requests are validated in canonical key-space range order. Each requested
/// sketch is serialized as little-endian syndrome coordinates with no length
/// prefix; the request capacities define the boundaries.
///
/// Structural and budget errors abort the batch. A normal decode failure is
/// isolated to its bucket so successfully decoded roots can be retained.
///
/// # Errors
/// Returns an error for invalid ordering, capacity, aggregate or byte length,
/// or when a decoder exceeds its work budget.
pub fn decode_bucket_sketches(
    encoded: &[u8],
    requests: &[BucketRequest],
) -> Result<BucketDecodeBatch, AlgebraicError> {
    validate_bucket_requests(requests)?;

    let mut offset = 0_usize;
    let mut successful_buckets = Vec::new();
    let mut failed_buckets = Vec::new();
    for request in requests {
        let byte_len = request
            .capacity
            .checked_mul(8)
            .ok_or(AlgebraicError::InvalidSketchLength)?;
        let end = offset
            .checked_add(byte_len)
            .ok_or(AlgebraicError::InvalidSketchLength)?;
        let bytes = encoded
            .get(offset..end)
            .ok_or(AlgebraicError::InvalidSketchLength)?;
        offset = end;

        let coordinates = bytes
            .chunks_exact(8)
            .map(|coordinate| {
                let mut value = [0; 8];
                value.copy_from_slice(coordinate);
                u64::from_le_bytes(value)
            })
            .collect();

        let sketch = SyndromeSketch::from_coordinates(coordinates)?;
        match sketch.decode_elements(request.capacity) {
            Ok(roots) => successful_buckets.push(BucketDecodeSuccess {
                depth: request.depth,
                prefix: request.prefix,
                roots,
            }),
            Err(AlgebraicError::DecodeFailure) => {
                failed_buckets.push((request.depth, request.prefix));
            }
            Err(error) => return Err(error),
        }
    }
    if offset != encoded.len() {
        return Err(AlgebraicError::InvalidSketchLength);
    }
    Ok(BucketDecodeBatch {
        successful_buckets,
        failed_buckets,
    })
}

/// Validates a list of bucket requests to ensure they adhere to limits and form an antichain.
///
/// Normatively, the request set MUST be an antichain under the prefix-containment relation.
/// For two requests `R_i = (d_i, p_i)` and `R_j = (d_j, p_j)`, `R_i` is an ancestor of `R_j`
/// if and only if `d_i <= d_j` and the `d_i` most-significant bits of `p_j` equal `p_i`.
/// A receiver MUST reject any request list containing an ancestor/descendant pair before
/// performing sketch subtraction or field operations.
///
/// This function also ensures no single request exceeds the per-node extraction limit
/// (`MAX_BUCKET_SKETCH_CAPACITY`), that the overall extraction respects
/// `MAX_BUCKETED_SKETCH_CAPACITY`, and that bucket indices are well-formed.
///
/// Implementation note (non-normative): a canonical `O(N log N)` verifier can sort requests
/// by ascending `depth`, then compare each candidate only against previously validated shallower
/// requests using the same prefix test. A binary prefix trie can reduce this to `O(N)`.
///
/// # Errors
/// Returns an error if any capacity or bound constraint is violated, or if the requests
/// overlap.
pub fn validate_bucket_requests(requests: &[BucketRequest]) -> Result<(), AlgebraicError> {
    validate_bucket_requests_with_limit(requests, MAX_BUCKET_SKETCH_CAPACITY)
}

/// Validates requests issued through the explicit local overflow path.
///
/// Normal request handling must continue to call [`validate_bucket_requests`].
/// This helper does not negotiate or advertise overflow support to peers.
///
/// # Errors
/// Returns an error when a request exceeds the overflow or aggregate capacity
/// limit, or when requests are malformed or overlap.
pub fn validate_overflow_bucket_requests(requests: &[BucketRequest]) -> Result<(), AlgebraicError> {
    validate_bucket_requests_with_limit(requests, MAX_OVERFLOW_BUCKET_CAPACITY)
}

fn validate_bucket_requests_with_limit(
    requests: &[BucketRequest],
    max_bucket_capacity: usize,
) -> Result<(), AlgebraicError> {
    let mut total_capacity = 0_usize;
    let mut previous_end = 0_u128;
    for request in requests {
        if request.capacity == 0 || request.capacity > max_bucket_capacity {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        if request.depth > MAX_DEPTH {
            return Err(AlgebraicError::InvalidBucketIndex);
        }

        if request.depth < MAX_DEPTH && request.prefix >= (1_u64 << request.depth) {
            return Err(AlgebraicError::InvalidBucketIndex);
        }

        total_capacity = total_capacity
            .checked_add(request.capacity)
            .ok_or(AlgebraicError::InvalidSketchCapacity)?;
        if total_capacity > MAX_BUCKETED_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }

        let start = bucket_range_start(request);
        let shift = u32::from(MAX_DEPTH.saturating_sub(request.depth));
        let end = start
            .checked_add(1_u128 << shift)
            .ok_or(AlgebraicError::InvalidBucketIndex)?;

        if start < previous_end {
            return Err(AlgebraicError::InvalidBucketIndex);
        }
        previous_end = end;
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::reconcile::{ElementHash, ResidentKernel};

    #[test]
    fn test_validate_bucket_requests_rejects_overlap() {
        // Correct disjoint requests
        assert!(validate_bucket_requests(&[BucketRequest::new(0, 0, 4)]).is_ok());

        // Nested ranges: depth 0 prefix 0 contains depth 1 prefix 0
        assert!(validate_bucket_requests(&[
            BucketRequest::new(0, 0, 4),
            BucketRequest::new(1, 0, 4)
        ])
        .is_err());

        // Same-depth out-of-order ranges are rejected.
        assert!(validate_bucket_requests(&[
            BucketRequest::new(1, 1, 4),
            BucketRequest::new(1, 0, 4)
        ])
        .is_err());

        // Same-depth disjoint ranges in canonical order are valid.
        assert!(validate_bucket_requests(&[
            BucketRequest::new(1, 0, 4),
            BucketRequest::new(1, 1, 4)
        ])
        .is_ok());

        // Nested ranges remain invalid in any order.
        assert!(validate_bucket_requests(&[
            BucketRequest::new(1, 0, 4),
            BucketRequest::new(0, 0, 4),
        ])
        .is_err());
    }

    #[test]
    fn test_validate_bucket_requests_enforces_depth_31_prefix_bounds() {
        assert!(validate_bucket_requests(&[BucketRequest::new(31, (1_u64 << 31) - 1, 4)]).is_ok());

        assert_eq!(
            validate_bucket_requests(&[BucketRequest::new(31, 1_u64 << 31, 4)]),
            Err(AlgebraicError::InvalidBucketIndex)
        );
    }

    #[test]
    fn test_validate_bucket_requests_accepts_full_h64_depth() {
        assert!(validate_bucket_requests(&[BucketRequest::new(MAX_DEPTH, u64::MAX, 4)]).is_ok());
    }

    #[test]
    fn overflow_requests_allow_larger_sketches_but_normal_requests_do_not() {
        let request = BucketRequest::new(1, 0, MAX_OVERFLOW_BUCKET_CAPACITY);

        assert_eq!(
            validate_bucket_requests(&[request]),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert!(validate_overflow_bucket_requests(&[request]).is_ok());
    }

    #[test]
    fn overflow_requests_enforce_the_aggregate_capacity_limit() {
        let requests = (0..17)
            .map(|prefix| BucketRequest::new(5, prefix, MAX_OVERFLOW_BUCKET_CAPACITY))
            .collect::<Vec<_>>();

        assert_eq!(
            validate_overflow_bucket_requests(&requests),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
    }

    fn toggle_stratum(strata: &mut [[u64; STRATUM_CAPACITY]; STRATA_COUNT], value: u64) {
        let event = ElementHash {
            h128: u128::from(value),
            h64: value,
        };
        let mut resident = ResidentKernel::new();
        resident.insert(event).unwrap();
        for (target, source) in strata.iter_mut().zip(resident.strata()) {
            for (coordinate, value) in target.iter_mut().zip(source) {
                *coordinate ^= value;
            }
        }
    }

    fn populate_stratum(
        strata: &mut [[u64; STRATUM_CAPACITY]; STRATA_COUNT],
        stratum: usize,
        odd_values: &[u64],
    ) {
        for odd in odd_values {
            toggle_stratum(strata, odd << stratum);
        }
    }

    #[test]
    fn strata_tail_is_exact_when_every_stratum_decodes() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        for value in [1, 2, 4, 8, 3, 5] {
            toggle_stratum(&mut remote, value);
        }
        assert_eq!(estimate_delta(&local, &remote), Ok(6));
        assert_eq!(estimate_delta(&local, &local), Ok(0));
    }

    #[test]
    fn empty_sparse_tail_uses_low_confidence_tail_estimate() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        for value in (1..=17).step_by(2) {
            toggle_stratum(&mut remote, value);
        }
        assert_eq!(estimate_delta(&local, &remote), Ok(18));
    }

    #[test]
    fn strata_estimator_marks_stratum_zero_overflow_low_confidence() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        for value in (1..=17).step_by(2) {
            toggle_stratum(&mut remote, value);
        }

        assert_eq!(
            pinsketch::decode(&remote[0], STRATUM_CAPACITY),
            Err(AlgebraicError::DecodeFailure)
        );
        assert_eq!(
            estimate_strata(&local, &remote),
            Ok(StrataEstimate {
                delta: 18,
                low_confidence: true,
            })
        );
    }

    #[test]
    fn low_confidence_estimate_uses_lowest_decoded_stratum() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;

        populate_stratum(&mut remote, 7, &[1, 3, 5, 7, 9]);
        populate_stratum(&mut remote, 6, &[1, 3, 5, 7, 9]);
        populate_stratum(&mut remote, 5, &[1, 3, 5, 7, 9]);
        populate_stratum(&mut remote, 4, &[1, 3, 5, 7, 9]);
        populate_stratum(&mut remote, 3, &[1, 3, 5, 7, 9, 11, 13, 15, 17]);

        assert_eq!(estimate_delta(&local, &remote), Ok(320));
        assert_eq!(
            estimate_strata(&local, &remote),
            Ok(StrataEstimate {
                delta: 320,
                low_confidence: true,
            })
        );
    }

    #[test]
    fn highest_stratum_overflow_remains_unmeasurable() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        populate_stratum(
            &mut remote,
            STRATA_COUNT - 1,
            &[1, 3, 5, 7, 9, 11, 13, 15, 17],
        );

        assert_eq!(
            pinsketch::decode(&remote[STRATA_COUNT - 1], STRATUM_CAPACITY),
            Err(AlgebraicError::DecodeFailure)
        );
        assert_eq!(
            estimate_delta(&local, &remote),
            Ok(SATURATED_DELTA_ESTIMATE)
        );
        assert_eq!(
            estimate_strata(&local, &remote),
            Ok(StrataEstimate {
                delta: SATURATED_DELTA_ESTIMATE,
                low_confidence: true,
            })
        );
    }

    #[test]
    fn bucket_decoder_retains_successes_and_isolates_decode_failures() {
        let requests = [BucketRequest::new(8, 1, 2), BucketRequest::new(8, 9, 2)];
        let mut first = SyndromeSketch::new(2).unwrap();
        first.toggle(7).unwrap();
        let mut encoded = first
            .coordinates()
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect::<Vec<_>>();
        let mut over_capacity = SyndromeSketch::new(2).unwrap();
        for value in [1, 2, 3] {
            over_capacity.toggle(value).unwrap();
        }
        encoded.extend(
            over_capacity
                .coordinates()
                .iter()
                .flat_map(|value| value.to_le_bytes()),
        );

        assert_eq!(
            decode_bucket_sketches(&encoded, &requests),
            Ok(BucketDecodeBatch {
                successful_buckets: vec![BucketDecodeSuccess {
                    depth: 8,
                    prefix: 1,
                    roots: vec![7],
                }],
                failed_buckets: vec![(8, 9)],
            })
        );
    }

    #[test]
    fn bucket_decoder_rejects_length_mismatches_and_nested_overlaps() {
        let unordered = [BucketRequest::new(8, 2, 1), BucketRequest::new(8, 1, 1)];
        assert_eq!(
            decode_bucket_sketches(&[0; 16], &unordered),
            Err(AlgebraicError::InvalidBucketIndex)
        );

        let nested = [BucketRequest::new(0, 0, 1), BucketRequest::new(1, 0, 1)];
        assert_eq!(
            decode_bucket_sketches(&[0; 16], &nested),
            Err(AlgebraicError::InvalidBucketIndex)
        );
        assert_eq!(
            decode_bucket_sketches(&[0; 7], &[BucketRequest::new(8, 1, 1)],),
            Err(AlgebraicError::InvalidSketchLength)
        );
        assert_eq!(
            decode_bucket_sketches(&[0; 9], &[BucketRequest::new(8, 1, 1)],),
            Err(AlgebraicError::InvalidSketchLength)
        );
    }
}
