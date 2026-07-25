// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Phase 0 difference estimation and bucket localization for MSC0500.

use alloc::vec::Vec;

use super::{pinsketch, AlgebraicError, SyndromeSketch, STRATA_COUNT, STRATUM_CAPACITY};

/// Maximum sum of capacities in one bucketed sketch request.
pub const MAX_BUCKETED_SKETCH_CAPACITY: usize = 4_096;
/// Maximum extraction capacity assigned to one bucket.
pub const MAX_BUCKET_SKETCH_CAPACITY: usize = 64;

/// One localized sketch request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BucketRequest {
    pub depth: u8,
    pub prefix: u32,
    pub capacity: usize,
}

/// Roots recovered from one independently decoded bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDecodeSuccess {
    pub depth: u8,
    pub prefix: u32,
    pub roots: Vec<u64>,
}

/// Partial result of decoding a concatenated bucket sketch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketDecodeBatch {
    pub successful_buckets: Vec<BucketDecodeSuccess>,
    /// Each entry is `(depth, prefix)` — the full bucket identifier, not prefix alone.
    pub failed_buckets: Vec<(u8, u32)>,
}

/// Estimates the symmetric difference from corresponding strata sketches.
///
/// Starting at the sparsest stratum, this decodes the longest consecutive tail.
/// If `r` is the lowest decoded stratum and `T` is the decoded tail cardinality,
/// `T * 2^r` estimates the complete difference. Decoding every stratum yields
/// the exact cardinality.
///
/// `None` means even the sparsest stratum exceeded its resident capacity.
///
/// # Errors
/// Returns an error when root finding exceeds its work budget.
pub fn estimate_delta(
    local: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    remote: &[[u64; STRATUM_CAPACITY]; STRATA_COUNT],
) -> Result<Option<u64>, AlgebraicError> {
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
            Err(AlgebraicError::DecodeFailure) => break,
            Err(error) => return Err(error),
        }
    }

    let Some(stratum) = lowest_decoded else {
        return Ok(None);
    };
    if decoded_tail == 0 && stratum != 0 {
        return Ok(None);
    }
    let shift = u32::try_from(stratum).map_err(|_| AlgebraicError::CountOverflow)?;
    // saturating_mul overflows to u64::MAX rather than silently collapsing to 0
    // (which the old checked_shl(shift).unwrap_or(0) scale factor could do).
    Ok(Some(decoded_tail.saturating_mul(1_u64 << shift)))
}

/// Parses and independently decodes concatenated residual bucket sketches.
///
/// Requests must be strictly ordered by ascending bucket ID. Each requested
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
/// Ensures no single request exceeds the per-node extraction limit (`MAX_BUCKET_SKETCH_CAPACITY`),
/// that the overall extraction respects `MAX_BUCKETED_SKETCH_CAPACITY`, and that the requests
/// do not overlap (thereby forming an antichain of subsets).
///
/// # Errors
/// Returns an error if any capacity or bound constraint is violated, or if the requests
/// overlap/are incorrectly ordered.
pub fn validate_bucket_requests(requests: &[BucketRequest]) -> Result<(), AlgebraicError> {
    let mut total_capacity = 0_usize;
    let mut previous_end_inclusive: Option<u64> = None;
    for request in requests {
        if request.capacity == 0 || request.capacity > MAX_BUCKET_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        if request.depth >= 32 || request.prefix >= (1_u32 << request.depth) {
            return Err(AlgebraicError::InvalidBucketIndex);
        }

        let shift = 64_u8.saturating_sub(request.depth);
        let start = if shift == 64 {
            0
        } else {
            u64::from(request.prefix) << shift
        };
        let end_inclusive = if shift == 64 {
            u64::MAX
        } else {
            start | (1_u64 << shift).wrapping_sub(1)
        };

        if let Some(prev_end) = previous_end_inclusive {
            if start <= prev_end {
                return Err(AlgebraicError::InvalidBucketIndex);
            }
        }
        previous_end_inclusive = Some(end_inclusive);

        total_capacity = total_capacity
            .checked_add(request.capacity)
            .ok_or(AlgebraicError::InvalidSketchCapacity)?;
        if total_capacity > MAX_BUCKETED_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;
    use crate::reconcile::{ElementHash, ResidentKernel};

    #[test]
    fn test_validate_bucket_requests_rejects_overlap() {
        // Correct disjoint requests
        assert!(validate_bucket_requests(&[BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 4
        }])
        .is_ok());

        // Nested ranges: depth 0 prefix 0 contains depth 1 prefix 0
        assert!(validate_bucket_requests(&[
            BucketRequest {
                depth: 0,
                prefix: 0,
                capacity: 4
            },
            BucketRequest {
                depth: 1,
                prefix: 0,
                capacity: 4
            }
        ])
        .is_err());

        // Unordered ranges
        assert!(validate_bucket_requests(&[
            BucketRequest {
                depth: 1,
                prefix: 1,
                capacity: 4
            },
            BucketRequest {
                depth: 1,
                prefix: 0,
                capacity: 4
            }
        ])
        .is_err());

        // Disjoint and ordered
        assert!(validate_bucket_requests(&[
            BucketRequest {
                depth: 1,
                prefix: 0,
                capacity: 4
            },
            BucketRequest {
                depth: 1,
                prefix: 1,
                capacity: 4
            }
        ])
        .is_ok());
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

    #[test]
    fn strata_tail_is_exact_when_every_stratum_decodes() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        for value in [1, 2, 4, 8, 3, 5] {
            toggle_stratum(&mut remote, value);
        }
        assert_eq!(estimate_delta(&local, &remote), Ok(Some(6)));
        assert_eq!(estimate_delta(&local, &local), Ok(Some(0)));
    }

    #[test]
    fn empty_sparse_tail_does_not_claim_large_difference_is_zero() {
        let local = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let mut remote = local;
        for value in (1..=17).step_by(2) {
            toggle_stratum(&mut remote, value);
        }
        assert_eq!(estimate_delta(&local, &remote), Ok(None));
    }

    #[test]
    fn bucket_decoder_retains_successes_and_isolates_decode_failures() {
        let requests = [
            BucketRequest {
                depth: 8,
                prefix: 1,
                capacity: 2,
            },
            BucketRequest {
                depth: 8,
                prefix: 9,
                capacity: 2,
            },
        ];
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
    fn bucket_decoder_rejects_order_and_length_mismatches() {
        let unordered = [
            BucketRequest {
                depth: 8,
                prefix: 2,
                capacity: 1,
            },
            BucketRequest {
                depth: 8,
                prefix: 1,
                capacity: 1,
            },
        ];
        assert_eq!(
            decode_bucket_sketches(&[0; 16], &unordered),
            Err(AlgebraicError::InvalidBucketIndex)
        );
        assert_eq!(
            decode_bucket_sketches(
                &[0; 7],
                &[BucketRequest {
                    depth: 8,
                    prefix: 1,
                    capacity: 1,
                }],
            ),
            Err(AlgebraicError::InvalidSketchLength)
        );
        assert_eq!(
            decode_bucket_sketches(
                &[0; 9],
                &[BucketRequest {
                    depth: 8,
                    prefix: 1,
                    capacity: 1,
                }],
            ),
            Err(AlgebraicError::InvalidSketchLength)
        );
    }
}
