// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Incrementally maintained MSC4521 reconciliation state.

use super::{
    algebraic::{AlgebraicError, ElementHash, RoomAccumulator},
    gf64,
};

/// Number of estimator strata.
pub const STRATA_COUNT: usize = 32;
/// Extraction capacity maintained in each estimator stratum.
pub const STRATUM_CAPACITY: usize = 8;

/// Version tag leading [`ResidentKernel::to_bytes`] output.
pub const RESIDENT_FORMAT_VERSION: u8 = 1;
/// Exact byte length of a serialized [`ResidentKernel`].
pub const RESIDENT_SERIALIZED_LEN: usize = 1 + 16 + 8 + STRATA_COUNT * STRATUM_CAPACITY * 8;

/// Per-population resident reconciliation state.
// TODO(prefix-grinding): this structure is built once and incrementally
// maintained, then reused to serve every peer that reconciles against it --
// deliberately, to amortize the build cost across many sessions. That
// design is in tension with the standard fix for h64 placement grinding
// (a per-session keyed hash): keying would make bucket geometry
// session-specific, forcing either a resident structure per active peer or
// a coarser (room-scoped) key that doesn't defend against a malicious room
// member, who already knows any room-scoped secret. See
// `ElementHash::from_digest32`'s doc comment in algebraic.rs for the full
// analysis; this is the amortization side of that tradeoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidentKernel {
    accumulator: RoomAccumulator,
    strata: [[u64; STRATUM_CAPACITY]; STRATA_COUNT],
}

impl Default for ResidentKernel {
    fn default() -> Self {
        Self {
            accumulator: RoomAccumulator::new(),
            strata: [[0; STRATUM_CAPACITY]; STRATA_COUNT],
        }
    }
}

impl ResidentKernel {
    /// Creates empty resident state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Rebuilds resident state from persisted parts.
    ///
    /// The parts are trusted to describe one population: `strata` must hold
    /// the odd syndromes of exactly the elements counted in `accumulator`,
    /// bucketed by trailing zeros as [`insert`](Self::insert) does. Only the
    /// empty-population case is checkable here, and it is checked by
    /// [`from_bytes`](Self::from_bytes), not this constructor.
    #[must_use]
    pub const fn from_parts(
        accumulator: RoomAccumulator,
        strata: [[u64; STRATUM_CAPACITY]; STRATA_COUNT],
    ) -> Self {
        Self {
            accumulator,
            strata,
        }
    }

    /// Serializes to a fixed-size, versioned record.
    ///
    /// Layout: version byte, accumulator digest (16 bytes big-endian), event
    /// count (8 bytes big-endian), then every stratum coordinate in order as
    /// 8 bytes little-endian (matching the sketch wire encoding).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; RESIDENT_SERIALIZED_LEN] {
        let mut out = [0; RESIDENT_SERIALIZED_LEN];
        out[0] = RESIDENT_FORMAT_VERSION;
        out[1..17].copy_from_slice(&self.accumulator.digest().to_be_bytes());
        out[17..25].copy_from_slice(&self.accumulator.known_event_count().to_be_bytes());
        let coordinates = self.strata.iter().flatten();
        for (chunk, coordinate) in out[25..].chunks_exact_mut(8).zip(coordinates) {
            chunk.copy_from_slice(&coordinate.to_le_bytes());
        }
        out
    }

    /// Parses the record written by [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    /// Returns [`AlgebraicError::InvalidSketchLength`] when `bytes` is not
    /// exactly [`RESIDENT_SERIALIZED_LEN`] long, and
    /// [`AlgebraicError::DecodeFailure`] for an unknown version or a record
    /// that claims an empty population but carries a non-zero digest or
    /// syndrome.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AlgebraicError> {
        if bytes.len() != RESIDENT_SERIALIZED_LEN {
            return Err(AlgebraicError::InvalidSketchLength);
        }
        if bytes[0] != RESIDENT_FORMAT_VERSION {
            return Err(AlgebraicError::DecodeFailure);
        }
        let (digest, count) = (
            bytes[1..17].try_into().map(u128::from_be_bytes),
            bytes[17..25].try_into().map(u64::from_be_bytes),
        );
        let (Ok(digest), Ok(count)) = (digest, count) else {
            return Err(AlgebraicError::InvalidSketchLength);
        };
        let mut strata = [[0; STRATUM_CAPACITY]; STRATA_COUNT];
        let coordinates = strata.iter_mut().flatten();
        for (coordinate, chunk) in coordinates.zip(bytes[25..].chunks_exact(8)) {
            let chunk = chunk
                .try_into()
                .map_err(|_| AlgebraicError::InvalidSketchLength)?;
            *coordinate = u64::from_le_bytes(chunk);
        }
        let kernel = Self::from_parts(RoomAccumulator::from_parts(digest, count), strata);
        if count == 0 && kernel != Self::new() {
            return Err(AlgebraicError::DecodeFailure);
        }
        Ok(kernel)
    }

    /// Returns the level-0 room accumulator.
    #[must_use]
    pub const fn accumulator(&self) -> RoomAccumulator {
        self.accumulator
    }

    /// Returns the estimator's odd syndrome coordinates by stratum.
    #[must_use]
    pub const fn strata(&self) -> &[[u64; STRATUM_CAPACITY]; STRATA_COUNT] {
        &self.strata
    }

    /// Adds an element to the reconciled population.
    ///
    /// # Errors
    /// Returns an error if the hash is zero, or if the accumulator rejects the
    /// update due to its own capacity and count limits.
    pub fn insert(&mut self, hash: ElementHash) -> Result<(), AlgebraicError> {
        if hash.h64 == 0 {
            // Defensive guard: normal construction should never yield a zero short id.
            return Err(AlgebraicError::ZeroShortIdentifier);
        }
        self.accumulator.insert(hash)?;
        toggle_stratum(&mut self.strata, hash.h64);
        Ok(())
    }

    /// Removes an element from the reconciled population.
    ///
    /// # Errors
    /// Returns an error if the hash is zero, or if the accumulator rejects the
    /// update because the population is already empty.
    pub fn remove(&mut self, hash: ElementHash) -> Result<(), AlgebraicError> {
        if hash.h64 == 0 {
            // Defensive guard: normal construction should never yield a zero short id.
            return Err(AlgebraicError::ZeroShortIdentifier);
        }
        self.accumulator.remove(hash)?;
        toggle_stratum(&mut self.strata, hash.h64);
        Ok(())
    }
}

fn toggle_stratum(strata: &mut [[u64; STRATUM_CAPACITY]; STRATA_COUNT], value: u64) {
    let trailing_zeros = usize::try_from(value.trailing_zeros()).unwrap();
    let index = trailing_zeros.min(STRATA_COUNT - 1);
    let squared = gf64::mul(value, value);
    let mut odd_power = value;
    for syndrome in &mut strata[index] {
        *syndrome ^= odd_power;
        odd_power = gf64::mul(odd_power, squared);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn hash(h128: u128, h64: u64) -> ElementHash {
        ElementHash { h128, h64 }
    }

    #[test]
    fn updates_all_resident_layers_and_reverses_cleanly() {
        let event = hash(0xfeed, 0x100);
        let mut resident = ResidentKernel::new();

        resident.insert(event).unwrap();
        assert_eq!(resident.accumulator().digest(), event.h128);
        assert_eq!(resident.accumulator().known_event_count(), 1);
        assert_eq!(resident.strata()[8][0], event.h64);

        resident.remove(event).unwrap();
        assert_eq!(resident, ResidentKernel::new());
    }

    #[test]
    fn strata_store_odd_powers_and_cap_large_trailing_zero_counts() {
        let mut resident = ResidentKernel::new();
        let event = hash(1, 1_u64 << 40);
        resident.insert(event).unwrap();

        let stratum = &resident.strata()[STRATA_COUNT - 1];
        let squared = gf64::mul(event.h64, event.h64);
        let mut expected = event.h64;
        for syndrome in stratum {
            assert_eq!(*syndrome, expected);
            expected = gf64::mul(expected, squared);
        }
    }

    #[test]
    fn bytes_round_trip_and_stay_incrementally_maintainable() {
        let mut resident = ResidentKernel::new();
        for (h128, h64) in [(7, 0x100), (9, 0x3), (11, 1_u64 << 40)] {
            resident.insert(hash(h128, h64)).unwrap();
        }

        let bytes = resident.to_bytes();
        assert_eq!(bytes.len(), RESIDENT_SERIALIZED_LEN);
        assert_eq!(bytes[0], RESIDENT_FORMAT_VERSION);
        let mut restored = ResidentKernel::from_bytes(&bytes).unwrap();
        assert_eq!(restored, resident);

        // A reloaded kernel keeps accepting updates identically.
        restored.remove(hash(9, 0x3)).unwrap();
        resident.remove(hash(9, 0x3)).unwrap();
        assert_eq!(restored, resident);
    }

    #[test]
    fn from_parts_matches_incremental_build() {
        let mut built = ResidentKernel::new();
        built.insert(hash(5, 0x40)).unwrap();
        let rebuilt = ResidentKernel::from_parts(built.accumulator(), *built.strata());
        assert_eq!(rebuilt, built);
    }

    #[test]
    fn empty_kernel_round_trips() {
        let bytes = ResidentKernel::new().to_bytes();
        assert_eq!(
            ResidentKernel::from_bytes(&bytes),
            Ok(ResidentKernel::new())
        );
    }

    #[test]
    fn from_bytes_rejects_malformed_records() {
        let mut resident = ResidentKernel::new();
        resident.insert(hash(5, 0x40)).unwrap();
        let good = resident.to_bytes();

        assert_eq!(
            ResidentKernel::from_bytes(&good[..good.len() - 1]),
            Err(AlgebraicError::InvalidSketchLength)
        );
        let mut long = good.to_vec();
        long.push(0);
        assert_eq!(
            ResidentKernel::from_bytes(&long),
            Err(AlgebraicError::InvalidSketchLength)
        );

        let mut bad_version = good;
        bad_version[0] = RESIDENT_FORMAT_VERSION + 1;
        assert_eq!(
            ResidentKernel::from_bytes(&bad_version),
            Err(AlgebraicError::DecodeFailure)
        );

        // Count says empty, but the digest says otherwise.
        let mut zero_count = good;
        zero_count[17..25].fill(0);
        assert_eq!(
            ResidentKernel::from_bytes(&zero_count),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn rejects_zero_short_identifier_on_insert() {
        let mut resident = ResidentKernel::new();

        assert_eq!(
            resident.insert(hash(1, 0)),
            Err(AlgebraicError::ZeroShortIdentifier)
        );
        assert_eq!(resident, ResidentKernel::new());
    }

    #[test]
    fn rejects_zero_short_identifier_on_remove() {
        let mut resident = ResidentKernel::new();

        assert_eq!(
            resident.remove(hash(1, 0)),
            Err(AlgebraicError::ZeroShortIdentifier)
        );
        assert_eq!(resident, ResidentKernel::new());
    }
}
