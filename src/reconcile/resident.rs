// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Incrementally maintained MSC0500 reconciliation state.

use super::{
    algebraic::{AlgebraicError, ElementHash, RoomAccumulator},
    gf64,
};

/// Number of estimator strata.
pub const STRATA_COUNT: usize = 32;
/// Extraction capacity maintained in each estimator stratum.
pub const STRATUM_CAPACITY: usize = 8;

/// Per-population resident reconciliation state.
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
