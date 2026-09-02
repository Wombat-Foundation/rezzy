// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! The MSC4521 `algebraic_v1` set reconciliation profile.

use alloc::{string::String, vec, vec::Vec};
use base64::{
    engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD},
    Engine as _,
};
use sha2::{Digest as Sha2Digest, Sha256};

pub use super::gf64::mul as gf64_mul;

/// Maximum extraction capacity for an unbucketed `algebraic_v1` sketch.
pub const MAX_SKETCH_CAPACITY: usize = 32;
/// Default local extraction limit for CPU-bounded sketch decoding.
pub const MAX_LOCAL_SKETCH_DECODE_CAPACITY: usize = MAX_SKETCH_CAPACITY;
const EVENT_HASH_ENCODED_LEN: usize = 43;

/// An invalid event identifier, wire digest, or sketch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgebraicError {
    InvalidEventId,
    InvalidBase64,
    InvalidDigestLength,
    InvalidSketchCapacity,
    InvalidSketchLength,
    DecodeFailure,
    BudgetExhausted,
    ZeroShortIdentifier,
    InvalidBucketIndex,
    CountOverflow,
    CountUnderflow,
}

/// Encoding used to derive a Matrix event ID's canonical 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIdFormat {
    /// Room versions 1 and 2 hash the complete event ID.
    Legacy,
    /// Room version 3 uses unpadded standard Base64.
    V3,
    /// Room versions 4 and later use unpadded URL-safe Base64.
    V4Plus,
}

/// The two truncations of a reconciled element's canonical 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementHash {
    /// First 128 bits, interpreted in network byte order.
    pub h128: u128,
    /// First non-zero 64-bit chunk of the element digest (network byte order),
    /// falling back to 1 if all four 64-bit chunks are zero.
    pub h64: u64,
}

impl ElementHash {
    /// Derives the MSC4521 profile truncations from a canonical 32-byte element digest.
    #[must_use]
    pub fn from_digest32(digest: [u8; 32]) -> Self {
        let mut wide = [0; 16];
        wide.copy_from_slice(&digest[..16]);
        let mut short = [0; 8];
        let h64 = digest
            .chunks_exact(8)
            .take(4)
            .map(|chunk| {
                short.copy_from_slice(chunk);
                u64::from_be_bytes(short)
            })
            .find(|value| *value != 0)
            .unwrap_or(1);
        Self {
            h128: u128::from_be_bytes(wide),
            h64,
        }
    }

    /// Derives an element hash from a Matrix event ID.
    ///
    /// This is the MSC4521 Matrix event-ID binding. The algebraic kernel itself
    /// is generic over canonical 32-byte element digests.
    ///
    /// # Errors
    /// Returns an error when the ID has no `$` sigil, contains invalid base64,
    /// or its decoded hash is not exactly 32 bytes (256 bits).
    pub fn from_matrix_event_id(
        event_id: &str,
        format: EventIdFormat,
    ) -> Result<Self, AlgebraicError> {
        Self::matrix_event_digest32(event_id, format).map(Self::from_digest32)
    }

    /// Derives the MSC4521 Matrix event-ID binding digest `D(e)`.
    ///
    /// # Errors
    /// Returns an error when the ID has no `$` sigil, contains invalid base64,
    /// or its decoded hash is not exactly 32 bytes.
    pub fn matrix_event_digest32(
        event_id: &str,
        format: EventIdFormat,
    ) -> Result<[u8; 32], AlgebraicError> {
        let encoded = event_id
            .strip_prefix('$')
            .ok_or(AlgebraicError::InvalidEventId)?;
        if format != EventIdFormat::Legacy && encoded.len() > EVENT_HASH_ENCODED_LEN {
            return Err(AlgebraicError::InvalidBase64);
        }
        let digest = match format {
            EventIdFormat::Legacy => Sha256::digest(event_id.as_bytes()).to_vec(),
            EventIdFormat::V3 => STANDARD_NO_PAD
                .decode(encoded)
                .map_err(|_| AlgebraicError::InvalidBase64)?,
            EventIdFormat::V4Plus => URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|_| AlgebraicError::InvalidBase64)?,
        };
        if digest.len() != 32 {
            return Err(AlgebraicError::InvalidEventId);
        }
        digest
            .try_into()
            .map_err(|_| AlgebraicError::InvalidEventId)
    }
}

/// Incrementally maintained level-0 set digest and exact element count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RoomAccumulator {
    digest: u128,
    count: u64,
}

impl RoomAccumulator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            digest: 0,
            count: 0,
        }
    }
    #[must_use]
    pub const fn digest(self) -> u128 {
        self.digest
    }
    #[must_use]
    pub const fn known_event_count(self) -> u64 {
        self.count
    }

    /// Adds a known element.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::CountOverflow`] at `u64::MAX` events.
    pub fn insert(&mut self, hash: ElementHash) -> Result<(), AlgebraicError> {
        self.count = self
            .count
            .checked_add(1)
            .ok_or(AlgebraicError::CountOverflow)?;
        self.digest ^= hash.h128;
        Ok(())
    }

    /// Removes a known element.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::CountUnderflow`] when the accumulator is empty.
    pub fn remove(&mut self, hash: ElementHash) -> Result<(), AlgebraicError> {
        self.count = self
            .count
            .checked_sub(1)
            .ok_or(AlgebraicError::CountUnderflow)?;
        self.digest ^= hash.h128;
        Ok(())
    }

    #[must_use]
    pub fn encode_digest(self) -> String {
        URL_SAFE_NO_PAD.encode(self.digest.to_be_bytes())
    }

    /// Decodes a level-0 digest.
    ///
    /// # Errors
    /// Returns an error for invalid base64 or any decoded length other than 16 bytes.
    ///
    /// # Panics
    /// Panics only if the prior length check is violated internally.
    pub fn decode_digest(encoded: &str) -> Result<u128, AlgebraicError> {
        if encoded.len() != 22 {
            return Err(AlgebraicError::InvalidDigestLength);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AlgebraicError::InvalidBase64)?;
        let bytes: [u8; 16] = bytes
            .as_slice()
            .try_into()
            .expect("digest length is validated before decode");
        Ok(u128::from_be_bytes(bytes))
    }

    #[must_use]
    pub const fn residual(self, other: Self) -> u128 {
        self.digest ^ other.digest
    }

    /// Computes the unquoted opaque value for the MSC0501 HTTP `ETag`.
    ///
    /// # Panics
    /// Panics only if `serde_json` fails to serialize a sequence of strings.
    #[must_use]
    pub fn etag<'a>(self, extremity_event_ids: impl IntoIterator<Item = &'a str>) -> String {
        let mut extremities: Vec<&str> = extremity_event_ids.into_iter().collect();
        extremities.sort_unstable();
        let canonical = serde_json::to_vec(&extremities).expect("string arrays are serializable");
        let frontier_hash = Sha256::digest(canonical);
        let mut etag = Vec::with_capacity(24);
        etag.extend_from_slice(&self.digest.to_be_bytes());
        etag.extend_from_slice(&frontier_hash[..8]);
        URL_SAFE_NO_PAD.encode(etag)
    }
}

/// Checks decoded difference identifiers against the 128-bit integrity residual.
#[must_use]
pub fn verify_residual(
    expected_residual: u128,
    hashes: impl IntoIterator<Item = ElementHash>,
) -> bool {
    hashes
        .into_iter()
        .fold(0, |residual, hash| residual ^ hash.h128)
        == expected_residual
}

/// Odd syndrome coordinates `s1, s3, ... s(2k-1)` over GF(2^64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyndromeSketch {
    coordinates: Vec<u64>,
}

impl SyndromeSketch {
    pub(crate) fn from_coordinates(coordinates: Vec<u64>) -> Result<Self, AlgebraicError> {
        Self::from_coordinates_checked(coordinates)
    }

    fn from_coordinates_checked(coordinates: Vec<u64>) -> Result<Self, AlgebraicError> {
        if coordinates.is_empty() || coordinates.len() > MAX_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(Self { coordinates })
    }

    /// Allocates an empty sketch with the requested extraction capacity.
    ///
    /// # Errors
    /// Returns an error for zero capacity or capacity above the profile maximum.
    pub fn new(capacity: usize) -> Result<Self, AlgebraicError> {
        if capacity == 0 || capacity > MAX_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(Self {
            coordinates: vec![0; capacity],
        })
    }

    #[must_use]
    pub fn capacity(&self) -> usize {
        self.coordinates.len()
    }
    #[must_use]
    pub fn coordinates(&self) -> &[u64] {
        &self.coordinates
    }

    /// Subtracts (XORs) another sketch's coordinates from this one.
    ///
    /// # Errors
    /// Returns an error when sketch capacities differ.
    pub fn xor(&mut self, other: &Self) -> Result<(), AlgebraicError> {
        if self.capacity() != other.capacity() {
            return Err(AlgebraicError::InvalidSketchLength);
        }
        for (a, b) in self.coordinates.iter_mut().zip(other.coordinates.iter()) {
            *a ^= b;
        }
        Ok(())
    }

    /// Inserts or removes a short identifier. Both operations are XOR in characteristic two.
    /// # Errors
    /// Returns an error because zero is not representable by a `PinSketch`.
    pub fn toggle(&mut self, value: u64) -> Result<(), AlgebraicError> {
        if value == 0 {
            return Err(AlgebraicError::ZeroShortIdentifier);
        }
        let squared = gf64_mul(value, value);
        let mut odd_power = value;
        for coordinate in &mut self.coordinates {
            *coordinate ^= odd_power;
            odd_power = gf64_mul(odd_power, squared);
        }
        Ok(())
    }

    /// Decodes up to `max_elements` from this residual sketch.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::DecodeFailure`] when the residual exceeds the
    /// bound, is malformed, or does not factor into distinct field elements.
    /// Returns [`AlgebraicError::InvalidSketchCapacity`] when `max_elements`
    /// exceeds the sketch capacity or the local decode policy, and
    /// [`AlgebraicError::BudgetExhausted`] when root finding reaches its work limit.
    pub fn decode_elements(&self, max_elements: usize) -> Result<Vec<u64>, AlgebraicError> {
        if max_elements == 0
            || max_elements > self.capacity()
            || max_elements > MAX_LOCAL_SKETCH_DECODE_CAPACITY
        {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        let decoded = super::pinsketch::decode(&self.coordinates[..max_elements], max_elements)?;
        self.validate_decoded_elements(decoded)
    }

    /// # Errors
    ///
    /// Returns [`AlgebraicError::DecodeFailure`] when the residual exceeds the
    /// bound, is malformed, or does not factor into distinct field elements.
    /// Returns [`AlgebraicError::InvalidSketchCapacity`] when `max_elements`
    /// exceeds the sketch capacity or the local decode policy, and
    /// [`AlgebraicError::BudgetExhausted`] when root finding reaches its work limit.
    pub fn decode_elements_with_budget(
        &self,
        max_elements: usize,
        budget: usize,
    ) -> Result<Vec<u64>, AlgebraicError> {
        if max_elements == 0
            || max_elements > self.capacity()
            || max_elements > MAX_LOCAL_SKETCH_DECODE_CAPACITY
        {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        let decoded = super::pinsketch::decode_with_budget(
            &self.coordinates[..max_elements],
            max_elements,
            budget,
        )?;
        self.validate_decoded_elements(decoded)
    }

    fn validate_decoded_elements(&self, decoded: Vec<u64>) -> Result<Vec<u64>, AlgebraicError> {
        if decoded.contains(&0) {
            return Err(AlgebraicError::DecodeFailure);
        }
        let mut check = Self::new(self.capacity())?;
        for element in &decoded {
            check
                .toggle(*element)
                .expect("decoded elements are validated to be nonzero");
        }
        (check == *self)
            .then_some(decoded)
            .ok_or(AlgebraicError::DecodeFailure)
    }

    /// XOR-subtracts another sketch.
    ///
    /// # Errors
    /// Returns an error when sketch capacities differ.
    pub fn subtract(&self, other: &Self) -> Result<Self, AlgebraicError> {
        if self.capacity() != other.capacity() {
            return Err(AlgebraicError::InvalidSketchLength);
        }
        Ok(Self {
            coordinates: self
                .coordinates
                .iter()
                .zip(&other.coordinates)
                .map(|(a, b)| a ^ b)
                .collect(),
        })
    }

    #[must_use]
    pub fn encode(&self) -> String {
        let byte_len = self.coordinates.len().checked_mul(8).unwrap_or(0);
        let mut bytes = Vec::with_capacity(byte_len);
        for coordinate in &self.coordinates {
            bytes.extend_from_slice(&coordinate.to_le_bytes());
        }
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Decodes a sketch with an externally negotiated capacity.
    ///
    /// # Errors
    /// Returns an error for invalid capacity, base64, or encoded byte length.
    pub fn decode(capacity: usize, encoded: &str) -> Result<Self, AlgebraicError> {
        if capacity == 0 || capacity > MAX_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        let expected_len = capacity
            .checked_mul(8)
            .ok_or(AlgebraicError::InvalidSketchLength)?;
        let expected_encoded_len =
            base64::encoded_len(expected_len, false).ok_or(AlgebraicError::InvalidSketchLength)?;
        if encoded.len() != expected_encoded_len {
            return Err(AlgebraicError::InvalidSketchLength);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| AlgebraicError::InvalidBase64)?;
        Self::from_encoded_bytes(capacity, &bytes)
    }

    fn from_encoded_bytes(capacity: usize, bytes: &[u8]) -> Result<Self, AlgebraicError> {
        let expected_len = capacity
            .checked_mul(8)
            .ok_or(AlgebraicError::InvalidSketchLength)?;
        if bytes.len() != expected_len {
            return Err(AlgebraicError::InvalidSketchLength);
        }
        let coordinates = bytes
            .chunks_exact(8)
            .map(|chunk| {
                let mut value = [0; 8];
                value.copy_from_slice(chunk);
                u64::from_le_bytes(value)
            })
            .collect();
        Ok(Self { coordinates })
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::vec;

    use super::*;

    fn hash(seed: u8) -> ElementHash {
        ElementHash {
            h128: u128::from(seed) << 120,
            h64: u64::from(seed) << 56,
        }
    }

    #[test]
    fn accumulator_wire_form_is_exactly_sixteen_bytes() {
        let mut accumulator = RoomAccumulator::new();
        accumulator.insert(hash(7)).unwrap();
        assert_eq!(
            RoomAccumulator::decode_digest(&accumulator.encode_digest()).unwrap(),
            accumulator.digest()
        );
        accumulator.remove(hash(7)).unwrap();
        assert_eq!(accumulator, RoomAccumulator::new());
    }

    #[test]
    fn sketch_subtraction_recovers_toggled_syndromes() {
        let mut left = SyndromeSketch::new(4).unwrap();
        let mut right = SyndromeSketch::new(4).unwrap();
        left.toggle(2).unwrap();
        left.toggle(3).unwrap();
        right.toggle(2).unwrap();
        let residual = left.subtract(&right).unwrap();
        let mut expected = SyndromeSketch::new(4).unwrap();
        expected.toggle(3).unwrap();
        assert_eq!(residual, expected);
        assert_eq!(
            SyndromeSketch::decode(4, &residual.encode()).unwrap(),
            residual
        );
    }

    #[test]
    fn etag_is_independent_of_extremity_order() {
        let accumulator = RoomAccumulator {
            digest: 42,
            count: 2,
        };
        assert_eq!(
            accumulator.etag(["$b", "$a"]),
            accumulator.etag(["$a", "$b"]),
        );
        assert_ne!(accumulator.etag(["$a"]), accumulator.etag(["$b"]));
    }

    #[test]
    fn counters_reject_underflow_and_profile_overflow() {
        let event = hash(1);
        assert_eq!(
            RoomAccumulator::new().remove(event),
            Err(AlgebraicError::CountUnderflow)
        );

        let mut accumulator = RoomAccumulator {
            digest: 0,
            count: u64::MAX,
        };
        assert_eq!(
            accumulator.insert(event),
            Err(AlgebraicError::CountOverflow)
        );
    }

    #[test]
    fn sketch_construction_rejects_invalid_capacities() {
        assert_eq!(
            SyndromeSketch::from_coordinates(Vec::new()),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert_eq!(
            SyndromeSketch::from_coordinates(vec![0; MAX_SKETCH_CAPACITY + 1]),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
    }

    #[test]
    fn sketch_xor_modifies_in_place() {
        let mut left = SyndromeSketch::new(4).unwrap();
        left.toggle(1).unwrap();
        left.toggle(2).unwrap();

        let mut right = SyndromeSketch::new(4).unwrap();
        right.toggle(2).unwrap();
        right.toggle(3).unwrap();

        left.xor(&right).unwrap();

        let mut expected = SyndromeSketch::new(4).unwrap();
        expected.toggle(1).unwrap();
        expected.toggle(3).unwrap();

        assert_eq!(left, expected);
    }

    #[test]
    fn sketch_xor_rejects_capacity_mismatch() {
        let mut left = SyndromeSketch::new(4).unwrap();
        let right = SyndromeSketch::new(3).unwrap();

        assert_eq!(left.xor(&right), Err(AlgebraicError::InvalidSketchLength));
    }

    #[test]
    fn sketch_decode_elements_rejects_zero_root() {
        let sketch = SyndromeSketch::new(1).unwrap();

        assert_eq!(
            sketch.validate_decoded_elements(vec![0]),
            Err(AlgebraicError::DecodeFailure)
        );
    }

    #[test]
    fn sketch_decode_rejects_invalid_capacity() {
        assert_eq!(
            SyndromeSketch::decode(0, ""),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert_eq!(
            SyndromeSketch::decode(MAX_SKETCH_CAPACITY + 1, ""),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
    }

    #[test]
    fn sketch_from_encoded_bytes_rejects_length_mismatch() {
        let bytes = vec![0; 7];

        assert_eq!(
            SyndromeSketch::from_encoded_bytes(1, &bytes),
            Err(AlgebraicError::InvalidSketchLength)
        );
    }
}
