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
use core::fmt::Write as _;
use sha2::{Digest as Sha2Digest, Sha256};

pub use super::gf64::mul as gf64_mul;

/// Maximum extraction capacity for an unbucketed `algebraic_v1` sketch.
pub const MAX_SKETCH_CAPACITY: usize = 32;
/// Default local extraction limit for CPU-bounded sketch decoding.
pub const MAX_LOCAL_SKETCH_DECODE_CAPACITY: usize = MAX_SKETCH_CAPACITY;
/// Hard-capped overflow capacity for adaptive reconciliation.
/// Separate from `MAX_SKETCH_CAPACITY`; only reachable after overflow request
/// validation passes.
// A full degree-256 decode is only affordable within `MAX_FACTOR_WORK`
// because `pinsketch::build_frobenius_basis` amortizes the root-finding
// ladder's dominant cost across all trials for a node instead of repeating
// it per trial -- see `MAX_FACTOR_WORK`'s comment for the measurement this
// capacity relies on, including the caveat that it covers observed
// balanced-split behavior, not a proven worst case.
pub const MAX_OVERFLOW_SKETCH_CAPACITY: usize = 256;
const EVENT_HASH_ENCODED_LEN: usize = 43;

/// An invalid event identifier, wire digest, or sketch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgebraicError {
    /// The event ID is not a valid reference-hash ID.
    InvalidEventId,
    /// The text is not valid unpadded base64 or base64url.
    InvalidBase64,
    /// A digest did not decode to the expected length.
    InvalidDigestLength,
    /// The sketch capacity is zero or above the allowed maximum.
    InvalidSketchCapacity,
    /// A sketch's byte length does not match its capacity.
    InvalidSketchLength,
    /// The sketch could not be decoded within its capacity.
    DecodeFailure,
    /// The work budget ran out before decoding finished.
    BudgetExhausted,
    /// An event hashed to the reserved zero short identifier.
    ZeroShortIdentifier,
    /// A bucket depth or prefix is out of range.
    InvalidBucketIndex,
    /// The event count overflowed.
    CountOverflow,
    /// Removing an event would take the count below zero.
    CountUnderflow,
    /// The room's event IDs are sender-chosen strings (room versions 1 and 2),
    /// so `algebraic_v1` MUST NOT build an `event_ids` frame for it.
    UnsupportedRoomVersion,
}

/// What a room's event IDs are, as far as MSC4521's `event_ids` binding cares.
///
/// This is the recon-local input for the once-per-room check; the caller maps
/// its room version onto it (room versions 1 and 2 are
/// [`SenderChosen`](Self::SenderChosen), 3 and later
/// [`ReferenceHash`](Self::ReferenceHash)), so this crate needs no dependency
/// on a room-version type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoomEventIdKind {
    /// Event IDs are sender-chosen strings (room versions 1 and 2).
    SenderChosen,
    /// Event IDs are reference hashes (room versions 3 and later).
    ReferenceHash,
}

impl RoomEventIdKind {
    /// Rejects rooms the `event_ids` binding must not be used for.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::UnsupportedRoomVersion`] for
    /// [`SenderChosen`](Self::SenderChosen).
    pub const fn require_event_ids_frame(self) -> Result<(), AlgebraicError> {
        match self {
            Self::SenderChosen => Err(AlgebraicError::UnsupportedRoomVersion),
            Self::ReferenceHash => Ok(()),
        }
    }
}

/// Encoding used to derive a Matrix event ID's canonical 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventIdFormat {
    /// Room version 3 uses unpadded standard Base64.
    V3,
    /// Room versions 4 and later use unpadded URL-safe Base64.
    V4Plus,
}

/// The two truncations of a reconciled element's canonical 32-byte digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ElementHash {
    /// Last 128 bits (bytes 16..32), interpreted in network byte order.
    ///
    /// Drawn from bytes disjoint from `h64` so the integrity residual stays
    /// independent of placement (the `h64` scan only reaches these bytes when
    /// the first two 8-byte chunks are zero).
    pub h128: u128,
    /// First non-zero 64-bit chunk of the element digest (network byte order),
    /// falling back to 1 if all four 64-bit chunks are zero.
    pub h64: u64,
}

impl ElementHash {
    // TODO(prefix-grinding): `h64` is derived unkeyed from the element
    // digest below. For V3/V4+ Matrix event IDs the digest *is* a content
    // hash the event's author controls (message body, custom content keys,
    // timestamp within clock-skew tolerance all give grinding room), so an
    // attacker with grinding room can search offline for events whose h64
    // shares a long common prefix -- roughly 2^k SHA-256/BLAKE-family
    // hashes for k bits, i.e. seconds of commodity CPU for k in the
    // mid-20s. Note this needs more than "can post events": an event that
    // replicated normally is present in both sides' sets and cancels out
    // of the symmetric difference, so it never reaches the bucket splitter
    // at all. The attacker needs the ground events to actually be *in* the
    // difference at reconciliation time -- e.g. selective federation, or
    // an attacker-operated homeserver that delivers them to some peers and
    // withholds them from others. A materially lower bar than compromising
    // a server, but a different (and narrower) threat model than "any room
    // member," and worth stating precisely before this goes into 4511-C.
    //
    // Given that precondition, `client.rs`'s bucket splitter descends one
    // h64 bit per round (`bucket_range_start`/the depth-increment in
    // `select_action`) over `MAX_RECONCILIATION_ROUNDS` (20) rounds before
    // giving up to `ClientAction::ExtremityDiff`, so a ~20+ bit shared
    // prefix reliably exhausts every round on that bucket before any real
    // split happens. This isn't a one-off cost either: h64 is fixed
    // forever once an event exists, so a single grinding pass taxes
    // *every future* pairwise reconciliation of the room that touches
    // those events (subject to the withholding precondition above), on
    // any pair of servers, indefinitely -- not just the session the
    // attacker ran it against.
    //
    // The fix from the literature (Yang et al., "Practical Rateless Set
    // Reconciliation" §4.3) is a keyed hash (e.g. SipHash) negotiated
    // per-session so placement isn't predictable offline. That is NOT a
    // drop-in here: `ResidentKernel` (resident.rs) is deliberately a
    // server-local structure built once and incrementally maintained
    // across the room's lifetime, then reused to serve *any* peer that
    // reconciles against it -- the whole point is amortizing the
    // build cost across many peers/sessions rather than rebuilding
    // per-session. Keying `h64` per-session breaks that: the bucket
    // geometry (and therefore the resident trie's shape) would become
    // session-specific, so the server would need either a separate
    // resident structure per active peer (defeats the amortization this
    // module exists for) or a coarser shared secret.
    //
    // A *static* room-scoped key doesn't solve it: the realistic
    // adversary is a room member grinding their own event content, and a
    // static room-scoped key is known to every room member by
    // construction. But what defeats grinding isn't secrecy of the key --
    // it's unpredictability at authoring time. Event IDs (and therefore
    // h64) are fixed when the event is created; if the placement key
    // didn't exist yet, no amount of offline grinding could have targeted
    // it. A room-scoped key that *rotates on an epoch* is still public to
    // every member and still defeats precomputation, because a
    // pre-ground event lands in an unpredictable bucket after the next
    // rotation. That preserves `ResidentKernel`'s amortization within an
    // epoch (one rebuild per rotation, not per session) -- a materially
    // different, more promising tradeoff than per-session keying. Needs
    // an MSC-level design decision (epoch-rotated placement key vs.
    // accepting the bounded liveness cost and documenting it, informed by
    // the client-side mitigation noted on `MAX_RECONCILIATION_ROUNDS` in
    // client.rs), not a code-level patch -- see 4511-C.
    /// Derives the MSC4521 profile truncations from a canonical 32-byte element digest.
    #[must_use]
    pub fn from_digest32(digest: [u8; 32]) -> Self {
        let mut wide = [0; 16];
        wide.copy_from_slice(&digest[16..]);
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

    /// Derives an element hash from opaque bytes as `SHA-256` of a canonical
    /// encoding chosen by the caller.
    ///
    /// This is for non-event populations (for example notary key IDs). It is
    /// not the event-ID binding: room versions 1 and 2 are out of scope for
    /// `algebraic_v1` because their sender-chosen IDs make `h64` collisions free.
    #[must_use]
    pub fn from_opaque_bytes(canonical: &[u8]) -> Self {
        Self::from_digest32(Sha256::digest(canonical).into())
    }

    /// Derives an element hash from a Matrix event ID.
    ///
    /// This is the MSC4521 Matrix event-ID binding (`event_ids`). The algebraic kernel itself
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
        if encoded.len() > EVENT_HASH_ENCODED_LEN {
            return Err(AlgebraicError::InvalidBase64);
        }
        let digest = match format {
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
    /// An empty accumulator: zero digest, zero events.
    pub const fn new() -> Self {
        Self {
            digest: 0,
            count: 0,
        }
    }
    #[must_use]
    /// Rebuilds an accumulator from a previously observed digest and count.
    ///
    /// This is the persistence counterpart of [`digest`](Self::digest) and
    /// [`known_event_count`](Self::known_event_count). The pair is trusted: it
    /// cannot be checked against the population it summarizes.
    pub const fn from_parts(digest: u128, count: u64) -> Self {
        Self { digest, count }
    }
    #[must_use]
    /// The accumulated 128-bit digest.
    pub const fn digest(self) -> u128 {
        self.digest
    }
    #[must_use]
    /// The number of events accumulated.
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
    /// The digest as unpadded base64url of its big-endian bytes.
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
    /// XOR of the two digests; zero when they agree.
    pub const fn residual(self, other: Self) -> u128 {
        self.digest ^ other.digest
    }

    /// Computes the unquoted opaque value for the MSC0501 HTTP `ETag`.
    #[must_use]
    pub fn etag<'a>(self, extremity_event_ids: impl IntoIterator<Item = &'a str>) -> String {
        let mut extremities: Vec<&str> = extremity_event_ids.into_iter().collect();
        extremities.sort_unstable();
        let canonical = alloc::format!(
            "[{}]",
            extremities
                .iter()
                .map(|s| {
                    let mut escaped = alloc::string::String::new();
                    for ch in s.chars() {
                        match ch {
                            '"' => escaped.push_str("\\\""),
                            '\\' => escaped.push_str("\\\\"),
                            '\u{08}' => escaped.push_str("\\b"),
                            '\u{0c}' => escaped.push_str("\\f"),
                            '\n' => escaped.push_str("\\n"),
                            '\r' => escaped.push_str("\\r"),
                            '\t' => escaped.push_str("\\t"),
                            c if (c as u32) < 0x20 => {
                                let _ = write!(escaped, "\\u{:04x}", c as u32);
                            }
                            c => escaped.push(c),
                        }
                    }
                    alloc::format!("\"{escaped}\"")
                })
                .collect::<alloc::vec::Vec<_>>()
                .join(",")
        );
        let frontier_hash = Sha256::digest(canonical.as_bytes());
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
    /// Number of coordinates, i.e. the sketch's capacity.
    pub const fn capacity(&self) -> usize {
        self.coordinates.len()
    }
    #[must_use]
    /// The sketch coordinates.
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
        self.validate_decode_capacity(max_elements, MAX_LOCAL_SKETCH_DECODE_CAPACITY)?;
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
        let mut remaining = budget;
        self.decode_elements_with_shared_budget(max_elements, &mut remaining)
    }

    /// Like [`decode_elements_with_budget`](Self::decode_elements_with_budget),
    /// but draws from and updates a caller-owned `budget` in place, so a
    /// caller decoding many sketches in a batch (e.g.
    /// [`super::triage::decode_bucket_sketches`]) can enforce one shared
    /// work ceiling across the whole batch instead of each sketch getting
    /// its own independent allowance.
    ///
    /// # Errors
    ///
    /// Same as [`decode_elements_with_budget`](Self::decode_elements_with_budget).
    pub(crate) fn decode_elements_with_shared_budget(
        &self,
        max_elements: usize,
        budget: &mut usize,
    ) -> Result<Vec<u64>, AlgebraicError> {
        self.validate_decode_capacity(max_elements, MAX_LOCAL_SKETCH_DECODE_CAPACITY)?;
        let decoded = super::pinsketch::decode_with_budget(
            &self.coordinates[..max_elements],
            max_elements,
            budget,
        )?;
        self.validate_decoded_elements(decoded)
    }

    const fn validate_decode_capacity(
        &self,
        max_elements: usize,
        limit: usize,
    ) -> Result<(), AlgebraicError> {
        if max_elements == 0 || max_elements > self.capacity() || max_elements > limit {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(())
    }

    fn validate_decoded_elements(&self, decoded: Vec<u64>) -> Result<Vec<u64>, AlgebraicError> {
        self.validate_decoded(decoded, Self::new)
    }

    fn validate_decoded(
        &self,
        decoded: Vec<u64>,
        new_check: fn(usize) -> Result<Self, AlgebraicError>,
    ) -> Result<Vec<u64>, AlgebraicError> {
        if decoded.len() > self.capacity() || decoded.contains(&0) {
            return Err(AlgebraicError::DecodeFailure);
        }
        let mut check = new_check(self.capacity())?;
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
    /// The sketch as base64url of its coordinates.
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
        Self::decode_with_limit(capacity, encoded, MAX_SKETCH_CAPACITY)
    }

    fn decode_with_limit(
        capacity: usize,
        encoded: &str,
        max_capacity: usize,
    ) -> Result<Self, AlgebraicError> {
        if capacity == 0 || capacity > max_capacity {
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

    /// Allocates an empty sketch with overflow extraction capacity.
    ///
    /// Overflow sketches are used when a standard 32-element sketch fails to
    /// decode and a larger sketch is requested under the local overflow policy.
    /// The capacity is validated against [`MAX_OVERFLOW_SKETCH_CAPACITY`].
    ///
    /// # Errors
    /// Returns an error for zero capacity or capacity above the overflow maximum.
    pub fn new_overflow(capacity: usize) -> Result<Self, AlgebraicError> {
        if capacity == 0 || capacity > MAX_OVERFLOW_SKETCH_CAPACITY {
            return Err(AlgebraicError::InvalidSketchCapacity);
        }
        Ok(Self {
            coordinates: vec![0; capacity],
        })
    }

    /// Decodes a sketch with overflow capacity from wire encoding.
    ///
    /// Like [`decode`](Self::decode) but validates against
    /// [`MAX_OVERFLOW_SKETCH_CAPACITY`].
    ///
    /// # Errors
    /// Returns an error for invalid capacity, base64, or encoded byte length.
    pub fn decode_overflow(capacity: usize, encoded: &str) -> Result<Self, AlgebraicError> {
        Self::decode_with_limit(capacity, encoded, MAX_OVERFLOW_SKETCH_CAPACITY)
    }

    /// Decodes up to `max_elements` with overflow capacity support.
    ///
    /// Like [`decode_elements_with_budget`](Self::decode_elements_with_budget)
    /// but validates against [`MAX_OVERFLOW_SKETCH_CAPACITY`] instead of
    /// [`MAX_LOCAL_SKETCH_DECODE_CAPACITY`].
    ///
    /// # Errors
    /// Returns [`AlgebraicError::InvalidSketchCapacity`] when `max_elements`
    /// exceeds the sketch capacity or the overflow capacity limit, and
    /// [`AlgebraicError::BudgetExhausted`] when root finding reaches its work
    /// limit.
    pub fn decode_elements_overflow_budget(
        &self,
        max_elements: usize,
        budget: usize,
    ) -> Result<Vec<u64>, AlgebraicError> {
        self.validate_decode_capacity(max_elements, MAX_OVERFLOW_SKETCH_CAPACITY)?;
        let mut remaining = budget;
        let decoded = super::pinsketch::decode_with_budget(
            &self.coordinates[..max_elements],
            max_elements,
            &mut remaining,
        )?;
        self.validate_decoded_overflow(decoded)
    }

    fn validate_decoded_overflow(&self, decoded: Vec<u64>) -> Result<Vec<u64>, AlgebraicError> {
        self.validate_decoded(decoded, Self::new_overflow)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use alloc::vec;

    use super::*;

    #[test]
    fn h128_comes_from_the_trailing_half_disjoint_from_h64() {
        let mut digest = [0_u8; 32];
        for (i, byte) in digest.iter_mut().enumerate() {
            *byte = u8::try_from(i + 1).unwrap();
        }
        let hash = ElementHash::from_digest32(digest);
        assert_eq!(hash.h64, 0x0102_0304_0506_0708);
        assert_eq!(hash.h128, 0x1112_1314_1516_1718_191a_1b1c_1d1e_1f20);

        // Two digests colliding on h64 still differ in h128.
        let mut other = digest;
        other[31] ^= 1;
        let collided = ElementHash::from_digest32(other);
        assert_eq!(collided.h64, hash.h64);
        assert_ne!(collided.h128, hash.h128);
    }

    #[test]
    fn h64_falls_back_past_zero_leading_chunks_but_h128_stays_trailing() {
        let mut digest = [0_u8; 32];
        digest[8..16].copy_from_slice(&7_u64.to_be_bytes());
        digest[31] = 9;
        let hash = ElementHash::from_digest32(digest);
        assert_eq!(hash.h64, 7);
        assert_eq!(hash.h128, 9);
    }

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

    #[test]
    fn overflow_capacity_rejects_above_limit() {
        assert_eq!(
            SyndromeSketch::new_overflow(MAX_OVERFLOW_SKETCH_CAPACITY + 1),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert_eq!(
            SyndromeSketch::new_overflow(0),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert!(SyndromeSketch::new_overflow(MAX_OVERFLOW_SKETCH_CAPACITY).is_ok());
        assert!(SyndromeSketch::new_overflow(64).is_ok());
    }

    #[test]
    fn overflow_decode_rejects_oversized_capacity_before_allocation() {
        assert_eq!(
            SyndromeSketch::decode_overflow(300, "AAAAAAAAAAAAAAAA"),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
        assert_eq!(
            SyndromeSketch::decode_overflow(0, ""),
            Err(AlgebraicError::InvalidSketchCapacity)
        );
    }

    #[test]
    fn overflow_decode_budget_exhaustion() {
        let mut sketch = SyndromeSketch::new_overflow(64).unwrap();
        for i in 1..=64u64 {
            sketch.toggle(i * 2 + 1).unwrap();
        }
        let res = sketch.decode_elements_overflow_budget(64, 100);
        assert_eq!(res, Err(AlgebraicError::BudgetExhausted));
    }

    /// Fast unit test for the capacity-mismatch check itself: a
    /// capacity-256 sketch must reject a 257-element decode even though
    /// re-encoding those values would reproduce the sketch exactly
    /// (`toggle` does not enforce capacity). The end-to-end variant of
    /// this scenario is [`overflow_257_vs_256_capacity`], which is
    /// ignored by default because it runs the full degree-256
    /// factorization.
    #[test]
    fn overflow_decode_rejects_more_values_than_capacity() {
        let mut sketch = SyndromeSketch::new_overflow(256).unwrap();
        for value in (1..=257u64).map(|i| i * 2 + 1) {
            sketch.toggle(value).unwrap();
        }
        let decoded: Vec<u64> = (1..=257u64).map(|i| i * 2 + 1).collect();
        assert_eq!(
            sketch.validate_decoded(decoded, SyndromeSketch::new_overflow),
            Err(AlgebraicError::DecodeFailure),
            "257 decoded values must not be accepted for capacity 256"
        );
    }

    /// End-to-end over-capacity decode (257 differences at capacity 256).
    ///
    /// Slow by design: it intentionally performs a full degree-256
    /// factorization, and the 16M budget (`MAX_FACTOR_WORK`) is needed so
    /// the run reaches a real `DecodeFailure` instead of exiting early
    /// with `BudgetExhausted`. That makes it an expensive stress test of
    /// the factoring path rather than a focused unit test of the
    /// capacity-mismatch check (covered in microseconds by
    /// [`overflow_decode_rejects_more_values_than_capacity`]). Note the
    /// 16M budget covers observed/practical degree-256 inputs, not a
    /// proven worst case -- see `MAX_FACTOR_WORK`'s comment in
    /// `pinsketch.rs`. Ignored by default; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "full degree-256 factorization; run with cargo test -- --ignored"]
    fn overflow_257_vs_256_capacity() {
        let mut sketch = SyndromeSketch::new_overflow(256).unwrap();
        for i in 1..=257u64 {
            sketch.toggle(i * 2 + 1).unwrap();
        }
        let res = sketch.decode_elements_overflow_budget(256, 16_000_000);
        assert_eq!(
            res,
            Err(AlgebraicError::DecodeFailure),
            "257 differences at capacity 256 must fail with DecodeFailure, not budget exhaustion"
        );
    }

    #[test]
    fn overflow_decode_recovers_symmetric_difference() {
        let mut local = SyndromeSketch::new_overflow(128).unwrap();
        let mut remote = SyndromeSketch::new_overflow(128).unwrap();
        for i in 1..=64u64 {
            local.toggle(i * 2 + 1).unwrap();
            remote.toggle(i * 2 + 1).unwrap();
        }
        for i in 65..=80u64 {
            remote.toggle(i * 2 + 1).unwrap();
        }
        for i in 81..=96u64 {
            local.toggle(i * 2 + 1).unwrap();
        }
        let residual = remote.subtract(&local).unwrap();
        let mut decoded = residual
            .decode_elements_overflow_budget(32, 8_000_000)
            .unwrap();
        decoded.sort_unstable();
        let mut expected: Vec<u64> = (65..=96).map(|i| i * 2 + 1).collect();
        expected.sort_unstable();
        assert_eq!(decoded, expected);
    }

    #[test]
    fn overflow_decode_rejects_truncated_coordinates() {
        let sketch = SyndromeSketch::new_overflow(128).unwrap();
        let result = sketch.decode_elements_overflow_budget(129, 8_000_000);
        assert_eq!(result, Err(AlgebraicError::InvalidSketchCapacity));
    }
}
