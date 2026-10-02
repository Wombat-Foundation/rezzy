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

//! Homomorphic state hashing via `LtHash` (MSC4500-shaped).
//!
//! `LtHash` (Lattice Hash) is based on the homomorphic hashing paradigm first
//! introduced by Bellare and Micciancio in their 1997 paper *"A New Paradigm
//! for Collision-Free Hashing: Incrementality at Reduced Cost"*. This specific
//! instantiation (by default 2048 bytes, using 1024 16-bit integers and
//! wrapping addition) is modeled after the industry-standard implementation in
//! Meta's Folly library (`folly::crypto::LtHash`).
//!
//! Each element is expanded to `2 * LANES` bytes with the BLAKE3 extendable
//! output function (XOF), unpacked into `LANES` little-endian 16-bit lanes.
//! The accumulator is the wrapping addition of those vectors, and the wire
//! digest is `BLAKE3(lattice)`. This provides:
//!
//! - **O(1) incremental updates**: insert = `hash + expanded`,
//!   remove = `hash - expanded`.
//! - **Order independence**: addition is commutative + associative.
//! - **Cryptographic security**: hard to find set collisions (SVP).
//!
//! # Why BLAKE3 instead of SHAKE256
//!
//! The original draft expanded elements with SHAKE256 (FIPS 202). Squeezing
//! 2048 bytes costs 16 `Keccak-f1600` permutations, and no mainstream CPU has
//! a Keccak instruction, so expansion dominated every insert at roughly
//! 99% of the per-element cost. BLAKE3 replaces it with an ARX construction
//! that maps to the same SIMD paths on every target (AVX2/AVX-512 on x86,
//! NEON on ARM, `simd128` on wasm), is constant-time by construction, and
//! produces the same 2048 bytes in about 220ns instead of 5500ns.
//!
//! The domain-separation tags are versioned `...:blake3:v1` so a digest
//! produced by this module can never be confused with a SHAKE256
//! instantiation of the same shape.
//!
//! # API layers
//!
//! - [`LtHash`] is the plumbing: seeds from raw bytes, key-value fields, or
//!   MSC4500 `(event_type, state_key, event_id)` elements, batch updates,
//!   algebraic traits, and tri-mode output (lattice / digest / both).
//! - [`RedactionOverlay`] and [`PduLtHash`] are thin domain layers over it.

use alloc::vec::Vec;
use core::iter::{Extend, FromIterator, Sum};
use core::ops::{Add, AddAssign, Sub, SubAssign};

/// A homomorphic lattice hash over `LANES` 16-bit lanes.
///
/// `LtHash` (Lattice Hash) is based on the homomorphic hashing paradigm first introduced
/// by Bellare and Micciancio in their 1997 paper *"A New Paradigm for Collision-Free
/// Hashing: Incrementality at Reduced Cost"*. The default 2048-byte instantiation
/// (1024 16-bit integers and wrapping addition) is modeled after the industry-standard
/// implementation in Meta's Folly library (`folly::crypto::LtHash`).
///
/// Each element is expanded to `2 * LANES` bytes with the BLAKE3 XOF, unpacked into
/// `LANES` little-endian 16-bit lanes. The accumulator is the wrapping addition of all
/// those vectors:
///
/// - **O(1) incremental updates**: insert = `hash + expanded`,
///   remove = `hash - expanded`.
/// - **Order independence**: addition is commutative + associative.
/// - **Cryptographic security**: hard to find set collisions (SVP).
///
/// `LANES` only needs to be even to be well-formed; it exists so callers that want a
/// smaller accumulator (or a larger one) do not have to fork this type.
///
/// `StateUpdate::New/Unchanged` now carry `&LtHash` (borrowed, zero-copy); callers
/// that need to retain the hash (e.g. across a thread channel) copy it explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LtLattice<const LANES: usize>(pub [u16; LANES]);

/// The MSC4500-shaped 2048-byte state hash: 1024 lanes of 16 bits.
///
/// This is [`LtLattice`]'s default instantiation. It is a type alias rather than a
/// defaulted `const LANES: usize = 1024` parameter on purpose: default const parameters
/// are only substituted in type position, so `LtHash::ZERO`, `LtHash::seed(..)` and
/// `LtHash::from_state(..)` would be un-inferable in every expression position. Naming
/// the instantiation keeps the pre-existing `LtHash` spelling working everywhere while
/// other widths stay available as `LtLattice<512>`.
pub type LtHash = LtLattice<1024>;

impl<const LANES: usize> Default for LtLattice<LANES> {
    fn default() -> Self {
        Self::ZERO
    }
}

/// Adapter that lets `core::fmt::Display` values be streamed into a BLAKE3 hasher.
struct HashWriter<'a> {
    hasher: &'a mut blake3::Hasher,
}

impl core::fmt::Write for HashWriter<'_> {
    #[inline]
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.hasher.update(s.as_bytes());
        Ok(())
    }
}

/// Truncate a string to fit within a `u16` length prefix (65535 bytes).
///
/// Valid Matrix events are capped at 64KiB total, so real event types and state keys
/// can never reach this limit. Truncation only applies to malformed/adversarial input.
#[inline]
fn truncate_to_u16_limit(s: &str) -> (&str, u16) {
    let limit = usize::from(u16::MAX);
    let s_len = s.len();
    if s_len > limit {
        let mut end = limit;
        while !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        (&s[..end], u16::try_from(end).unwrap())
    } else {
        (s, u16::try_from(s_len).unwrap())
    }
}

/// Squeezes `LANES * 2` bytes out of a fresh BLAKE3 hasher and unpacks them into
/// little-endian 16-bit lanes.
///
/// Lanes are unpacked in 128-lane (256-byte) windows so each [`blake3::OutputReader::fill`]
/// call is a whole number of 64-byte blocks; the scratch buffer is fixed-size so no
/// heap allocation happens on the hot insert path regardless of `LANES`.
#[must_use]
fn expand_lanes<const LANES: usize>(feed: impl FnOnce(&mut blake3::Hasher)) -> [u16; LANES] {
    let mut hasher = blake3::Hasher::new();
    feed(&mut hasher);

    let mut reader = hasher.finalize_xof();
    let mut out = [0u16; LANES];
    let mut scratch = [0u8; 256];
    for chunk in out.chunks_mut(128) {
        let n = chunk.len().wrapping_mul(2);
        reader.fill(&mut scratch[..n]);
        for (lane, pair) in chunk.iter_mut().zip(scratch[..n].chunks_exact(2)) {
            *lane = u16::from_le_bytes([pair[0], pair[1]]);
        }
    }
    out
}

/// Computes the lane expansion for a single state entry under the given
/// domain-separation tag.
///
/// Input encoding: `len(type) || type || len(state_key) || state_key || event_id`
/// where each `len()` is an unsigned 16-bit little-endian byte count.
#[must_use]
fn seed_lattice<const LANES: usize>(
    dst: &[u8],
    event_type: &str,
    state_key: &str,
    event_id: &dyn core::fmt::Display,
) -> [u16; LANES] {
    let (event_type, type_len) = truncate_to_u16_limit(event_type);
    let (state_key, sk_len) = truncate_to_u16_limit(state_key);

    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(&type_len.to_le_bytes());
        hasher.update(event_type.as_bytes());
        hasher.update(&sk_len.to_le_bytes());
        hasher.update(state_key.as_bytes());

        // `HashWriter::write_str` only forwards to `Hasher::update`, so the
        // formatting result can never be an error.
        let mut writer = HashWriter { hasher };
        let _ = core::fmt::write(&mut writer, format_args!("{event_id}"));
    })
}

/// Expands an opaque byte string under `dst`: `dst || bytes`.
///
/// Unlike the field and state-entry encodings this one carries no length prefix, so the
/// caller must supply a byte string that cannot be confused with a neighboring element
/// by an alternate split (for example by hashing a framed length itself).
#[must_use]
fn seed_bytes_lattice<const LANES: usize>(dst: &[u8], bytes: &[u8]) -> [u16; LANES] {
    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(bytes);
    })
}

/// Expands one key-value field under `dst`:
/// `dst || len(key) || key || len(val) || val`.
///
/// Both lengths are unsigned 16-bit little-endian byte counts and both halves are
/// truncated to that limit exactly like a state entry.
#[must_use]
fn seed_field_lattice<const LANES: usize>(dst: &[u8], key: &str, val: &str) -> [u16; LANES] {
    let (key, key_len) = truncate_to_u16_limit(key);
    let (val, val_len) = truncate_to_u16_limit(val);

    expand_lanes(|hasher| {
        hasher.update(dst);
        hasher.update(&key_len.to_le_bytes());
        hasher.update(key.as_bytes());
        hasher.update(&val_len.to_le_bytes());
        hasher.update(val.as_bytes());
    })
}

/// Adds `src` into `dst` lane-wise with wrapping addition.
///
/// Processed in 8-lane chunks to assist SIMD auto-vectorization; any leftover lanes
/// (only reachable for a `LANES` that is not a multiple of 8) are handled scalar-wise.
#[inline]
fn add_lattice<const LANES: usize>(dst: &mut [u16; LANES], src: &[u16; LANES]) {
    let mut dst_chunks = dst.chunks_exact_mut(8);
    let mut src_chunks = src.chunks_exact(8);
    for (a, b) in (&mut dst_chunks).zip(&mut src_chunks) {
        a[0] = a[0].wrapping_add(b[0]);
        a[1] = a[1].wrapping_add(b[1]);
        a[2] = a[2].wrapping_add(b[2]);
        a[3] = a[3].wrapping_add(b[3]);
        a[4] = a[4].wrapping_add(b[4]);
        a[5] = a[5].wrapping_add(b[5]);
        a[6] = a[6].wrapping_add(b[6]);
        a[7] = a[7].wrapping_add(b[7]);
    }
    for (a, b) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder())
    {
        *a = a.wrapping_add(*b);
    }
}

/// Subtracts `src` from `dst` lane-wise with wrapping subtraction.
///
/// Processed in 8-lane chunks to assist SIMD auto-vectorization; see [`add_lattice`].
#[inline]
fn sub_lattice<const LANES: usize>(dst: &mut [u16; LANES], src: &[u16; LANES]) {
    let mut dst_chunks = dst.chunks_exact_mut(8);
    let mut src_chunks = src.chunks_exact(8);
    for (a, b) in (&mut dst_chunks).zip(&mut src_chunks) {
        a[0] = a[0].wrapping_sub(b[0]);
        a[1] = a[1].wrapping_sub(b[1]);
        a[2] = a[2].wrapping_sub(b[2]);
        a[3] = a[3].wrapping_sub(b[3]);
        a[4] = a[4].wrapping_sub(b[4]);
        a[5] = a[5].wrapping_sub(b[5]);
        a[6] = a[6].wrapping_sub(b[6]);
        a[7] = a[7].wrapping_sub(b[7]);
    }
    for (a, b) in dst_chunks
        .into_remainder()
        .iter_mut()
        .zip(src_chunks.remainder())
    {
        *a = a.wrapping_sub(*b);
    }
}

/// Collapses a lattice into its 32-byte wire digest: `BLAKE3(S)`, where `S` is the
/// little-endian serialization of the `LANES` 16-bit values.
#[must_use]
fn lattice_digest<const LANES: usize>(lattice: &[u16; LANES]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    let mut scratch = [0u8; 256];
    for chunk in lattice.chunks(128) {
        let n = chunk.len().wrapping_mul(2);
        for (pair, lane) in scratch[..n].chunks_exact_mut(2).zip(chunk) {
            pair.copy_from_slice(&lane.to_le_bytes());
        }
        hasher.update(&scratch[..n]);
    }
    *hasher.finalize().as_bytes()
}

impl<const LANES: usize> LtLattice<LANES> {
    /// The identity element (empty state).
    pub const ZERO: Self = Self([0u16; LANES]);

    /// Domain separation tag for the primary state accumulator.
    pub const DST: &'static [u8] = b"msc4500:lthash16:blake3:v1";

    /// Compute the lane expansion for a single state entry under [`Self::DST`].
    ///
    /// Input encoding (MSC4500 §1): `len(type) || type || len(state_key) || state_key || event_id`
    /// where each `len()` is an unsigned 16-bit little-endian byte count.
    ///
    /// Expansion: `BLAKE3(tag || element, 2 * LANES)`
    ///
    /// # Performance & Validation
    ///
    /// Full cryptographic and syntactic validation of the Matrix Event ID (e.g., verifying
    /// length, prefix, character sets, or room-version-specific syntax) is intentionally
    /// **not** performed within this function for performance reasons and to allow flexible
    /// event ID formats across legacy/modern room versions. Any syntactic validation of
    /// event IDs must be enforced by the caller at the application ingestion boundary if desired.
    #[must_use]
    pub fn seed(event_type: &str, state_key: &str, event_id: &dyn core::fmt::Display) -> Self {
        Self(seed_lattice(Self::DST, event_type, state_key, event_id))
    }

    /// Compute the lane expansion for a single state entry under an explicit tag.
    ///
    /// Same element encoding as [`Self::seed`]; use this when a caller needs its own
    /// domain rather than the shared [`Self::DST`].
    #[must_use]
    pub fn seed_with_dst(
        dst: &[u8],
        event_type: &str,
        state_key: &str,
        event_id: &dyn core::fmt::Display,
    ) -> Self {
        Self(seed_lattice(dst, event_type, state_key, event_id))
    }

    /// Compute the lane expansion for an opaque byte string under an explicit tag.
    ///
    /// See [`seed_bytes_lattice`] for the encoding contract.
    #[must_use]
    pub fn seed_bytes(dst: &[u8], bytes: &[u8]) -> Self {
        Self(seed_bytes_lattice(dst, bytes))
    }

    /// Compute the lane expansion for one key-value field under an explicit tag.
    ///
    /// See [`seed_field_lattice`] for the encoding contract.
    #[must_use]
    pub fn seed_field(dst: &[u8], key: &str, val: &str) -> Self {
        Self(seed_field_lattice(dst, key, val))
    }

    /// Add a seed into the hash (insert).
    #[inline]
    pub fn add_seed(&mut self, seed: &Self) {
        add_lattice(&mut self.0, &seed.0);
    }

    /// Subtract a seed from the hash (remove).
    #[inline]
    pub fn sub_seed(&mut self, seed: &Self) {
        sub_lattice(&mut self.0, &seed.0);
    }

    /// Seeds `(event_type, state_key, event_id)` and adds it when `add` is
    /// true, otherwise subtracts it.
    fn accumulate(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
        add: bool,
    ) {
        let s = Self::seed(event_type, state_key, &event_id);
        if add {
            self.add_seed(&s);
        } else {
            self.sub_seed(&s);
        }
    }

    /// Record a state entry being inserted.
    pub fn insert(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.accumulate(event_type, state_key, event_id, true);
    }

    /// Record a state entry being removed.
    pub fn remove(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.accumulate(event_type, state_key, event_id, false);
    }

    /// Record a state entry being replaced (old → new).
    pub fn replace(
        &mut self,
        event_type: &str,
        state_key: &str,
        old_event_id: &(impl core::fmt::Display + ?Sized),
        new_event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        let old = Self::seed(event_type, state_key, &old_event_id);
        let new = Self::seed(event_type, state_key, &new_event_id);
        self.sub_seed(&old);
        self.add_seed(&new);
    }

    /// Record a replacement that is required to stay on the same `(event_type, state_key)`.
    ///
    /// This is a defensive wrapper for callers that want an explicit invariant check before
    /// performing the remove/add pair.
    ///
    /// # Panics
    ///
    /// Panics if `old_event_type != new_event_type` or `old_state_key != new_state_key`.
    pub fn replace_checked(
        &mut self,
        old_event_type: &str,
        old_state_key: &str,
        old_event_id: &(impl core::fmt::Display + ?Sized),
        new_event_type: &str,
        new_state_key: &str,
        new_event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        assert!(
            old_event_type == new_event_type && old_state_key == new_state_key,
            "mismatched replacement key: ({old_event_type}, {old_state_key}) -> ({new_event_type}, {new_state_key})",
        );
        self.sub_seed(&Self::seed(old_event_type, old_state_key, &old_event_id));
        self.add_seed(&Self::seed(new_event_type, new_state_key, &new_event_id));
    }

    /// Record an opaque byte string being inserted.
    pub fn insert_bytes(&mut self, dst: &[u8], bytes: &[u8]) {
        self.add_seed(&Self::seed_bytes(dst, bytes));
    }

    /// Record an opaque byte string being removed.
    pub fn remove_bytes(&mut self, dst: &[u8], bytes: &[u8]) {
        self.sub_seed(&Self::seed_bytes(dst, bytes));
    }

    /// Record an opaque byte string being replaced (old → new).
    pub fn replace_bytes(&mut self, dst: &[u8], old_bytes: &[u8], new_bytes: &[u8]) {
        self.sub_seed(&Self::seed_bytes(dst, old_bytes));
        self.add_seed(&Self::seed_bytes(dst, new_bytes));
    }

    /// Record one key-value field being inserted.
    pub fn insert_field(&mut self, dst: &[u8], key: &str, val: &str) {
        self.add_seed(&Self::seed_field(dst, key, val));
    }

    /// Record one key-value field being removed.
    pub fn remove_field(&mut self, dst: &[u8], key: &str, val: &str) {
        self.sub_seed(&Self::seed_field(dst, key, val));
    }

    /// Record one key-value field being replaced (old value → new value).
    ///
    /// The field name must stay on the same `key`; only the value is swapped.
    ///
    /// # Panics
    ///
    /// Never; the key is supplied once. Use [`Self::remove_field`] plus
    /// [`Self::insert_field`] when the key itself changes.
    pub fn replace_field(&mut self, dst: &[u8], key: &str, old_val: &str, new_val: &str) {
        self.sub_seed(&Self::seed_field(dst, key, old_val));
        self.add_seed(&Self::seed_field(dst, key, new_val));
    }

    /// Record a batch of `(event_type, state_key, event_id)` entries as inserts.
    ///
    /// Equivalent to calling [`Self::insert`] once per item, under [`Self::DST`].
    pub fn insert_batch<'a, I>(&mut self, items: I)
    where
        I: IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    {
        for (event_type, state_key, event_id) in items {
            self.insert(event_type, state_key, &event_id);
        }
    }

    /// Record a batch of `(event_type, state_key, event_id)` entries as removes.
    ///
    /// Equivalent to calling [`Self::remove`] once per item, under [`Self::DST`].
    pub fn remove_batch<'a, I>(&mut self, items: I)
    where
        I: IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    {
        for (event_type, state_key, event_id) in items {
            self.remove(event_type, state_key, &event_id);
        }
    }

    /// Record a batch of `(event_type, state_key, event_id)` entries as inserts under `dst`.
    pub fn insert_batch_with_dst<'a, I>(&mut self, dst: &[u8], items: I)
    where
        I: IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    {
        for (event_type, state_key, event_id) in items {
            self.add_seed(&Self::seed_with_dst(dst, event_type, state_key, &event_id));
        }
    }

    /// Record a batch of `(event_type, state_key, event_id)` entries as removes under `dst`.
    pub fn remove_batch_with_dst<'a, I>(&mut self, dst: &[u8], items: I)
    where
        I: IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    {
        for (event_type, state_key, event_id) in items {
            self.sub_seed(&Self::seed_with_dst(dst, event_type, state_key, &event_id));
        }
    }

    /// Compute the full hash from a state map (non-incremental).
    #[must_use]
    pub fn from_state<Id, K>(state: &crate::state::at::SharedState<Id, K>) -> Self
    where
        Id: crate::basespec::rezzy_types::EventId,
        K: Ord + AsRef<str>,
    {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in state {
            let s = Self::seed(event_type.as_str(), state_key.as_ref(), event_id);
            hash.add_seed(&s);
        }
        hash
    }

    /// Borrow the raw lanes.
    #[must_use]
    pub fn lattice(&self) -> &[u16; LANES] {
        &self.0
    }

    /// Consume the accumulator and return its raw lanes.
    #[must_use]
    pub fn into_lattice(self) -> [u16; LANES] {
        self.0
    }

    /// Serialize the raw lanes as the little-endian byte string the digest is taken over.
    ///
    /// This is the same 2048-byte buffer a [`Self::digest`] hashes, exposed for callers
    /// that need to transmit or store the accumulator itself.
    #[must_use]
    pub fn lattice_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.0.len().wrapping_mul(2));
        for lane in self.0.iter() {
            bytes.extend_from_slice(&lane.to_le_bytes());
        }
        bytes
    }

    /// Finalize into the 32-byte wire digest: `BLAKE3(S)`, where `S` is the lattice.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        lattice_digest(&self.0)
    }

    /// Finalize into both the raw lattice and the 32-byte wire digest in one pass.
    #[must_use]
    pub fn finalize_both(&self) -> ([u16; LANES], [u8; 32]) {
        (self.0, self.digest())
    }
}

impl<const LANES: usize> Add for LtLattice<LANES> {
    type Output = Self;

    #[inline]
    fn add(mut self, rhs: Self) -> Self {
        add_lattice(&mut self.0, &rhs.0);
        self
    }
}

impl<const LANES: usize> Sub for LtLattice<LANES> {
    type Output = Self;

    #[inline]
    fn sub(mut self, rhs: Self) -> Self {
        sub_lattice(&mut self.0, &rhs.0);
        self
    }
}

impl<const LANES: usize> AddAssign for LtLattice<LANES> {
    #[inline]
    fn add_assign(&mut self, rhs: Self) {
        add_lattice(&mut self.0, &rhs.0);
    }
}

impl<const LANES: usize> SubAssign for LtLattice<LANES> {
    #[inline]
    fn sub_assign(&mut self, rhs: Self) {
        sub_lattice(&mut self.0, &rhs.0);
    }
}

impl<const LANES: usize> Sum for LtLattice<LANES> {
    #[inline]
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, item| acc + item)
    }
}

impl<'a, const LANES: usize> Sum<&'a Self> for LtLattice<LANES> {
    #[inline]
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, item| acc + *item)
    }
}

impl<'a, const LANES: usize> Extend<(&'a str, &'a str, &'a str)> for LtLattice<LANES> {
    fn extend<I: IntoIterator<Item = (&'a str, &'a str, &'a str)>>(&mut self, items: I) {
        self.insert_batch(items);
    }
}

impl<'a, const LANES: usize> FromIterator<(&'a str, &'a str, &'a str)> for LtLattice<LANES> {
    fn from_iter<I: IntoIterator<Item = (&'a str, &'a str, &'a str)>>(items: I) -> Self {
        let mut hash = Self::ZERO;
        hash.extend(items);
        hash
    }
}

/// A homomorphic digest of the redaction overlay associated with a resolved
/// state.  The overlay is deliberately a separate accumulator from
/// [`LtHash`]: it does not describe another state snapshot.  Each entry names
/// one selected state event that is effectively redacted at the DAG point.
///
/// Callers should insert only selected state events that are effectively
/// redacted by authorized causal redactions at the state point being
/// described.  An empty overlay is a known empty overlay; `None` in
/// [`StateDigest`] means that the sender did not compute one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RedactionOverlay(pub LtHash);

impl Default for RedactionOverlay {
    fn default() -> Self {
        Self::ZERO
    }
}

impl RedactionOverlay {
    /// The identity element (no effectively redacted selected events).
    pub const ZERO: Self = Self(LtHash::ZERO);

    /// Domain separation tag for the overlay accumulator.
    pub const DST: &'static [u8] = b"msc4500:redactions:blake3:v1";

    // The overlay shares `LtHash`'s element encoding, lattice updates, and
    // digest serialization (see the module-level helpers), injecting only its
    // own domain-separation tag. The event ID is appended raw, matching the
    // primary MSC4500 element encoding: it is self-delimiting under Matrix
    // event-ID syntax and must not acquire a second length prefix.
    #[must_use]
    pub fn seed(
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) -> Self {
        Self(LtHash(seed_lattice(
            Self::DST,
            event_type,
            state_key,
            &event_id,
        )))
    }

    /// Adds one effectively redacted selected state event to the overlay.
    ///
    /// The caller must maintain set semantics: inserting the same tuple more
    /// than once intentionally changes the lattice, just as it does for the
    /// primary accumulator.
    pub fn insert(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.0
            .add_seed(&Self::seed(event_type, state_key, event_id).0);
    }

    /// Removes one overlay entry previously inserted with [`Self::insert`].
    /// Callers must not remove an entry that is absent from the authoritative
    /// overlay set.
    pub fn remove(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        self.0
            .sub_seed(&Self::seed(event_type, state_key, event_id).0);
    }

    /// Collapses the overlay lattice to its 32-byte wire digest.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.0.digest()
    }

    /// Borrows the underlying lattice.
    #[must_use]
    pub fn lattice(&self) -> &LtHash {
        &self.0
    }

    /// Returns the underlying lattice.
    #[must_use]
    pub fn into_inner(self) -> LtHash {
        self.0
    }
}

/// A field-by-field accumulator for a single protocol data unit (PDU).
///
/// This is the porcelain over [`LtHash`] for callers that hash a structured object one
/// field at a time: the domain tag is bound at construction, so every field goes through
/// [`PduLtHash::insert_field`] without repeating the tag. Two PDUs that carry the same
/// field multiset under the same tag collapse to the same digest regardless of the order
/// the fields were inserted in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PduLtHash {
    dst: Vec<u8>,
    inner: LtHash,
}

impl Default for PduLtHash {
    fn default() -> Self {
        Self::new(&[])
    }
}

impl PduLtHash {
    /// The identity element (a PDU with no fields).
    pub const ZERO: Self = Self {
        dst: Vec::new(),
        inner: LtHash::ZERO,
    };

    /// Binds a domain-separation tag for subsequent field insertions.
    #[must_use]
    pub fn new(dst: impl Into<Vec<u8>>) -> Self {
        Self {
            dst: dst.into(),
            inner: LtHash::ZERO,
        }
    }

    /// Records one field being present with the given value.
    pub fn insert_field(&mut self, key: &str, val: &str) {
        self.inner
            .add_seed(&LtHash::seed_field(&self.dst, key, val));
    }

    /// Records one field being absent with the given value.
    pub fn remove_field(&mut self, key: &str, val: &str) {
        self.inner
            .sub_seed(&LtHash::seed_field(&self.dst, key, val));
    }

    /// Records one field changing value (same key, old value → new value).
    pub fn replace_field(&mut self, key: &str, old_val: &str, new_val: &str) {
        self.inner
            .sub_seed(&LtHash::seed_field(&self.dst, key, old_val));
        self.inner
            .add_seed(&LtHash::seed_field(&self.dst, key, new_val));
    }

    /// Records an opaque byte string being present.
    pub fn insert_bytes(&mut self, bytes: &[u8]) {
        self.inner.add_seed(&LtHash::seed_bytes(&self.dst, bytes));
    }

    /// Records an opaque byte string being absent.
    pub fn remove_bytes(&mut self, bytes: &[u8]) {
        self.inner.sub_seed(&LtHash::seed_bytes(&self.dst, bytes));
    }

    /// Records an opaque byte string being replaced (old → new).
    pub fn replace_bytes(&mut self, old_bytes: &[u8], new_bytes: &[u8]) {
        self.inner
            .sub_seed(&LtHash::seed_bytes(&self.dst, old_bytes));
        self.inner
            .add_seed(&LtHash::seed_bytes(&self.dst, new_bytes));
    }

    /// The domain-separation tag this accumulator is bound to.
    #[must_use]
    pub fn dst(&self) -> &[u8] {
        &self.dst
    }

    /// Whether no field has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner == LtHash::ZERO
    }

    /// Borrows the raw lattice.
    #[must_use]
    pub fn lattice(&self) -> &[u16; 1024] {
        self.inner.lattice()
    }

    /// Finalize into the 32-byte wire digest: `BLAKE3(S)`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        self.inner.digest()
    }

    /// Finalize into both the raw lattice and the 32-byte wire digest.
    #[must_use]
    pub fn finalize_both(&self) -> ([u16; 1024], [u8; 32]) {
        self.inner.finalize_both()
    }

    /// Returns the underlying accumulator and discards the bound tag.
    #[must_use]
    pub fn into_inner(self) -> LtHash {
        self.inner
    }
}

/// The MSC4500 state digest for one DAG point: the primary resolved-state
/// digest and, when supported, its causal redaction overlay digest.
///
/// MSC4500 carries these values as `before` and `after` fields around a state
/// transition (alongside `redactions_before` and `redactions_after`). This
/// type represents one such point; [`StateDigestTransition`] represents the
/// pair. `overlay` is optional for wire compatibility and must never be
/// interpreted as agreement when absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDigest {
    pub primary: [u8; 32],
    pub overlay: Option<[u8; 32]>,
}

/// The before/after digest pair carried for one MSC4500 state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateDigestTransition {
    pub before: StateDigest,
    pub after: StateDigest,
}

/// Result of comparing two state digest advertisements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAgreement {
    /// The selected `(type, state_key, event_id)` maps differ.
    PrimaryMismatch,
    /// Primary maps agree and both overlay digests agree.
    FullySynchronized,
    /// Primary maps agree but causal redaction overlays differ.
    OverlayMismatch,
    /// Primary maps agree, but at least one side omitted its overlay.
    OverlayUnknown,
}

impl StateDigest {
    /// Compares primary state first, then treats the overlay as a diagnostic.
    #[must_use]
    pub fn compare(self, remote: Self) -> DigestAgreement {
        if self.primary == remote.primary {
            match (self.overlay, remote.overlay) {
                (Some(left), Some(right)) if left == right => DigestAgreement::FullySynchronized,
                (Some(_), Some(_)) => DigestAgreement::OverlayMismatch,
                _ => DigestAgreement::OverlayUnknown,
            }
        } else {
            DigestAgreement::PrimaryMismatch
        }
    }
}

/// Computes a deterministic 256-bit `LtHash` fingerprint of a
/// state map, returned as a 32-byte array.
///
/// This is a convenience wrapper around
/// [`LtHash::from_state`]. Each
/// `(event_type, state_key, event_id)` entry is expanded via
/// the BLAKE3 XOF to a 2048-byte seed, and the state hash is the
/// wrapping addition of all seeds — making it order-independent and
/// incrementally updatable.
#[must_use]
pub fn compute_state_hash<Id: crate::basespec::rezzy_types::EventId, K: Ord + AsRef<str>>(
    state: &crate::state::at::SharedState<Id, K>,
) -> [u8; 32] {
    LtHash::from_state(state).digest()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    type StateMap = imbl::OrdMap<(crate::basespec::event_types::EventType, String), String>;

    /// Builds a `StateMap` from `(event_type, state_key) -> event_id` rows.
    fn state_map(
        rows: impl IntoIterator<Item = ((&'static str, &'static str), &'static str)>,
    ) -> StateMap {
        rows.into_iter()
            .map(|((event_type, state_key), id)| {
                ((event_type.into(), state_key.into()), String::from(id))
            })
            .collect()
    }

    #[test]
    fn test_state_hash_determinism() {
        let state = state_map([
            (("m.room.create", ""), "$1"),
            (("m.room.member", "@alice:example.com"), "$2"),
        ]);

        let h1 = compute_state_hash(&state);
        let h2 = compute_state_hash(&state);
        assert_eq!(h1, h2, "same state must produce same hash");
        assert_eq!(h1.len(), 32, "LtHash final digest should be 32 bytes");
    }

    #[test]
    fn test_state_hash_sensitivity() {
        let state_a = state_map([(("m.room.create", ""), "$1")]);
        let state_b = state_map([(("m.room.create", ""), "$2")]);

        assert_ne!(
            compute_state_hash(&state_a),
            compute_state_hash(&state_b),
            "different states must produce different hashes"
        );
    }

    #[test]
    fn test_lthash_determinism() {
        let state = state_map([
            (("m.room.create", ""), "$1"),
            (("m.room.member", "@a:x"), "$2"),
        ]);
        let h1 = LtHash::from_state(&state);
        let h2 = LtHash::from_state(&state);
        assert_eq!(h1, h2);
        assert_ne!(h1, LtHash::ZERO);
        assert_eq!(h1.digest().len(), 32);
    }

    #[test]
    fn test_lthash_sensitivity() {
        let a = state_map([(("m.room.create", ""), "$1")]);
        let b = state_map([(("m.room.create", ""), "$2")]);
        assert_ne!(LtHash::from_state(&a), LtHash::from_state(&b),);
    }

    #[test]
    fn test_redaction_overlay_is_separate_and_order_independent() {
        let mut left = RedactionOverlay::ZERO;
        left.insert("m.room.member", "@alice:example.org", "$state");

        let mut right = RedactionOverlay::ZERO;
        right.insert("m.room.member", "@alice:example.org", "$other-state");
        assert_ne!(left.digest(), right.digest());

        let mut reordered = RedactionOverlay::ZERO;
        reordered.insert("m.room.member", "@bob:example.org", "$other-state");
        reordered.insert("m.room.member", "@alice:example.org", "$state");
        let mut expected = left;
        expected.insert("m.room.member", "@bob:example.org", "$other-state");
        assert_eq!(reordered, expected);

        reordered.remove("m.room.member", "@bob:example.org", "$other-state");
        assert_eq!(reordered, left);
    }

    #[test]
    fn test_state_digest_comparison_preserves_unknown_overlay_semantics() {
        let primary = [7u8; 32];
        let overlay = [9u8; 32];
        let same = StateDigest {
            primary,
            overlay: Some(overlay),
        };
        assert_eq!(same.compare(same), DigestAgreement::FullySynchronized);
        assert_eq!(
            same.compare(StateDigest {
                primary,
                overlay: Some([8u8; 32]),
            }),
            DigestAgreement::OverlayMismatch
        );
        assert_eq!(
            same.compare(StateDigest {
                primary,
                overlay: None,
            }),
            DigestAgreement::OverlayUnknown
        );
        assert_eq!(
            same.compare(StateDigest {
                primary: [6u8; 32],
                overlay: Some(overlay),
            }),
            DigestAgreement::PrimaryMismatch
        );
    }

    #[test]
    fn test_lthash_order_independence() {
        // Insert in different orders, same result
        let mut h1 = LtHash::ZERO;
        h1.insert("m.room.create", "", "$c");
        h1.insert("m.room.member", "@a:x", "$m");

        let mut h2 = LtHash::ZERO;
        h2.insert("m.room.member", "@a:x", "$m");
        h2.insert("m.room.create", "", "$c");

        assert_eq!(h1, h2);
    }

    #[test]
    fn test_lthash_incremental_matches_full() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$c".into());
        state.insert(("m.room.topic".into(), String::new()), "$t".into());

        let full = LtHash::from_state(&state);

        let mut inc = LtHash::ZERO;
        inc.insert("m.room.create", "", "$c");
        inc.insert("m.room.topic", "", "$t");

        assert_eq!(full, inc);
    }

    #[test]
    fn test_lthash_insert_remove_roundtrip() {
        let mut h = LtHash::ZERO;
        h.insert("m.room.topic", "", "$t");
        assert_ne!(h, LtHash::ZERO);
        h.remove("m.room.topic", "", "$t");
        assert_eq!(h, LtHash::ZERO);
    }

    #[test]
    fn test_lthash_replace() {
        // Build state with $t1, then replace → $t2
        let mut h = LtHash::ZERO;
        h.insert("m.room.create", "", "$c");
        h.insert("m.room.topic", "", "$t1");
        h.replace("m.room.topic", "", "$t1", "$t2");

        // Build state with $t2 from scratch
        let mut expected = LtHash::ZERO;
        expected.insert("m.room.create", "", "$c");
        expected.insert("m.room.topic", "", "$t2");

        assert_eq!(h, expected);
    }

    #[test]
    fn test_lthash_replace_checked_success() {
        let mut actual = LtHash::ZERO;
        actual.insert("m.room.topic", "", "$old");
        actual.replace_checked("m.room.topic", "", "$old", "m.room.topic", "", "$new");

        let mut expected = LtHash::ZERO;
        expected.insert("m.room.topic", "", "$new");
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_lthash_defaults_to_zero() {
        assert_eq!(LtHash::default(), LtHash::ZERO);
        assert_eq!(RedactionOverlay::default(), RedactionOverlay::ZERO);
    }

    #[test]
    fn test_lthash_mismatched_state_key_replace_panics() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut h = LtHash::ZERO;
            h.replace_checked(
                "m.room.member",
                "@alice:example.com",
                "$old",
                "m.room.member",
                "@bob:example.com",
                "$new",
            );
        }));

        assert!(result.is_err(), "mismatched replacement key should panic");
    }

    #[test]
    #[should_panic(expected = "mismatched replacement key")]
    fn test_lthash_mismatched_event_type_replace_panics() {
        let mut h = LtHash::ZERO;
        h.replace_checked(
            "m.room.member",
            "@alice:example.com",
            "$old",
            "m.room.power_levels",
            "@alice:example.com",
            "$new",
        );
    }

    #[test]
    fn test_lthash_wrapping_algebraic_properties() {
        let seed = LtHash::seed("m.room.message", "", &"$1");

        // 2^16 = 65536 additions of the same seed to ZERO
        let mut h = LtHash::ZERO;
        for _ in 0..65536 {
            h.add_seed(&seed);
        }
        assert_eq!(
            h,
            LtHash::ZERO,
            "65536 additions of any seed should wrap to ZERO"
        );

        // 2^16 - 1 = 65535 subtractions from ZERO should equal exactly 1 addition
        let mut h_sub = LtHash::ZERO;
        for _ in 0..65535 {
            h_sub.sub_seed(&seed);
        }
        let mut h_add = LtHash::ZERO;
        h_add.add_seed(&seed);
        assert_eq!(
            h_sub, h_add,
            "65535 subtractions from ZERO should equal 1 addition"
        );
    }

    #[test]
    fn test_lthash_algebraic_traits_match_seed_api() {
        let a = LtHash::seed("m.room.create", "", "$c");
        let b = LtHash::seed("m.room.member", "@a:x", "$m");

        let mut manual = LtHash::ZERO;
        manual.add_seed(&a);
        manual.add_seed(&b);
        assert_eq!(a + b, manual);

        let mut manual_sub = manual;
        manual_sub.sub_seed(&b);
        assert_eq!(manual - b, manual_sub);

        let mut manual_assign = LtHash::ZERO;
        manual_assign += a;
        manual_assign += b;
        assert_eq!(manual_assign, manual);

        manual_assign -= a;
        manual_assign -= b;
        assert_eq!(manual_assign, LtHash::ZERO);

        // Subtraction is the additive inverse: (a + b) - b == a.
        assert_eq!(manual - b + b, manual);

        assert_eq!(<LtHash as Sum>::sum([a, b, a]), a + a + b);
        assert_eq!(
            <LtHash as Sum<&LtHash>>::sum([&a, &b, &a]),
            <LtHash as Sum>::sum([a, a, b])
        );
    }

    #[test]
    fn test_lthash_batch_parity() {
        let rows = [
            ("m.room.create", "", "$c"),
            ("m.room.member", "@a:x", "$m"),
            ("m.room.topic", "", "$t"),
        ];

        let mut batched = LtHash::ZERO;
        batched.insert_batch(rows);

        let mut one_by_one = LtHash::ZERO;
        for row in rows {
            one_by_one.insert(row.0, row.1, row.2);
        }
        assert_eq!(batched, one_by_one);

        batched.remove_batch(rows);
        assert_eq!(batched, LtHash::ZERO);

        let collected: LtHash = rows.into_iter().collect();
        assert_eq!(collected, one_by_one);

        let mut extended = LtHash::ZERO;
        extended.extend(rows);
        assert_eq!(extended, collected);

        // A different domain tag is a different element, so a from-scratch
        // accumulator built under the tag must agree with the tagged batch.
        let custom = b"rezzy:test:tagged";
        let mut tagged = LtHash::ZERO;
        tagged.insert_batch_with_dst(custom, rows);
        let mut tagged_one_by_one = LtHash::ZERO;
        for row in rows {
            tagged_one_by_one.add_seed(&LtHash::seed_with_dst(custom, row.0, row.1, row.2));
        }
        assert_eq!(tagged, tagged_one_by_one);
        assert_ne!(tagged, one_by_one);

        let mut untagged = LtHash::ZERO;
        untagged.remove_batch_with_dst(custom, rows);
        assert_eq!(untagged, LtHash::ZERO);
    }

    #[test]
    fn test_lthash_raw_bytes_and_field_roundtrips() {
        let mut h = LtHash::ZERO;
        h.insert_bytes(b"rezzy:test:bytes", b"payload");
        assert_ne!(h, LtHash::ZERO);
        h.remove_bytes(b"rezzy:test:bytes", b"payload");
        assert_eq!(h, LtHash::ZERO);

        let mut f = LtHash::ZERO;
        f.insert_field(b"rezzy:test:field", "sender", "@alice:example.org");
        assert_ne!(f, LtHash::ZERO);
        f.replace_field(
            b"rezzy:test:field",
            "sender",
            "@alice:example.org",
            "@bob:example.org",
        );
        f.remove_field(b"rezzy:test:field", "sender", "@bob:example.org");
        assert_eq!(f, LtHash::ZERO);

        // A field encoding is length-delimited, so `ab`+`c` must not collide
        // with `a`+`bc`.
        let mut split_one = LtHash::ZERO;
        split_one.insert_field(b"rezzy:test:field", "ab", "c");
        let mut split_two = LtHash::ZERO;
        split_two.insert_field(b"rezzy:test:field", "a", "bc");
        assert_ne!(split_one, split_two);

        // ... and the domain tag is part of the element identity.
        let mut other_dst = LtHash::ZERO;
        other_dst.insert_field(b"rezzy:test:other", "sender", "@alice:example.org");
        assert_ne!(
            other_dst,
            LtHash::seed_field(b"rezzy:test:field", "sender", "@alice:example.org")
                .into_iter()
                .collect::<LtHash>()
        );

        let mut r = LtHash::ZERO;
        r.insert_bytes(b"rezzy:test:bytes", b"old");
        r.replace_bytes(b"rezzy:test:bytes", b"old", b"new");
        r.remove_bytes(b"rezzy:test:bytes", b"new");
        assert_eq!(r, LtHash::ZERO);
    }

    #[test]
    fn test_lthash_tri_mode_output_agrees() {
        let mut h = LtHash::ZERO;
        h.insert("m.room.create", "", "$c");
        h.insert("m.room.member", "@a:x", "$m");

        assert_eq!(*h.lattice(), h.into_lattice());
        assert_eq!(h.finalize_both().0, h.into_lattice());
        assert_eq!(h.finalize_both().1, h.digest());
        assert_eq!(h.lattice_bytes().len(), 2048);
        assert_eq!(
            h.lattice_bytes(),
            h.into_lattice()
                .iter()
                .flat_map(|lane| lane.to_le_bytes())
                .collect::<Vec<u8>>()
        );
    }

    #[test]
    fn test_lthash_non_default_lane_counts_work() {
        // Exercises the generic paths with a lane count that is not a multiple
        // of 8 (so the scalar remainder loop runs) and with the default.
        for lanes in [2_usize, 7, 8, 9, 1024] {
            let mut h = LtLattice::<lanes>::ZERO;
            h.insert("m.room.create", "", "$c");
            h.insert("m.room.member", "@a:x", "$m");
            assert_ne!(h, LtLattice::<lanes>::ZERO);

            let digest = h.digest();
            assert_eq!(h.finalize_both(), (h.into_lattice(), digest));

            h.remove("m.room.create", "", "$c");
            h.remove("m.room.member", "@a:x", "$m");
            assert_eq!(h, LtLattice::<lanes>::ZERO);
            assert_ne!(h.digest(), digest);
        }

        // A wider lattice gives a wider accumulator and an independent digest.
        let narrow = LtLattice::<8>::seed("m.room.create", "", "$c");
        let wide = LtHash::seed("m.room.create", "", "$c");
        assert_ne!(narrow.digest(), wide.digest());
        assert_ne!(narrow.lattice_bytes().len(), wide.lattice_bytes().len());
    }

    #[test]
    fn test_pdu_lthash_field_parity_and_roundtrip() {
        let mut pdu = PduLtHash::new(b"rezzy:test:pdu");
        assert!(pdu.is_empty());
        pdu.insert_field("type", "m.room.message");
        pdu.insert_field("sender", "@alice:example.org");
        assert!(!pdu.is_empty());

        let mut reordered = PduLtHash::new(b"rezzy:test:pdu");
        reordered.insert_field("sender", "@alice:example.org");
        reordered.insert_field("type", "m.room.message");
        assert_eq!(pdu.digest(), reordered.digest());

        // A different tag is a different PDU domain.
        let mut other_tag = PduLtHash::new(b"rezzy:test:pdu:other");
        other_tag.insert_field("type", "m.room.message");
        other_tag.insert_field("sender", "@alice:example.org");
        assert_ne!(pdu.digest(), other_tag.digest());

        pdu.replace_field("sender", "@alice:example.org", "@bob:example.org");
        pdu.remove_field("sender", "@bob:example.org");
        pdu.remove_field("type", "m.room.message");
        assert!(pdu.is_empty());
        assert_eq!(pdu, PduLtHash::new(b"rezzy:test:pdu"));

        let mut bytes = PduLtHash::new(b"rezzy:test:pdu");
        bytes.insert_bytes(b"opaque");
        bytes.replace_bytes(b"opaque", b"other");
        bytes.remove_bytes(b"other");
        assert!(bytes.is_empty());
        assert_eq!(bytes.dst(), b"rezzy:test:pdu");
        assert_eq!(bytes.into_inner(), LtHash::ZERO);
    }

    /// Regression pins for the BLAKE3 instantiation (`msc4500:lthash16:blake3:v1`).
    ///
    /// These are rezzy-derived values, not published MSC4500 vectors: MSC4500's own
    /// vectors are pinned to SHAKE256 expansion plus BLAKE2b collapse, which this module
    /// deliberately does not implement. Changing the expansion or the collapse function
    /// changes every value below, so treat this as the place to re-derive them.
    #[test]
    fn dump_lthash_blake3_vectors() {
        fn hex(bytes: &[u8]) -> String {
            use core::fmt::Write;
            bytes
                .iter()
                .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                })
        }
        fn b64u(bytes: &[u8]) -> String {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
            URL_SAFE_NO_PAD.encode(bytes)
        }
        fn lanes_hex(hash: &LtHash) -> String {
            hex(&hash.lattice_bytes()[..16])
        }

        println!("EMPTY   {}", b64u(&LtHash::ZERO.digest()));

        let seed1 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_1");
        println!("SEED1   {}", hex(&seed1.lattice_bytes()[..8]));
        let mut s1 = LtHash::ZERO;
        s1.add_seed(&seed1);
        println!("S1LAT   {}", lanes_hex(&s1));
        println!("S1      {}", b64u(&s1.digest()));

        let seed2 = LtHash::seed("m.room.name", "", &"$event_2");
        println!("SEED2   {}", hex(&seed2.lattice_bytes()[..8]));
        let mut s2 = s1;
        s2.add_seed(&seed2);
        println!("S2LAT   {}", lanes_hex(&s2));
        println!("S2      {}", b64u(&s2.digest()));

        let seed3 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_3");
        println!("SEED3   {}", hex(&seed3.lattice_bytes()[..8]));
        let mut s3 = s2;
        s3.sub_seed(&seed1);
        s3.add_seed(&seed3);
        println!("S3LAT   {}", lanes_hex(&s3));
        println!("S3      {}", b64u(&s3.digest()));

        let mut back = s3;
        back.sub_seed(&seed3);
        println!("BACK    {}", b64u(&back.digest()));

        let mut overlay = RedactionOverlay::ZERO;
        overlay.insert("m.room.member", "@alice:example.org", "$state");
        println!("OVL1    {}", hex(&overlay.digest()));
        let mut two = RedactionOverlay::ZERO;
        two.insert("m.room.create", "", "$create");
        two.insert("m.room.member", "@alice:example.org", "$state");
        println!("OVL2    {}", hex(&two.digest()));
        let mut custom = RedactionOverlay::ZERO;
        custom.insert("org.example.custom", "key", "$custom");
        println!("OVL3    {}", hex(&custom.digest()));

        // Plumbing-only surfaces, pinned so an accidental encoding change is visible.
        println!(
            "BYTES   {}",
            b64u(&LtHash::seed_bytes(b"rezzy:test:bytes", b"payload").digest())
        );
        println!(
            "FIELD   {}",
            b64u(&LtHash::seed_field(b"rezzy:test:field", "sender", "@alice:example.org").digest())
        );
        println!(
            "NARROW  {}",
            b64u(&LtLattice::<8>::seed("m.room.create", "", "$c").digest())
        );
    }

    #[test]
    fn test_lthash_differential_random_mutations() {
        struct Lcg(u32);
        impl Lcg {
            fn next(&mut self) -> u32 {
                self.0 = self.0.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                self.0
            }
            fn next_range(&mut self, min: u32, max: u32) -> u32 {
                min + (self.next() % (max - min + 1))
            }
        }

        let mut rng = Lcg(12345);
        let mut state = StateMap::new();
        let mut running_hash = LtHash::ZERO;

        // Populate state with some initial keys to work with
        let mut keys = Vec::new();
        for i in 0..15 {
            let key = (
                crate::basespec::event_types::EventType::from(alloc::format!("type_{i}")),
                alloc::format!("state_key_{i}"),
            );
            let val = alloc::format!("$initial_event_{i}");
            state.insert(key.clone(), val.clone());
            running_hash.insert(key.0.as_str(), &key.1, &val);
            keys.push(key);
        }

        assert_eq!(running_hash, LtHash::from_state(&state));

        // Let's do 200 mutations
        for step in 0..200 {
            let op = rng.next_range(0, 2); // 0 = insert/overwrite, 1 = remove, 2 = replace
            if op == 0 || keys.is_empty() {
                // Insert a new key or overwrite an existing one
                let key = if !keys.is_empty() && rng.next_range(0, 1) == 1 {
                    // Overwrite an existing key
                    let keys_len = u32::try_from(keys.len()).unwrap();
                    let idx = rng.next_range(0, keys_len - 1) as usize;
                    keys[idx].clone()
                } else {
                    // Create a new key
                    let id = rng.next();
                    let key = (
                        crate::basespec::event_types::EventType::from(alloc::format!("type_{id}")),
                        alloc::format!("state_key_{id}"),
                    );
                    keys.push(key.clone());
                    key
                };

                let new_val = alloc::format!("$event_{}", rng.next());

                // If it existed, we do a replace under the hood, or insert/remove.
                if let Some(old_val) = state.get(&key) {
                    running_hash.replace(key.0.as_str(), &key.1, old_val, &new_val);
                } else {
                    running_hash.insert(key.0.as_str(), &key.1, &new_val);
                }
                state.insert(key, new_val);
            } else if op == 1 && !keys.is_empty() {
                // Remove an existing key
                let keys_len = u32::try_from(keys.len()).unwrap();
                let idx = rng.next_range(0, keys_len - 1) as usize;
                let key = keys.swap_remove(idx);
                if let Some(val) = state.remove(&key) {
                    running_hash.remove(key.0.as_str(), &key.1, &val);
                }
            } else {
                // Replace via explicit .replace API
                let keys_len = u32::try_from(keys.len()).unwrap();
                let idx = rng.next_range(0, keys_len - 1) as usize;
                let key = &keys[idx];
                if let Some(old_val) = state.get(key).cloned() {
                    let new_val = alloc::format!("$replaced_{}", rng.next());
                    running_hash.replace(key.0.as_str(), &key.1, &old_val, &new_val);
                    state.insert(key.clone(), new_val);
                }
            }

            // Verify parity at every single step!
            assert_eq!(
                running_hash,
                LtHash::from_state(&state),
                "Hash mismatch at step {step}"
            );
        }
    }

    #[test]
    fn test_lthash_boundary_validation() {
        // EXACT boundary of u16::MAX (65535 bytes) should work
        let max_event_type = "a".repeat(65535);
        let _seed_max = LtHash::seed(&max_event_type, "", &"$1");

        let max_state_key = "b".repeat(65535);
        let _seed_max_sk = LtHash::seed("", &max_state_key, &"$1");
    }

    #[test]
    fn test_lthash_boundary_exceeded_event_type_truncates() {
        let over_max = "a".repeat(65536);
        let seed_over = LtHash::seed(&over_max, "", &"$1");
        let seed_exact = LtHash::seed(&"a".repeat(65535), "", &"$1");
        assert_eq!(
            seed_over, seed_exact,
            "over_max should truncate to exact 65535 boundary"
        );
    }

    #[test]
    fn test_lthash_boundary_exceeded_state_key_truncates() {
        let over_max = "b".repeat(65536);
        let seed_over = LtHash::seed("", &over_max, &"$1");
        let seed_exact = LtHash::seed("", &"b".repeat(65535), &"$1");
        assert_eq!(
            seed_over, seed_exact,
            "over_max should truncate to exact 65535 boundary"
        );
    }

    #[test]
    fn test_lthash_boundary_multibyte_truncation_rounds_back_to_char_boundary() {
        // Force the truncation point to land inside a 4-byte UTF-8 character so
        // the loop has to back up more than once before it reaches a boundary.
        let over_max = alloc::format!("{}🚀", "a".repeat(65533));
        let seed_over = LtHash::seed(&over_max, "", &"$1");
        let seed_exact = LtHash::seed(&"a".repeat(65533), "", &"$1");
        assert_eq!(
            seed_over, seed_exact,
            "truncate_to_u16_limit should back up to the previous char boundary"
        );
    }

    #[test]
    fn test_lthash_field_boundary_truncates() {
        let over_max = "k".repeat(65536);
        assert_eq!(
            LtHash::seed_field(b"rezzy:test:f", &over_max, "v"),
            LtHash::seed_field(b"rezzy:test:f", &"k".repeat(65535), "v"),
        );
        assert_eq!(
            LtHash::seed_field(b"rezzy:test:f", "k", &over_max),
            LtHash::seed_field(b"rezzy:test:f", "k", &"v".repeat(65535)),
        );
    }

    #[test]
    fn test_lthash_cryptographic_uniformity_and_avalanche() {
        let seed1 = LtHash::seed("m.room.message", "", &"$1");
        let seed2 = LtHash::seed("m.room.message", "", &"$2");

        // Avalanche Effect: seed1 and seed2 event_id differ by only 1 character ('1' vs '2').
        let mut different_elements = 0;
        for (a, b) in seed1.0.iter().zip(seed2.0.iter()) {
            if a != b {
                different_elements += 1;
            }
        }
        // At least 95% of the elements should differ.
        assert!(
            different_elements > 950,
            "Avalanche effect failed: only {different_elements} / 1024 elements differed"
        );

        // Uniformity: Mean of elements should be reasonably close to 32767.5.
        let sum: u32 = seed1.0.iter().map(|&x| u32::from(x)).sum();
        let mean = f64::from(sum) / 1024.0;
        assert!(
            (30000.0..=35000.0).contains(&mean),
            "Uniformity check failed: mean of elements is {mean}"
        );
    }

    #[test]
    fn test_lthash_utf8_handling() {
        let key = ("m.room.message💥", "🔑_🦀");
        let val = "$🇩🇪_🇫🇷";
        let seed = LtHash::seed(key.0, key.1, &val);
        assert_ne!(seed, LtHash::ZERO);
    }
}
