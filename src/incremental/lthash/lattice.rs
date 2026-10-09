//! The `LtLattice` accumulator, its arithmetic traits and serialization.

use alloc::vec::Vec;
use core::iter::{Extend, FromIterator, Sum};
use core::ops::{Add, AddAssign, Sub, SubAssign};

use super::encoding::{
    add_lattice, lattice_digest, seed_bytes_lattice, seed_field_lattice, seed_lattice, sub_lattice,
};

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
pub struct LtLattice<const LANES: usize>([u16; LANES]);

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

impl<const LANES: usize> LtLattice<LANES> {
    /// The identity element (empty state).
    pub const ZERO: Self = Self([0u16; LANES]);

    /// Builds an accumulator directly from raw lanes.
    ///
    /// [`LtHash`] is a type alias for one instantiation of this type, and Rust does not
    /// allow a type alias to be used as a tuple-struct constructor, so this is the
    /// supported way to spell `LtHash([..])`. See also `From<[u16; LANES]>` and
    /// [`LtLattice::from_bytes`].
    #[must_use]
    pub const fn from_lanes(lanes: [u16; LANES]) -> Self {
        Self(lanes)
    }

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
    /// See the internal `seed_bytes_lattice` implementation for the encoding contract.
    #[must_use]
    pub fn seed_bytes(dst: &[u8], bytes: &[u8]) -> Self {
        Self(seed_bytes_lattice(dst, bytes))
    }

    /// Compute the lane expansion for one key-value field under an explicit tag.
    ///
    /// See the internal `seed_field_lattice` implementation for the encoding contract.
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
    /// that need to transmit or store the accumulator itself. The inverse is
    /// [`Self::from_bytes`].
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.0.len().wrapping_mul(2));
        for lane in &self.0 {
            bytes.extend_from_slice(&lane.to_le_bytes());
        }
        bytes
    }

    /// Parse an accumulator back out of a little-endian lane byte string.
    ///
    /// Returns [`None`] unless `bytes` is exactly `LANES * 2` long; there is no
    /// zero-padding or truncation, so a length mismatch is always a corrupt or
    /// foreign buffer rather than a recoverable one.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != LANES.wrapping_mul(2) {
            return None;
        }
        let mut lanes = [0u16; LANES];
        for (lane, chunk) in lanes.iter_mut().zip(bytes.chunks_exact(2)) {
            *lane = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Some(Self(lanes))
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
        iter.fold(Self::ZERO, |mut acc, item| {
            add_lattice(&mut acc.0, &item.0);
            acc
        })
    }
}

impl<'a, const LANES: usize> Sum<&'a Self> for LtLattice<LANES> {
    #[inline]
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |mut acc, item| {
            add_lattice(&mut acc.0, &item.0);
            acc
        })
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

/// `lanes.into()` / `LtHash::from(lanes)`.
///
/// [`LtHash`] is a type alias, and Rust does not let a type alias be called as a
/// tuple-struct constructor, so this plus [`LtLattice::from_lanes`] are the ways to
/// spell the constructor that `LtHash([..])` would have been.
impl<const LANES: usize> From<[u16; LANES]> for LtLattice<LANES> {
    #[inline]
    fn from(lanes: [u16; LANES]) -> Self {
        Self(lanes)
    }
}

/// Inverse of [`LtLattice::to_bytes`]; see [`LtLattice::from_bytes`].
///
/// Fails if the slice is not exactly `LANES * 2` bytes.
impl<const LANES: usize> TryFrom<&[u8]> for LtLattice<LANES> {
    type Error = WrongLatticeLength;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(bytes).ok_or(WrongLatticeLength {
            expected: LANES.wrapping_mul(2),
            found: bytes.len(),
        })
    }
}

/// A lattice byte string was not `LANES * 2` bytes long.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrongLatticeLength {
    /// Byte length the target width requires.
    pub expected: usize,
    /// Byte length the input actually had.
    pub found: usize,
}

impl core::fmt::Display for WrongLatticeLength {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "lattice byte string is {} bytes, expected {}",
            self.found, self.expected
        )
    }
}

impl core::error::Error for WrongLatticeLength {}

impl<const LANES: usize> From<LtLattice<LANES>> for [u16; LANES] {
    #[inline]
    fn from(lattice: LtLattice<LANES>) -> Self {
        lattice.into_lattice()
    }
}

impl<const LANES: usize> AsRef<[u16]> for LtLattice<LANES> {
    #[inline]
    fn as_ref(&self) -> &[u16] {
        self.lattice()
    }
}
