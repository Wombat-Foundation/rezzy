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

//! Homomorphic state hashing via `LtHash16` (MSC4500).
//!
//! `LtHash` (Lattice Hash) is based on the homomorphic hashing paradigm first
//! introduced by Bellare and Micciancio in their 1997 paper *"A New Paradigm
//! for Collision-Free Hashing: Incrementality at Reduced Cost"*. This specific
//! 2048-byte instantiation (using 1024 16-bit integers and wrapping addition)
//! is modeled after the industry-standard implementation in Meta's Folly library
//! (`folly::crypto::LtHash`).
//!
//! Each `(event_type, state_key, event_id)` entry is expanded to 1024 16-bit
//! integers via SHAKE256 XOF (NIST FIPS 202). The state hash is the wrapping
//! addition of all these vectors. This provides:
//!
//! - **O(1) incremental updates**: insert = `hash + expanded`,
//!   remove = `hash - expanded`.
//! - **Order independence**: addition is commutative + associative.
//! - **Cryptographic security**: hard to find multiset collisions (SVP).

/// A 2048-byte homomorphic state hash using `LtHash`.
///
/// `LtHash` (Lattice Hash) is based on the homomorphic hashing paradigm first introduced
/// by Bellare and Micciancio in their 1997 paper *"A New Paradigm for Collision-Free
/// Hashing: Incrementality at Reduced Cost"*. This specific 2048-byte instantiation
/// (using 1024 16-bit integers and wrapping addition) is modeled after the industry-standard
/// implementation in Meta's Folly library (`folly::crypto::LtHash`).
///
/// Each `(event_type, state_key, event_id)` entry is expanded to 1024 16-bit
/// integers via SHAKE256 XOF (NIST FIPS 202). The state hash is the wrapping
/// addition of all these vectors. This provides:
///
/// - **O(1) incremental updates**: insert = `hash + expanded`,
///   remove = `hash - expanded`.
/// - **Order independence**: addition is commutative + associative.
/// - **Cryptographic security**: hard to find multiset collisions (SVP).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LtHash(pub [u16; 1024]);

impl Default for LtHash {
    fn default() -> Self {
        Self::ZERO
    }
}

impl LtHash {
    /// The identity element (empty state).
    pub const ZERO: Self = Self([0u16; 1024]);

    /// Domain separation tag per MSC4500.
    const DST: &[u8] = b"msc4500_lthash16\x00";

    /// Compute the 2048-byte SHAKE256 expansion for a single state entry.
    ///
    /// Input encoding (MSC4500 §1): `len(type) || type || len(state_key) || state_key || event_id`
    /// where each `len()` is an unsigned 16-bit little-endian byte count.
    ///
    /// Expansion (MSC4500 §2): `SHAKE256(tag || element, 2048)`
    #[must_use]
    fn seed(event_type: &str, state_key: &str, event_id: &dyn core::fmt::Display) -> Self {
        use sha3::digest::{ExtendableOutput, Update};

        let mut input = alloc::vec::Vec::with_capacity(128);
        input.extend_from_slice(Self::DST);
        let type_len = u16::try_from(event_type.len()).expect("event_type exceeds u16::MAX bytes");
        input.extend_from_slice(&type_len.to_le_bytes());
        input.extend_from_slice(event_type.as_bytes());
        let sk_len = u16::try_from(state_key.len()).expect("state_key exceeds u16::MAX bytes");
        input.extend_from_slice(&sk_len.to_le_bytes());
        input.extend_from_slice(state_key.as_bytes());
        let eid = alloc::format!("{event_id}");
        input.extend_from_slice(eid.as_bytes());

        let mut xof = sha3::Shake256::default();
        xof.update(&input);

        let mut buf = [0u8; 2048];
        xof.finalize_xof_into(&mut buf);

        let mut out = [0u16; 1024];
        for (i, chunk) in buf.chunks_exact(2).enumerate() {
            out[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Self(out)
    }

    /// Add a seed into the hash (insert).
    fn add_seed(&mut self, seed: &Self) {
        for (a, b) in self.0.iter_mut().zip(seed.0.iter()) {
            *a = a.wrapping_add(*b);
        }
    }

    /// Subtract a seed from the hash (remove).
    fn sub_seed(&mut self, seed: &Self) {
        for (a, b) in self.0.iter_mut().zip(seed.0.iter()) {
            *a = a.wrapping_sub(*b);
        }
    }

    /// Record a state entry being inserted.
    pub fn insert(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        let s = Self::seed(event_type, state_key, &event_id);
        self.add_seed(&s);
    }

    /// Record a state entry being removed.
    pub fn remove(
        &mut self,
        event_type: &str,
        state_key: &str,
        event_id: &(impl core::fmt::Display + ?Sized),
    ) {
        let s = Self::seed(event_type, state_key, &event_id);
        self.sub_seed(&s);
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

    /// Compute the full hash from a state map (non-incremental).
    #[must_use]
    pub fn from_state<Id>(state: &crate::state::at::SharedState<Id>) -> Self
    where
        Id: crate::basespec::rezzy_types::EventId,
    {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in state {
            let s = Self::seed(event_type, state_key, event_id);
            hash.add_seed(&s);
        }
        hash
    }

    /// Finalize into the 32-byte wire digest per MSC4500 §6:
    /// `BLAKE2b-256(S)`, where `S` is the 2048-byte lattice.
    #[must_use]
    pub fn checksum(&self) -> [u8; 32] {
        use blake2::digest::consts::U32;
        use blake2::{Blake2b, Digest};
        let mut hasher = Blake2b::<U32>::new();
        for val in &self.0 {
            hasher.update(val.to_le_bytes());
        }
        hasher.finalize().into()
    }
}

/// Computes a deterministic 256-bit `LtHash` fingerprint of a
/// state map, returned as a 32-byte array.
///
/// This is a convenience wrapper around
/// [`LtHash::from_state`]. Each
/// `(event_type, state_key, event_id)` entry is expanded via
/// SHAKE256 to a 2048-byte seed, and the state hash is the
/// wrapping addition of all seeds — making it order-independent and
/// incrementally updatable.
#[must_use]
pub fn compute_state_hash<Id: crate::basespec::rezzy_types::EventId>(
    state: &crate::state::at::SharedState<Id>,
) -> [u8; 32] {
    LtHash::from_state(state).checksum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    type StateMap = imbl::OrdMap<(String, String), String>;

    #[test]
    fn test_state_hash_determinism() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$1".into());
        state.insert(
            ("m.room.member".into(), "@alice:example.com".into()),
            "$2".into(),
        );

        let h1 = compute_state_hash(&state);
        let h2 = compute_state_hash(&state);
        assert_eq!(h1, h2, "same state must produce same hash");
        assert_eq!(h1.len(), 32, "LtHash final checksum should be 32 bytes");
    }

    #[test]
    fn test_state_hash_sensitivity() {
        let mut state_a = StateMap::new();
        state_a.insert(("m.room.create".into(), String::new()), "$1".into());

        let mut state_b = StateMap::new();
        state_b.insert(("m.room.create".into(), String::new()), "$2".into());

        assert_ne!(
            compute_state_hash(&state_a),
            compute_state_hash(&state_b),
            "different states must produce different hashes"
        );
    }

    #[test]
    fn test_lthash_determinism() {
        let mut state = StateMap::new();
        state.insert(("m.room.create".into(), String::new()), "$1".into());
        state.insert(("m.room.member".into(), "@a:x".into()), "$2".into());
        let h1 = LtHash::from_state(&state);
        let h2 = LtHash::from_state(&state);
        assert_eq!(h1, h2);
        assert_ne!(h1, LtHash::ZERO);
        assert_eq!(h1.checksum().len(), 32);
    }

    #[test]
    fn test_lthash_sensitivity() {
        let mut a = StateMap::new();
        a.insert(("m.room.create".into(), String::new()), "$1".into());
        let mut b = StateMap::new();
        b.insert(("m.room.create".into(), String::new()), "$2".into());
        assert_ne!(LtHash::from_state(&a), LtHash::from_state(&b),);
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

    /// Validate against the official MSC4500 test vectors.
    ///
    /// These vectors use SHAKE256 expansion (with domain separation tag
    /// `msc4500_lthash16\x00`) and BLAKE2b-256 collapse.
    #[test]
    fn test_msc4500_vectors() {
        fn hex(bytes: &[u8]) -> alloc::string::String {
            use core::fmt::Write;
            bytes.iter().fold(
                alloc::string::String::with_capacity(bytes.len() * 2),
                |mut s, b| {
                    write!(s, "{b:02x}").unwrap();
                    s
                },
            )
        }

        // --- Empty state (n=0) ---
        let s0 = LtHash::ZERO;
        assert_eq!(
            hex(&s0.checksum()),
            "200823e5158b3774c11b5c61850ada762f8264144a9bebec3ebac5a2adde67b8"
        );

        // --- Scenario 1: Add element 1 ---
        let seed1 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_1");
        let exp1_bytes: Vec<u8> = seed1.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&exp1_bytes), "d72df88a72ff61da6b2287649ff6001c");

        let mut s1 = s0;
        s1.add_seed(&seed1);
        let s1_bytes: Vec<u8> = s1.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s1_bytes), "d72df88a72ff61da6b2287649ff6001c");
        assert_eq!(
            hex(&s1.checksum()),
            "3bcd9f595b4b5c7095b300ec5cf37ff1ff3f79400643f7ba66171e150ddb6606"
        );

        // --- Scenario 2: Remove element 1 ---
        let mut s_back = s1;
        s_back.sub_seed(&seed1);
        assert_eq!(s_back, LtHash::ZERO);
        assert_eq!(
            hex(&s_back.checksum()),
            "200823e5158b3774c11b5c61850ada762f8264144a9bebec3ebac5a2adde67b8"
        );

        // --- Scenario 3: Add element 2 ---
        let seed2 = LtHash::seed("m.room.name", "", &"$event_2");
        let exp2_bytes: Vec<u8> = seed2.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&exp2_bytes), "8c9d4997da61e28d7e6b83255fff064e");

        let mut s2 = s1;
        s2.add_seed(&seed2);
        let s2_bytes: Vec<u8> = s2.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s2_bytes), "63cb41224c614368e98d0a8afef5066a");
        assert_eq!(
            hex(&s2.checksum()),
            "99d3ed0ae604d2fb5849f7280062e27ecea4425b64b25190e067e3d6a755680c"
        );

        // --- Scenario 4: Replace element 1 with element 3 ---
        let seed3 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_3");
        let exp3_bytes: Vec<u8> = seed3.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&exp3_bytes), "9dd1af20e6ee125f8e98969793b8c650");

        let mut s3 = s2;
        s3.sub_seed(&seed1);
        s3.add_seed(&seed3);
        let s3_bytes: Vec<u8> = s3.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s3_bytes), "296ff8b7c050f4ec0c0419bdf2b7cc9e");
        assert_eq!(
            hex(&s3.checksum()),
            "8b611750bb056a38f9e3f9fcc74ae1f0771f12ade0daecc6963e302d15f8e67f"
        );
    }

    #[test]
    fn test_lthash_default() {
        let _def = LtHash::default();
    }
}
