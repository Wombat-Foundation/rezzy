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
//! - **Cryptographic security**: hard to find set collisions (SVP).

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
/// - **Cryptographic security**: hard to find set collisions (SVP).
///
/// TODO: `LtHash` is `Copy` over `[u16; 1024]` (2 KiB), so `StateUpdate::New/Unchanged`
/// copies the full value. If profiling shows this is hot, consider boxing or
/// using references in rebuild loops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LtHash(pub [u16; 1024]);

impl Default for LtHash {
    fn default() -> Self {
        Self::ZERO
    }
}

struct HashWriter<'a, H> {
    hasher: &'a mut H,
}

impl<H> core::fmt::Write for HashWriter<'_, H>
where
    H: sha3::digest::Update,
{
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

impl LtHash {
    /// The identity element (empty state).
    pub const ZERO: Self = Self([0u16; 1024]);

    /// Domain separation tag per MSC4500.
    const DST: &'static [u8] = b"msc4500_lthash16_v1\x00";

    /// Compute the 2048-byte SHAKE256 expansion for a single state entry.
    ///
    /// Input encoding (MSC4500 §1): `len(type) || type || len(state_key) || state_key || event_id`
    /// where each `len()` is an unsigned 16-bit little-endian byte count.
    ///
    /// Expansion (MSC4500 §2): `SHAKE256(tag || element, 2048)`
    ///
    /// # Performance & Validation
    ///
    /// Full cryptographic and syntactic validation of the Matrix Event ID (e.g., verifying
    /// length, prefix, character sets, or room-version-specific syntax) is intentionally
    /// **not** performed within this function for performance reasons and to allow flexible
    /// event ID formats across legacy/modern room versions. Any syntactic validation of
    /// event IDs must be enforced by the caller at the application ingestion boundary if desired.
    #[must_use]
    fn seed(event_type: &str, state_key: &str, event_id: &dyn core::fmt::Display) -> Self {
        use core::fmt::Write;
        use sha3::digest::{ExtendableOutput, Update};

        let (event_type, type_len) = truncate_to_u16_limit(event_type);
        let (state_key, sk_len) = truncate_to_u16_limit(state_key);

        let mut xof = sha3::Shake256::default();
        xof.update(Self::DST);
        xof.update(&type_len.to_le_bytes());
        xof.update(event_type.as_bytes());
        xof.update(&sk_len.to_le_bytes());
        xof.update(state_key.as_bytes());

        let mut writer = HashWriter { hasher: &mut xof };
        write!(writer, "{event_id}").expect("failed to write event_id to hasher");

        let mut buf = [0u8; 2048];
        xof.finalize_xof_into(&mut buf);

        let mut out = [0u16; 1024];
        for (i, chunk) in buf.chunks_exact(2).enumerate() {
            out[i] = u16::from_le_bytes([chunk[0], chunk[1]]);
        }
        Self(out)
    }

    /// Add a seed into the hash (insert).
    #[inline]
    fn add_seed(&mut self, seed: &Self) {
        // Process in 8-lane chunks to assist SIMD auto-vectorization
        for (a, b) in self.0.chunks_exact_mut(8).zip(seed.0.chunks_exact(8)) {
            a[0] = a[0].wrapping_add(b[0]);
            a[1] = a[1].wrapping_add(b[1]);
            a[2] = a[2].wrapping_add(b[2]);
            a[3] = a[3].wrapping_add(b[3]);
            a[4] = a[4].wrapping_add(b[4]);
            a[5] = a[5].wrapping_add(b[5]);
            a[6] = a[6].wrapping_add(b[6]);
            a[7] = a[7].wrapping_add(b[7]);
        }
    }

    /// Subtract a seed from the hash (remove).
    #[inline]
    fn sub_seed(&mut self, seed: &Self) {
        // Process in 8-lane chunks to assist SIMD auto-vectorization
        for (a, b) in self.0.chunks_exact_mut(8).zip(seed.0.chunks_exact(8)) {
            a[0] = a[0].wrapping_sub(b[0]);
            a[1] = a[1].wrapping_sub(b[1]);
            a[2] = a[2].wrapping_sub(b[2]);
            a[3] = a[3].wrapping_sub(b[3]);
            a[4] = a[4].wrapping_sub(b[4]);
            a[5] = a[5].wrapping_sub(b[5]);
            a[6] = a[6].wrapping_sub(b[6]);
            a[7] = a[7].wrapping_sub(b[7]);
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

    /// Compute the full hash from a state map (non-incremental).
    #[must_use]
    pub fn from_state<Id>(state: &crate::state::at::SharedState<Id>) -> Self
    where
        Id: crate::basespec::rezzy_types::EventId,
    {
        let mut hash = Self::ZERO;
        for ((event_type, state_key), event_id) in state {
            let s = Self::seed(event_type.as_str(), state_key, event_id);
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
        let mut bytes = [0u8; 2048];
        for (i, val) in self.0.iter().enumerate() {
            let le = val.to_le_bytes();
            let idx = i.wrapping_mul(2);
            bytes[idx] = le[0];
            bytes[idx.wrapping_add(1)] = le[1];
        }
        hasher.update(&bytes[..]);
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    type StateMap = imbl::OrdMap<(crate::basespec::event_types::EventType, String), String>;

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

    /// Validate against the official MSC4500 test vectors.
    ///
    /// These vectors use SHAKE256 expansion (with domain separation tag
    /// `msc4500_lthash16_v1\x00`) and BLAKE2b-256 collapse.
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
        assert_eq!(hex(&exp1_bytes), "c6a4f2e8f4016c9aaf9c52e67020f221");

        let mut s1 = s0;
        s1.add_seed(&seed1);
        let s1_bytes: Vec<u8> = s1.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s1_bytes), "c6a4f2e8f4016c9aaf9c52e67020f221");
        assert_eq!(
            hex(&s1.checksum()),
            "d26472b7d70e5811b22aa575e1ada898b3c83891547d7d0b90972aa44db42db2"
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
        assert_eq!(hex(&exp2_bytes), "8107236052d1e6d7193cada70d85fa2c");

        let mut s2 = s1;
        s2.add_seed(&seed2);
        let s2_bytes: Vec<u8> = s2.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s2_bytes), "47ac154946d35272c8d8ff8d7da5ec4e");
        assert_eq!(
            hex(&s2.checksum()),
            "687f1b5c3c5c4132b6fdc03c070e01287b01aec044e98560ccdfee501009cc0f"
        );

        // --- Scenario 4: Replace element 1 with element 3 ---
        let seed3 = LtHash::seed("m.room.member", "@alice:example.com", &"$event_3");
        let exp3_bytes: Vec<u8> = seed3.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&exp3_bytes), "14e9b8900236b9d0d2e07dc6b392fa14");

        let mut s3 = s2;
        s3.sub_seed(&seed1);
        s3.add_seed(&seed3);
        let s3_bytes: Vec<u8> = s3.0[..8].iter().flat_map(|v| v.to_le_bytes()).collect();
        assert_eq!(hex(&s3_bytes), "95f0dbf054079fa8eb1c2a6ec017f441");
        assert_eq!(
            hex(&s3.checksum()),
            "0c1eb97da39dcc2ab9cfa61c4da329dbcd8e230b892a70583857c934424927a9"
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
