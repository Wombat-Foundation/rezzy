#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! # Rezzy — Matrix State Resolution Engine
//!
//! Spec-compliant implementation of Matrix state resolution versions
//! **V1**, **V2**, **V2.1** ([MSC4297]), **V2.1.1**, and **V2.2** ([MSC4242]).
//! Runs in `#![no_std]` environments with `alloc`.
//!
//! ## Feature Flags
//!
//! | Feature     | Default | Description |
//! |-------------|:-------:|-------------|
//! | `std`       | ✓       | Enables `std::collections::{HashMap, HashSet}` and thread-parallel lattice resolution. |
//! | `cli`       | ✗       | Builds the `rezzy` CLI binary and merge utilities. |
//! | `mock-ruma` | ✗       | Enables Ruma SDK interop for upstream parity testing. |
//! | `regen`     | ✗       | Builds the `regen-oracles` snapshot regeneration binary. |
//! | `signing`   | ✗       | Signature-verification traits (`SignatureVerifier` et al.), backend-agnostic. |
//! | `signing-core` | ✗    | Backend-agnostic signature verification (`SignatureVerifier` et al.). |
//! | `signing-consensus` | ✗   | `ed25519-zebra`-backed (ZIP 215) `SignatureVerifier` implementation. |
//!
//! Canonical-JSON SHA-256 hashing is always compiled in — see [`reference_hash`]
//! and [`verify_content_hash`].
//!
//! ## Spec References
//!
//! - [Matrix Spec — Server-Server API §3: State Resolution (V1)](https://spec.matrix.org/v1.13/server-server-api/#room-state-resolution)
//! - [Matrix Spec — Room Versions](https://spec.matrix.org/v1.13/rooms/)
//! - [MSC1693 — State Resolution V2][MSC1693]
//! - [MSC4297 — State Resolution V2.1][MSC4297]
//! - [MSC4242 — State DAGs (V2.2)][MSC4242]
//!
//! [MSC1693]: https://github.com/matrix-org/matrix-spec-proposals/pull/1693
//! [MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
//! [MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242

#[cfg(feature = "std")]
extern crate std;

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

extern crate alloc;

pub use rezzy_json as json;
pub use rezzy_json::json;

mod base64_utils;

use alloc::string::String;
use alloc::vec::Vec;

pub mod auth;
pub mod basespec;
pub mod bitmap;
pub mod cuckoo_verify;
pub mod dag;
pub mod dense_index;
pub mod hamt;
pub mod incremental;
pub mod merkle;
pub mod raw_event;
pub mod resolve;
#[cfg(feature = "signing-core")]
pub mod signing;
pub mod state;
pub mod warnings;

pub use auth::validate::*;
pub use basespec::event_types::EventType;
pub use basespec::rezzy_types::*;
pub use dag::*;
pub use dense_index::{DenseIndex, IndexTooLarge};
pub use raw_event::*;
pub use resolve::*;
pub use rezzy_json::{
    write_raw_canonical_filtered, write_raw_canonical_filtered_strict, write_string_value_filtered,
    Error as JsonError, FieldMask, MemberSpan, Number as JsonNumber, Object as JsonObject, Token,
    Tokenizer, TokenizerError, Value as JsonValue, ValueRef, ValueType as JsonValueType,
};
pub use state::*;
pub use warnings::{Outcome, Warning};

/// Selects the presentation shape for resolved room data.
///
/// This is a library-level input so downstream callers can choose between
/// timeline-oriented output and the raw resolved-state view without depending
/// on the CLI binary.
#[derive(Debug, Clone, Copy, Default)]
pub enum OutputFormat {
    #[default]
    Events,
    Default,
    Deltas,
    Federation,
    Summary,
    Timeline,
    TimelineChronological,
    ResolveState,
    Hamt,
}

#[cfg(feature = "cli")]
impl clap::ValueEnum for OutputFormat {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::Events,
            Self::Default,
            Self::Deltas,
            Self::Federation,
            Self::Summary,
            Self::Timeline,
            Self::TimelineChronological,
            Self::ResolveState,
            Self::Hamt,
        ]
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        Some(match self {
            Self::Events => clap::builder::PossibleValue::new("events"),
            Self::Default => clap::builder::PossibleValue::new("default"),
            Self::Deltas => clap::builder::PossibleValue::new("deltas"),
            Self::Federation => clap::builder::PossibleValue::new("federation"),
            Self::Summary => clap::builder::PossibleValue::new("summary"),
            Self::Timeline => clap::builder::PossibleValue::new("timeline"),
            Self::TimelineChronological => {
                clap::builder::PossibleValue::new("timeline-chronological")
            }
            Self::ResolveState => {
                clap::builder::PossibleValue::new("resolve-state").alias("resolve_state")
            }
            Self::Hamt => clap::builder::PossibleValue::new("hamt"),
        })
    }
}

/// One resolved-state entry in `(type, state_key, event_id)` form.
#[derive(Debug, PartialEq, Eq)]
pub struct ResolvedStateEntry<Id = String, K = String> {
    pub event_type: EventType,
    pub state_key: K,
    pub event_id: Id,
}

/// Converts a resolved state map into a stable, sorted list of entries.
#[must_use]
pub fn resolved_state_entries<Id, K>(
    final_state_map: &crate::state::at::SharedState<Id, K>,
) -> Vec<ResolvedStateEntry<Id, K>>
where
    Id: basespec::rezzy_types::EventId,
    K: basespec::rezzy_types::StateKey,
{
    let mut entries = final_state_map
        .iter()
        .map(|((event_type, state_key), event_id)| ResolvedStateEntry {
            event_type: event_type.clone(),
            state_key: state_key.clone(),
            event_id: event_id.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|a, b| {
        a.event_type
            .cmp(&b.event_type)
            .then_with(|| a.state_key.cmp(&b.state_key))
    });
    entries
}

/// Re-exported hashmap and hashset — uses `std::collections` when `std` is
/// enabled, falls back to `hashbrown` for `no_std` targets.
///
/// All resolution functions are generic over `BuildHasher`, so this is
/// purely a convenience for callers who don't need a specific hasher.
#[cfg(feature = "std")]
pub use std::collections::{HashMap, HashSet};

/// See the `std` variant's documentation.
#[cfg(not(feature = "std"))]
pub use hashbrown::{HashMap, HashSet};

/// DoS-resistant per-instance seeded `BuildHasher` for internal and
/// narrow-conflict hash tables (`FastMap`, `FastSet`, `SeededMap`, `SeededSet`).
///
/// When the `std` feature is enabled, this delegates directly to
/// `std::collections::hash_map::RandomState` (OS CSPRNG-seeded `SipHash-1-3`).
/// In `#![no_std]` builds, each instance derives a unique 128-bit `SipHash-1-3`
/// key by mixing a monotonic atomic counter and stack address through BLAKE3.
#[derive(Clone, Debug)]
pub struct FastHashBuilder {
    #[cfg(feature = "std")]
    inner: std::collections::hash_map::RandomState,
    #[cfg(not(feature = "std"))]
    k0: u64,
    #[cfg(not(feature = "std"))]
    k1: u64,
}

impl FastHashBuilder {
    /// Creates a new per-instance randomly seeded `FastHashBuilder`.
    #[must_use]
    pub fn new() -> Self {
        #[cfg(feature = "std")]
        {
            Self {
                inner: std::collections::hash_map::RandomState::new(),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            static COUNTER: core::sync::atomic::AtomicU64 =
                core::sync::atomic::AtomicU64::new(0x9e37_79b9_7f4a_7c15);
            let seq = COUNTER.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            let stack_addr = core::ptr::from_ref(&seq) as usize as u64;
            let mut input = [0u8; 16];
            input[..8].copy_from_slice(&seq.to_le_bytes());
            input[8..].copy_from_slice(&stack_addr.to_le_bytes());
            let digest = blake3::hash(&input);
            let bytes = digest.as_bytes();
            let k0 = u64::from_le_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]);
            let k1 = u64::from_le_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]);
            Self { k0, k1 }
        }
    }
}

impl Default for FastHashBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "std"))]
#[derive(Clone, Debug)]
pub struct SipHasher13 {
    v0: u64,
    v1: u64,
    v2: u64,
    v3: u64,
    tail: u64,
    ntail: usize,
    length: usize,
}

#[cfg(not(feature = "std"))]
impl SipHasher13 {
    #[inline]
    const fn new_with_keys(k0: u64, k1: u64) -> Self {
        Self {
            v0: k0 ^ 0x736f_6d65_7073_6575,
            v1: k1 ^ 0x646f_7261_6e64_6f6d,
            v2: k0 ^ 0x6c79_6765_6e65_7261,
            v3: k1 ^ 0x7465_6462_7974_6573,
            tail: 0,
            ntail: 0,
            length: 0,
        }
    }

    #[inline]
    fn sip_round(&mut self) {
        self.v0 = self.v0.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(13);
        self.v1 ^= self.v0;
        self.v0 = self.v0.rotate_left(32);
        self.v2 = self.v2.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(16);
        self.v3 ^= self.v2;
        self.v0 = self.v0.wrapping_add(self.v3);
        self.v3 = self.v3.rotate_left(21);
        self.v3 ^= self.v0;
        self.v2 = self.v2.wrapping_add(self.v1);
        self.v1 = self.v1.rotate_left(17);
        self.v1 ^= self.v2;
        self.v2 = self.v2.rotate_left(32);
    }
}

#[cfg(not(feature = "std"))]
impl core::hash::Hasher for SipHasher13 {
    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len());
        let mut idx = 0usize;
        if self.ntail != 0 {
            while idx < bytes.len() && self.ntail < 8 {
                let shift = (self.ntail & 7) << 3;
                self.tail |= u64::from(bytes[idx]) << shift;
                self.ntail = self.ntail.wrapping_add(1);
                idx = idx.wrapping_add(1);
            }
            if self.ntail == 8 {
                self.v3 ^= self.tail;
                self.sip_round();
                self.v0 ^= self.tail;
                self.tail = 0;
                self.ntail = 0;
            }
        }
        while idx.wrapping_add(8) <= bytes.len() {
            let chunk = &bytes[idx..idx.wrapping_add(8)];
            let m = u64::from_le_bytes([
                chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
            ]);
            self.v3 ^= m;
            self.sip_round();
            self.v0 ^= m;
            idx = idx.wrapping_add(8);
        }
        while idx < bytes.len() {
            let shift = (self.ntail & 7) << 3;
            self.tail |= u64::from(bytes[idx]) << shift;
            self.ntail = self.ntail.wrapping_add(1);
            idx = idx.wrapping_add(1);
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        let mut state = self.clone();
        let b: u64 = ((state.length as u64 & 0xff) << 56) | state.tail;
        state.v3 ^= b;
        state.sip_round();
        state.v0 ^= b;
        state.v2 ^= 0xff;
        state.sip_round();
        state.sip_round();
        state.sip_round();
        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
    }
}

impl core::hash::BuildHasher for FastHashBuilder {
    #[cfg(feature = "std")]
    type Hasher = <std::collections::hash_map::RandomState as core::hash::BuildHasher>::Hasher;
    #[cfg(not(feature = "std"))]
    type Hasher = SipHasher13;

    #[inline]
    fn build_hasher(&self) -> Self::Hasher {
        #[cfg(feature = "std")]
        {
            self.inner.build_hasher()
        }
        #[cfg(not(feature = "std"))]
        {
            SipHasher13::new_with_keys(self.k0, self.k1)
        }
    }
}

pub(crate) type FastMap<K, V> = hashbrown::HashMap<K, V, FastHashBuilder>;

/// A hash set using rezzy's per-instance seeded DoS-resistant hasher.
///
/// This is public because the narrow-conflict override APIs accept it. Most
/// callers should not need it: their state resolution entry point derives the
/// conflicted-key set itself.
pub type FastSet<K> = hashbrown::HashSet<K, FastHashBuilder>;

/// A hash map keyed with [`FastHashBuilder`] (CSPRNG/BLAKE3-seeded `SipHash-1-3`)
/// for untrusted external string keys (`event_id`, `state_key`, `sender`).
pub type SeededMap<K, V> = hashbrown::HashMap<K, V, FastHashBuilder>;

/// A hash set keyed with [`FastHashBuilder`] (CSPRNG/BLAKE3-seeded `SipHash-1-3`)
/// for untrusted external string keys (`event_id`, `state_key`, `sender`).
pub type SeededSet<K> = hashbrown::HashSet<K, FastHashBuilder>;

pub use basespec::interned_key::{InternId, InternedRoomState, Interner, StaticInternId};

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn resolved_state_entries_orders_by_type_then_state_key() {
        let mut state: state::at::SharedState<String> = state::at::SharedState::new();
        state.insert(("m.room.member".into(), "@bob:x".into()), "$b".into());
        state.insert(("m.room.create".into(), String::new()), "$c".into());
        state.insert(("m.room.member".into(), "@alice:x".into()), "$a".into());

        let entries = resolved_state_entries(&state);
        assert_eq!(
            entries,
            vec![
                ResolvedStateEntry {
                    event_type: EventType::RoomCreate,
                    state_key: String::new(),
                    event_id: "$c".into(),
                },
                ResolvedStateEntry {
                    event_type: EventType::RoomMember,
                    state_key: "@alice:x".into(),
                    event_id: "$a".into(),
                },
                ResolvedStateEntry {
                    event_type: EventType::RoomMember,
                    state_key: "@bob:x".into(),
                    event_id: "$b".into(),
                },
            ]
        );
    }

    #[test]
    fn fast_set_and_fast_map_use_per_instance_randomized_seeds_f_09_01() {
        use core::hash::BuildHasher;

        assert!(
            core::any::type_name::<FastSet<String>>().contains("FastHashBuilder"),
            "F-09-01: FastSet must use FastHashBuilder (CSPRNG/BLAKE3-seeded SipHash) rather than unseeded foldhash"
        );

        #[inline(never)]
        fn make_fast_set() -> FastSet<String> {
            FastSet::default()
        }

        let set_a = make_fast_set();
        let set_b = make_fast_set();
        let hash_a = set_a.hasher().hash_one("$untrusted_event_id:example.org");
        let hash_b = set_b.hasher().hash_one("$untrusted_event_id:example.org");
        assert_ne!(
            hash_a, hash_b,
            "F-09-01: distinct FastSet instances must use per-instance randomized seeds to resist HashDoS"
        );
    }
}
