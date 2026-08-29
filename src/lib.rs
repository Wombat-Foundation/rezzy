#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! # Rezzy — Matrix State Resolution Engine
//!
//! A high-performance, spec-compliant implementation of [Matrix](https://spec.matrix.org/)
//! state resolution versions **V1**, **V2**, **V2.1** ([MSC4297]), **V2.1.1**
//! (experimental), and **V2.2** (experimental [MSC4242]) support.
//!
//! Rezzy is designed for correctness-first operation inside homeservers, bridges,
//! and formal-verification toolchains. It runs in `#![no_std]` environments (with
//! `alloc`) and optionally leverages SIMD-width bitmask sweeps for CDO filtering.
//!
//! ## Quick Start Example (Room V11 / State Res V2)
//!
//! ```rust,no_run
//! use rezzy::{resolve_iterative_sort, LeanEvent, SharedState, StateResVersion, HashMap};
//!
//! // Build the unconflicted state (agreed upon by all forks).
//! let unconflicted_state = SharedState::new();
//!
//! // Populate conflicted events and full auth context.
//! let conflicted_subgraph: HashMap<String, LeanEvent> = HashMap::new();
//! let auth_context: HashMap<String, LeanEvent> = HashMap::new();
//!
//! // Resolve the winning state.
//! let resolved = resolve_iterative_sort(
//!     unconflicted_state,
//!     conflicted_subgraph,
//!     &auth_context,
//!     StateResVersion::V2,
//!     &mut HashMap::new(),
//! );
//! ```
//!
//! ## Feature Flags
//!
//! | Feature     | Default | Description |
//! |-------------|:-------:|-------------|
//! | `std`       | ✓       | Enables `std::collections::{HashMap, HashSet}` and thread-parallel lattice resolution. |
//! | `alloc`     | ✓       | Bare `alloc` support for `no_std` targets (implied by `std`). |
//! | `cli`       | ✗       | Builds the `rezzy` CLI binary and the `merge` module. |
//! | `hashing`   | ✗       | SHA-256 content-hashing for events missing an `event_id`. |
//! | `mock-ruma` | ✗       | Enables Ruma SDK interop for upstream parity testing. |
//! | `regen`     | ✗       | Builds the `regen_oracles` snapshot regeneration binary. |
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

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

pub mod auth;
pub mod basespec;
pub mod cuckoo_verify;
pub mod dense_index;
pub mod hamt;
pub mod merkle;
pub mod reconcile;
pub mod resolve;
pub mod state;

pub use basespec::rezzy_types::*;
pub use reconcile::*;
pub use resolve::*;
pub use state::*;

/// Selects the presentation shape for resolved room data.
///
/// This is a library-level input so downstream callers can choose between
/// timeline-oriented output and the raw resolved-state view without depending
/// on the CLI binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum OutputFormat {
    #[default]
    Events,
    Default,
    Deltas,
    Federation,
    Summary,
    Timeline,
    #[cfg_attr(feature = "cli", value(alias = "resolve_state"))]
    ResolveState,
}

/// One resolved-state entry in `(type, state_key, event_id)` form.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedStateEntry {
    pub event_type: String,
    pub state_key: String,
    pub event_id: String,
}

/// Converts a resolved state map into a stable, sorted list of entries.
#[must_use]
pub fn resolved_state_entries<Id: basespec::rezzy_types::EventId>(
    final_state_map: &crate::state::at::SharedState<Id>,
) -> Vec<ResolvedStateEntry> {
    let mut entries = final_state_map
        .iter()
        .map(|((event_type, state_key), event_id)| ResolvedStateEntry {
            event_type: event_type.to_string(),
            state_key: state_key.clone(),
            event_id: event_id.to_string(),
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

/// Internal-only hashmap/hashset for maps rezzy builds and owns entirely
/// (never a caller-supplied parameter or a public field), keyed with
/// `hashbrown`'s `foldhash`-based `DefaultHashBuilder` instead of
/// `std::collections`'s `SipHash13`.
///
/// State keys and event IDs handled by resolution originate from federation
/// input an attacker can choose, so these maps still benefit from a randomized
/// hasher. `foldhash` gives us a fast, minimally DoS-resistant, non-cryptographic
/// default; that is appropriate here because the maps are internal-only, but we
/// do not treat it as a security boundary. Not part of the public API:
/// swapping the hasher on a caller-visible `HashMap<K, V, S>` parameter would
/// silently break every external caller that passes a
/// `std::collections::HashMap` there, since `S: BuildHasher` genericity only
/// covers the hasher, not the underlying map type. See `benches/state_backend.rs`
/// and the perf investigation this followed for how that was found out the hard
/// way.
pub(crate) type FastMap<K, V> = hashbrown::HashMap<K, V, hashbrown::DefaultHashBuilder>;

/// See [`FastMap`]'s documentation.
#[allow(dead_code)]
pub(crate) type FastSet<K> = hashbrown::HashSet<K, hashbrown::DefaultHashBuilder>;

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
                    event_type: "m.room.create".into(),
                    state_key: String::new(),
                    event_id: "$c".into(),
                },
                ResolvedStateEntry {
                    event_type: "m.room.member".into(),
                    state_key: "@alice:x".into(),
                    event_id: "$a".into(),
                },
                ResolvedStateEntry {
                    event_type: "m.room.member".into(),
                    state_key: "@bob:x".into(),
                    event_id: "$b".into(),
                },
            ]
        );
    }
}
