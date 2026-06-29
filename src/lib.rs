#![no_std]
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
//! use rezzy::{resolve_lean, LeanEvent, StateResVersion, HashMap};
//! use imbl::OrdMap;
//!
//! // Build the unconflicted state (agreed upon by all forks).
//! let unconflicted_state: imbl::OrdMap<(String, Option<String>), String> = imbl::OrdMap::new();
//!
//! // Populate conflicted events and full auth context.
//! let conflicted_subgraph: HashMap<String, LeanEvent> = HashMap::new();
//! let auth_context: HashMap<String, LeanEvent> = HashMap::new();
//!
//! // Resolve the winning state.
//! let resolved = resolve_lean(
//!     unconflicted_state,
//!     conflicted_subgraph,
//!     &auth_context,
//!     StateResVersion::V2,
//! );
//! ```
//!
//! ## Feature Flags
//!
//! | Feature     | Default | Description |
//! |-------------|:-------:|-------------|
//! | `std`       | ✓       | Enables `std::collections::HashMap` and thread-parallel lattice resolution. |
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

pub mod auth;
pub mod cdo;
pub mod event_types;
pub mod lattice;
#[cfg(feature = "cli")]
pub mod merge;
pub mod resolve;
pub mod sorting;
pub mod state_at;
pub mod state_delta;
pub mod subgraph;
pub mod types;

pub use cdo::*;
pub use lattice::*;
#[cfg(feature = "cli")]
pub use merge::*;
pub use resolve::*;
pub use sorting::*;
pub use state_at::*;
pub use subgraph::*;
pub use types::*;

/// Re-exported hashmap — uses `std::collections::HashMap` when `std` is
/// enabled, falls back to `hashbrown::HashMap` for `no_std` targets.
///
/// All resolution functions are generic over `BuildHasher`, so this is
/// purely a convenience for callers who don't need a specific hasher.
#[cfg(feature = "std")]
pub use std::collections::HashMap;

/// See the `std` variant's documentation.
#[cfg(not(feature = "std"))]
pub use hashbrown::HashMap;
