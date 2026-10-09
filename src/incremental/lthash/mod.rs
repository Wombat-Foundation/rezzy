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

//! Extensible homomorphic accumulation via `LtHash`.
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
//! a Keccak instruction, so expansion dominated every insert. BLAKE3 replaces
//! it with an ARX construction that maps to the same SIMD paths on every
//! target (AVX2/AVX-512 on x86, NEON on ARM, `simd128` on wasm) and is
//! constant-time by construction.
//!
//! The win is real but it is a constant factor, not an order of magnitude: on a
//! 3.6 GHz Skylake-derived core this module squeezes 2048 bytes in roughly
//! 1.8 us against roughly 5.5 us for the SHAKE256 path it replaces, so expect
//! single-digit microseconds per seed rather than nanoseconds. Reproduce with
//! `cargo bench --manifest-path benches/Cargo.toml -- lthash_comprehensive`,
//! whose expansion section measures the XOF and the collapse separately, or
//! with `cargo bench --manifest-path benches/Cargo.toml --bench rezzy -- lthash_backends`, which times this stack head to head against the
//! retired SHAKE256 + `BLAKE2b` one after checking it against the published
//! MSC4500 vectors.
//!
//! Note that the pinned `blake3` dependency keeps `default-features = false`,
//! so expansion uses the portable backend. Enabling blake3's `std` feature
//! turns on runtime SIMD detection; the digest is fixed by the BLAKE3 spec, so
//! both backends agree byte for byte, and it was not measurably faster for the
//! XOF path when measured here.
//!
//! The domain-separation tags are versioned `...:blake3:v1` so a digest
//! produced by this module can never be confused with a SHAKE256
//! instantiation of the same shape.
//!
//! # Layout
//!
//! - `lattice` holds [`LtLattice`], [`LtHash`], the arithmetic traits and
//!   serialization.
//! - `encoding` holds the BLAKE3 expansion and seed encodings.
//!
//! This module has no dependency on room state. The MSC4500 domain layers
//! (`RedactionOverlay`, `ResolutionInputs`, `PduLtHash`) and `from_state`
//! live in [`crate::state::lthash`].

mod encoding;
mod lattice;
#[cfg(test)]
mod tests;

pub(crate) use self::encoding::{seed_lattice, truncate_to_u16_limit};
pub use self::lattice::*;
