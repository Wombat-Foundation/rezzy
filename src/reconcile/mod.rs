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

//! Minisketch reconciliation helpers.

pub mod algebraic;
pub mod client;
pub mod gf64;
pub mod gf64_simd;
mod pinsketch;
pub mod resident;
pub mod server;
pub mod triage;

/// Maximum depth of an `h64` bucket request.
pub const MAX_DEPTH: u8 = 64;

/// Internal bit width of the `h64` trie used to materialize bucket ranges.
pub const H64_TRIE_WIDTH: u8 = 64;

pub use algebraic::{
    gf64_mul, verify_residual, AlgebraicError, ElementHash, EventIdFormat, RoomAccumulator,
    SyndromeSketch, MAX_LOCAL_SKETCH_DECODE_CAPACITY, MAX_OVERFLOW_SKETCH_CAPACITY,
    MAX_SKETCH_CAPACITY,
};
pub use client::{
    BucketExchange, ClientAction, ReconciliationClient, RemoteDigest, MAX_BUCKETS_PER_ROUND,
    MAX_RECONCILIATION_ROUNDS,
};
pub use resident::{ResidentKernel, STRATA_COUNT, STRATUM_CAPACITY};
pub use server::{
    build_bucket_sketches, compute_frame_digest, ForwardGraph, H64Index, ReconciliationContext,
};
pub use triage::{
    decode_bucket_sketches, estimate_strata, validate_overflow_bucket_requests, BucketDecodeBatch,
    BucketDecodeSuccess, BucketRequest, StrataEstimate, MAX_BATCH_FACTOR_WORK,
    MAX_BUCKETED_SKETCH_CAPACITY, MAX_OVERFLOW_BUCKET_CAPACITY,
};

// These are cross-module invariant checks, not dead asserts on a literal --
// each catches independent constants silently drifting apart across the
// pinsketch/resident/triage submodules. clippy::assertions_on_constants
// only sees the current (agreeing) values and flags them as always-true.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MAX_SKETCH_CAPACITY == 32);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(MAX_OVERFLOW_SKETCH_CAPACITY == 256);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(resident::STRATA_COUNT == 32);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(resident::STRATUM_CAPACITY == 8);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_BUCKET_SKETCH_CAPACITY == 32);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_OVERFLOW_BUCKET_CAPACITY == 256);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_BUCKETED_SKETCH_CAPACITY == 4_096);
// MAX_BATCH_FACTOR_WORK is already *derived* (in triage.rs) from
// MAX_BUCKETS_PER_ROUND, MAX_BUCKET_SKETCH_CAPACITY, and the pinsketch cost
// model, so it automatically tracks changes to any of them -- a formula
// restated here would just be a tautology. Pinning the concrete number
// instead means a change to any of those three inputs shows up as a visible
// diff to this assert, rather than silently moving the batch-decode default
// (currently ~46M) without anyone noticing.
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_BATCH_FACTOR_WORK == 46_006_272);
