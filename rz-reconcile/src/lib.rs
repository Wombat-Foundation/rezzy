#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! Minisketch reconciliation helpers (MSC4521).
//!
//! This crate is independent of the core state resolution engine and depends
//! only on `base64`, `sha2`, and the local `EventId` trait alias it
//! defines locally.

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub mod algebraic;
pub mod client;
pub mod gf64;
pub mod gf64_simd;
mod pinsketch;
pub mod resident;
pub mod server;
pub mod triage;

/// Trait alias for types that can serve as event identifiers.
///
/// This is intentionally identical to `rz_core::basespec::rezzy_types::EventId`
/// so that both crates accept the same concrete types (typically `String`).
pub trait EventId:
    Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display
{
}
impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display> EventId for T {}

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
    MAX_BUCKETED_SKETCH_CAPACITY, MAX_OVERFLOW_BUCKET_CAPACITY, MAX_STRATA_FACTOR_WORK,
};

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
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_BATCH_FACTOR_WORK == 36_700_160);
#[allow(clippy::assertions_on_constants)]
const _: () = assert!(triage::MAX_STRATA_FACTOR_WORK == 1_458_176);
