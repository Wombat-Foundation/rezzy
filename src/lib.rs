#![no_std]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
//! # Rezzy — Matrix State Resolution Engine
//!
//! Spec-compliant implementation of Matrix state resolution versions
//! **V1**, **V2**, **V2.1** ([MSC4297]), **V2.1.1**, and **V2.2** ([MSC4242]).
//! Runs in `#![no_std]` environments with `alloc`.
//!
//! This crate is a thin facade that re-exports [`rz_core`] for backwards
//! compatibility. New downstream code should depend on `rz-core` directly.
//!
//! [MSC4297]: https://github.com/matrix-org/matrix-spec-proposals/pull/4297
//! [MSC4242]: https://github.com/matrix-org/matrix-spec-proposals/pull/4242

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub use rz_core::*;
