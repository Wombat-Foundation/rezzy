//! State-facing exports for the incremental `LtHash` implementation.
//!
//! The accumulator itself is domain-independent and lives in [`crate::incremental`].
//! This module remains as a compatibility path for callers that associate the
//! MSC4500-shaped default accumulator with room state.

pub use crate::incremental::lthash::*;
