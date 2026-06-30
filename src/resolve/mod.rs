//! State resolution algorithms and pipeline primitives.
//!
//! This module contains:
//! - [`iterative`] — the sequential, spec-compliant resolver ([`resolve_lean`])
//! - [`lattice`] — the parallel lattice-coordinatized resolver ([`resolve_lattice_coordinatized`])
//! - [`sorting`] — topological (Kahn) and mainline sorting
//! - [`cdo`] — Causal Domination Operator pre-filter (V2.1.1)
//! - [`subgraph`] — conflicted subgraph extraction (V2.1+)

pub mod cdo;
pub mod iterative;
pub mod lattice;
pub mod sorting;
pub mod subgraph;

pub use cdo::*;
pub use iterative::*;
pub use lattice::*;
pub use sorting::*;
pub use subgraph::*;
