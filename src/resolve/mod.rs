//! State resolution algorithms and pipeline primitives.

pub mod cdo;
pub mod iterative;
pub mod lattice;
pub mod multi;
pub mod reachability;
pub mod sorting;
pub mod subgraph;
pub mod v3;

// Deliberately not `pub use cdo::*;`: the CDO module is retired/unsound
// legacy code (see its module docs) kept only for its tests and as a
// reference for the replacement. `apply_cdo_filter` and `is_ancestor` stay
// reachable at their full path (`rezzy::resolve::cdo::...` /
// `rezzy::cdo::...`) for the differential-harness and regression tests that
// still exercise them, but they are not re-exported into the flat public
// API via crate root globs.
pub use iterative::*;
pub use lattice::*;
pub use multi::*;
pub use reachability::*;
pub use sorting::*;
pub use subgraph::*;
