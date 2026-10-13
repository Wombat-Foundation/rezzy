//! Incremental, order-independent accumulators.

pub mod lthash;

pub use lthash::{LtHash, LtLattice, WrongLatticeLength};
