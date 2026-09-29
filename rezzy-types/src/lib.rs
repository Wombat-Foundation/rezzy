#![no_std]
//! Shared primitive contracts used across Rezzy crates.

/// Trait alias for types that can serve as event identifiers.
///
/// Any type that is `Clone + Eq + Hash + Ord + Debug + Display` automatically
/// implements this trait via the blanket implementation. Common choices are
/// `String` for human-readable event IDs and integer IDs for interned storage.
/// The `Display` implementation must produce the stable canonical event ID;
/// the core crate uses that representation when computing content-addressed
/// state hashes.
pub trait EventId:
    Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display
{
}

impl<T: Clone + Eq + core::hash::Hash + Ord + core::fmt::Debug + core::fmt::Display> EventId for T {}
