//! Structural hashing and state-group identity for HAMT nodes.

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use core::hash::Hasher;

/// A 256-bit structural hash for HAMT nodes.
///
/// This is a local storage/cache key used to skip identical subtrees within a
/// caller-selected structural-key namespace; it is not a wire format. The
/// structural key is included in both node identity and routing, so callers
/// using distinct per-room keys intentionally produce disjoint node hashes.
///
/// The structural key separates the caller-selected namespaces and is included
/// in both routing and node identity. Its public nature does not raise the
/// cost of a collision within a namespace, so a full 256-bit digest is retained
/// to provide a 128-bit generic collision-security margin.
///
/// # Threat model
///
/// The `structural_key` is the room's `room_id`: fully public, not a secret,
/// and known in advance to anyone who can address the room. This is safe for
/// HAMT routing because:
///
/// - **BLAKE2b-256 is collision-resistant** at 128-bit security. Grinding
///   a shallow-prefix collision (k levels of 5-bit agreement) costs
///   `2^(5k)` hash evaluations; for k ≤ ~10 this is practical (seconds),
///   but only causes O(depth) slowdown — the tree still terminates.
/// - **Full-depth exhaustion** (52 levels = 2^260 hashes) is
///   computationally infeasible.
/// - `HamtBuildError::HashCollision` at max depth is a safe error return,
///   not a panic or data corruption.
///
/// The threat model assumes:
/// 1. The structural key is per-room (`room_id`), so precomputed collisions
///    for one room cannot be transferred to another.
/// 2. Callers of `build_hamt_with_key_hash` do **not** feed wire-derived
///    path hashes through the custom `key_hash` closure without local
///    re-keying via `key_path_hash(structural_key, key)`.
///
/// Because the key is public and fixed to `room_id`, an attacker can precompute
/// shallow collisions against a known room. That residual cost (seconds of compute
/// for a handful of extra tree levels) is bounded and accepted; defending against
/// deliberate depth spam within a single room is an admission / rate-limiting
/// concern at the homeserver level.
pub type StructuralHash = [u8; 32];

/// A 32-byte state-group identifier derived from the full root lattice.
///
/// This is the cross-server, deduplicable identifier for a resolved root. It
/// must not be confused with the local-only `StructuralHash`.
pub type StateGroupId = [u8; 32];

/// Current codec version (1 = dense format with 32-byte structural hashes).
pub const HAMT_CODEC_VERSION: u8 = 1;
/// Current routing version (1 = full keyed structural hash routing).
pub const HAMT_ROUTING_VERSION: u8 = 1;

fn default_codec_version() -> u8 {
    HAMT_CODEC_VERSION
}

fn default_routing_version_v1() -> u8 {
    HAMT_ROUTING_VERSION
}

/// A resolved root handle carrying the local structural hash, global state-group identifier,
/// and explicit codec/routing version metadata.
///
/// # Persistence contract
///
/// `RootHandle` is designed for **JSON persistence only**. Its `[u8; 32]` fields
/// serialize as JSON number arrays, and the `#[serde(default)]` attributes on the
/// version fields ensure backward compatibility with legacy JSON documents that
/// predate `codec_version` / `routing_version` / `routing_params`.
///
/// **Do not use bincode or other positional binary formats** with this struct.
/// The field layout has changed since initial design (`StructuralHash` widened from
/// `[u8; 16]` to `[u8; 32]`, version fields were prepended), and bincode's
/// position-dependent decoding would silently misparse legacy payloads. If binary
/// persistence is needed, use a versioned envelope with an explicit format tag.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct RootHandle {
    pub codec_version: u8,
    pub routing_version: u8,
    pub routing_params: [u8; 4],
    pub structural_hash: StructuralHash,
    pub state_group_id: StateGroupId,
}

impl RootHandle {
    /// Builds a root handle with the current codec and v1 routing from a precomputed
    /// structural hash and a state lattice.
    #[must_use]
    pub fn from_lthash(structural_hash: StructuralHash, lattice: &crate::state::LtHash) -> Self {
        Self::with_versions(
            HAMT_CODEC_VERSION,
            HAMT_ROUTING_VERSION,
            [0; 4],
            structural_hash,
            lattice,
        )
    }

    /// Builds a root handle with explicit codec and routing versioning.
    #[must_use]
    pub fn with_versions(
        codec_version: u8,
        routing_version: u8,
        routing_params: [u8; 4],
        structural_hash: StructuralHash,
        lattice: &crate::state::LtHash,
    ) -> Self {
        Self {
            codec_version,
            routing_version,
            routing_params,
            structural_hash,
            state_group_id: state_group_id_from_lthash(lattice),
        }
    }
}

/// The parameterized BLAKE2b-256 variant, rather than a truncated BLAKE2b-512
/// digest, makes the persisted structural-hash width explicit.
type Blake2b256 = Blake2b<U32>;

pub(crate) struct StructuralHashBuilder(Blake2b256);

impl StructuralHashBuilder {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut hasher = Blake2b256::new();
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key);
        Self(hasher)
    }

    pub(crate) fn finalize(self) -> StructuralHash {
        self.0.finalize().into()
    }
}

impl Hasher for StructuralHashBuilder {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }
}

/// Computes the 32-byte state-group identifier from the full resolved lattice.
///
/// This uses the `LtHash` digest, which is `BLAKE2b-256(lattice)`.
#[must_use]
pub fn state_group_id_from_lthash(lattice: &crate::state::LtHash) -> StateGroupId {
    lattice.digest()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_root_handle_hashable() {
        let handle = RootHandle {
            codec_version: HAMT_CODEC_VERSION,
            routing_version: HAMT_ROUTING_VERSION,
            routing_params: [0; 4],
            structural_hash: [1; 32],
            state_group_id: [2; 32],
        };
        let mut set = HashSet::new();
        set.insert(handle.clone());
        assert!(set.contains(&handle));
    }
}
