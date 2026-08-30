//! Structural hashing and state-group identity for HAMT nodes.

use blake2::{digest::Digest, Blake2b512};
use core::hash::Hasher;

/// A 128-bit structural hash for HAMT nodes.
///
/// This is a local cache key used to skip identical subtrees across HAMT
/// instances. It is not a wire format.
pub type StructuralHash = [u8; 16];

/// A 32-byte state-group identifier derived from the full root lattice.
///
/// This is the cross-server, deduplicable identifier for a resolved root. It
/// must not be confused with the local-only `StructuralHash`.
pub type StateGroupId = [u8; 32];

/// Default codec version (1 = dense v1 binary format).
pub const HAMT_CODEC_VERSION_V1: u8 = 1;
/// Default routing version (1 = full keyed structural hash routing).
pub const HAMT_ROUTING_VERSION_V1: u8 = 1;

/// A resolved root handle carrying the local structural hash, global state-group identifier,
/// and explicit codec/routing version metadata for migration safety.
///
/// Legacy pre-change handles (missing the version fields) deserialize with
/// `codec_version`/`routing_version` defaulting to [`HAMT_CODEC_VERSION_V1`]/
/// [`HAMT_ROUTING_VERSION_V1`] (not a bare zero, which could be mistaken for a
/// real "version 0" format) -- matching what [`RootHandle::from_lthash`]
/// would have produced for the same data, so a legacy payload round-trips
/// through this struct identically to a freshly-built v1 handle.
/// Bincode payloads shifted by the added fields still require a versioned
/// migration or explicit data migration for recovery.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RootHandle {
    #[serde(default = "default_codec_version_v1")]
    pub codec_version: u8,
    #[serde(default = "default_routing_version_v1")]
    pub routing_version: u8,
    #[serde(default)]
    pub routing_params: [u8; 4],
    pub structural_hash: StructuralHash,
    pub state_group_id: StateGroupId,
}

fn default_codec_version_v1() -> u8 {
    HAMT_CODEC_VERSION_V1
}

fn default_routing_version_v1() -> u8 {
    HAMT_ROUTING_VERSION_V1
}

impl RootHandle {
    /// Builds a root handle with default v1 codec and v1 routing from a precomputed
    /// structural hash and a state lattice.
    #[must_use]
    pub fn from_lthash(structural_hash: StructuralHash, lattice: &crate::state::LtHash) -> Self {
        Self::with_versions(
            HAMT_CODEC_VERSION_V1,
            HAMT_ROUTING_VERSION_V1,
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

pub(crate) struct StructuralHashBuilder(Blake2b512);

impl StructuralHashBuilder {
    pub(crate) fn new(key: &[u8]) -> Self {
        let mut hasher = Blake2b512::new();
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key);
        Self(hasher)
    }

    pub(crate) fn finish(self) -> StructuralHash {
        let result = self.0.finalize();
        let mut out = [0_u8; 16];
        out.copy_from_slice(&result[..16]);
        out
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
            codec_version: HAMT_CODEC_VERSION_V1,
            routing_version: HAMT_ROUTING_VERSION_V1,
            routing_params: [0; 4],
            structural_hash: [1; 16],
            state_group_id: [2; 32],
        };
        let mut set = HashSet::new();
        set.insert(handle.clone());
        assert!(set.contains(&handle));
    }

    /// A legacy JSON payload missing `codec_version`/`routing_version`
    /// entirely (as any `RootHandle` serialized before those fields existed
    /// would be) must deserialize to the same handle
    /// `RootHandle::from_lthash` would have produced for the same
    /// `structural_hash`/`state_group_id` -- i.e. explicit v1, not a bare zero
    /// that could be confused with a real "version 0" format.
    #[test]
    fn test_legacy_payload_defaults_to_explicit_v1_not_zero() {
        let legacy_json = serde_json::json!({
            "routing_params": [0, 0, 0, 0],
            "structural_hash": alloc::vec![1_u8; 16],
            "state_group_id": alloc::vec![2_u8; 32],
        });
        let decoded: RootHandle = serde_json::from_value(legacy_json).expect("legacy decode");

        assert_eq!(decoded.codec_version, HAMT_CODEC_VERSION_V1);
        assert_eq!(decoded.routing_version, HAMT_ROUTING_VERSION_V1);

        let lattice = crate::state::LtHash::ZERO;
        let fresh = RootHandle::from_lthash([1; 16], &lattice);
        assert_eq!(decoded.codec_version, fresh.codec_version);
        assert_eq!(decoded.routing_version, fresh.routing_version);

        // Round-trips: re-encoding the decoded handle and decoding it again
        // is a no-op.
        let reencoded = serde_json::to_value(&decoded).expect("re-encode");
        let redecoded: RootHandle = serde_json::from_value(reencoded).expect("re-decode");
        assert_eq!(decoded, redecoded);
    }
}
