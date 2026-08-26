use super::*;
use crate::hamt::codec::PersistedInternalNode;
use crate::hamt::delta::{isolate_delta, HamtTraversalError};
use crate::hamt::{build_hamt, build_hamt_root_handle, HamtBuildError};
use crate::state::LtHash;
use alloc::vec;
use core::borrow::Borrow;
use core::hash::{Hash, Hasher};
#[cfg(feature = "std")]
use std::error::Error as _;
#[cfg(feature = "std")]
use std::format;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VariableBytes(&'static [u8]);

impl Hash for VariableBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.0);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct NonCloneKey(u64);

impl Hash for NonCloneKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

impl Borrow<u64> for NonCloneKey {
    fn borrow(&self) -> &u64 {
        &self.0
    }
}

#[test]
fn test_structural_hash_equivalence() {
    let key = b"dummy_server_key";
    let leaf1 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf2 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf3 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2, 200)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });

    // Identical leaves should have the same structural hash
    assert_eq!(leaf1.structural_hash, leaf2.structural_hash);
    assert_ne!(leaf1.structural_hash, leaf3.structural_hash);

    let internal1 = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(leaf1.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(leaf1.clone())],
        ),
    });

    let internal2 = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(leaf2.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(leaf2.clone())],
        ),
    });

    // Even though they are different Arc instances, their structural hashes must match
    assert_eq!(internal1.structural_hash, internal2.structural_hash);
}

#[test]
fn test_structural_hash_separates_variable_length_leaf_fields() {
    let key = b"dummy_server_key";

    let left = HamtNode::compute_structural_hash(
        key,
        1,
        0,
        &[(VariableBytes(b"ab"), VariableBytes(b"c"))],
        &[],
    );
    let right = HamtNode::compute_structural_hash(
        key,
        1,
        0,
        &[(VariableBytes(b"a"), VariableBytes(b"bc"))],
        &[],
    );

    assert_ne!(left, right);
}

#[test]
#[cfg(feature = "std")]
fn test_hamt_mutate_error_display_and_source() {
    let collision = HamtMutateError::<std::io::Error>::HashCollision {
        depth: 7,
        bucket_size: 3,
    };
    assert_eq!(
        format!("{collision}"),
        "hamt mutation hash collision at depth 7 with bucket size 3"
    );
    assert!(collision.source().is_none());

    let resolve = HamtMutateError::Resolve(std::io::Error::other("boom"));
    assert_eq!(format!("{resolve}"), "hamt mutation resolver failed: boom");
    let source = resolve
        .source()
        .expect("resolve variant should expose source");
    assert_eq!(format!("{source}"), "boom");
}

#[test]
#[cfg(feature = "std")]
fn test_hamt_traversal_error_display_and_source() {
    let max_depth = HamtTraversalError::<std::io::Error>::MaxDepthExceeded { depth: 42 };
    assert_eq!(
        format!("{max_depth}"),
        "hamt traversal exceeded max depth at 42"
    );
    assert!(max_depth.source().is_none());

    let resolve = HamtTraversalError::Resolve(std::io::Error::other("boom"));
    assert_eq!(format!("{resolve}"), "hamt traversal resolver failed: boom");
    let source = resolve
        .source()
        .expect("resolve variant should expose source");
    assert_eq!(format!("{source}"), "boom");
}

#[test]
fn test_lthash_short_circuit() {
    let key = b"dummy_server_key";
    let leaf1 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let lattice_a = LtHash::default();
    let lattice_b = LtHash::default();

    let mut resolver = |_hash: &StructuralHash| Ok::<_, ()>(leaf1.clone());

    // Simulate identical roots.
    let (added, removed) =
        isolate_delta(&leaf1, &lattice_a, &leaf1, &lattice_b, &mut resolver).unwrap();
    assert!(added.is_empty());
    assert!(removed.is_empty());
}

#[test]
fn test_lthash_equal_does_not_mask_different_roots() {
    let key = b"dummy_server_key";
    let root_a = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2, 200)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });

    let lattice_a = LtHash([7u16; 1024]);
    let lattice_b = LtHash([7u16; 1024]);
    let (added, removed) = isolate_delta(
        &root_a,
        &lattice_a,
        &root_b,
        &lattice_b,
        &mut panic_resolver,
    )
    .unwrap();

    assert_eq!(removed, vec![(1, 100)]);
    assert_eq!(added, vec![(2, 200)]);
}

#[test]
fn test_isolate_delta_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(leaf.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::<u64, u64>::Lazy(leaf.structural_hash)],
        ),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0,
        leaves: vec![],
        children: vec![],
        structural_hash: HamtNode::<u64, u64>::compute_structural_hash(key, 0, 0, &[], &[]),
    });

    let mut resolver = |hash: &StructuralHash| {
        assert_eq!(hash, &leaf.structural_hash);
        Ok::<_, ()>(leaf.clone())
    };

    let (added, removed) = isolate_delta(
        &root_a,
        &LtHash::default(),
        &root_b,
        &LtHash([1u16; 1024]),
        &mut resolver,
    )
    .expect("delta should resolve lazy child");

    assert!(added.is_empty());
    assert_eq!(removed, vec![(1, 100)]);
}

#[test]
fn test_persisted_internal_node_round_trip() {
    let node = PersistedInternalNode {
        datamap: 0b011,
        nodemap: 0b100,
        structural_hash: [0xaa; 16],
        leaves: vec![(1_i32, 10_i32), (2_i32, 20_i32)],
        child_hashes: vec![[0x11; 16]],
    };

    let encoded = node.encode_v1();
    let decoded = PersistedInternalNode::decode_v1(&encoded).expect("round-trip must decode");

    assert_eq!(decoded, node);
}

#[test]
fn test_decode_v1_rejects_trailing_bytes() {
    let node = PersistedInternalNode {
        datamap: 0b1,
        nodemap: 0b0,
        structural_hash: [0xaa; 16],
        leaves: vec![(1_i32, 10_i32)],
        child_hashes: vec![],
    };

    let mut encoded = node.encode_v1();
    encoded.extend_from_slice(&[0xde, 0xad]);

    assert!(PersistedInternalNode::<i32, i32>::decode_v1(&encoded).is_err());
}

#[test]
fn test_decode_v1_rejects_shape_mismatches() {
    let node = PersistedInternalNode {
        datamap: 0b01,
        nodemap: 0b10,
        structural_hash: [0xaa; 16],
        leaves: vec![(1_i32, 10_i32)],
        child_hashes: vec![[0x11; 16]],
    };
    let encoded = node.encode_v1();

    assert_eq!(
        PersistedInternalNode::<i32, i32>::decode_v1(&[]),
        Err("Invalid version byte")
    );
    assert_eq!(
        PersistedInternalNode::<i32, i32>::decode_v1(&encoded[..3]),
        Err("Buffer too short for v1 header")
    );

    let mut bad_leaf_count = encoded.clone();
    bad_leaf_count[25..29].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        PersistedInternalNode::<i32, i32>::decode_v1(&bad_leaf_count),
        Err("Leaf count does not match datamap")
    );

    let mut bad_child_count = encoded.clone();
    bad_child_count[29..33].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        PersistedInternalNode::<i32, i32>::decode_v1(&bad_child_count),
        Err("Child count does not match nodemap")
    );

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(
        PersistedInternalNode::<i32, i32>::decode_v1(&truncated),
        Err("Buffer too short for child hashes")
    );
}

#[test]
fn test_hamt_codec_numeric_round_trips() {
    use crate::hamt::codec::HamtCodec;

    macro_rules! round_trip {
        ($ty:ty, $value:expr) => {{
            let mut out = Vec::new();
            let value: $ty = $value;
            value.encode_hamt(&mut out);
            let mut cursor = 0;
            assert_eq!(<$ty>::decode_hamt(&out, &mut cursor), Ok(value));
            assert_eq!(cursor, out.len());
        }};
    }

    round_trip!(u8, 7);
    round_trip!(u16, 7_000);
    round_trip!(u32, 7_000_000);
    round_trip!(u64, 7_000_000_000);
    round_trip!(u128, 7_000_000_000_000);
    round_trip!(i8, -7);
    round_trip!(i16, -7_000);
    round_trip!(i32, -7_000_000);
    round_trip!(i64, -7_000_000_000);
    round_trip!(i128, -7_000_000_000_000);
    round_trip!(usize, 7);
    round_trip!(isize, -7);

    let mut cursor = 0;
    assert_eq!(
        usize::decode_hamt(&[1, 2, 3], &mut cursor),
        Err("HAMT codec buffer too short")
    );
    let mut cursor = 0;
    assert_eq!(
        isize::decode_hamt(&[1, 2, 3], &mut cursor),
        Err("HAMT codec buffer too short")
    );
}

#[test]
#[should_panic(expected = "leaf count must match datamap bits")]
fn test_encode_v1_panics_when_leaf_count_mismatches_datamap() {
    let node = PersistedInternalNode::<i32, i32> {
        datamap: 0b1,
        nodemap: 0,
        structural_hash: [0xaa; 16],
        leaves: vec![],
        child_hashes: vec![],
    };
    let _ = node.encode_v1();
}

#[test]
#[should_panic(expected = "child count must match nodemap bits")]
fn test_encode_v1_panics_when_child_count_mismatches_nodemap() {
    let node = PersistedInternalNode::<i32, i32> {
        datamap: 0,
        nodemap: 0b1,
        structural_hash: [0xaa; 16],
        leaves: vec![],
        child_hashes: vec![],
    };
    let _ = node.encode_v1();
}

#[test]
fn test_structural_hash_accepts_long_key() {
    let key = [0x5au8; 100];
    let hash = HamtNode::<u8, u8>::compute_structural_hash(&key, 0, 0, &[], &[]);
    assert_eq!(hash.len(), 16);
}

#[test]
fn test_root_handle_uses_distinct_state_group_id() {
    let lattice = LtHash::default();
    let structural_hash = [0x42; 16];
    let handle = RootHandle::from_lthash(structural_hash, &lattice);

    assert_eq!(handle.structural_hash, structural_hash);
    assert_eq!(handle.state_group_id, state_group_id_from_lthash(&lattice));
    assert_eq!(handle.state_group_id.len(), 32);
}

#[test]
fn test_build_hamt_creates_expected_root_shape() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(1_u8, 10_u8), (2_u8, 20_u8)]).expect("build should work");

    assert_eq!(root.leaves.len(), 2);
    assert_eq!(root.children.len(), 0);
    assert_eq!(root.datamap.count_ones(), 2);
    assert_eq!(root.nodemap, 0);
}

#[test]
fn test_build_hamt_root_handle_tracks_root_identity() {
    let key = b"dummy_server_key";
    let lattice = LtHash::default();
    let (handle, root) = build_hamt_root_handle(key, &lattice, vec![(1_u8, 10_u8)])
        .expect("build with handle should work");

    assert_eq!(handle.structural_hash, root.structural_hash);
    assert_eq!(handle.state_group_id, state_group_id_from_lthash(&lattice));
}

#[test]
fn test_hamt_get_resolved_lookup() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(1_u64, 10_u64)]).expect("build should work");

    assert_eq!(root.get(key, &1_u64), Some(&10_u64));
    assert_eq!(root.get(key, &2_u64), None);
}

#[test]
fn test_hamt_get_mismatched_leaf_returns_none() {
    let key = b"dummy_server_key";
    let stored_key = find_key_with_root_slot(key, 4);
    let query_key = find_different_key_with_root_slot(key, 4, stored_key);
    let root = HamtNode {
        datamap: 1_u32 << 4,
        nodemap: 0,
        leaves: vec![(stored_key, 10_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            1_u32 << 4,
            0,
            &[(stored_key, 10_u64)],
            &[],
        ),
    };

    assert_eq!(root.get(key, &query_key), None);
}

#[test]
fn test_hamt_get_returns_none_for_lazy_child() {
    let key = b"dummy_server_key";
    let query_key = find_key_with_path_slots(key, 3, 7);
    let child = Arc::new(HamtNode {
        datamap: 1_u32 << 7,
        nodemap: 0,
        leaves: vec![(query_key, 42_u64)],
        children: vec![],
        structural_hash: HamtNode::<u64, u64>::compute_structural_hash(
            key,
            1_u32 << 7,
            0,
            &[(query_key, 42_u64)],
            &[],
        ),
    });
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        ),
    };

    assert_eq!(root.get(key, &query_key), None);
}

#[test]
fn test_hamt_search_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child_hash =
        HamtNode::<u64, u64>::compute_structural_hash(key, 1_u32 << 7, 0, &[(query, 42_u64)], &[]);
    let child = Arc::new(HamtNode {
        datamap: 1_u32 << 7,
        nodemap: 0,
        leaves: vec![(query, 42_u64)],
        children: vec![],
        structural_hash: child_hash,
    });
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        ),
    };

    let mut calls = 0_usize;
    let mut resolver = |hash: &StructuralHash| {
        calls = calls.wrapping_add(1);
        assert_eq!(hash, &child.structural_hash);
        Ok::<_, ()>(child.clone())
    };

    let found = root
        .search(key, &query, &mut resolver)
        .expect("search should succeed");
    assert_eq!(found, Some(42_u64));
    assert_eq!(calls, 1);
}

/// Covers the `NodeRef::Resolved` child recursion in
/// `search_by_path_hash_inner` (mod.rs:459-461): a search whose path descends
/// through an already-materialized (non-lazy) internal child must recurse into
/// it directly, never invoking the resolver. Mirrors
/// `test_hamt_search_resolves_lazy_child`, but with the child resolved instead
/// of lazy, exercising the sibling branch of the same `slot_at` dispatch.
#[test]
fn test_hamt_search_descends_resolved_child() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child = Arc::new(HamtNode {
        datamap: 1_u32 << 7,
        nodemap: 0,
        leaves: vec![(query, 42_u64)],
        children: vec![],
        structural_hash: HamtNode::<u64, u64>::compute_structural_hash(
            key,
            1_u32 << 7,
            0,
            &[(query, 42_u64)],
            &[],
        ),
    });
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Resolved(child.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Resolved(child.clone())],
        ),
    };

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("resolved child should not be resolved lazily")
    };

    let found = root
        .search(key, &query, &mut resolver)
        .expect("search should succeed");
    assert_eq!(found, Some(42_u64));
}

/// Covers the `depth >= HAMT_MAX_DEPTH` guard in
/// `search_by_path_hash_inner` (mod.rs:450-452): a search that recurses past
/// the deepest a legitimately-built HAMT can be must return `Ok(None)` rather
/// than keep descending (or overflow the stack). A zero path-hash routes to
/// slot 0 at every level, so searching the single-child `build_deep_chain`
/// descends one level per recursion until the guard fires.
#[test]
fn test_hamt_search_by_path_hash_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH, 0xAA);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("fully resolved chain, no lazy children")
    };

    let result = root.search_by_path_hash(&0_u64, &[0u8; 16], &mut resolver);
    assert_eq!(
        result,
        Ok(None),
        "search must terminate at HAMT_MAX_DEPTH, not recurse further"
    );
}

/// Covers the `depth >= HAMT_MAX_DEPTH` guard in `get_by_path_hash_inner`
/// (mod.rs:423-425): a resolved (non-lazy) lookup that recurses past the
/// deepest a legitimately-built HAMT can be must return `None` rather than
/// keep descending. A zero path-hash routes slot 0 at every level, so
/// descending the single-child `build_deep_chain` hits the guard exactly at
/// `HAMT_MAX_DEPTH`.
#[test]
fn test_hamt_get_by_path_hash_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH, 0xAA);

    assert_eq!(
        root.get_by_path_hash(&0_u64, &[0u8; 16]),
        None,
        "get must terminate at HAMT_MAX_DEPTH, not recurse further"
    );
}

#[test]
fn test_hamt_lookup_with_custom_key_hash() {
    let key = b"dummy_server_key";
    let query = (0_u64..1_000_000)
        .find(|candidate| bucket_index(&key_path_hash(key, candidate), 0) != 4)
        .expect("should find a key whose default root slot differs");
    let custom_hash = {
        let mut hash = [0_u8; 16];
        hash[0] = 4;
        hash
    };
    let root =
        crate::hamt::build_hamt_with_key_hash(key, vec![(NonCloneKey(query), 70_u64)], |_| {
            custom_hash
        })
        .expect("build with custom hash should work");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<NonCloneKey, u64>>, ()> {
        unreachable!("single-leaf tree should not resolve lazily");
    };

    assert_eq!(root.get(key, &query), None);
    assert_eq!(
        root.get_with_key_hash(&query, |_| custom_hash),
        Some(&70_u64)
    );
    assert_eq!(root.get_by_path_hash(&query, &custom_hash), Some(&70_u64));
    assert_eq!(root.search(key, &query, &mut resolver), Ok(None));
    assert_eq!(
        root.search_with_key_hash(&query, |_| custom_hash, &mut resolver),
        Ok(Some(70_u64))
    );
    assert_eq!(
        root.search_by_path_hash(&query, &custom_hash, &mut resolver),
        Ok(Some(70_u64))
    );
}

#[test]
fn test_hamt_mutation_with_custom_key_hash() {
    let key = b"dummy_server_key";
    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };

    let root = crate::hamt::build_hamt_with_key_hash(key, vec![(1_u64, 10_u64)], |key| {
        custom_routing_hash(*key)
    })
    .expect("build with custom hash should work");

    let (root, displaced) = crate::hamt::insert_with_key_hash(
        &root,
        key,
        2_u64,
        20_u64,
        |key| custom_routing_hash(*key),
        &mut resolver,
    )
    .expect("custom insert should work");
    assert_eq!(displaced, None);
    assert_eq!(
        root.get_with_key_hash(&1_u64, |key| custom_routing_hash(*key)),
        Some(&10_u64)
    );
    assert_eq!(
        root.get_with_key_hash(&2_u64, |key| custom_routing_hash(*key)),
        Some(&20_u64)
    );

    let (root, removed) = crate::hamt::remove_with_key_hash(
        &root,
        key,
        &1_u64,
        |key: &u64| custom_routing_hash(*key),
        &mut resolver,
    )
    .expect("custom remove should work");
    assert_eq!(removed, Some(10_u64));
    assert_eq!(
        root.get_with_key_hash(&1_u64, |key| custom_routing_hash(*key)),
        None
    );
    assert_eq!(
        root.get_with_key_hash(&2_u64, |key| custom_routing_hash(*key)),
        Some(&20_u64)
    );
}

#[test]
fn test_hamt_remove_with_custom_key_hash_collapses_to_leaf() {
    let key = b"dummy_server_key";
    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };

    let root =
        crate::hamt::build_hamt_with_key_hash(key, vec![(1_u64, 10_u64), (2_u64, 20_u64)], |key| {
            custom_routing_hash(*key)
        })
        .expect("build with custom hash should work");

    let (root, removed) = crate::hamt::remove_with_key_hash(
        &root,
        key,
        &1_u64,
        |key: &u64| custom_routing_hash(*key),
        &mut resolver,
    )
    .expect("custom remove should work");

    assert_eq!(removed, Some(10_u64));
    assert_eq!(root.datamap.count_ones(), 1);
    assert_eq!(root.nodemap, 0);
    assert_eq!(
        root.get_with_key_hash(&2_u64, |key| custom_routing_hash(*key)),
        Some(&20_u64)
    );
    assert_eq!(
        root.get_with_key_hash(&1_u64, |key| custom_routing_hash(*key)),
        None
    );

    let expected = crate::hamt::build_hamt_with_key_hash(key, vec![(2_u64, 20_u64)], |key| {
        custom_routing_hash(*key)
    })
    .expect("single-entry rebuild should work");

    assert_eq!(root.structural_hash, expected.structural_hash);
    assert_eq!(root.datamap, expected.datamap);
    assert_eq!(root.nodemap, expected.nodemap);
}

#[test]
fn test_hamt_search_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child_hash =
        HamtNode::<u64, u64>::compute_structural_hash(key, 1_u32 << 7, 0, &[(query, 42_u64)], &[]);
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child_hash)],
        ),
    };

    let mut calls = 0_usize;
    let mut resolver = |_hash: &StructuralHash| {
        calls = calls.wrapping_add(1);
        Err::<Arc<HamtNode<u64, u64>>, _>("boom")
    };

    assert_eq!(root.search(key, &query, &mut resolver), Err("boom"));
    assert_eq!(calls, 1);
}

#[test]
fn test_hamt_visit_entries_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child_hash =
        HamtNode::<u64, u64>::compute_structural_hash(key, 1_u32 << 7, 0, &[(query, 42_u64)], &[]);
    let child = Arc::new(HamtNode {
        datamap: 1_u32 << 7,
        nodemap: 0,
        leaves: vec![(query, 42_u64)],
        children: vec![],
        structural_hash: child_hash,
    });
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        ),
    };

    let mut resolver = |hash: &StructuralHash| {
        assert_eq!(hash, &child.structural_hash);
        Ok::<_, ()>(child.clone())
    };
    let mut entries = Vec::new();

    root.visit_entries(&mut resolver, &mut |k, v| {
        entries.push((*k, *v));
        Ok::<_, ()>(())
    })
    .expect("walk should succeed");

    assert_eq!(entries, vec![(query, 42_u64)]);
}

#[test]
fn test_hamt_visit_entries_propagates_visitor_error() {
    let key = b"dummy_server_key";
    let child_datamap = (1_u32 << 7) | (1_u32 << 9);
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(1_u64, 10_u64), (2_u64, 20_u64)],
        &[],
    );
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child_hash)],
        ),
    };

    let mut resolver_calls = 0_usize;
    let mut visitor_calls = 0_usize;
    let mut resolver = |_hash: &StructuralHash| {
        resolver_calls = resolver_calls.wrapping_add(1);
        Ok::<_, &str>(Arc::new(HamtNode {
            datamap: child_datamap,
            nodemap: 0,
            leaves: vec![(1_u64, 10_u64), (2_u64, 20_u64)],
            children: vec![],
            structural_hash: child_hash,
        }))
    };
    let mut visitor = |_k: &u64, _v: &u64| -> Result<(), &str> {
        visitor_calls = visitor_calls.wrapping_add(1);
        Err("nope")
    };

    assert_eq!(root.visit_entries(&mut resolver, &mut visitor), Err("nope"));
    assert_eq!(resolver_calls, 1);
    assert_eq!(visitor_calls, 1);
}

#[test]
fn test_hamt_visit_entries_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let child_datamap = (1_u32 << 7) | (1_u32 << 9);
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(1_u64, 10_u64), (2_u64, 20_u64)],
        &[],
    );
    let root = HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child_hash)],
        ),
    };

    let mut visitor_calls = 0_usize;
    let mut resolver = |_hash: &StructuralHash| Err::<Arc<HamtNode<u64, u64>>, _>("boom");
    let mut visitor = |_k: &u64, _v: &u64| -> Result<(), &str> {
        visitor_calls = visitor_calls.wrapping_add(1);
        Err("unreachable")
    };

    assert_eq!(root.visit_entries(&mut resolver, &mut visitor), Err("boom"));
    assert_eq!(visitor_calls, 0);
}

#[test]
fn test_hamt_is_empty() {
    let empty_node = HamtNode::<u64, u64> {
        datamap: 0,
        nodemap: 0,
        leaves: vec![],
        children: vec![],
        structural_hash: [0; 16],
    };
    assert!(empty_node.is_empty());

    let leaf_node = HamtNode::<u64, u64> {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 10)],
        children: vec![],
        structural_hash: [1; 16],
    };
    assert!(!leaf_node.is_empty());
}

#[test]
fn test_hamt_any_entry_short_circuits() {
    use std::cell::Cell;

    let key = b"dummy_key";
    let child_datamap = (1_u32 << 7) | (1_u32 << 9);
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(10_u64, 100_u64), (20_u64, 200_u64)],
        &[],
    );
    let child = Arc::new(HamtNode {
        datamap: child_datamap,
        nodemap: 0,
        leaves: vec![(10_u64, 100_u64), (20_u64, 200_u64)],
        children: vec![],
        structural_hash: child_hash,
    });

    let root = HamtNode {
        datamap: 1_u32 << 1,
        nodemap: 1_u32 << 3,
        leaves: vec![(5_u64, 50_u64)],
        children: vec![NodeRef::Lazy(child_hash)],
        structural_hash: [0; 16],
    };

    let resolver_calls = Cell::new(0);
    let mut resolver = |hash: &StructuralHash| {
        resolver_calls.set(resolver_calls.get() + 1);
        if hash == &child_hash {
            Ok::<_, &'static str>(child.clone())
        } else {
            Err("not found")
        }
    };

    // Root leaf match: should return Ok(true) WITHOUT invoking resolver
    let has_root_leaf = root
        .any_entry(&mut resolver, &mut |k, _v| Ok(*k == 5))
        .expect("search should succeed");
    assert!(has_root_leaf);
    assert_eq!(resolver_calls.get(), 0);

    // Child leaf match: should invoke resolver and return Ok(true)
    let has_child_leaf = root
        .any_entry(&mut resolver, &mut |k, _v| Ok(*k == 20))
        .expect("search should succeed");
    assert!(has_child_leaf);
    assert_eq!(resolver_calls.get(), 1);

    // No match: returns Ok(false)
    let has_missing = root
        .any_entry(&mut resolver, &mut |k, _v| Ok(*k == 999))
        .expect("search should succeed");
    assert!(!has_missing);

    // Fallible predicate error propagation
    let err_result = root.any_entry(&mut resolver, &mut |_k, _v| Err("db error"));
    assert_eq!(err_result, Err(HamtTraversalError::Resolve("db error")));
}

#[test]
fn test_hamt_find_entry() {
    let key = b"dummy_key";
    let child_datamap = 1_u32 << 3;
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(42_u64, 420_u64)],
        &[],
    );
    let child = Arc::new(HamtNode {
        datamap: child_datamap,
        nodemap: 0,
        leaves: vec![(42_u64, 420_u64)],
        children: vec![],
        structural_hash: child_hash,
    });

    let root = HamtNode {
        datamap: 1_u32 << 1,
        nodemap: 1_u32 << 5,
        leaves: vec![(7_u64, 70_u64)],
        children: vec![NodeRef::Lazy(child_hash)],
        structural_hash: [0; 16],
    };

    let mut resolver = |hash: &StructuralHash| {
        if hash == &child_hash {
            Ok::<_, ()>(child.clone())
        } else {
            Err(())
        }
    };

    let found = root
        .find_entry(&mut resolver, &mut |k, _v| Ok::<_, ()>(*k == 42))
        .expect("find should succeed");
    assert_eq!(found, Some((42_u64, 420_u64)));

    let not_found = root
        .find_entry(&mut resolver, &mut |k, _v| Ok::<_, ()>(*k == 999))
        .expect("find should succeed");
    assert_eq!(not_found, None);
}

/// Deterministic PRNG (`splitmix64`) so the property test below is
/// reproducible without adding a `rand` dependency.
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// For random insert/remove sequences, the incrementally mutated tree must
/// stay semantically correct after every mutation and match a rebuilt tree
/// at the end. The per-step checks validate the touched key, and the final
/// step performs the rebuild plus one full semantic sweep.
#[test]
fn test_hamt_insert_remove_matches_build_hamt() {
    let key = b"dummy_server_key";
    let mut rng_state = 0x1234_5678_9abc_def0_u64;
    let mut model: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut root: Arc<HamtNode<u64, u64>> =
        build_hamt(key, Vec::new()).expect("empty build should work");
    let total_steps = 2000_u32;
    let mut unreachable_resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("fully resolved tree should never need to resolve a lazy child")
    };

    for step in 0..total_steps {
        let op = splitmix64(&mut rng_state) % 3;
        let k = splitmix64(&mut rng_state) % 200;

        if op == 0 || op == 1 {
            let v = splitmix64(&mut rng_state);
            let (new_root, displaced) =
                crate::hamt::insert(&root, key, k, v, &mut unreachable_resolver)
                    .expect("insert should not collide within this key space");
            assert_eq!(displaced, model.insert(k, v));
            root = new_root;
        } else {
            let (new_root, displaced) =
                crate::hamt::remove(&root, key, &k, &mut unreachable_resolver)
                    .expect("remove should not need to resolve anything");
            assert_eq!(displaced, model.remove(&k));
            root = new_root;
        }

        // Fast path: validate the key touched by this mutation on every step.
        assert_eq!(root.get(key, &k), model.get(&k));

        // Rebuild and compare canonical shape periodically, plus one final full sweep.
        if (step + 1) % 64 == 0 || step + 1 == total_steps {
            let expected =
                build_hamt(key, model.iter().map(|(&k, &v)| (k, v))).expect("rebuild should work");
            assert_eq!(root.structural_hash, expected.structural_hash);
            assert_eq!(root.datamap, expected.datamap);
            assert_eq!(root.nodemap, expected.nodemap);
        }

        if step + 1 == total_steps {
            for (&k, &v) in &model {
                assert_eq!(root.get(key, &k), Some(&v));
            }
        }
    }
}

#[test]
fn test_hamt_insert_replaces_existing_value() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(1_u64, 10_u64), (2_u64, 20_u64)]).expect("build should work");

    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };
    let (new_root, displaced) =
        crate::hamt::insert(&root, key, 1_u64, 99_u64, &mut resolver).expect("insert should work");

    assert_eq!(displaced, Some(10_u64));
    assert_eq!(new_root.get(key, &1_u64), Some(&99_u64));
    assert_eq!(new_root.get(key, &2_u64), Some(&20_u64));
}

#[test]
fn test_hamt_insert_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let existing = find_key_with_path_slots(key, 3, 7);
    let new_key = find_key_with_path_slots(key, 3, 11);
    let child_datamap = 1_u32 << 7;
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(existing, 1_u64)],
        &[],
    );
    let child = Arc::new(HamtNode {
        datamap: child_datamap,
        nodemap: 0,
        leaves: vec![(existing, 1_u64)],
        children: vec![],
        structural_hash: child_hash,
    });
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        ),
    });

    let mut calls = 0_usize;
    let mut resolver = |hash: &StructuralHash| {
        calls = calls.wrapping_add(1);
        assert_eq!(hash, &child.structural_hash);
        Ok::<_, ()>(child.clone())
    };

    let (new_root, displaced) = crate::hamt::insert(&root, key, new_key, 2_u64, &mut resolver)
        .expect("insert through a lazy child should succeed");

    assert_eq!(displaced, None);
    assert_eq!(calls, 1);
    assert_eq!(new_root.get(key, &existing), Some(&1_u64));
    assert_eq!(new_root.get(key, &new_key), Some(&2_u64));
}

#[test]
fn test_hamt_insert_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let existing = find_key_with_path_slots(key, 3, 7);
    let new_key = find_key_with_path_slots(key, 3, 11);
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        1_u32 << 7,
        0,
        &[(existing, 1_u64)],
        &[],
    );
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child_hash)],
        ),
    });

    let mut resolver = |_hash: &StructuralHash| Err::<Arc<HamtNode<u64, u64>>, _>("boom");

    assert!(matches!(
        crate::hamt::insert(&root, key, new_key, 2_u64, &mut resolver),
        Err(HamtMutateError::Resolve("boom"))
    ));
}

#[test]
fn test_hamt_remove_missing_key_is_noop() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(1_u64, 10_u64), (2_u64, 20_u64)]).expect("build should work");

    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };
    let (new_root, displaced) =
        crate::hamt::remove(&root, key, &999_u64, &mut resolver).expect("remove should work");

    assert_eq!(displaced, None);
    assert_eq!(new_root.structural_hash, root.structural_hash);
}

#[test]
fn test_hamt_remove_collapses_sibling_to_leaf() {
    let key = b"dummy_server_key";
    let a = find_key_with_path_slots(key, 3, 7);
    let b = find_key_with_path_slots(key, 3, 11);
    let root = build_hamt(key, vec![(a, 1_u64), (b, 2_u64)]).expect("build should work");
    // Both keys route through the same root slot 3, forcing a child node.
    assert_eq!(root.nodemap.count_ones(), 1);
    assert_eq!(root.datamap, 0);

    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };
    let (new_root, displaced) =
        crate::hamt::remove(&root, key, &a, &mut resolver).expect("remove should work");

    assert_eq!(displaced, Some(1_u64));
    // The remaining key must have collapsed back into a root-level leaf,
    // matching what build_hamt would produce for the single remaining key.
    let expected = build_hamt(key, vec![(b, 2_u64)]).expect("build should work");
    assert_eq!(new_root.structural_hash, expected.structural_hash);
    assert_eq!(new_root.nodemap, 0);
    assert_eq!(new_root.datamap.count_ones(), 1);
    assert_eq!(new_root.get(key, &b), Some(&2_u64));
    assert_eq!(new_root.get(key, &a), None);
}

#[test]
fn test_hamt_remove_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let a = find_key_with_path_slots(key, 3, 7);
    let b = find_key_with_path_slots(key, 3, 11);
    let child_datamap = (1_u32 << 7) | (1_u32 << 11);
    let child_hash = HamtNode::<u64, u64>::compute_structural_hash(
        key,
        child_datamap,
        0,
        &[(a, 1_u64), (b, 2_u64)],
        &[],
    );
    let child = Arc::new(HamtNode {
        datamap: child_datamap,
        nodemap: 0,
        leaves: vec![(a, 1_u64), (b, 2_u64)],
        children: vec![],
        structural_hash: child_hash,
    });
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child.structural_hash)],
        ),
    });

    let mut calls = 0_usize;
    let mut resolver = |hash: &StructuralHash| {
        calls = calls.wrapping_add(1);
        assert_eq!(hash, &child.structural_hash);
        Ok::<_, ()>(child.clone())
    };

    let (new_root, displaced) = crate::hamt::remove(&root, key, &a, &mut resolver)
        .expect("remove through a lazy child should succeed");

    assert_eq!(displaced, Some(1_u64));
    assert_eq!(calls, 1);
    assert_eq!(new_root.get(key, &b), Some(&2_u64));
}

#[test]
fn test_hamt_remove_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let a = find_key_with_path_slots(key, 3, 7);
    let child_hash =
        HamtNode::<u64, u64>::compute_structural_hash(key, 1_u32 << 7, 0, &[(a, 1_u64)], &[]);
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1_u32 << 3,
        leaves: vec![],
        children: vec![NodeRef::<u64, u64>::Lazy(child_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1_u32 << 3,
            &[],
            &[NodeRef::<u64, u64>::Lazy(child_hash)],
        ),
    });

    let mut resolver = |_hash: &StructuralHash| Err::<Arc<HamtNode<u64, u64>>, _>("boom");

    assert!(matches!(
        crate::hamt::remove(&root, key, &a, &mut resolver),
        Err(HamtMutateError::Resolve("boom"))
    ));
}

/// `build_hamt` must refuse to build past `HAMT_MAX_DEPTH`, and `insert`
/// must surface that same failure (via `HamtMutateError`'s `From<HamtBuildError>`
/// conversion) when a leaf-vs-leaf split it triggers can't be resolved within
/// the remaining depth. A key type whose `Hash` impl ignores its own value
/// forces every instance to route to the same slot at every depth, which is
/// the only practical way to manufacture a real exhausted-depth collision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CollidingKey(u64);

impl Hash for CollidingKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(b"always the same bytes");
    }
}

impl HamtCodec for CollidingKey {
    fn encode_hamt(&self, out: &mut Vec<u8>) {
        self.0.encode_hamt(out);
    }

    fn decode_hamt(input: &[u8], cursor: &mut usize) -> Result<Self, &'static str> {
        u64::decode_hamt(input, cursor).map(Self)
    }
}

#[test]
fn test_build_hamt_with_key_hash_reports_max_depth_exhaustion() {
    let key = b"dummy_server_key";
    let result = crate::hamt::build_hamt_with_key_hash(
        key,
        vec![(CollidingKey(1), 10_u64), (CollidingKey(2), 20_u64)],
        |_| [0u8; 16],
    );

    assert_eq!(
        result.unwrap_err(),
        HamtBuildError::HashCollision {
            depth: HAMT_MAX_DEPTH - 1,
            bucket_size: 2,
        }
    );
}

#[test]
fn test_build_hamt_adversarial_multi_key_collision() {
    let key = b"dummy_server_key";
    let entries = vec![
        (CollidingKey(1), 10_u64),
        (CollidingKey(2), 20_u64),
        (CollidingKey(3), 30_u64),
        (CollidingKey(4), 40_u64),
        (CollidingKey(5), 50_u64),
    ];
    let result = crate::hamt::build_hamt_with_key_hash(key, entries, |_| [0u8; 16]);

    assert_eq!(
        result.unwrap_err(),
        HamtBuildError::HashCollision {
            depth: HAMT_MAX_DEPTH - 1,
            bucket_size: 5,
        }
    );
}

#[test]
fn test_hamt_insert_propagates_build_hash_collision() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(CollidingKey(1), 10_u64)]).expect("build should work");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<CollidingKey, u64>>, ()> {
        unreachable!("no lazy children in a freshly built tree")
    };

    // CollidingKey's Hash impl makes every instance route to the exact same
    // slot at every depth, so inserting a second, different CollidingKey
    // forces the leaf-split path all the way to HAMT_MAX_DEPTH.
    let result = crate::hamt::insert(&root, key, CollidingKey(2), 20_u64, &mut resolver);

    assert_eq!(
        result.unwrap_err(),
        HamtMutateError::HashCollision {
            depth: HAMT_MAX_DEPTH - 1,
            bucket_size: 2,
        }
    );
}

#[test]
fn test_insert_node_with_ctx_guards_max_depth_reentry() {
    // Exercises the `depth >= HAMT_MAX_DEPTH` guard in `insert_node_with_ctx`
    // directly. This is a defensive re-entry check: `insert_into_child_slot`
    // always calls back in with `next_depth = depth.saturating_add(1)`, so in
    // practice the guard is reached one recursion after the last real slot,
    // rather than through the leaf-split-at-`build_node` path already covered
    // by `test_hamt_insert_propagates_build_hash_collision`.
    let key = b"dummy_server_key";
    let node = Arc::new(HamtNode::<u64, u64> {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 10_u64)],
        children: vec![],
        structural_hash: [0; 16],
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("resolver should not be called at a depth-exhausted guard")
    };
    let mut key_hash_fn = |k: &u64| key_path_hash(key, k);
    let mut ctx = InsertCtx {
        structural_key: key,
        key_hash: &mut key_hash_fn,
        resolver: &mut resolver,
        sink: None,
    };

    let result = insert_node_with_ctx(&node, 2_u64, 20_u64, [0u8; 16], HAMT_MAX_DEPTH, &mut ctx);

    assert_eq!(
        result.unwrap_err(),
        HamtMutateError::HashCollision {
            depth: HAMT_MAX_DEPTH,
            bucket_size: 2,
        }
    );
}

/// Covers the `depth >= HAMT_MAX_DEPTH` entry guard in `remove_node_with_ctx`
/// (mod.rs:1189-1191): a removal invoked already at max depth must return the
/// node untouched (nothing removed) instead of descending. This is the
/// defensive re-entry check; `remove` always starts at depth 0, so it is only
/// reachable by calling the context function directly.
#[test]
fn test_remove_node_with_ctx_guards_max_depth_entry() {
    let key = b"dummy_server_key";
    let node = Arc::new(HamtNode::<u64, u64> {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 10_u64)],
        children: vec![],
        structural_hash: [0; 16],
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("entry guard returns before any resolver call")
    };

    let mut ctx = crate::hamt::RemoveCtx {
        structural_key: key,
        resolver: &mut resolver,
        sink: None,
    };

    let (outcome, removed) =
        remove_node_with_ctx(&node, &1_u64, &[0u8; 16], HAMT_MAX_DEPTH, &mut ctx)
            .expect("guard returns Ok, not Err");
    assert!(matches!(outcome, RemoveOutcome::Node(_)));
    assert_eq!(removed, None);
}

/// Covers the `next_depth >= HAMT_MAX_DEPTH` re-entry guard in
/// `remove_node_with_ctx` (mod.rs:1228-1230): a removal that resolved a child
/// at depth `HAMT_MAX_DEPTH - 1` must bail before recursing one level too
/// deep. The caller must land on the nodemap branch (a child at the routed
/// slot) so `depth.checked_add(1)` is actually reached; a zero path-hash
/// routes slot 0 at every depth.
#[test]
fn test_remove_node_with_ctx_guards_max_depth_reentry() {
    let key = b"dummy_server_key";
    let child = Arc::new(HamtNode::<u64, u64> {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 20_u64)],
        children: vec![],
        structural_hash: [0; 16],
    });
    let node = Arc::new(HamtNode::<u64, u64> {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(child)],
        structural_hash: [0; 16],
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("resolved child is never resolved lazily")
    };

    let depth = HAMT_MAX_DEPTH - 1;
    let mut ctx = crate::hamt::RemoveCtx {
        structural_key: key,
        resolver: &mut resolver,
        sink: None,
    };
    let (outcome, removed) = remove_node_with_ctx(&node, &2_u64, &[0u8; 16], depth, &mut ctx)
        .expect("re-entry guard returns Ok, not Err");
    assert!(matches!(outcome, RemoveOutcome::Node(_)));
    assert_eq!(removed, None);
}

#[test]
fn test_hamt_insert_value_replacement() {
    let key = b"dummy_server_key";
    let root = build_hamt(key, vec![(10_u64, 100_u64)]).expect("build should work");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("no lazy children in tree")
    };

    // Replace value for existing key 10
    let (new_root, old_val) = crate::hamt::insert(&root, key, 10_u64, 200_u64, &mut resolver)
        .expect("insert should succeed");

    assert_eq!(old_val, Some(100_u64));
    assert_eq!(new_root.get(key, &10_u64), Some(&200_u64));
}

#[test]
fn test_hamt_error_display_formatting() {
    use alloc::string::ToString;

    let build_err = HamtBuildError::HashCollision {
        depth: 26,
        bucket_size: 2,
    };
    assert_eq!(
        build_err.to_string(),
        "hamt build hash collision at depth 26 with bucket size 2"
    );

    let mutate_err_collision: HamtMutateError<&str> = HamtMutateError::HashCollision {
        depth: 26,
        bucket_size: 2,
    };
    assert_eq!(
        mutate_err_collision.to_string(),
        "hamt mutation hash collision at depth 26 with bucket size 2"
    );

    let mutate_err_resolve: HamtMutateError<&str> = HamtMutateError::Resolve("missing node");
    assert_eq!(
        mutate_err_resolve.to_string(),
        "hamt mutation resolver failed: missing node"
    );
}

fn find_key_with_slot_at_depth(key: &[u8], depth: usize, slot: usize) -> u64 {
    for candidate in 0_u64..1_000_000 {
        let hash = leaf_hash_for_key(key, candidate);
        if bucket_index(&hash, depth) == slot {
            return candidate;
        }
    }
    panic!("no key found for requested depth/slot");
}

fn find_different_key_with_slot_at_depth(
    key: &[u8],
    depth: usize,
    slot: usize,
    excluded: u64,
) -> u64 {
    for candidate in 0_u64..1_000_000 {
        if candidate == excluded {
            continue;
        }
        let hash = leaf_hash_for_key(key, candidate);
        if bucket_index(&hash, depth) == slot {
            return candidate;
        }
    }
    panic!("no alternate key found for requested depth/slot");
}

/// White-box test exercising `insert_node`'s own max-depth guard directly:
/// a leaf-vs-leaf collision discovered one level below `HAMT_MAX_DEPTH - 1`
/// can't be resolved with a single more level of splitting, so it must
/// error instead of building a corrupt tree. Real trees never reach
/// `HAMT_MAX_DEPTH - 1` through ordinary hashing, so this constructs the
/// node directly rather than building up to it through `insert`.
#[test]
fn test_insert_node_errors_at_max_depth_boundary() {
    let key = b"dummy_server_key";
    let depth = HAMT_MAX_DEPTH - 1;
    // At depth = HAMT_MAX_DEPTH - 1 (depth 25 for a 128-bit hash with 5-bit levels),
    // 3 bits remain in the hash, so slot 3 is a valid, reachable slot index (< 8).
    let slot = 3_usize;
    let existing = find_key_with_slot_at_depth(key, depth, slot);
    let new_key = find_different_key_with_slot_at_depth(key, depth, slot, existing);

    let node = Arc::new(HamtNode {
        datamap: 1_u32 << slot,
        nodemap: 0,
        leaves: vec![(existing, 1_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            1_u32 << slot,
            0,
            &[(existing, 1_u64)],
            &[],
        ),
    });
    let new_path_hash = leaf_hash_for_key(key, new_key);
    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };

    let result = insert_node(
        &node,
        key,
        new_key,
        2_u64,
        &new_path_hash,
        depth,
        &mut resolver,
    );

    assert!(matches!(
        result,
        Err(HamtMutateError::HashCollision {
            depth: d,
            bucket_size: 2
        }) if d == HAMT_MAX_DEPTH
    ));
}

/// A leaf legitimately placed at `HAMT_MAX_DEPTH - 1` (a singleton bucket,
/// which `build_node` permits) must still be updatable in place: matching
/// the existing key is a value replacement, not a split, so it must not hit
/// the max-depth collision guard.
#[test]
fn test_insert_node_updates_existing_leaf_at_max_depth_boundary() {
    let key = b"dummy_server_key";
    let depth = HAMT_MAX_DEPTH - 1;
    let residual_bits =
        (core::mem::size_of::<StructuralHash>() * 8).saturating_sub(depth * HAMT_BRANCH_BITS);
    let slot = 1_usize << residual_bits.saturating_sub(1);
    let existing = find_key_with_slot_at_depth(key, depth, slot);

    let node = Arc::new(HamtNode {
        datamap: 1_u32 << slot,
        nodemap: 0,
        leaves: vec![(existing, 1_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            1_u32 << slot,
            0,
            &[(existing, 1_u64)],
            &[],
        ),
    });
    let existing_path_hash = leaf_hash_for_key(key, existing);
    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };

    let (new_node, old_value) = insert_node(
        &node,
        key,
        existing,
        2_u64,
        &existing_path_hash,
        depth,
        &mut resolver,
    )
    .expect("updating an existing max-depth leaf must succeed");

    assert_eq!(old_value, Some(1_u64));
    assert_eq!(new_node.leaves, vec![(existing, 2_u64)]);
}

#[test]
fn test_hamt_remove_empties_root() {
    let key = b"dummy_server_key";
    let only = find_key_with_root_slot(key, 4);
    let root = build_hamt(key, vec![(only, 42_u64)]).expect("build should work");

    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };
    let (new_root, displaced) =
        crate::hamt::remove(&root, key, &only, &mut resolver).expect("remove should work");

    assert_eq!(displaced, Some(42_u64));
    assert_eq!(new_root.datamap, 0);
    assert_eq!(new_root.nodemap, 0);
    assert!(new_root.leaves.is_empty());
    assert!(new_root.children.is_empty());
}

/// A `NodeRef::Resolved` child holding exactly one leaf can't arise from
/// `build_hamt` (single-entry buckets are always inlined as leaves), but
/// `HamtNode`'s fields are public, so a caller assembling a tree from
/// persisted/foreign data could still hand `remove` one. When removing that
/// child's only entry empties it out, the parent must drop the child slot
/// entirely — exercising `remove_node`'s nodemap-branch `RemoveOutcome::Empty`
/// cascade — while any of the parent's own unrelated leaves survive intact.
#[test]
fn test_hamt_remove_drops_child_that_becomes_fully_empty() {
    let key = b"dummy_server_key";
    let leaf_b = find_key_with_root_slot(key, 1);
    let leaf_d = find_different_key_with_root_slot(key, 2, leaf_b);
    let child_key = find_key_with_path_slots(key, 3, 7);

    let child = Arc::new(HamtNode {
        datamap: 1_u32 << 7,
        nodemap: 0,
        leaves: vec![(child_key, 30_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            1_u32 << 7,
            0,
            &[(child_key, 30_u64)],
            &[],
        ),
    });
    let root_leaves = vec![(leaf_b, 10_u64), (leaf_d, 20_u64)];
    let root_children = vec![NodeRef::Resolved(child)];
    let root = Arc::new(HamtNode {
        datamap: (1_u32 << 1) | (1_u32 << 2),
        nodemap: 1_u32 << 3,
        structural_hash: HamtNode::compute_structural_hash(
            key,
            (1_u32 << 1) | (1_u32 << 2),
            1_u32 << 3,
            &root_leaves,
            &root_children,
        ),
        leaves: root_leaves,
        children: root_children,
    });

    let mut resolver =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> { unreachable!() };
    let (new_root, displaced) =
        crate::hamt::remove(&root, key, &child_key, &mut resolver).expect("remove should work");

    assert_eq!(displaced, Some(30_u64));
    assert_eq!(new_root.nodemap, 0);
    assert!(new_root.children.is_empty());
    assert_eq!(new_root.get(key, &leaf_b), Some(&10_u64));
    assert_eq!(new_root.get(key, &leaf_d), Some(&20_u64));
    assert_eq!(new_root.get(key, &child_key), None);
}

fn find_key_with_path_slots(key: &[u8], root_slot: usize, child_slot: usize) -> u64 {
    for candidate in 0_u64..1_000_000 {
        let hash = leaf_hash_for_key(key, candidate);
        if bucket_index(&hash, 0) == root_slot && bucket_index(&hash, 1) == child_slot {
            return candidate;
        }
    }
    panic!("no key found for requested path slots");
}

fn leaf_hash_for_key(key: &[u8], value: u64) -> StructuralHash {
    key_path_hash(key, &value)
}

fn custom_routing_hash(key: u64) -> StructuralHash {
    let mut hash = [0_u8; 16];
    match key {
        1 => hash[0] = 0b0010_0011,
        2 => hash[0] = 0b1010_0011,
        _ => unreachable!("unexpected test key"),
    }
    hash
}

fn find_key_with_root_slot(key: &[u8], root_slot: usize) -> u64 {
    for candidate in 0_u64..1_000_000 {
        let hash = leaf_hash_for_key(key, candidate);
        if bucket_index(&hash, 0) == root_slot {
            return candidate;
        }
    }
    panic!("no key found for requested root slot");
}

fn find_different_key_with_root_slot(key: &[u8], root_slot: usize, excluded: u64) -> u64 {
    for candidate in 0_u64..1_000_000 {
        if candidate == excluded {
            continue;
        }
        let hash = leaf_hash_for_key(key, candidate);
        if bucket_index(&hash, 0) == root_slot {
            return candidate;
        }
    }
    panic!("no alternate key found for requested root slot");
}

#[test]
fn test_build_hamt_reports_hash_collisions() {
    let key = b"dummy_server_key";
    let result =
        crate::hamt::build_hamt_with_key_hash(key, vec![(1_u8, 10_u8), (2_u8, 20_u8)], |_| {
            [0u8; 16]
        });

    assert!(matches!(
        result,
        Err(HamtBuildError::HashCollision {
            depth: 25,
            bucket_size: 2
        })
    ));
}

#[test]
fn test_build_hamt_uses_final_partial_hash_chunk() {
    let key = b"dummy_server_key";
    let root =
        crate::hamt::build_hamt_with_key_hash(key, vec![(1_u8, 10_u8), (2_u8, 20_u8)], |entry| {
            match entry {
                1 => {
                    let mut hash = [0_u8; 16];
                    hash[15] = 0b0010_0000;
                    hash
                }
                2 => {
                    let mut hash = [0_u8; 16];
                    hash[15] = 0b0100_0000;
                    hash
                }
                _ => unreachable!("unexpected test key"),
            }
        })
        .expect("final partial chunk should separate entries");

    let mut node = &root;
    while let [child] = node.children.as_slice() {
        match child {
            NodeRef::Resolved(next) => node = next,
            NodeRef::Lazy(_) => panic!("builder should materialize resolved children"),
        }
    }

    assert_eq!(node.leaves.len(), 2);
    assert_eq!(node.children.len(), 0);
    assert_eq!(node.datamap.count_ones(), 2);
    assert_eq!(node.nodemap, 0);
}

#[test]
fn test_diff_hamt_nodes_shortcut() {
    let key = b"dummy_server_key";
    let root_a = build_hamt(key, vec![(1_u64, 100_u64), (2_u64, 200_u64)]).expect("build A");
    let root_b = build_hamt(key, vec![(1_u64, 100_u64), (2_u64, 250_u64)]).expect("build B");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("no lazy children in tree")
    };

    let (added, removed) =
        crate::hamt::diff_hamt_nodes(&root_a, &root_b, &mut resolver).expect("diff should succeed");

    assert_eq!(added, vec![(2, 250)]);
    assert_eq!(removed, vec![(2, 200)]);

    // Identical structural hash fast-path
    let (added_same, removed_same) =
        crate::hamt::diff_hamt_nodes(&root_a, &root_a, &mut resolver).expect("diff should succeed");
    assert!(added_same.is_empty());
    assert!(removed_same.is_empty());
}

#[test]
fn test_diff_node_hashes_root_only_change() {
    let key = b"dummy_server_key";
    let root_a = build_hamt(key, vec![(1_u64, 100_u64), (2_u64, 200_u64)]).expect("build A");
    let root_b = build_hamt(key, vec![(1_u64, 100_u64), (2_u64, 250_u64)]).expect("build B");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("no lazy children in tree")
    };

    let delta = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect("diff should succeed");

    // Both roots are single, leaf-only nodes: the whole "spine" is just the
    // root itself changing shape.
    assert_eq!(delta.superseded_node_hashes, vec![root_a.structural_hash]);
    assert_eq!(delta.new_node_hashes, vec![root_b.structural_hash]);

    // Identical roots: nothing superseded, nothing new.
    let delta_same = crate::hamt::diff_node_hashes(&root_a, &root_a, &mut resolver)
        .expect("diff should succeed");
    assert!(delta_same.superseded_node_hashes.is_empty());
    assert!(delta_same.new_node_hashes.is_empty());
}

#[test]
fn test_diff_node_hashes_tracks_insert_and_remove_spine() {
    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let root_a = build_hamt(key, entries).expect("build A");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("tree is fully resolved")
    };

    // Insert a new key: the new root and every node along the path to the
    // new leaf get a new structural hash; the old nodes on that path are
    // superseded.
    let (root_b, displaced) =
        insert(&root_a, key, 1000_u64, 9999_u64, &mut resolver).expect("insert should succeed");
    assert_eq!(displaced, None);
    assert_ne!(root_a.structural_hash, root_b.structural_hash);

    let delta = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect("diff should succeed");

    // The root itself always changed (it commits to every hash below it).
    assert!(delta
        .superseded_node_hashes
        .contains(&root_a.structural_hash));
    assert!(delta.new_node_hashes.contains(&root_b.structural_hash));
    assert!(!delta.superseded_node_hashes.is_empty());
    assert!(!delta.new_node_hashes.is_empty());

    assert_diff_is_gc_safe(
        &root_a,
        &root_b,
        &delta.superseded_node_hashes,
        &delta.new_node_hashes,
        &mut resolver,
    );

    // Removing the same key should walk (roughly) the same spine back down,
    // superseding root_b's path nodes and reintroducing root_a's.
    let (root_c, removed_value) =
        remove(&root_b, key, &1000_u64, &mut resolver).expect("remove should succeed");
    assert_eq!(removed_value, Some(9999_u64));
    assert_eq!(root_c.structural_hash, root_a.structural_hash);

    let delta_rm = crate::hamt::diff_node_hashes(&root_b, &root_c, &mut resolver)
        .expect("diff should succeed");
    assert!(delta_rm
        .superseded_node_hashes
        .contains(&root_b.structural_hash));
    assert!(delta_rm.new_node_hashes.contains(&root_c.structural_hash));

    assert_diff_is_gc_safe(
        &root_b,
        &root_c,
        &delta_rm.superseded_node_hashes,
        &delta_rm.new_node_hashes,
        &mut resolver,
    );
}

/// Checks the safety properties a refcount-based GC scheme actually depends
/// on for a diff between adjacent roots `root_a` -> `root_b`:
///
/// - `new` only contains hashes genuinely reachable from `root_b`.
/// - `superseded` only contains hashes genuinely reachable from `root_a`.
/// - No hash in `superseded` is still reachable from `root_b` — deleting it
///   once `root_a` retires must never remove something `root_b` still uses.
/// - Every hash newly reachable from `root_b` (i.e. not reachable from
///   `root_a`) is accounted for in `new` — otherwise a store incrementing
///   only from `new` would silently under-count and eventually GC a live
///   node.
fn assert_diff_is_gc_safe<F>(
    root_a: &Arc<HamtNode<u64, u64>>,
    root_b: &Arc<HamtNode<u64, u64>>,
    superseded: &[StructuralHash],
    new: &[StructuralHash],
    resolver: &mut F,
) where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<u64, u64>>, ()>,
{
    use std::collections::BTreeSet;

    let reachable_a: BTreeSet<_> = crate::hamt::reachable_node_hashes(root_a, resolver)
        .expect("reachability walk over root_a should succeed")
        .into_iter()
        .collect();
    let reachable_b: BTreeSet<_> = crate::hamt::reachable_node_hashes(root_b, resolver)
        .expect("reachability walk over root_b should succeed")
        .into_iter()
        .collect();

    for hash in new {
        assert!(
            reachable_b.contains(hash),
            "new_node_hashes contained a hash not reachable from the new root"
        );
    }
    for hash in superseded {
        assert!(
            reachable_a.contains(hash),
            "superseded_node_hashes contained a hash not reachable from the old root"
        );
        assert!(
            !reachable_b.contains(hash),
            "superseded_node_hashes contained a hash still reachable from the new root \
             — deleting it on retirement of the old root would corrupt live data"
        );
    }

    let new_set: BTreeSet<_> = new.iter().copied().collect();
    for hash in reachable_b.difference(&reachable_a) {
        assert!(
            new_set.contains(hash),
            "a hash newly reachable from the new root was not reported in new_node_hashes \
             — a refcount store would under-count and could GC it later"
        );
    }
}

#[test]
fn test_diff_node_hashes_structural_hash_fast_path_without_ptr_eq() {
    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();

    // Two independently-built trees from identical entries: same content and
    // therefore the same structural_hash, but distinct `Arc` allocations, so
    // `Arc::ptr_eq` is false and only the structural-hash comparison can
    // short-circuit the recursion.
    let root_a = build_hamt(key, entries.clone()).expect("build A");
    let root_b = build_hamt(key, entries).expect("build B");
    assert!(!Arc::ptr_eq(&root_a, &root_b));
    assert_eq!(root_a.structural_hash, root_b.structural_hash);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("structural-hash equality should short-circuit before any resolve")
    };

    let delta = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect("diff should succeed");
    assert!(delta.superseded_node_hashes.is_empty());
    assert!(delta.new_node_hashes.is_empty());
}

#[test]
fn test_diff_node_hashes_resolves_lazy_children() {
    let key = b"dummy_server_key";

    // A leaf-bearing subtree that will be referenced only lazily by both
    // roots, so any code path that forgets to resolve `NodeRef::Lazy` will
    // either panic (via the resolver below) or silently drop its hash.
    let shared_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    // A second subtree, unique to root_a, that will be resolved via the
    // `(true, false)` "whole subtree only on one side" arm.
    let removed_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 200_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });
    // A third subtree, unique to root_b, resolved via the `(false, true)` arm.
    let added_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(3_u64, 300_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(3, 300)], &[]),
    });

    let shared_lazy = NodeRef::<u64, u64>::Lazy(shared_leaf.structural_hash);
    let removed_lazy = NodeRef::<u64, u64>::Lazy(removed_leaf.structural_hash);
    let added_lazy = NodeRef::<u64, u64>::Lazy(added_leaf.structural_hash);

    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b11,
        leaves: vec![],
        children: vec![shared_lazy.clone(), removed_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b11,
            &[],
            &[shared_lazy.clone(), removed_lazy.clone()],
        ),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b101,
        leaves: vec![],
        children: vec![shared_lazy.clone(), added_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b101,
            &[],
            &[shared_lazy.clone(), added_lazy.clone()],
        ),
    });

    let mut resolved: Vec<StructuralHash> = Vec::new();
    let mut resolver = |hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        resolved.push(*hash);
        if *hash == shared_leaf.structural_hash {
            Ok(shared_leaf.clone())
        } else if *hash == removed_leaf.structural_hash {
            Ok(removed_leaf.clone())
        } else if *hash == added_leaf.structural_hash {
            Ok(added_leaf.clone())
        } else {
            panic!("unexpected lazy resolution: {hash:?}")
        }
    };

    let delta = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect("diff should succeed");
    let superseded = &delta.superseded_node_hashes;
    let new = &delta.new_node_hashes;

    // The shared lazy child must never be resolved: its structural hash is
    // identical on both sides, so the fast path should skip it entirely.
    assert!(!resolved.contains(&shared_leaf.structural_hash));
    assert!(!superseded.contains(&shared_leaf.structural_hash));
    assert!(!new.contains(&shared_leaf.structural_hash));

    // A lazy-only subtree unique to root_a must land in `superseded`, not `new`.
    assert!(superseded.contains(&removed_leaf.structural_hash));
    assert!(!new.contains(&removed_leaf.structural_hash));

    // A lazy-only subtree unique to root_b must land in `new`, not `superseded`.
    assert!(new.contains(&added_leaf.structural_hash));
    assert!(!superseded.contains(&added_leaf.structural_hash));

    assert!(superseded.contains(&root_a.structural_hash));
    assert!(new.contains(&root_b.structural_hash));
}

#[test]
fn test_reachable_node_hashes_resolves_lazy_children() {
    let key = b"dummy_server_key";
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf_lazy = NodeRef::<u64, u64>::Lazy(leaf.structural_hash);
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![leaf_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            core::slice::from_ref(&leaf_lazy),
        ),
    });

    let mut resolve_called = false;
    let mut resolver = |hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        assert_eq!(*hash, leaf.structural_hash);
        resolve_called = true;
        Ok(leaf.clone())
    };

    let hashes = crate::hamt::reachable_node_hashes(&root, &mut resolver)
        .expect("walk should resolve the lazy child");

    assert!(resolve_called);
    assert!(hashes.contains(&root.structural_hash));
    assert!(hashes.contains(&leaf.structural_hash));
    assert_eq!(hashes.len(), 2);
}

#[test]
fn test_diff_node_hashes_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let other_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 200_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });
    let child_lazy = NodeRef::<u64, u64>::Lazy(leaf.structural_hash);
    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![child_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            core::slice::from_ref(&child_lazy),
        ),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 200_u64)],
        children: vec![],
        structural_hash: other_leaf.structural_hash,
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, &'static str> {
        Err("resolve failed")
    };

    let err = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect_err("resolver failure should propagate");
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::Resolve("resolve failed")
    );
}

#[test]
fn test_walk_reachable_node_hashes_shares_subtrees_across_roots() {
    use std::collections::BTreeSet;

    let key = b"dummy_server_key";
    // Two independently built trees from identical entries: distinct `Arc`
    // allocations, identical content, and therefore identical node hashes at
    // every level. Walking the second one must mark nothing new.
    let entries_a: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let entries_b: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let root_a = build_hamt(key, entries_a).expect("build A");
    let root_b = build_hamt(key, entries_b).expect("build B");
    assert!(!Arc::ptr_eq(&root_a, &root_b));
    assert_eq!(
        root_a.structural_hash, root_b.structural_hash,
        "identical entries must build identical trees, just as different allocations"
    );

    let mut resolve_calls: usize = 0;
    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        resolve_calls = resolve_calls.saturating_add(1);
        unreachable!("no lazy children in either tree")
    };

    let mut seen: BTreeSet<StructuralHash> = BTreeSet::new();

    {
        let mut mark = |hash: StructuralHash| seen.insert(hash);
        crate::hamt::walk_reachable_node_hashes(&root_a, &mut resolver, &mut mark)
            .expect("walk over root_a should succeed");
    }
    let total_after_a = seen.len();
    assert!(total_after_a > 1, "a 64-entry tree has more than one node");

    // Walking root_b, which is structurally identical to root_a, must mark
    // nothing new: every node hash it would visit was already recorded by
    // the walk over root_a, and the walk must never call `resolver` (no
    // lazy children exist, but more importantly, it must never even
    // *attempt* to recurse into an already-marked subtree).
    {
        let mut mark = |hash: StructuralHash| seen.insert(hash);
        crate::hamt::walk_reachable_node_hashes(&root_b, &mut resolver, &mut mark)
            .expect("walk over root_b should succeed");
    }
    assert_eq!(
        seen.len(),
        total_after_a,
        "walking a structurally-identical second root must not grow the seen set"
    );
    assert_eq!(
        resolve_calls, 0,
        "neither tree has lazy children to resolve"
    );
}

#[test]
fn test_walk_reachable_node_hashes_skips_shared_lazy_child_without_resolving() {
    use std::collections::BTreeSet;

    let key = b"dummy_server_key";

    // A lazy subtree shared by both roots. If the walk ever resolves an
    // already-marked child (instead of checking `mark` on the child's hash
    // first), this resolver call is where that shows up.
    let shared_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let unique_leaf_a = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 200_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });
    let unique_leaf_b = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(3_u64, 300_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(3, 300)], &[]),
    });

    let shared_lazy = NodeRef::<u64, u64>::Lazy(shared_leaf.structural_hash);
    let unique_a_lazy = NodeRef::<u64, u64>::Lazy(unique_leaf_a.structural_hash);
    let unique_b_lazy = NodeRef::<u64, u64>::Lazy(unique_leaf_b.structural_hash);

    // Two roots with genuinely different structural hashes (different
    // second child), each sharing the same first child subtree.
    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b11,
        leaves: vec![],
        children: vec![shared_lazy.clone(), unique_a_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b11,
            &[],
            &[shared_lazy.clone(), unique_a_lazy.clone()],
        ),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b11,
        leaves: vec![],
        children: vec![shared_lazy.clone(), unique_b_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b11,
            &[],
            &[shared_lazy.clone(), unique_b_lazy.clone()],
        ),
    });
    assert_ne!(
        root_a.structural_hash, root_b.structural_hash,
        "roots must genuinely differ so root-level mark() can't short-circuit the whole walk"
    );

    let mut shared_resolve_count = 0_usize;
    let mut resolver = |hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        if *hash == shared_leaf.structural_hash {
            shared_resolve_count = shared_resolve_count.saturating_add(1);
            Ok(shared_leaf.clone())
        } else if *hash == unique_leaf_a.structural_hash {
            Ok(unique_leaf_a.clone())
        } else if *hash == unique_leaf_b.structural_hash {
            Ok(unique_leaf_b.clone())
        } else {
            panic!("unexpected lazy resolution: {hash:?}")
        }
    };

    let mut seen: BTreeSet<StructuralHash> = BTreeSet::new();
    {
        let mut mark = |hash: StructuralHash| seen.insert(hash);
        crate::hamt::walk_reachable_node_hashes(&root_a, &mut resolver, &mut mark)
            .expect("walk over root_a should succeed");
    }
    {
        let mut mark = |hash: StructuralHash| seen.insert(hash);
        crate::hamt::walk_reachable_node_hashes(&root_b, &mut resolver, &mut mark)
            .expect("walk over root_b should succeed");
    }

    // The root-level hashes genuinely differ, so both roots get walked --
    // but the shared child must be resolved exactly once across both
    // walks, and the whole reachable set is root_a + root_b + 3 leaves.
    assert_eq!(shared_resolve_count, 1);
    assert!(seen.contains(&root_a.structural_hash));
    assert!(seen.contains(&root_b.structural_hash));
    assert!(seen.contains(&shared_leaf.structural_hash));
    assert!(seen.contains(&unique_leaf_a.structural_hash));
    assert!(seen.contains(&unique_leaf_b.structural_hash));
    assert_eq!(seen.len(), 5);
}

#[test]
fn test_walk_reachable_node_hashes_root_already_seen_short_circuits() {
    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let root = build_hamt(key, entries).expect("build root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("mark rejecting the root must prevent any resolver calls at all")
    };
    let mut mark = |_hash: StructuralHash| false;

    crate::hamt::walk_reachable_node_hashes(&root, &mut resolver, &mut mark)
        .expect("walk should succeed even though nothing gets visited");
}

#[test]
fn test_walk_reachable_node_hashes_propagates_resolver_error() {
    let key = b"dummy_server_key";
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf_lazy = NodeRef::<u64, u64>::Lazy(leaf.structural_hash);
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![leaf_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            core::slice::from_ref(&leaf_lazy),
        ),
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, &'static str> {
        Err("resolve failed")
    };
    let mut mark = |_hash: StructuralHash| true;

    let err = crate::hamt::walk_reachable_node_hashes(&root, &mut resolver, &mut mark)
        .expect_err("resolver failure should propagate");
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::Resolve("resolve failed")
    );
}

/// Builds an internal-node chain `depth` levels deep, tagged with `tag` so
/// two chains built with different tags never share a `structural_hash` at
/// any level (needed to keep [`diff_node_hashes`](crate::hamt::diff_node_hashes)
/// from short-circuiting before it ever recurses deep enough to hit a depth
/// guard). The hashes here are synthetic, not computed via
/// `compute_structural_hash` — this fixture exists purely to exercise
/// recursion depth, not routing correctness.
fn build_deep_chain(depth: usize, tag: u8) -> Arc<HamtNode<u64, u64>> {
    let mut node = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(0_u64, u64::from(tag))],
        children: vec![],
        structural_hash: [tag; 16],
    });
    for i in 0..depth {
        let mut hash = [tag; 16];
        hash[0..8].copy_from_slice(&(i as u64).to_le_bytes());
        node = Arc::new(HamtNode {
            datamap: 0,
            nodemap: 1,
            leaves: vec![],
            children: vec![NodeRef::Resolved(node)],
            structural_hash: hash,
        });
    }
    node
}

#[test]
fn test_reachable_node_hashes_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chain is fully resolved, no lazy children")
    };

    let err = crate::hamt::reachable_node_hashes(&root, &mut resolver)
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_walk_reachable_node_hashes_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chain is fully resolved, no lazy children")
    };
    let mut mark = |_hash: StructuralHash| true;

    let err = crate::hamt::walk_reachable_node_hashes(&root, &mut resolver, &mut mark)
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_diff_node_hashes_rejects_excessive_depth() {
    // Two chains that differ (via distinct tags) at every level, so the
    // diff can never short-circuit on a matching structural_hash before it
    // recurses past HAMT_MAX_DEPTH.
    let root_a = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);
    let root_b = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xBB);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chains are fully resolved, no lazy children")
    };

    let err = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_isolate_delta_rejects_excessive_depth() {
    let root_a = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);
    let root_b = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xBB);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chains are fully resolved, no lazy children")
    };

    let err = isolate_delta(
        &root_a,
        &LtHash::default(),
        &root_b,
        &LtHash::default(),
        &mut resolver,
    )
    .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_diff_hamt_nodes_rejects_excessive_depth() {
    // Two chains that differ (via distinct tags) at every level, so the
    // diff can never short-circuit on a matching structural_hash before it
    // recurses past HAMT_MAX_DEPTH.
    let root_a = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);
    let root_b = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xBB);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chains are fully resolved, no lazy children")
    };

    let err = crate::hamt::diff_hamt_nodes(&root_a, &root_b, &mut resolver)
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_diff_hamt_nodes_rejects_excessive_depth_via_collect_all_leaves() {
    // One side is a chain deeper than HAMT_MAX_DEPTH while the other has no
    // matching nodemap child, so diff_nodes takes the (true, false) branch
    // and routes the whole chain through collect_all_leaves — whose own
    // depth guard (not diff_nodes') is what must fire here.
    let root_a = build_deep_chain(HAMT_MAX_DEPTH, 0xAA);
    let root_b = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 1_u64)],
        children: vec![],
        structural_hash: [0xBB; 16],
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chains are fully resolved, no lazy children")
    };

    let err = crate::hamt::diff_hamt_nodes(&root_a, &root_b, &mut resolver).expect_err(
        "collect_all_leaves must reject a chain deeper than HAMT_MAX_DEPTH, not stack-overflow",
    );
    assert_eq!(
        err,
        HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_any_entry_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chain is fully resolved, no lazy children")
    };

    let err = root
        .any_entry(&mut resolver, &mut |_k, _v| Ok::<_, ()>(false))
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_find_entry_rejects_excessive_depth() {
    let root = build_deep_chain(HAMT_MAX_DEPTH.saturating_add(3), 0xAA);

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("chain is fully resolved, no lazy children")
    };

    let err = root
        .find_entry(&mut resolver, &mut |_k, _v| Ok::<_, ()>(false))
        .expect_err("a chain deeper than HAMT_MAX_DEPTH must be rejected, not stack-overflow");
    assert_eq!(
        err,
        HamtTraversalError::MaxDepthExceeded {
            depth: HAMT_MAX_DEPTH
        }
    );
}

#[test]
fn test_reachable_node_hashes_matches_manual_walk() {
    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let root = build_hamt(key, entries).expect("build root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("tree is fully resolved")
    };

    let hashes =
        crate::hamt::reachable_node_hashes(&root, &mut resolver).expect("walk should succeed");

    // The root is always included, and every entry must be unique per node
    // identity — a HAMT built from 64 distinct keys necessarily has more
    // than one internal node.
    assert!(hashes.contains(&root.structural_hash));
    assert!(hashes.len() > 1);
    assert_eq!(hashes.len(), manual_node_count(&root));
}

fn manual_node_count<K, V>(node: &Arc<HamtNode<K, V>>) -> usize {
    let children_count: usize = node
        .children
        .iter()
        .map(|child| match child {
            NodeRef::Resolved(child) => manual_node_count(child),
            NodeRef::Lazy(_) => panic!("no lazy children in this tree"),
        })
        .sum();
    1_usize.saturating_add(children_count)
}

#[test]
fn test_diff_nodes_and_lazy_resolver() {
    let key = b"dummy_server_key";

    // Create a few basic nodes containing 1 leaf each.
    // They will act as children to our test roots.
    let leaf1 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf2 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2, 200)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });
    let leaf3 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(3, 300)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(3, 300)], &[]),
    });
    let leaf4 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(4, 400)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(4, 400)], &[]),
    });

    // Node A will have:
    // Slot 0: leaf1 (Resolved)
    // Slot 1: leaf2 (Resolved)
    // Slot 2: leaf3 (Lazy - will need to be resolved)
    let child_a1 = NodeRef::Resolved(leaf1.clone());
    let child_a2 = NodeRef::Resolved(leaf2.clone());
    let child_a3_lazy = NodeRef::Lazy(leaf3.structural_hash);

    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b0111,
        leaves: vec![],
        children: vec![child_a1.clone(), child_a2.clone(), child_a3_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b0111,
            &[],
            &[child_a1.clone(), child_a2.clone(), child_a3_lazy.clone()],
        ),
    });

    // Node B will have:
    // Slot 0: leaf1 (Resolved - matches Node A)
    // Slot 1: leaf4 (Resolved - replaces leaf2)
    // Slot 3: leaf3 (Resolved - added new slot)
    let child_b1 = NodeRef::Resolved(leaf1.clone());
    let child_b2 = NodeRef::Resolved(leaf4.clone());
    let child_b4 = NodeRef::Resolved(leaf3.clone());

    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b1011,
        leaves: vec![],
        children: vec![child_b1.clone(), child_b2.clone(), child_b4.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b1011,
            &[],
            &[child_b1.clone(), child_b2.clone(), child_b4.clone()],
        ),
    });

    // Ensure lattice short-circuit does not fire
    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);

    let mut resolve_called = false;
    let mut resolver = |hash: &StructuralHash| {
        if hash == &leaf3.structural_hash {
            resolve_called = true;
            Ok::<_, ()>(leaf3.clone())
        } else {
            panic!("Unexpected lazy resolution");
        }
    };

    let (added, removed) =
        isolate_delta(&root_a, &lattice_a, &root_b, &lattice_b, &mut resolver).unwrap();

    assert!(
        resolve_called,
        "Resolver should have been called for the lazy leaf3 child"
    );

    // Removals expected: leaf2 (slot 1 diff) and leaf3 (slot 2 removed in B)
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&(2, 200)));
    assert!(removed.contains(&(3, 300)));

    // Additions expected: leaf4 (slot 1 diff) and leaf3 (slot 3 added in B)
    assert_eq!(added.len(), 2);
    assert!(added.contains(&(4, 400)));
    assert!(added.contains(&(3, 300)));
}

#[test]
fn test_hamt_codec_types() {
    use crate::hamt::codec::HamtCodec;
    use alloc::string::String;
    let mut out = Vec::new();

    // bool
    true.encode_hamt(&mut out);
    false.encode_hamt(&mut out);
    let mut cursor = 0;
    assert_eq!(bool::decode_hamt(&out, &mut cursor), Ok(true));
    assert_eq!(bool::decode_hamt(&out, &mut cursor), Ok(false));
    assert!(bool::decode_hamt(&[2u8], &mut 0).is_err());

    out.clear();
    // String
    let s1 = String::from("hello");
    let s2 = String::new();
    s1.encode_hamt(&mut out);
    s2.encode_hamt(&mut out);
    let mut cursor = 0;
    assert_eq!(String::decode_hamt(&out, &mut cursor), Ok(s1));
    assert_eq!(String::decode_hamt(&out, &mut cursor), Ok(s2));
    assert!(String::decode_hamt(&out[0..2], &mut 0).is_err());

    out.clear();
    // Vec<u8>
    let v1 = vec![1, 2, 3, 4, 5];
    let v2: Vec<u8> = vec![];
    v1.encode_hamt(&mut out);
    v2.encode_hamt(&mut out);
    let mut cursor = 0;
    assert_eq!(Vec::<u8>::decode_hamt(&out, &mut cursor), Ok(v1));
    assert_eq!(Vec::<u8>::decode_hamt(&out, &mut cursor), Ok(v2));
    assert!(Vec::<u8>::decode_hamt(&out[0..2], &mut 0).is_err());
}

#[test]
fn test_leaf_differences() {
    let key = b"dummy_server_key";

    // Node A will have leaves at slots 0, 1
    let root_a = Arc::new(HamtNode {
        datamap: 0b11,
        nodemap: 0,
        leaves: vec![(1, 100), (2, 200)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b11,
            0,
            &[(1, 100), (2, 200)],
            &[],
        ),
    });

    // Node B will have leaves at slots 1, 2
    let root_b = Arc::new(HamtNode {
        datamap: 0b110,
        nodemap: 0,
        leaves: vec![(2, 250), (3, 300)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b110,
            0,
            &[(2, 250), (3, 300)],
            &[],
        ),
    });

    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);

    let (added, removed) = isolate_delta(
        &root_a,
        &lattice_a,
        &root_b,
        &lattice_b,
        &mut panic_resolver,
    )
    .unwrap();

    // slot 0 (true, false): removed (1, 100)
    // slot 1 (true, true): differs, removed (2, 200) added (2, 250)
    // slot 2 (false, true): added (3, 300)
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&(1, 100)));
    assert!(removed.contains(&(2, 200)));

    assert_eq!(added.len(), 2);
    assert!(added.contains(&(2, 250)));
    assert!(added.contains(&(3, 300)));
}
fn panic_resolver<K, V>(_hash: &StructuralHash) -> Result<Arc<HamtNode<K, V>>, ()> {
    panic!("unexpected lazy");
}

#[test]
fn test_collect_all_leaves_recursion() {
    let key = b"dummy_server_key";

    // Build a subtree: root -> internal -> leaf
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let internal = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(leaf.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(leaf.clone())],
        ),
    });

    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(internal.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(internal.clone())],
        ),
    });

    // root_b has nothing in slot 0. So root_a's slot 0 will be completely removed,
    // triggering collect_all_leaves on internal, which then recurses into its children (leaf).
    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0,
        leaves: vec![],
        children: vec![],
        structural_hash: HamtNode::<i32, i32>::compute_structural_hash(key, 0, 0, &[], &[]),
    });

    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);

    let (added, removed) = isolate_delta(
        &root_a,
        &lattice_a,
        &root_b,
        &lattice_b,
        &mut panic_resolver,
    )
    .unwrap();

    assert!(added.is_empty());
    assert_eq!(removed.len(), 1);
    assert!(removed.contains(&(1, 100)));
}

#[test]
fn test_collect_all_leaves_recursion_added_side() {
    // Mirror of `test_collect_all_leaves_recursion`, but with a and b swapped:
    // root_a has nothing in slot 0, root_b has a whole subtree there. This is
    // the `else if in_b` arm of the nodemap loop in `diff_nodes` (a branch that
    // exists only on the b side), which the removed-side test above never
    // exercises.
    let key = b"dummy_server_key";

    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let internal = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(leaf.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(leaf.clone())],
        ),
    });

    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![NodeRef::Resolved(internal.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            &[NodeRef::Resolved(internal.clone())],
        ),
    });

    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0,
        leaves: vec![],
        children: vec![],
        structural_hash: HamtNode::<i32, i32>::compute_structural_hash(key, 0, 0, &[], &[]),
    });

    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);

    let (added, removed) = isolate_delta(
        &root_a,
        &lattice_a,
        &root_b,
        &lattice_b,
        &mut panic_resolver,
    )
    .unwrap();

    assert!(removed.is_empty());
    assert_eq!(added.len(), 1);
    assert!(added.contains(&(1, 100)));
}

#[test]
fn test_structural_hash_builder_hasher() {
    use crate::hamt::hash::StructuralHashBuilder;
    use core::hash::Hasher;

    let builder = StructuralHashBuilder::new(b"key");
    assert_eq!(Hasher::finish(&builder), 0);
}

#[test]
fn test_diff_nodes_fast_paths() {
    let key = b"dummy_server_key";

    let node1 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let node2 = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);

    // -- Arc pointer equality --
    // node1 and node1 are the same Arc allocation.
    let (added1, removed1) =
        isolate_delta(&node1, &lattice_a, &node1, &lattice_b, &mut panic_resolver).unwrap();
    assert!(added1.is_empty());
    assert!(removed1.is_empty());

    // -- Structural hash equality --
    // node1 and node2 are different Arcs, but have the exact same structural hash.
    let (added2, removed2) =
        isolate_delta(&node1, &lattice_a, &node2, &lattice_b, &mut panic_resolver).unwrap();
    assert!(added2.is_empty());
    assert!(removed2.is_empty());
}

#[test]
fn test_hamt_node_persisted_round_trip() {
    use crate::hamt::codec::PersistedInternalNode;
    use core::convert::TryFrom;

    let key = b"dummy_server_key";

    // Build a HamtNode with leaves and children
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    let original = HamtNode {
        datamap: 0b10,
        nodemap: 0b1,
        leaves: vec![(2, 200)],
        children: vec![NodeRef::Resolved(leaf.clone())],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b10,
            0b1,
            &[(2, 200)],
            &[NodeRef::Resolved(leaf.clone())],
        ),
    };

    // 1. Convert to PersistedInternalNode
    let persisted: PersistedInternalNode<i32, i32> = (&original).into();

    // 2. Encode to bytes
    let encoded = persisted.encode_v1();

    // 3. Decode from bytes
    let decoded = PersistedInternalNode::<i32, i32>::decode_v1(&encoded).expect("decode failed");

    // 4. TryFrom back to HamtNode
    let restored = HamtNode::try_from(decoded).expect("try_from failed");

    // Assertions
    assert_eq!(restored.structural_hash, original.structural_hash);
    assert_eq!(restored.datamap, original.datamap);
    assert_eq!(restored.nodemap, original.nodemap);
    assert_eq!(restored.leaves, original.leaves);

    // Check children (restored children will be Lazy, original are Resolved)
    assert_eq!(restored.children.len(), original.children.len());
    for (restored_child, original_child) in restored.children.iter().zip(original.children.iter()) {
        assert!(matches!(restored_child, NodeRef::Lazy(_)));
        assert_eq!(
            restored_child.structural_hash(),
            original_child.structural_hash()
        );
    }
}

#[test]
fn test_unreachable_node_hashes_reports_only_the_orphan() {
    use std::collections::BTreeSet;

    // Two entirely distinct trees keyed under different structural keys, so
    // they share no node hashes at any level: `root_live` stands in for a
    // still-referenced state group, `root_orphan` for one whose only root
    // record was already deleted upstream (the case this function exists to
    // find).
    let live_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let orphan_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(7))).collect();
    let root_live = build_hamt(b"live_key", live_entries).expect("build live root");
    let root_orphan = build_hamt(b"orphan_key", orphan_entries).expect("build orphan root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("both trees are fully resolved, no lazy children")
    };

    let expected_orphan_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_orphan, &mut resolver)
            .expect("orphan walk should succeed")
            .into_iter()
            .collect();
    let live_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_live, &mut resolver)
            .expect("live walk should succeed")
            .into_iter()
            .collect();
    assert!(
        expected_orphan_hashes.is_disjoint(&live_hashes),
        "fixture must not accidentally share node hashes between the two trees"
    );

    let universe = live_hashes
        .iter()
        .copied()
        .chain(expected_orphan_hashes.iter().copied());

    let unreachable: BTreeSet<StructuralHash> =
        crate::hamt::audit::unreachable_node_hashes([root_live], universe, &mut resolver)
            .expect("audit should succeed")
            .into_iter()
            .collect();

    assert_eq!(
        unreachable, expected_orphan_hashes,
        "only the orphan tree's node hashes should come back as unreachable"
    );
}

#[test]
fn test_reachability_audit_partitions_universe_and_agrees_with_unreachable_node_hashes() {
    use std::collections::BTreeSet;

    // Same two-disjoint-trees fixture as
    // `test_unreachable_node_hashes_reports_only_the_orphan`, reused here to
    // check the fuller `NodeReachabilityAudit` result: `reachable` must be the
    // exact complement of `unreachable` within `universe`, and must agree
    // with what `unreachable_node_hashes` reports for the same inputs (it
    // is defined as a thin wrapper over `node_reachability_audit`).
    let live_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let orphan_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(7))).collect();
    let root_live = build_hamt(b"live_key", live_entries).expect("build live root");
    let root_orphan = build_hamt(b"orphan_key", orphan_entries).expect("build orphan root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("both trees are fully resolved, no lazy children")
    };

    let expected_live_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_live, &mut resolver)
            .expect("live walk should succeed")
            .into_iter()
            .collect();
    let expected_orphan_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_orphan, &mut resolver)
            .expect("orphan walk should succeed")
            .into_iter()
            .collect();

    let universe: Vec<StructuralHash> = expected_live_hashes
        .iter()
        .copied()
        .chain(expected_orphan_hashes.iter().copied())
        .collect();

    let audit =
        crate::hamt::node_reachability_audit([root_live.clone()], universe.clone(), &mut resolver)
            .expect("audit should succeed");

    let reachable_set: BTreeSet<StructuralHash> = audit.reachable.iter().copied().collect();
    assert_eq!(
        reachable_set, expected_live_hashes,
        "reachable side must be exactly the live tree's hashes"
    );
    let unreachable_set: BTreeSet<StructuralHash> = audit.unreachable.iter().copied().collect();
    assert_eq!(
        unreachable_set, expected_orphan_hashes,
        "unreachable side must be exactly the orphan tree's hashes"
    );

    // reachable and unreachable must partition universe: no overlap, and
    // together they account for every hash in it.
    assert!(reachable_set.is_disjoint(&unreachable_set));
    let universe_set: BTreeSet<StructuralHash> = universe.iter().copied().collect();
    let mut recombined: BTreeSet<StructuralHash> = reachable_set.clone();
    recombined.extend(unreachable_set.iter().copied());
    assert_eq!(recombined, universe_set);

    // Must agree with the unreachable_node_hashes convenience wrapper on
    // identical inputs.
    let via_wrapper: BTreeSet<StructuralHash> =
        crate::hamt::audit::unreachable_node_hashes([root_live], universe, &mut resolver)
            .expect("wrapper audit should succeed")
            .into_iter()
            .collect();
    assert_eq!(via_wrapper, unreachable_set);
}

#[test]
fn test_bitmap_reachability_audit_agrees_with_reachability_audit() {
    use std::collections::BTreeSet;

    // Same two-disjoint-trees fixture as
    // `test_reachability_audit_partitions_universe_and_agrees_with_unreachable_node_hashes`.
    // The bitmap variant must partition the same way and, once its dense
    // indexes are mapped back through `IndexedUniverse`, must agree exactly
    // with the `StructuralHash`-keyed `node_reachability_audit` result on the
    // same inputs.
    let live_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(10))).collect();
    let orphan_entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(7))).collect();
    let root_live = build_hamt(b"live_key", live_entries).expect("build live root");
    let root_orphan = build_hamt(b"orphan_key", orphan_entries).expect("build orphan root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("both trees are fully resolved, no lazy children")
    };

    let expected_live_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_live, &mut resolver)
            .expect("live walk should succeed")
            .into_iter()
            .collect();
    let expected_orphan_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_orphan, &mut resolver)
            .expect("orphan walk should succeed")
            .into_iter()
            .collect();

    let universe: Vec<StructuralHash> = expected_live_hashes
        .iter()
        .copied()
        .chain(expected_orphan_hashes.iter().copied())
        .collect();

    let bitmap_audit = crate::hamt::bitmap_node_reachability_audit(
        [root_live.clone()],
        universe.clone(),
        &mut resolver,
    )
    .expect("bitmap audit should succeed");

    // Every index in `universe` must land in exactly one of the two bitmaps.
    assert!((&bitmap_audit.reachable & &bitmap_audit.unreachable).is_empty());
    let mut recombined = bitmap_audit.reachable.clone();
    recombined |= &bitmap_audit.unreachable;
    let all_indices: roaring::RoaringBitmap =
        (0..u32::try_from(universe.len()).expect("small test universe")).collect();
    assert_eq!(recombined, all_indices);

    let reachable_via_bitmap: BTreeSet<StructuralHash> = bitmap_audit
        .reachable
        .iter()
        .map(|idx| {
            bitmap_audit
                .universe
                .hash_at(idx)
                .expect("every set index was assigned by IndexedUniverse::try_build")
        })
        .collect();
    assert_eq!(
        reachable_via_bitmap, expected_live_hashes,
        "bitmap reachable side, resolved back through IndexedUniverse, must match the live tree"
    );

    let unreachable_via_bitmap: BTreeSet<StructuralHash> = bitmap_audit
        .unreachable
        .iter()
        .map(|idx| {
            bitmap_audit
                .universe
                .hash_at(idx)
                .expect("every set index was assigned by IndexedUniverse::try_build")
        })
        .collect();
    assert_eq!(
        unreachable_via_bitmap, expected_orphan_hashes,
        "bitmap unreachable side, resolved back through IndexedUniverse, must match the orphan tree"
    );

    // Must agree with the StructuralHash-keyed node_reachability_audit on the
    // exact same inputs.
    let hash_audit = crate::hamt::node_reachability_audit([root_live], universe, &mut resolver)
        .expect("hash audit should succeed");
    let hash_reachable_set: BTreeSet<StructuralHash> =
        hash_audit.reachable.iter().copied().collect();
    assert_eq!(reachable_via_bitmap, hash_reachable_set);
}

/// Regression for the duplicate-unreachable dedup: `node_reachability_audit`'s
/// `unreachable` field is a `Vec` that must remain a *partition* of `universe`
/// (each hash at most once), matching the dedup the bitmap variant's
/// `IndexedUniverse` provides. When `universe` repeats an unreachable hash,
/// both audit paths must still emit it exactly once.
#[test]
fn test_reachability_audit_dedups_duplicate_unreachable_hashes() {
    use std::collections::BTreeSet;

    let entries: Vec<(u64, u64)> = (0_u64..8).map(|i| (i, i)).collect();
    let root_live = build_hamt(b"live_key", entries).expect("build live root");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("fully resolved tree, no lazy children")
    };

    let live_hashes: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_live, &mut resolver)
            .expect("live walk should succeed")
            .into_iter()
            .collect();

    // An orphan hash that is NOT reachable from `root_live`.
    let orphan: StructuralHash = [0xFF; 16];
    assert!(!live_hashes.contains(&orphan));

    // Duplicate the orphan (and a live hash too) in `universe`.
    let mut universe: Vec<StructuralHash> = Vec::new();
    universe.extend(live_hashes.iter().copied());
    universe.push(orphan);
    universe.push(orphan); // duplicate unreachable
    universe.push(orphan); // triplicate

    let hash_audit =
        crate::hamt::node_reachability_audit([root_live.clone()], universe.clone(), &mut resolver)
            .expect("hash audit should succeed");
    // `unreachable` must be a partition: the orphan appears exactly once,
    // not once per occurrence in `universe`.
    let unreachable_count = hash_audit
        .unreachable
        .iter()
        .filter(|h| **h == orphan)
        .count();
    assert_eq!(
        unreachable_count, 1,
        "duplicate unreachable hash must be emitted exactly once, got {unreachable_count}"
    );

    // And it must agree with the bitmap variant's dedup.
    let bitmap_audit =
        crate::hamt::bitmap_node_reachability_audit([root_live], universe, &mut resolver)
            .expect("bitmap audit should succeed");
    let bitmap_unreachable: BTreeSet<StructuralHash> = bitmap_audit
        .unreachable
        .iter()
        .map(|idx| {
            bitmap_audit
                .universe
                .hash_at(idx)
                .expect("every set index was assigned by IndexedUniverse::try_build")
        })
        .collect();
    let hash_unreachable: BTreeSet<StructuralHash> =
        hash_audit.unreachable.iter().copied().collect();
    assert_eq!(
        hash_unreachable, bitmap_unreachable,
        "hash and bitmap audits must agree on the deduped unreachable set"
    );
    assert_eq!(hash_unreachable, BTreeSet::from([orphan]));
}

#[test]
fn test_indexed_universe_assigns_stable_dense_indices_and_collapses_duplicates() {
    let h1: StructuralHash = [1; 16];
    let h2: StructuralHash = [2; 16];
    let h3: StructuralHash = [3; 16];

    // h1 appears twice; it must collapse onto a single index rather than
    // being assigned two.
    let universe = crate::hamt::IndexedUniverse::try_build([h1, h2, h1, h3])
        .expect("small test universe fits in u32");

    assert_eq!(
        universe.len(),
        3,
        "duplicate hash must not inflate the count"
    );
    assert!(!universe.is_empty());

    let idx1 = universe.index_of(&h1).expect("h1 was indexed");
    let idx2 = universe.index_of(&h2).expect("h2 was indexed");
    let idx3 = universe.index_of(&h3).expect("h3 was indexed");
    // Indexes are assigned in first-seen order (input is [h1, h2, h1, h3]):
    // h1 was first seen at 0, h2 at 1, h3 at 2. The duplicates collapse onto
    // the first-seen index, so these exact expectations are load-bearing for
    // the documented first-seen ordering, not just distinctness.
    assert_eq!(idx1, 0, "h1 is the first hash seen, so it must own index 0");
    assert_eq!(
        idx2, 1,
        "h2 is the second distinct hash seen, so it must own index 1"
    );
    assert_eq!(
        idx3, 2,
        "h3 is the third distinct hash seen, so it must own index 2"
    );
    assert_ne!(idx1, idx2);
    assert_ne!(idx1, idx3);
    assert_ne!(idx2, idx3);

    assert_eq!(universe.hash_at(idx1), Some(h1));
    assert_eq!(universe.hash_at(idx2), Some(h2));
    assert_eq!(universe.hash_at(idx3), Some(h3));

    let missing: StructuralHash = [9; 16];
    assert_eq!(universe.index_of(&missing), None);
    assert_eq!(
        universe.hash_at(u32::try_from(universe.len()).unwrap()),
        None
    );

    assert_eq!(universe.hashes().len(), 3);
}

/// `bucket_index`'s `hash.get(next_index)` is `None` exactly when
/// `byte_index` is the hash's last valid index (15, for the 16-byte
/// `StructuralHash`) -- i.e. at `depth` 24 and 25 (`HAMT_MAX_DEPTH - 2` and
/// `HAMT_MAX_DEPTH - 1`), where the 5-bit slot window runs past the hash's
/// available 128 bits. This is not a missing case to panic or early-return
/// on: it's intentional zero-extension -- the high byte simply isn't OR'd
/// into `word`, so the slot is computed from whatever low bits remain. It's
/// exactly what lets `HAMT_MAX_DEPTH` (`ceil(128 / 5)`) be reachable at all
/// without an out-of-bounds read, since 128 isn't a multiple of 5. Ordinary
/// (non-adversarial) routing hashes essentially never collide 120+ bits deep,
/// so this branch doesn't occur under random test data -- hence why it read
/// as uncovered. This directly exercises it (and depth 23, the last depth
/// where the high byte read still succeeds, as the contrasting case) rather
/// than changing behavior at the boundary.
#[test]
fn test_bucket_index_zero_extends_past_the_last_hash_byte() {
    // All-0xFF except the last two bytes, so a wrong zero-extension (e.g. if
    // it accidentally wrapped and read byte 0 as "next") would show up as a
    // nonzero high contribution instead of silently matching by coincidence.
    let mut hash: StructuralHash = [0xFF_u8; 16];
    hash[14] = 0b1010_1100; // byte_index for depth 23
    hash[15] = 0b0110_0101; // byte_index for depth 24 and 25 (last valid index)

    // depth 23: bit_offset=115, byte_index=14, bit_shift=3. next_index=15 is
    // in bounds, so word = hash[14] | (hash[15] << 8), matching the Some arm.
    let expected_23 = {
        let word = u16::from(hash[14]) | (u16::from(hash[15]) << 8);
        usize::from((word >> 3) & HAMT_BRANCH_MASK)
    };
    assert_eq!(bucket_index(&hash, 23), expected_23);

    // depth 24: bit_offset=120, byte_index=15, bit_shift=0. next_index=16 is
    // out of bounds (hash.get(16) is None) -- word is hash[15] alone, no OR.
    let expected_24 = usize::from(u16::from(hash[15]) & HAMT_BRANCH_MASK);
    assert_eq!(bucket_index(&hash, 24), expected_24);

    // depth 25 (HAMT_MAX_DEPTH - 1, the deepest depth bucket_index is ever
    // called at): bit_offset=125, byte_index=15, bit_shift=5. Same None arm,
    // different shift -- only 3 bits of real hash remain (a StructuralHash
    // has no byte 16 to supply the rest), the top bits of the slot are 0.
    let expected_25 = usize::from((u16::from(hash[15]) >> 5) & HAMT_BRANCH_MASK);
    assert_eq!(bucket_index(&hash, 25), expected_25);
    assert_eq!(
        HAMT_MAX_DEPTH - 1,
        25,
        "assumption behind this test's depths"
    );
}

#[test]
fn test_universe_too_large_from_index_too_large_preserves_distinct_count() {
    // The overflow-counting logic itself ("keep counting distinct items past
    // the bound") belongs to, and is already tested directly on,
    // `DenseIndex::try_build_bounded` (see `dense_index.rs`'s
    // `bounded_reports_true_distinct_count` /
    // `bounded_allows_exactly_bound_distinct_items`). The only thing
    // `IndexedUniverse` adds on top is this error-type conversion, which is
    // what's actually worth a dedicated test.
    use crate::dense_index::IndexTooLarge;
    use crate::hamt::audit::UniverseTooLarge;

    let err: UniverseTooLarge = IndexTooLarge {
        distinct_count: 4_294_967_297,
    }
    .into();
    assert_eq!(err.distinct_count, 4_294_967_297);
}

#[test]
fn test_universe_too_large_display() {
    use alloc::string::ToString;

    let err = crate::hamt::audit::UniverseTooLarge {
        distinct_count: 4_294_967_296,
    };
    assert_eq!(
        err.to_string(),
        "universe has 4294967296 distinct hashes, more than u32::MAX can index"
    );
}

#[test]
fn test_bitmap_audit_error_display_and_conversions() {
    use alloc::string::ToString;

    let universe_err = crate::hamt::audit::UniverseTooLarge { distinct_count: 42 };
    let wrapped: crate::hamt::BitmapAuditError<&str> = universe_err.into();
    assert_eq!(
        wrapped.to_string(),
        "universe has 42 distinct hashes, more than u32::MAX can index"
    );
    assert!(matches!(
        wrapped,
        crate::hamt::BitmapAuditError::Universe(_)
    ));

    let traversal_err: HamtTraversalError<&str> = HamtTraversalError::MaxDepthExceeded { depth: 7 };
    let wrapped: crate::hamt::BitmapAuditError<&str> = traversal_err.into();
    assert_eq!(
        wrapped.to_string(),
        "hamt traversal exceeded max depth at 7"
    );
    assert!(matches!(
        wrapped,
        crate::hamt::BitmapAuditError::Traversal(_)
    ));
}

/// Exercises the `source()` chain on [`BitmapAuditError`] (audit.rs's
/// `std::error::Error` impl): both variants must forward their wrapped error,
/// and each must downcast back to the concrete inner type. This is the one
/// piece of the audit error surface not pinned down by
/// `test_bitmap_audit_error_display_and_conversions`, which only checks
/// Display and `From` conversion.
#[test]
#[cfg(feature = "std")]
fn test_bitmap_audit_error_source_and_downcast() {
    use alloc::string::ToString;
    use std::error::Error as _;

    // Universe variant: `source()` returns the wrapped UniverseTooLarge.
    let universe_err = crate::hamt::audit::UniverseTooLarge {
        distinct_count: 123,
    };
    let wrapped: crate::hamt::BitmapAuditError<std::io::Error> = universe_err.into();
    assert_eq!(
        wrapped.to_string(),
        "universe has 123 distinct hashes, more than u32::MAX can index"
    );
    let source = wrapped
        .source()
        .expect("Universe variant must expose a source");
    let downcast = source
        .downcast_ref::<crate::hamt::audit::UniverseTooLarge>()
        .expect("Universe source must downcast to UniverseTooLarge");
    assert_eq!(downcast.distinct_count, 123);

    // Traversal variant: `source()` returns the wrapped HamtTraversalError,
    // whose own `source()` in turn exposes the inner resolver error.
    let traversal: crate::hamt::HamtTraversalError<std::io::Error> =
        crate::hamt::HamtTraversalError::Resolve(std::io::Error::other("boom"));
    let wrapped: crate::hamt::BitmapAuditError<std::io::Error> = traversal.into();
    assert_eq!(wrapped.to_string(), "hamt traversal resolver failed: boom");
    let source = wrapped
        .source()
        .expect("Traversal variant must expose a source");
    let downcast = source
        .downcast_ref::<crate::hamt::HamtTraversalError<std::io::Error>>()
        .expect("Traversal source must downcast to HamtTraversalError");
    assert!(matches!(
        downcast,
        crate::hamt::HamtTraversalError::Resolve(_)
    ));
    assert_eq!(downcast.to_string(), "hamt traversal resolver failed: boom");
    let inner_source = downcast
        .source()
        .expect("HamtTraversalError::Resolve must expose its inner io::Error");
    let io_downcast = inner_source
        .downcast_ref::<std::io::Error>()
        .expect("inner source must downcast to io::Error");
    assert_eq!(io_downcast.to_string(), "boom");
}

#[test]
fn test_bitmap_reachability_audit_dedupes_shared_hash_missing_from_universe() {
    // `universe` deliberately omits a hash the walk actually reaches, so
    // `bitmap_node_reachability_audit` must fall back to `visited_outside_universe`
    // for it. Two roots share that same out-of-universe subtree, so the
    // resolver must still only be asked to resolve it once across the whole
    // walk — proving the outside-universe fallback set is doing real dedup,
    // not just being populated and ignored.
    let key = b"outside_universe_key";
    let shared_leaf: Arc<HamtNode<u64, u64>> = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });

    // root_a and root_b each keep one leaf of their own (in different slots,
    // so their structural hashes differ) alongside a shared reference to the
    // same lazy child, `shared_leaf` — the case where dedup can't just rely
    // on the root-level check short-circuiting the whole walk.
    let root_a_leaves = [(2_u64, 200_u64)];
    let root_a_children = [NodeRef::<u64, u64>::Lazy(shared_leaf.structural_hash)];
    let root_a: Arc<HamtNode<u64, u64>> = Arc::new(HamtNode {
        datamap: 0b01,
        nodemap: 0b10,
        leaves: root_a_leaves.to_vec(),
        children: vec![NodeRef::Lazy(shared_leaf.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b01,
            0b10,
            &root_a_leaves,
            &root_a_children,
        ),
    });
    let root_b_leaves = [(3_u64, 300_u64)];
    let root_b_children = [NodeRef::<u64, u64>::Lazy(shared_leaf.structural_hash)];
    let root_b: Arc<HamtNode<u64, u64>> = Arc::new(HamtNode {
        datamap: 0b01,
        nodemap: 0b10,
        leaves: root_b_leaves.to_vec(),
        children: vec![NodeRef::Lazy(shared_leaf.structural_hash)],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b01,
            0b10,
            &root_b_leaves,
            &root_b_children,
        ),
    });
    assert_ne!(
        root_a.structural_hash, root_b.structural_hash,
        "root_a and root_b must be distinct roots for this test to be meaningful"
    );

    let resolve_count = std::cell::Cell::new(0_u32);
    let mut resolver = |hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        assert_eq!(*hash, shared_leaf.structural_hash);
        resolve_count.set(resolve_count.get() + 1);
        Ok(shared_leaf.clone())
    };

    // `universe` only covers the two roots' own hashes, not the shared leaf
    // they both lazily reference.
    let universe = vec![root_a.structural_hash, root_b.structural_hash];

    let bitmap_audit = crate::hamt::bitmap_node_reachability_audit(
        [root_a.clone(), root_b.clone()],
        universe,
        &mut resolver,
    )
    .expect("bitmap audit should succeed");

    assert_eq!(
        resolve_count.get(),
        1,
        "shared out-of-universe subtree must be resolved and walked only once"
    );
    // Both roots are in `universe` and reachable from themselves.
    assert_eq!(bitmap_audit.reachable.len(), 2);
    assert_eq!(bitmap_audit.unreachable.len(), 0);
}

#[test]
fn test_unreachable_node_hashes_shares_subtrees_across_roots() {
    let key = b"dummy_server_key";

    // Same shared-child fixture used by
    // `test_walk_reachable_node_hashes_skips_shared_lazy_child_without_resolving`:
    // both roots reference `shared_leaf`, so it must never show up as
    // unreachable, and the resolver must only be asked to resolve it once
    // across the whole multi-root audit.
    let shared_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let unique_leaf_a = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(2_u64, 200_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(2, 200)], &[]),
    });
    // An orphan leaf that neither root references at all.
    let orphan_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(4_u64, 400_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(4, 400)], &[]),
    });

    let shared_lazy = NodeRef::<u64, u64>::Lazy(shared_leaf.structural_hash);
    let unique_a_lazy = NodeRef::<u64, u64>::Lazy(unique_leaf_a.structural_hash);

    let root_a = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 0b11,
        leaves: vec![],
        children: vec![shared_lazy.clone(), unique_a_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            0b11,
            &[],
            &[shared_lazy.clone(), unique_a_lazy.clone()],
        ),
    });
    // root_b only references the shared child, wrapped so its own hash
    // differs from root_a's.
    let root_b = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![shared_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            core::slice::from_ref(&shared_lazy),
        ),
    });

    let mut shared_resolve_count = 0_usize;
    let mut resolver = |hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        if *hash == shared_leaf.structural_hash {
            shared_resolve_count = shared_resolve_count.saturating_add(1);
            Ok(shared_leaf.clone())
        } else if *hash == unique_leaf_a.structural_hash {
            Ok(unique_leaf_a.clone())
        } else {
            panic!("unexpected lazy resolution: {hash:?}")
        }
    };

    let universe = [
        root_a.structural_hash,
        root_b.structural_hash,
        shared_leaf.structural_hash,
        unique_leaf_a.structural_hash,
        orphan_leaf.structural_hash,
    ];

    let unreachable =
        crate::hamt::audit::unreachable_node_hashes([root_a, root_b], universe, &mut resolver)
            .expect("audit should succeed");

    assert_eq!(
        unreachable,
        vec![orphan_leaf.structural_hash],
        "only the never-referenced leaf should be reported unreachable"
    );
    assert_eq!(
        shared_resolve_count, 1,
        "the shared child must be resolved once across both roots, not once per root"
    );
}

#[test]
fn test_unreachable_node_hashes_empty_roots_reports_entire_universe() {
    let root = Arc::new(HamtNode::<u64, u64> {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1, 100)],
        children: vec![],
        structural_hash: [0xEE; 16],
    });
    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("no roots means nothing is ever walked")
    };

    let universe = [root.structural_hash];
    let unreachable = crate::hamt::audit::unreachable_node_hashes([], universe, &mut resolver)
        .expect("audit over an empty root set should still succeed");

    assert_eq!(
        unreachable, universe,
        "with no live roots, every node in the universe is a GC candidate"
    );
}

#[test]
fn test_unreachable_node_hashes_propagates_resolver_error_without_partial_result() {
    let key = b"dummy_server_key";
    let leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(1_u64, 100_u64)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(1, 100)], &[]),
    });
    let leaf_lazy = NodeRef::<u64, u64>::Lazy(leaf.structural_hash);
    let root = Arc::new(HamtNode {
        datamap: 0,
        nodemap: 1,
        leaves: vec![],
        children: vec![leaf_lazy.clone()],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0,
            1,
            &[],
            core::slice::from_ref(&leaf_lazy),
        ),
    });

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, &'static str> {
        Err("resolve failed")
    };

    let universe = [root.structural_hash, leaf.structural_hash];
    let err = crate::hamt::audit::unreachable_node_hashes([root], universe, &mut resolver)
        .expect_err(
        "resolver failure during the mark phase must propagate, not degrade to a partial answer",
    );
    assert_eq!(
        err,
        crate::hamt::HamtTraversalError::Resolve("resolve failed")
    );
}

// --- isolate_delta order-invariance -----------------------------------
//
// `diff_nodes` (src/hamt/delta.rs) derives three disjoint slot classes per
// bitmap (both/only_a/only_b) via bitwise set ops instead of a naive 0..32
// scan. Within a class, bits are still visited in ascending slot order (the
// `bits & bits.wrapping_neg()` / `bits &= bits.wrapping_sub(1)` idiom always
// peels the lowest set bit first), but the *classes* are now emitted one
// after another rather than interleaved by slot number the way a single
// 0..32 pass would. `added`/`removed` are documented as unordered Vecs
// (see delta.rs), but nothing previously pinned that down against a
// consumer that assumes slot-major order. These tests do.
//
// The oracle is built independently of `diff_nodes`'s bitmask shape: full
// leaf enumeration of both roots via `visit_entries` into `BTreeMap`s, then
// a plain key/value set difference. A shape-twin oracle (e.g. a naive
// 0..32 loop) would agree with `diff_nodes` on every bug they share, so it
// is deliberately not used.

/// Sorted `(key, value)` pairs for one side of a delta, using `u32` keys and
/// values so no signed/narrowing conversion is ever required against the
/// `usize`-based bit-scan indices in `diff_nodes` or the `usize`-based
/// `Rng::below`.
type DeltaEntries = alloc::vec::Vec<(u32, u32)>;

/// Enumerates every leaf of `root` into a `BTreeMap`, resolving lazy
/// children with `resolver`. Independent of `diff_nodes`'s traversal shape.
fn oracle_leaves<F>(
    root: &Arc<HamtNode<u32, u32>>,
    resolver: &mut F,
) -> alloc::collections::BTreeMap<u32, u32>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<u32, u32>>, core::convert::Infallible>,
{
    let mut out = alloc::collections::BTreeMap::new();
    root.visit_entries(resolver, &mut |k: &u32, v: &u32| {
        out.insert(*k, *v);
        Ok::<(), core::convert::Infallible>(())
    })
    .expect("infallible resolver cannot fail");
    out
}

/// Computes `added`/`removed` as sorted `(key, value)` vectors from the
/// oracle leaf maps, independent of `isolate_delta`'s emission order.
fn oracle_delta(
    a: &alloc::collections::BTreeMap<u32, u32>,
    b: &alloc::collections::BTreeMap<u32, u32>,
) -> (DeltaEntries, DeltaEntries) {
    let mut removed: DeltaEntries = a
        .iter()
        .filter(|(k, v)| b.get(k) != Some(v))
        .map(|(k, v)| (*k, *v))
        .collect();
    let mut added: DeltaEntries = b
        .iter()
        .filter(|(k, v)| a.get(k) != Some(v))
        .map(|(k, v)| (*k, *v))
        .collect();
    removed.sort_unstable();
    added.sort_unstable();
    (added, removed)
}

/// Asserts `isolate_delta`'s output matches the oracle as sorted multisets,
/// i.e. up to reordering only (no missing/extra/duplicated entries).
fn assert_delta_matches_oracle(root_a: &Arc<HamtNode<u32, u32>>, root_b: &Arc<HamtNode<u32, u32>>) {
    let mut infallible =
        |_hash: &StructuralHash| -> Result<Arc<HamtNode<u32, u32>>, core::convert::Infallible> {
            unreachable!("fixtures below contain no lazy nodes")
        };

    let leaves_a = oracle_leaves(root_a, &mut infallible);
    let leaves_b = oracle_leaves(root_b, &mut infallible);
    let (mut want_added, mut want_removed) = oracle_delta(&leaves_a, &leaves_b);

    let lattice_a = LtHash::default();
    let lattice_b = LtHash([1u16; 1024]);
    let (mut got_added, mut got_removed) =
        isolate_delta(root_a, &lattice_a, root_b, &lattice_b, &mut infallible)
            .expect("isolate_delta should succeed against lazy-free fixtures");
    got_added.sort_unstable();
    got_removed.sort_unstable();
    want_added.sort_unstable();
    want_removed.sort_unstable();

    assert_eq!(got_added, want_added, "added set diverges from oracle");
    assert_eq!(
        got_removed, want_removed,
        "removed set diverges from oracle"
    );
}

/// A single HAMT node deliberately built to straddle all three bitmask
/// classes at once, at both the datamap and the nodemap level, so a
/// slot-major (single 0..32 pass) consumer and a class-major
/// (both-then-only_a-then-only_b) consumer would disagree on order:
///
/// datamap slots: 0 (both, differing value), 1 (`only_a`), 2 (`only_b`)
/// nodemap slots: 3 (both, differing child), 4 (`only_a`), 5 (`only_b`)
#[test]
fn test_isolate_delta_boundary_straddling_class_order_invariant() {
    let key = b"order_invariance_boundary";

    let child_a_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(30_u32, 3000_u32)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(30, 3000)], &[]),
    });
    let child_b_leaf = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(31_u32, 3100_u32)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(31, 3100)], &[]),
    });
    let only_a_child = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(40_u32, 4000_u32)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(40, 4000)], &[]),
    });
    let only_b_child = Arc::new(HamtNode {
        datamap: 1,
        nodemap: 0,
        leaves: vec![(50_u32, 5000_u32)],
        children: vec![],
        structural_hash: HamtNode::compute_structural_hash(key, 1, 0, &[(50, 5000)], &[]),
    });

    // datamap slot 0: differing value (both classes) -> removed(0,100)/added(0,101)
    // datamap slot 1: only in A -> removed(1,200)
    // datamap slot 2: only in B -> added(2,300)
    // nodemap slot 3: differing child (both) -> removed(30,3000)/added(31,3100)
    // nodemap slot 4: only in A -> removed(40,4000)
    // nodemap slot 5: only in B -> added(50,5000)
    let root_a = Arc::new(HamtNode {
        datamap: 0b011,
        nodemap: 0b011 << 3,
        leaves: vec![(0_u32, 100_u32), (1_u32, 200_u32)],
        children: vec![
            NodeRef::Resolved(child_a_leaf.clone()),
            NodeRef::Resolved(only_a_child.clone()),
        ],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b011,
            0b011 << 3,
            &[(0, 100), (1, 200)],
            &[
                NodeRef::Resolved(child_a_leaf.clone()),
                NodeRef::Resolved(only_a_child.clone()),
            ],
        ),
    });
    let root_b = Arc::new(HamtNode {
        datamap: 0b101,
        nodemap: 0b101 << 3,
        leaves: vec![(0_u32, 101_u32), (2_u32, 300_u32)],
        children: vec![
            NodeRef::Resolved(child_b_leaf.clone()),
            NodeRef::Resolved(only_b_child.clone()),
        ],
        structural_hash: HamtNode::compute_structural_hash(
            key,
            0b101,
            0b101 << 3,
            &[(0, 101), (2, 300)],
            &[
                NodeRef::Resolved(child_b_leaf.clone()),
                NodeRef::Resolved(only_b_child.clone()),
            ],
        ),
    });

    assert_delta_matches_oracle(&root_a, &root_b);
}

/// Deterministic xorshift64* PRNG, matching the idiom already used in
/// `tests/differential_harness.rs` (Phase B harness).
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Returns a value in `0..n`, computed entirely in `u64` and narrowed
    /// back to `u32` via a checked conversion. `n` is always a small,
    /// compile-time-bounded constant at call sites in this module (well
    /// under `u32::MAX`), so `self.next() % u64::from(n)` is itself `< n`
    /// and the narrowing conversion below cannot fail; `expect` documents
    /// that invariant instead of silently discarding a truncation via a
    /// cast or a clippy allow.
    fn below(&mut self, n: u32) -> u32 {
        let n64 = u64::from(n);
        let r64 = self
            .next()
            .checked_rem(n64)
            .expect("n64 = u64::from(n: u32) is 0 only if n is 0; no call site passes n = 0");
        u32::try_from(r64).expect("r64 < n64 = u64::from(u32), so it always fits back in u32")
    }
}

#[test]
fn test_isolate_delta_order_invariant_randomized() {
    let mut rng = Rng::new(0xD15C_0DE1);

    // Trials that actually build both roots and run the assertions. Collisions
    // are skipped *without* counting, so a run where many trials collide does
    // not trip the floor below.
    let mut completed = 0_u32;

    for trial in 0..500_u32 {
        let key = format!("order_invariance_random_{trial}");
        let key_bytes = key.as_bytes();

        let n_a = 1 + rng.below(24);
        let n_b = 1 + rng.below(24);
        let key_space = 40_u32;

        let entries_a: DeltaEntries = (0..n_a)
            .map(|_| (rng.below(key_space), rng.below(1000)))
            .collect();
        let entries_b: DeltaEntries = (0..n_b)
            .map(|_| (rng.below(key_space), rng.below(1000)))
            .collect();

        // Later entries for the same key win (build_hamt inserts in order),
        // so dedupe the same way for the oracle input.
        let mut map_a: alloc::collections::BTreeMap<u32, u32> = alloc::collections::BTreeMap::new();
        for (k, v) in entries_a.iter().copied() {
            map_a.insert(k, v);
        }
        let mut map_b: alloc::collections::BTreeMap<u32, u32> = alloc::collections::BTreeMap::new();
        for (k, v) in entries_b.iter().copied() {
            map_b.insert(k, v);
        }

        // Small integer keys can occasionally collide in path-hash space at
        // this key_space size; that's an unrelated property of build_hamt's
        // hashing, not something this order-invariance property test is
        // checking, so skip (not fail) on the rare collision.
        let (Ok(root_a), Ok(root_b)) = (
            build_hamt::<u32, u32, _>(key_bytes, entries_a),
            build_hamt::<u32, u32, _>(key_bytes, entries_b),
        ) else {
            continue;
        };
        completed = completed.saturating_add(1);

        let mut infallible =
            |_hash: &StructuralHash| -> Result<Arc<HamtNode<u32, u32>>, core::convert::Infallible> {
                unreachable!("build_hamt fixtures contain no lazy nodes")
            };

        let (mut want_added, mut want_removed) = oracle_delta(&map_a, &map_b);
        let lattice_a = LtHash::default();
        let lattice_b = LtHash([1u16; 1024]);
        let (mut got_added, mut got_removed) =
            isolate_delta(&root_a, &lattice_a, &root_b, &lattice_b, &mut infallible)
                .expect("isolate_delta should succeed against lazy-free random fixtures");

        got_added.sort_unstable();
        got_removed.sort_unstable();
        want_added.sort_unstable();
        want_removed.sort_unstable();

        assert_eq!(
            got_added, want_added,
            "trial {trial}: added set diverges from oracle"
        );
        assert_eq!(
            got_removed, want_removed,
            "trial {trial}: removed set diverges from oracle"
        );
    }

    // Most trials must actually build both roots and run the assertions
    // (collisions are skipped without counting). Small integer keys collide
    // in path-hash space relatively often at this key_space size, so the
    // floor is deliberately modest -- it only guards against a regression
    // where the assertions effectively never run.
    assert!(
        completed >= 20,
        "too few completed (non-colliding) trials: {completed} < 20"
    );
}

#[test]
fn test_refcount_table_apply_new_increments() {
    use crate::hamt::gc::RefcountTable;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..8).map(|i| (i, i)).collect();
    let root = build_hamt(key, entries).expect("build root");
    let hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root, &mut panic_resolver).expect("walk");

    let mut table = RefcountTable::new();
    assert!(table.is_empty());
    table.apply_new(&hashes);

    for h in &hashes {
        assert_eq!(table.count(h), 1);
    }
    assert_eq!(table.len(), hashes.len());

    // Applying the same new_node_hashes twice (e.g. two roots that happen to
    // share the same subtree) accumulates, not overwrites.
    table.apply_new(&hashes);
    for h in &hashes {
        assert_eq!(table.count(h), 2);
    }
}

#[test]
fn test_refcount_table_apply_superseded_decrements_and_reports_zeroed() {
    use crate::hamt::gc::RefcountTable;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..8).map(|i| (i, i)).collect();
    let root = build_hamt(key, entries).expect("build root");
    let hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root, &mut panic_resolver).expect("walk");

    let mut table = RefcountTable::new();
    table.apply_new(&hashes);

    let zeroed = table
        .apply_superseded(&hashes)
        .expect("decrementing exactly what was incremented must succeed");

    let mut zeroed_sorted = zeroed.clone();
    zeroed_sorted.sort_unstable();
    let mut hashes_sorted = hashes.clone();
    hashes_sorted.sort_unstable();
    assert_eq!(
        zeroed_sorted, hashes_sorted,
        "every hash incremented exactly once must reach zero and be reported"
    );
    assert!(
        table.is_empty(),
        "a fully-decremented table has nothing left tracked"
    );
}

#[test]
fn test_refcount_table_shared_hash_not_zeroed_by_one_of_two_referrers() {
    use crate::hamt::gc::RefcountTable;

    // Two roots sharing a subtree: incrementing for both, then superseding
    // only one, must not zero out the shared hash -- the other root still
    // references it. This is exactly the structural-sharing scenario the
    // module doc's "branching hazard" note warns about; this test covers the
    // case that note says a *linear-chain* diff+retire correctly handles
    // (the shared hash simply never appears in either side's superseded
    // list unless truly unreferenced).
    let key = b"dummy_server_key";
    let shared_entries: Vec<(u64, u64)> = (0_u64..8).map(|i| (i, i)).collect();
    let root_a = build_hamt(key, shared_entries.clone()).expect("build root_a");
    let root_b = build_hamt(key, shared_entries).expect("build root_b (identical content)");
    assert_eq!(
        root_a.structural_hash, root_b.structural_hash,
        "identical content must structurally share, matching this test's premise"
    );

    let hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_a, &mut panic_resolver).expect("walk");

    let mut table = RefcountTable::new();
    // Both roots persisted: each contributes its own increments.
    table.apply_new(&hashes);
    table.apply_new(&hashes);
    for h in &hashes {
        assert_eq!(table.count(h), 2);
    }

    // root_a retired: decrement once. Nothing should zero -- root_b still
    // references every one of these hashes.
    let zeroed = table
        .apply_superseded(&hashes)
        .expect("decrementing one of two referrers must succeed");
    assert!(
        zeroed.is_empty(),
        "shared hashes must not be reported as GC candidates while root_b is still live"
    );
    for h in &hashes {
        assert_eq!(table.count(h), 1);
    }
}

#[test]
fn test_refcount_table_apply_superseded_underflow_is_atomic() {
    use crate::hamt::gc::{RefcountTable, RefcountUnderflow};
    use alloc::string::ToString;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i)).collect();
    let root = build_hamt(key, entries).expect("build root");
    let hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root, &mut panic_resolver).expect("walk");
    assert!(hashes.len() >= 2, "need at least 2 hashes for this test");

    let mut table = RefcountTable::new();
    // Only increment the first hash -- the rest are untracked (count 0).
    table.apply_new(&hashes[..1]);

    let before = table.clone();
    let err = table
        .apply_superseded(&hashes)
        .expect_err("decrementing untracked hashes must fail, not silently no-op");
    assert!(matches!(err, RefcountUnderflow { .. }));
    assert_eq!(
        err.to_string(),
        "refcount underflow: decremented a hash with no tracked positive count \
         (missing or out-of-order apply_new, or a double decrement)"
    );

    // Atomicity: the tracked hash's count must be untouched, even though it
    // appeared earlier in `hashes` than the untracked ones that caused the
    // failure -- apply_superseded validates the whole batch before mutating
    // anything.
    assert_eq!(table.count(&hashes[0]), before.count(&hashes[0]));
    assert_eq!(table.len(), before.len());
}

#[test]
fn test_refcount_table_apply_superseded_repeated_hash_in_one_batch() {
    use crate::hamt::gc::RefcountTable;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..4).map(|i| (i, i)).collect();
    let root = build_hamt(key, entries).expect("build root");
    let hash = root.structural_hash;

    let mut table = RefcountTable::new();
    table.apply_new(&[hash, hash, hash]); // count = 3

    // A batch that repeats the same hash twice should decrement it by 2, not
    // treat repeats as redundant.
    let zeroed = table
        .apply_superseded(&[hash, hash])
        .expect("2 decrements against a count of 3 must succeed");
    assert!(
        zeroed.is_empty(),
        "count should be 1, not zero, after this batch"
    );
    assert_eq!(table.count(&hash), 1);

    let zeroed = table
        .apply_superseded(&[hash])
        .expect("final decrement must succeed");
    assert_eq!(zeroed, vec![hash]);
    assert_eq!(table.count(&hash), 0);
}

#[test]
fn test_refcount_table_bootstrap_seeds_counts_per_occurrence() {
    use crate::hamt::gc::RefcountTable;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..4).map(|i| (i, i)).collect();
    let root = build_hamt(key, entries).expect("build root");
    let hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root, &mut panic_resolver).expect("walk");

    let mut table = RefcountTable::new();
    // Bootstrapping from 3 roots that all reference the same tree (as a
    // real caller would by walking each currently-live root and chaining
    // the results) must count each hash 3 times, not once.
    table.bootstrap(hashes.iter().copied());
    table.bootstrap(hashes.iter().copied());
    table.bootstrap(hashes.iter().copied());

    for h in &hashes {
        assert_eq!(table.count(h), 3);
    }
}

/// End-to-end: drive a real `RefcountTable` from a real
/// [`diff_node_hashes`] output across an actual HAMT mutation, and confirm
/// the result agrees with an independent full reachability walk -- the same
/// property [`assert_diff_is_gc_safe`] checks for `diff_node_hashes` itself,
/// now checked through the incremental table a caller would actually use.
#[test]
fn test_refcount_table_end_to_end_with_diff_node_hashes_matches_reachability() {
    use crate::hamt::gc::RefcountTable;
    use std::collections::BTreeSet;

    let key = b"dummy_server_key";
    let entries: Vec<(u64, u64)> = (0_u64..64).map(|i| (i, i.wrapping_mul(7))).collect();
    let root_a = build_hamt(key, entries).expect("build root_a");

    let mut resolver = |_hash: &StructuralHash| -> Result<Arc<HamtNode<u64, u64>>, ()> {
        unreachable!("fully resolved tree, no lazy children")
    };

    let (root_b, _displaced) =
        insert(&root_a, key, 1000_u64, 9999_u64, &mut resolver).expect("insert should succeed");

    let delta = crate::hamt::diff_node_hashes(&root_a, &root_b, &mut resolver)
        .expect("diff should succeed");

    // Bootstrap as if root_a already existed in the store.
    let root_a_hashes: Vec<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_a, &mut resolver).expect("walk root_a");
    let mut table = RefcountTable::new();
    table.bootstrap(root_a_hashes.iter().copied());

    // New root persisted: increment immediately (per the timing contract).
    table.apply_new(&delta.new_node_hashes);

    // Old root retired later, and root_b is its one and only live successor
    // here (a strict linear chain -- exactly the case the module doc allows
    // apply_superseded to be the sole decrement source for).
    let zeroed = table
        .apply_superseded(&delta.superseded_node_hashes)
        .expect("superseding root_a's own spine, which bootstrap seeded, must succeed");

    // Cross-check against an independent full walk: everything the table
    // reports as zeroed must be unreachable from root_b, and everything
    // still tracked with a nonzero count must be reachable from root_b.
    let reachable_b: BTreeSet<StructuralHash> =
        crate::hamt::reachable_node_hashes(&root_b, &mut resolver)
            .expect("walk root_b")
            .into_iter()
            .collect();

    for hash in &zeroed {
        assert!(
            !reachable_b.contains(hash),
            "a hash the table reports as GC-safe must not be reachable from the live root"
        );
    }
    for hash in &root_a_hashes {
        if reachable_b.contains(hash) {
            assert!(
                table.count(hash) > 0,
                "a hash still reachable from root_b must still have a positive tracked count"
            );
        }
    }
}

#[derive(Default)]
struct FakeNodeStore {
    storage: std::collections::HashMap<StructuralHash, Vec<u8>>,
    resolutions: std::cell::Cell<usize>,
}

impl FakeNodeStore {
    fn new() -> Self {
        Self::default()
    }

    fn store_tree<K: HamtCodec + Clone, V: HamtCodec + Clone>(
        &mut self,
        node: &Arc<HamtNode<K, V>>,
    ) {
        let bytes = PersistedInternalNode::from(node.as_ref()).encode_v1();
        self.storage.insert(node.structural_hash, bytes);
        for child in &node.children {
            if let NodeRef::Resolved(child_node) = child {
                self.store_tree(child_node);
            }
        }
    }

    fn resolver<K, V>(
        &self,
    ) -> impl FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, &'static str> + '_
    where
        K: HamtCodec,
        V: HamtCodec,
    {
        |hash| {
            self.resolutions
                .set(self.resolutions.get().saturating_add(1));
            let bytes = self.storage.get(hash).ok_or("node missing in fake store")?;
            let persisted = PersistedInternalNode::<K, V>::decode_v1(bytes)?;
            HamtNode::try_from(persisted)
                .map(Arc::new)
                .map_err(|_| "failed to convert persisted node")
        }
    }
}

#[test]
fn test_persist_mutation_rebuild_equivalence() {
    let key = b"prop_test_server_key";
    let mut state: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    for i in 0..50 {
        state.insert(i, u64::from(i) * 10);
    }

    let mut current_root = build_hamt(key, state.clone()).expect("build initial hamt");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    // Perform sequence of 100 pseudo-random mutations (inserts, updates, deletes)
    let mut rng_state: u64 = 0xdead_beef;
    let mut next_rnd = || -> u64 {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        rng_state
    };

    for _ in 0..100 {
        let op = next_rnd() % 3;
        let k = (next_rnd() % 100) as u32;
        let v = next_rnd() % 1000;

        let opt_val = if op == 0 {
            // Remove
            state.remove(&k);
            None
        } else {
            // Insert / Update
            state.insert(k, v);
            Some(v)
        };

        let (new_root, _, created) =
            persist_mutation(&current_root, key, k, opt_val, &mut no_resolver)
                .expect("persist_mutation must succeed");

        // Rebuild from scratch and assert identical structural hash
        let rebuilt_root = build_hamt(key, state.clone()).expect("rebuild hamt");
        assert_eq!(
            new_root.structural_hash, rebuilt_root.structural_hash,
            "incremental persist_mutation root must match from-scratch rebuild exactly"
        );

        if new_root.structural_hash == current_root.structural_hash {
            assert!(
                created.is_empty(),
                "noop mutation must produce zero created nodes"
            );
        } else {
            assert!(
                !created.is_empty(),
                "real state change must produce at least one created node"
            );
        }

        current_root = new_root;
    }
}

#[test]
fn test_lazy_resolver_mutation_and_resolution_bounds() {
    let key = b"lazy_resolver_test_key";
    let entries: Vec<(u32, u64)> = (0_u32..60_u32).map(|i| (i, u64::from(i) * 100)).collect();
    let resident_root = build_hamt(key, entries).expect("build tree");

    let mut store = FakeNodeStore::new();
    store.store_tree(&resident_root);

    // Decode root node directly from store so all its children are NodeRef::Lazy
    let root_bytes = store
        .storage
        .get(&resident_root.structural_hash)
        .expect("root in store");
    let persisted_root =
        PersistedInternalNode::<u32, u64>::decode_v1(root_bytes).expect("decode root");
    let lazy_root = Arc::new(HamtNode::try_from(persisted_root).expect("lazy root"));

    let mut resident_resolver =
        |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, &'static str> {
            panic!("unexpected resolution on resident root")
        };

    // Mutate multiple keys to test both root leaves and child subtrees.
    let mut exercised_lazy_child = false;
    for target_key in [5_u32, 25_u32, 45_u32, 999_u32] {
        let new_val = Some(u64::from(target_key) * 999);

        let (res_new_root, res_disp, res_created) = persist_mutation(
            &resident_root,
            key,
            target_key,
            new_val,
            &mut resident_resolver,
        )
        .expect("resident persist_mutation succeeds");

        store.resolutions.set(0);
        let mut lazy_res = store.resolver();
        let (lazy_new_root, lazy_disp, lazy_created) =
            persist_mutation(&lazy_root, key, target_key, new_val, &mut lazy_res)
                .expect("lazy persist_mutation succeeds");

        // Invariant assertions
        assert_eq!(res_new_root.structural_hash, lazy_new_root.structural_hash);
        assert_eq!(res_disp, lazy_disp);
        assert_eq!(res_created.len(), lazy_created.len());

        let res_hashes: std::collections::BTreeSet<StructuralHash> =
            res_created.iter().map(|(h, _)| *h).collect();
        let lazy_hashes: std::collections::BTreeSet<StructuralHash> =
            lazy_created.iter().map(|(h, _)| *h).collect();
        assert_eq!(
            res_hashes, lazy_hashes,
            "created node sets must be identical"
        );

        // Resolver invocations must be bounded by trie depth (proves zero double resolution)
        assert!(
            store.resolutions.get() <= HAMT_MAX_DEPTH,
            "resolutions ({}) must be bounded by HAMT_MAX_DEPTH ({})",
            store.resolutions.get(),
            HAMT_MAX_DEPTH
        );
        exercised_lazy_child |= store.resolutions.get() > 0;
    }
    assert!(
        exercised_lazy_child,
        "fixture must exercise at least one lazy child resolution"
    );
}

#[test]
fn test_persist_chain_coverage() {
    let key = b"prop_chain_coverage_key";
    let prev_root =
        build_hamt(key, (0_u32..20_u32).map(|i| (i, u64::from(i) * 100))).expect("build root");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    let prev_reachable: std::collections::BTreeSet<StructuralHash> =
        reachable_node_hashes(&prev_root, &mut no_resolver)
            .expect("reachable prev")
            .into_iter()
            .collect();

    let mutations = vec![
        (5_u32, Some(555_u64)),
        (100_u32, Some(1000_u64)),
        (2_u32, None),
        (101_u32, Some(1010_u64)),
        (102_u32, Some(1020_u64)),
        (100_u32, None),
        (5_u32, Some(500_u64)), // revert to original value
    ];

    let steps = persist_chain(&prev_root, key, mutations, &mut no_resolver)
        .expect("persist_chain must succeed");

    assert_eq!(steps.len(), 7);

    let mut cumulative_created = prev_reachable;
    for (i, step) in steps.iter().enumerate() {
        for (hash, bytes) in &step.created {
            assert_eq!(
                *hash,
                PersistedInternalNode::<u32, u64>::decode_v1(bytes)
                    .expect("valid decode")
                    .structural_hash
            );
            cumulative_created.insert(*hash);
        }

        // Chain coverage invariant: every node reachable from root_i must be present
        // in cumulative_created (union of created_j for j<=i and reachable(prev_root))
        let root_i_reachable =
            reachable_node_hashes(&step.root, &mut no_resolver).expect("reachable step");
        for hash in &root_i_reachable {
            assert!(
                cumulative_created.contains(hash),
                "step {i}: node {hash:?} reachable from root_{i} was not created in any prior step"
            );
        }
    }
}

#[test]
fn test_persist_chain_refcount_closure_with_retirement() {
    let key = b"prop_refcount_closure_key";
    let prev_root =
        build_hamt(key, (0_u32..10_u32).map(|i| (i, u64::from(i)))).expect("build root");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    let mutations = vec![
        (1_u32, Some(100_u64)),
        (2_u32, Some(200_u64)),
        (3_u32, Some(300_u64)),
        (1_u32, Some(1_u64)), // revert
        (4_u32, None),
    ];

    let steps = persist_chain(&prev_root, key, mutations, &mut no_resolver).expect("persist_chain");

    let mut table = RefcountTable::new();

    // Initial root refcounts
    table.bootstrap(reachable_node_hashes(&prev_root, &mut no_resolver).expect("reachable"));

    // Apply per-step increments
    let mut all_created_hashes = Vec::new();
    for step in &steps {
        let step_hashes: Vec<StructuralHash> = step.created.iter().map(|(h, _)| *h).collect();
        table.apply_new(&step_hashes);
        all_created_hashes.extend(step_hashes);
    }

    let all_roots: Vec<Arc<HamtNode<u32, u64>>> = std::iter::once(prev_root.clone())
        .chain(steps.iter().map(|s| s.root.clone()))
        .collect();

    // Linearly retire root 0 (superseded by 1) and root 1 (superseded by 2)
    let delta_1 = diff_node_hashes(&all_roots[0], &all_roots[1], &mut no_resolver).expect("diff 1");
    table
        .apply_superseded(&delta_1.superseded_node_hashes)
        .expect("apply superseded 1");

    let delta_2 = diff_node_hashes(&all_roots[1], &all_roots[2], &mut no_resolver).expect("diff 2");
    table
        .apply_superseded(&delta_2.superseded_node_hashes)
        .expect("apply superseded 2");

    // Surviving roots: [2, 3, 4, 5]
    let surviving_roots = vec![
        all_roots[2].clone(),
        all_roots[3].clone(),
        all_roots[4].clone(),
        all_roots[5].clone(),
    ];

    let universe: Vec<StructuralHash> = reachable_node_hashes(&prev_root, &mut no_resolver)
        .expect("reachable")
        .into_iter()
        .chain(all_created_hashes)
        .collect();

    let audit =
        crate::hamt::audit::node_reachability_audit(surviving_roots, universe, &mut no_resolver)
            .expect("audit");

    // Invariant 1: Every node reachable from surviving roots MUST have positive count
    for hash in &audit.reachable {
        assert!(
            table.count(hash) > 0,
            "node {hash:?} reachable from surviving roots must have positive count"
        );
    }

    // Invariant 2: Any hash that reached count 0 MUST NOT be reachable from surviving roots
    for hash in &audit.unreachable {
        if table.count(hash) == 0 {
            assert!(
                !audit.reachable.contains(hash),
                "zeroed node {hash:?} must be unreachable from surviving roots"
            );
        }
    }
}

#[test]
fn test_persist_chain_overwrite_then_revert() {
    let key = b"overwrite_revert_key";
    let root_0 = build_hamt(key, vec![(1_u32, 100_u64)]).expect("root 0");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    let mutations = vec![
        (1_u32, Some(200_u64)), // Step 1: overwrite
        (1_u32, Some(100_u64)), // Step 2: revert to original
    ];

    let steps = persist_chain(&root_0, key, mutations, &mut no_resolver).expect("chain");
    assert_eq!(steps.len(), 2);

    assert_eq!(steps[0].displaced, Some(100_u64));
    assert_ne!(steps[0].root_hash, root_0.structural_hash);
    assert!(!steps[0].created.is_empty());

    assert_eq!(steps[1].displaced, Some(200_u64));
    // Step 2 restored state to exact root_0
    assert_eq!(steps[1].root_hash, root_0.structural_hash);
    assert_eq!(
        steps[1].root.structural_hash, root_0.structural_hash,
        "reverting value must produce identical structural hash"
    );
}

#[test]
fn test_hamt_order_independence() {
    let key = b"order_independence_key";
    let entries_a: Vec<(u32, u64)> = (0_u32..40_u32).map(|i| (i, u64::from(i) * 3)).collect();

    // Deterministically permute entries
    let mut entries_b = entries_a.clone();
    entries_b.reverse();
    entries_b.swap(5, 20);
    entries_b.swap(10, 35);

    let root_a = build_hamt(key, entries_a).expect("build a");
    let root_b = build_hamt(key, entries_b).expect("build b");

    assert_eq!(
        root_a.structural_hash, root_b.structural_hash,
        "HAMT structural hash must be strictly independent of insertion order"
    );
}

#[test]
fn test_hamt_deep_split_mutation() {
    let key = b"deep_split_key";
    let mut root = build_hamt(key, vec![(1_u32, 100_u64)]).expect("root");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    // Insert 100 entries to force multi-level trie branching at depth >= 2
    for i in 2..=100_u32 {
        let (new_root, _, created) =
            persist_mutation(&root, key, i, Some(u64::from(i) * 10), &mut no_resolver)
                .expect("persist mutation");
        assert!(!created.is_empty());
        root = new_root;
    }

    assert!(
        root.nodemap.count_ones() > 0,
        "root must have child branches"
    );
}

#[test]
fn test_descend_level_batched_exact_lookup() {
    fn store_nodes(
        node: &Arc<HamtNode<u32, u64>>,
        storage: &mut std::collections::HashMap<StructuralHash, Vec<u8>>,
    ) {
        let bytes = PersistedInternalNode::from(node.as_ref()).encode_v1();
        storage.insert(node.structural_hash, bytes);
        for child in &node.children {
            if let NodeRef::Resolved(child_node) = child {
                store_nodes(child_node, storage);
            }
        }
    }

    let key = b"descend_level_key";
    let entries: Vec<(u32, u64)> = (0_u32..50_u32).map(|i| (i, u64::from(i) * 7)).collect();
    let root = build_hamt(key, entries.clone()).expect("build");

    let mut no_resolver = |_h: &StructuralHash| -> Result<Arc<HamtNode<u32, u64>>, ()> {
        panic!("unexpected lazy resolution in memory test")
    };

    // Collect all internal nodes encoded
    let _all_hashes = reachable_node_hashes(&root, &mut no_resolver).expect("reachable");
    let mut storage: std::collections::HashMap<StructuralHash, Vec<u8>> =
        std::collections::HashMap::new();

    store_nodes(&root, &mut storage);

    // Prepare requested keys: 50 present keys + 20 absent keys
    let mut requested_hashes = Vec::new();
    for i in 0..70 {
        requested_hashes.push(crate::hamt::key_path_hash(key, &i));
    }

    let mut found_map: std::collections::HashMap<KeyPathHash, u64> =
        std::collections::HashMap::new();
    let mut absent_set: std::collections::HashSet<KeyPathHash> = std::collections::HashSet::new();

    // Start level-synchronous descent from root
    let mut frontier: Vec<(StructuralHash, usize, Vec<KeyPathHash>)> =
        vec![(root.structural_hash, 0, requested_hashes)];

    while !frontier.is_empty() {
        let mut nodes_batch: Vec<(StructuralHash, &[u8], usize, &[KeyPathHash])> = Vec::new();
        let mut borrowed_node_bytes: Vec<&[u8]> = Vec::new();

        for (node_hash, _, _) in &frontier {
            let node_bytes = storage.get(node_hash).expect("node exists in storage");
            borrowed_node_bytes.push(node_bytes.as_slice());
        }

        for (i, (node_hash, depth, keys)) in frontier.iter().enumerate() {
            nodes_batch.push((*node_hash, borrowed_node_bytes[i], *depth, keys.as_slice()));
        }

        let result: DescendResult<u64> =
            descend_level::<u32, u64, _>(&nodes_batch, |k| crate::hamt::key_path_hash(key, k))
                .expect("descend_level succeeds");

        for (h, v) in result.found {
            found_map.insert(h, v);
        }
        for h in result.absent {
            absent_set.insert(h);
        }

        frontier = result
            .pending
            .into_iter()
            .map(|(child_hash, keys)| (child_hash, frontier[0].1 + 1, keys))
            .collect();
    }

    // Verify results
    assert_eq!(found_map.len(), 50, "all 50 present keys must be found");
    for (k, v) in &entries {
        let h = crate::hamt::key_path_hash(key, k);
        assert_eq!(found_map.get(&h), Some(v));
    }

    assert_eq!(
        absent_set.len(),
        20,
        "all 20 absent keys must be proven absent"
    );
    for k in 50..70 {
        let h = crate::hamt::key_path_hash(key, &k);
        assert!(absent_set.contains(&h));
    }
}

#[test]
fn test_descend_level_rejects_corruption() {
    let key = b"corrupt_test_key";
    let req_hash = crate::hamt::key_path_hash(key, &42_u32);

    // 1. Truncated buffer: returns Decode error
    let truncated_buf = vec![0x01, 0x00];
    let res = descend_level::<u32, u64, _>(&[([0; 16], &truncated_buf, 0, &[req_hash])], |k| {
        crate::hamt::key_path_hash(key, k)
    });
    assert!(matches!(res, Err(DescendError::Decode(_))));

    // 2. Overlapping datamap & nodemap: returns Decode error
    let mut corrupt_header = vec![0x01]; // v1
    corrupt_header.extend_from_slice(&1_u32.to_le_bytes()); // datamap bit 0
    corrupt_header.extend_from_slice(&1_u32.to_le_bytes()); // nodemap bit 0 (overlap!)
    corrupt_header.extend_from_slice(&[0u8; 16]); // structural hash
    corrupt_header.extend_from_slice(&1_u32.to_le_bytes()); // leaves count 1
    corrupt_header.extend_from_slice(&1_u32.to_le_bytes()); // child count 1
    corrupt_header.extend_from_slice(&42_u32.to_le_bytes()); // leaf key
    corrupt_header.extend_from_slice(&100_u64.to_le_bytes()); // leaf val
    corrupt_header.extend_from_slice(&[0u8; 16]); // child hash
    let res2 = descend_level::<u32, u64, _>(&[([0; 16], &corrupt_header, 0, &[req_hash])], |k| {
        crate::hamt::key_path_hash(key, k)
    });
    assert!(matches!(res2, Err(DescendError::Decode(_))));

    // 3. A valid node returned for the wrong requested hash is corruption.
    let root = build_hamt(key, vec![(42_u32, 100_u64)]).expect("build root");
    let node_bytes = PersistedInternalNode::from(root.as_ref()).encode_v1();
    let wrong_hash = [0xff; 16];
    let res3 = descend_level::<u32, u64, _>(&[(wrong_hash, &node_bytes, 0, &[req_hash])], |k| {
        crate::hamt::key_path_hash(key, k)
    });
    assert!(matches!(res3, Err(DescendError::CorruptNode(_))));
}
