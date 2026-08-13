use super::*;
use crate::hamt::codec::PersistedInternalNode;
use crate::hamt::delta::isolate_delta;
use crate::hamt::{build_hamt, build_hamt_root_handle, HamtBuildError};
use crate::state::LtHash;
use alloc::vec;
use core::hash::{Hash, Hasher};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VariableBytes(&'static [u8]);

impl Hash for VariableBytes {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(self.0);
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
fn test_persisted_internal_node_round_trip() {
    let node = PersistedInternalNode {
        datamap: 0b11,
        nodemap: 0b1,
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
        datamap: 0b1,
        nodemap: 0b1,
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
fn test_hamt_search_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child_hash = leaf_hash_for_key(key, query);
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

#[test]
fn test_hamt_visit_entries_resolves_lazy_child() {
    let key = b"dummy_server_key";
    let query = find_key_with_path_slots(key, 3, 7);
    let child_hash = leaf_hash_for_key(key, query);
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
