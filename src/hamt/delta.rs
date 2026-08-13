use std::{hash::Hash, sync::Arc, vec::Vec};

use crate::state::LtHash;

use super::{HamtNode, NodeRef, StructuralHash};

pub type Delta<K, V> = Vec<(K, V)>;
pub type DeltaResult<K, V, E> = Result<(Delta<K, V>, Delta<K, V>), E>;

/// Isolates the delta (added/removed items) between two HAMT tries in O(|Delta|
/// * log32 N) time. Uses the `LtHash` lattice to quickly short-circuit if the
///   tries are convergently identical.
///
/// # Errors
/// Returns the error from the `resolver` closure if it fails to resolve a lazy node.
pub fn isolate_delta<K, V, F, E>(
    root_a: &Arc<HamtNode<K, V>>,
    lattice_a: &LtHash,
    root_b: &Arc<HamtNode<K, V>>,
    lattice_b: &LtHash,
    resolver: &mut F,
) -> DeltaResult<K, V, E>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    // Short-circuit only when both the lattice and the root structural hashes
    // match. A lattice collision alone must not suppress a real structural
    // diff.
    if lattice_a == lattice_b && root_a.structural_hash == root_b.structural_hash {
        return Ok((Vec::new(), Vec::new()));
    }

    let mut added = Vec::new();
    let mut removed = Vec::new();

    // Begin recursive diffing
    diff_nodes(root_a, root_b, &mut added, &mut removed, resolver)?;

    Ok((added, removed))
}

fn diff_nodes<K, V, F, E>(
    node_a: &Arc<HamtNode<K, V>>,
    node_b: &Arc<HamtNode<K, V>>,
    added: &mut Vec<(K, V)>,
    removed: &mut Vec<(K, V)>,
    resolver: &mut F,
) -> Result<(), E>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    // Pointer equality check (fastest path for structurally shared nodes)
    if Arc::ptr_eq(node_a, node_b) {
        return Ok(());
    }

    // Structural hash check (fast path across process/storage boundaries)
    if node_a.structural_hash == node_b.structural_hash {
        return Ok(());
    }

    // Traverse datamaps
    let d_a = node_a.datamap;
    let d_b = node_b.datamap;

    let mut idx_a = 0;
    let mut idx_b = 0;

    for i in 0..32 {
        let bit = 1 << i;
        let in_a = (d_a & bit) != 0;
        let in_b = (d_b & bit) != 0;

        match (in_a, in_b) {
            (true, true) => {
                let (k_a, v_a) = &node_a.leaves[idx_a];
                let (k_b, v_b) = &node_b.leaves[idx_b];
                if k_a != k_b || v_a != v_b {
                    removed.push((k_a.clone(), v_a.clone()));
                    added.push((k_b.clone(), v_b.clone()));
                }
                idx_a = idx_a.wrapping_add(1);
                idx_b = idx_b.wrapping_add(1);
            }
            (true, false) => {
                let (k_a, v_a) = &node_a.leaves[idx_a];
                removed.push((k_a.clone(), v_a.clone()));
                idx_a = idx_a.wrapping_add(1);
            }
            (false, true) => {
                let (k_b, v_b) = &node_b.leaves[idx_b];
                added.push((k_b.clone(), v_b.clone()));
                idx_b = idx_b.wrapping_add(1);
            }
            (false, false) => {}
        }
    }

    // Traverse nodemaps
    let n_a = node_a.nodemap;
    let n_b = node_b.nodemap;

    let mut cidx_a = 0;
    let mut cidx_b = 0;

    for i in 0..32 {
        let bit = 1 << i;
        let in_a = (n_a & bit) != 0;
        let in_b = (n_b & bit) != 0;

        match (in_a, in_b) {
            (true, true) => {
                let child_a = &node_a.children[cidx_a];
                let child_b = &node_b.children[cidx_b];

                if child_a.structural_hash() != child_b.structural_hash() {
                    let res_a = resolve_node(child_a, resolver)?;
                    let res_b = resolve_node(child_b, resolver)?;
                    diff_nodes(&res_a, &res_b, added, removed, resolver)?;
                }

                cidx_a = cidx_a.wrapping_add(1);
                cidx_b = cidx_b.wrapping_add(1);
            }
            (true, false) => {
                let child_a = &node_a.children[cidx_a];
                let res_a = resolve_node(child_a, resolver)?;
                collect_all_leaves(&res_a, removed, resolver)?;
                cidx_a = cidx_a.wrapping_add(1);
            }
            (false, true) => {
                let child_b = &node_b.children[cidx_b];
                let res_b = resolve_node(child_b, resolver)?;
                collect_all_leaves(&res_b, added, resolver)?;
                cidx_b = cidx_b.wrapping_add(1);
            }
            (false, false) => {}
        }
    }

    Ok(())
}

fn resolve_node<K, V, F, E>(
    node_ref: &NodeRef<K, V>,
    resolver: &mut F,
) -> Result<Arc<HamtNode<K, V>>, E>
where
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    match node_ref {
        NodeRef::Resolved(arc) => Ok(arc.clone()),
        NodeRef::Lazy(hash) => resolver(hash),
    }
}

fn collect_all_leaves<K, V, F, E>(
    node: &Arc<HamtNode<K, V>>,
    collection: &mut Vec<(K, V)>,
    resolver: &mut F,
) -> Result<(), E>
where
    K: Hash + Clone + Eq,
    V: Hash + Clone + Eq,
    F: FnMut(&StructuralHash) -> Result<Arc<HamtNode<K, V>>, E>,
{
    for (k, v) in &node.leaves {
        collection.push((k.clone(), v.clone()));
    }
    for child in &node.children {
        let resolved = resolve_node(child, resolver)?;
        collect_all_leaves(&resolved, collection, resolver)?;
    }
    Ok(())
}
