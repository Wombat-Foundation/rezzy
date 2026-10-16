//! HAMT delta resolution (`diff_hamt_nodes`) with fully in-memory trees and
//! with cold trees whose nodes below a given depth must come from a resolver.
//!
//! Two flavors of "cold" are reported:
//! - `ram-store`: the resolver is a zero-latency in-memory map, so this only
//!   measures resolver-call overhead, NOT storage cost.
//! - `disk`: nodes are encoded into a file and every fetch is an `O_DIRECT`
//!   `pread` + decode, so the page cache cannot serve it. Reflects whatever
//!   device holds the repo's `target/` directory.
//!
//! "cache layers L" = the number of internal-node layers kept resident from
//! the root: L=0 means only the two roots are held and every child is a
//! `NodeRef::Lazy` fetch; L=1 keeps the root's children resident, etc. The
//! Each fetch count is printed alongside the time.
//!
//! Run with: `cargo bench --bench rezzy -- hamt_delta`
#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::items_after_statements,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use rezzy::hamt::delta::diff_hamt_nodes;
use rezzy::hamt::hash::StructuralHash;
use rezzy::hamt::{self, HamtNode, NodeRef};

use crate::common::{make_string_entries, unreachable_resolver};

type Key = String;
type Value = String;
type Node = Arc<HamtNode<Key, Value>>;
type Store = HashMap<StructuralHash, Node>;

const STRUCTURAL_KEY: &[u8] = b"bench-hamt-delta";

/// Copies `node` with every child replaced by `Lazy(hash)` and records the
/// copy (and, recursively, all descendants) in `store`.
fn store_all(node: &Node, store: &mut Store) {
    if store.contains_key(&node.structural_hash) {
        return;
    }
    for child in &node.children {
        if let NodeRef::Resolved(c) = child {
            store_all(c, store);
        }
    }
    store.insert(node.structural_hash, Arc::new(lazy_copy(node)));
}

fn lazy_copy(node: &Node) -> HamtNode<Key, Value> {
    HamtNode {
        datamap: node.datamap,
        nodemap: node.nodemap,
        leaves: node.leaves.clone(),
        children: node
            .children
            .iter()
            .map(|c| NodeRef::Lazy(c.structural_hash()))
            .collect(),
        structural_hash: node.structural_hash,
    }
}

/// Rebuilds `node` keeping `layers` levels of children resident and turning
/// everything deeper into `Lazy` refs.
fn cache_layers(node: &Node, layers: usize) -> Node {
    if layers == 0 {
        return Arc::new(lazy_copy(node));
    }
    let children = node
        .children
        .iter()
        .map(|c| match c {
            NodeRef::Resolved(c) => NodeRef::Resolved(cache_layers(c, layers - 1)),
            lazy @ NodeRef::Lazy(_) => lazy.clone(),
        })
        .collect();
    Arc::new(HamtNode {
        datamap: node.datamap,
        nodemap: node.nodemap,
        leaves: node.leaves.clone(),
        children,
        structural_hash: node.structural_hash,
    })
}

fn tree_depth(node: &Node) -> usize {
    1 + node
        .children
        .iter()
        .filter_map(|c| match c {
            NodeRef::Resolved(c) => Some(tree_depth(c)),
            NodeRef::Lazy(_) => None,
        })
        .max()
        .unwrap_or(0)
}

/// Applies `edits` mutations (half overwrites of existing keys, half new keys).
fn mutate(base: &Node, entries: &[(Key, Value)], edits: usize) -> Node {
    let mut root = Arc::clone(base);
    for i in 0..edits {
        let (k, v) = if i % 2 == 0 {
            (
                entries[(i * 7919) % entries.len()].0.clone(),
                format!("$edited{i}:example.org"),
            )
        } else {
            (
                format!("room_member|@delta{i}:example.org"),
                format!("$new{i}:example.org"),
            )
        };
        let mut r = unreachable_resolver();
        root = hamt::insert(&root, STRUCTURAL_KEY, k, v, &mut r)
            .expect("insert should not collide")
            .0;
    }
    root
}

fn run_one(label: &str, a: &Node, b: &Node, store: &Store, reps: u32) {
    let mut fetches = 0u64;
    let mut delta_len = 0usize;
    let start = Instant::now();
    for _ in 0..reps {
        fetches = 0;
        let mut resolver = |h: &StructuralHash| -> Result<Node, ()> {
            fetches += 1;
            Ok(Arc::clone(store.get(h).ok_or(())?))
        };
        let (added, removed) = diff_hamt_nodes(a, b, &mut resolver).expect("diff");
        delta_len = added.len() + removed.len();
        black_box((&added, &removed));
    }
    let per = start.elapsed() / reps;
    println!(
        "  {label}: {:.1} ns/op ({fetches} fetches, {delta_len} delta leaves)",
        per.as_nanos() as f64
    );
}

fn bench(n: usize, delta: usize) {
    let entries = make_string_entries(n, 0x5EED_0000 + n as u64);
    let base = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");
    let next = mutate(&base, &entries, delta);
    let depth = tree_depth(&base).max(tree_depth(&next));
    println!("hamt delta (n={n}, edits={delta}, depth={depth}):");

    let reps = if n >= 65536 { 2000 } else { 5000 };
    run_one(
        &format!("in-memory (n={n}, d={delta})"),
        &base,
        &next,
        &Store::new(),
        reps,
    );

    let mut store = Store::new();
    store_all(&base, &mut store);
    store_all(&next, &mut store);
    for layers in 0..depth {
        let (a, b) = (cache_layers(&base, layers), cache_layers(&next, layers));
        run_one(
            &format!("ram-store, {layers} cached layers (n={n}, d={delta})"),
            &a,
            &b,
            &store,
            reps,
        );
    }
}

/// Node file layout: 4 KiB-aligned slots at pseudo-random positions inside a
/// `SPAN`-byte file, so reads pay realistic seeks instead of landing in one
/// short-stroked region.
mod disk {
    use super::{cache_layers, hamt, mutate, tree_depth, Key, Node, Store, Value, STRUCTURAL_KEY};
    use crate::common::{make_string_entries, to_persisted, Xorshift128};
    use rezzy::hamt::codec::PersistedInternalNode;
    use rezzy::hamt::hash::StructuralHash;
    use std::alloc::{alloc, dealloc, Layout};
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Instant;

    const SLOT: u64 = 4096;
    const SPAN: u64 = 1 << 30;
    #[cfg(target_arch = "x86_64")]
    const O_DIRECT: i32 = 0o40000;
    #[cfg(target_arch = "aarch64")]
    const O_DIRECT: i32 = 0o200000;

    struct AlignedBuf(*mut u8, Layout);
    impl AlignedBuf {
        fn new(len: usize) -> Self {
            let layout = Layout::from_size_align(len, SLOT as usize).unwrap();
            // SAFETY: non-zero size; zeroed so reads never see uninit memory.
            let ptr = unsafe { alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { ptr.write_bytes(0, len) };
            Self(ptr, layout)
        }
        fn as_mut(&mut self) -> &mut [u8] {
            unsafe { std::slice::from_raw_parts_mut(self.0, self.1.size()) }
        }
    }
    impl Drop for AlignedBuf {
        fn drop(&mut self) {
            unsafe { dealloc(self.0, self.1) };
        }
    }

    struct DiskStore {
        path: PathBuf,
        file: File,
        index: HashMap<StructuralHash, (u64, usize)>,
    }

    impl DiskStore {
        fn build(path: PathBuf, mem: &Store) -> Self {
            let slots = SPAN / SLOT;
            let mut rng = Xorshift128::new(0xD15C);
            let mut used = std::collections::HashSet::new();
            let mut index = HashMap::new();
            let mut w = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("create node file");
            // Fill the span so blocks are really allocated across it.
            let zeros = vec![0u8; 1 << 20];
            for _ in 0..(SPAN >> 20) {
                w.write_all(&zeros).unwrap();
            }
            for (hash, node) in mem {
                let bytes = to_persisted(node).encode_v1();
                assert!(
                    bytes.len() as u64 <= SLOT,
                    "node > one slot: {}",
                    bytes.len()
                );
                let slot = loop {
                    let c = rng.next_u64() % slots;
                    if used.insert(c) {
                        break c;
                    }
                };
                w.write_all_at(&bytes, slot * SLOT).unwrap();
                index.insert(*hash, (slot * SLOT, bytes.len()));
            }
            w.sync_all().unwrap();
            drop(w);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(O_DIRECT)
                .open(&path)
                .expect("open O_DIRECT");
            Self { path, file, index }
        }

        fn fetch(&self, buf: &mut AlignedBuf, hash: &StructuralHash) -> Result<Node, ()> {
            let &(off, len) = self.index.get(hash).ok_or(())?;
            self.file.read_exact_at(buf.as_mut(), off).map_err(|_| ())?;
            let p = PersistedInternalNode::<Key, Value>::decode_v1_unverified(&buf.as_mut()[..len])
                .map_err(|_| ())?;
            Ok(Arc::new(
                p.into_hamt_node_verified(STRUCTURAL_KEY, *hash)
                    .map_err(|_| ())?,
            ))
        }
    }

    impl Drop for DiskStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    pub fn bench(n: usize, delta: usize, reps: u32) {
        let entries = make_string_entries(n, 0x5EED_0000 + n as u64);
        let base = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
            .expect("build");
        let next = mutate(&base, &entries, delta);
        let depth = tree_depth(&base).max(tree_depth(&next));
        let mut mem = Store::new();
        super::store_all(&base, &mut mem);
        super::store_all(&next, &mut mem);
let path = std::env::temp_dir().join(format!(
            "hamt_delta_nodes-{}-{}.bin",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        let store = DiskStore::build(path, &mem);
        println!(
            "hamt delta on disk (n={n}, edits={delta}, depth={depth}, {} nodes):",
            store.index.len()
        );
        let mut buf = AlignedBuf::new(SLOT as usize);
        for layers in 0..depth {
            let (a, b) = (cache_layers(&base, layers), cache_layers(&next, layers));
            let mut fetches = 0u64;
            let mut delta_len = 0;
            let start = Instant::now();
            for _ in 0..reps {
                fetches = 0;
                let mut r = |h: &StructuralHash| -> Result<Node, ()> {
                    fetches += 1;
                    store.fetch(&mut buf, h)
                };
                let (ad, rm) = hamt::delta::diff_hamt_nodes(&a, &b, &mut r).expect("diff");
                delta_len = ad.len() + rm.len();
            }
            let per = start.elapsed() / reps;
            println!(
                "  disk, {layers} cached layers (n={n}, d={delta}): {:.3} ms/op ({fetches} fetches, {:.2} ms/fetch, {delta_len} delta leaves)",
                per.as_secs_f64() * 1e3,
                per.as_secs_f64() * 1e3 / fetches.max(1) as f64
            );
        }
    }
}

pub fn run() {
    for &n in &[1024usize, 16384, 131_072] {
        for &delta in &[1usize, 10, 100] {
            bench(n, delta);
        }
    }
    for &n in &[16384usize, 131_072] {
        for &delta in &[1usize, 10, 100] {
            disk::bench(n, delta, 1);
        }
    }
}
