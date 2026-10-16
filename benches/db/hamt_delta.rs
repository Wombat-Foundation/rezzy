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
/// copy and its resolved descendants in `store`. Hashes already present in
/// `store` are skipped along with their descendants; lazy children are not loaded.
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

/// Copies `node` with lazy child references, preserving its leaves and hash.
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
/// Zero keeps only `node` resident; existing lazy references stay lazy.
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

/// Returns the longest resolved path's node count, including `node` itself.
/// Lazy children are ignored, so a node with no resolved children has depth 1.
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

/// Returns a root after `edits` mutations, alternating overwrites of keys from
/// `entries` with generated new keys, starting with an overwrite. Odd counts
/// therefore include one extra overwrite. `variant` varies the selected keys
/// and generated names; `base` is left unchanged, and zero edits returns it.
///
/// # Panics
/// Panics if `edits` is nonzero and `entries` is empty, if an edit requires
/// resolving a lazy child, or if HAMT insertion fails.
fn mutate(base: &Node, entries: &[(Key, Value)], edits: usize, variant: usize) -> Node {
    let mut root = Arc::clone(base);
    for i in 0..edits {
        let (k, v) = if i % 2 == 0 {
            (
                entries[(i * 7919 + variant * 104_729) % entries.len()]
                    .0
                    .clone(),
                format!("$edited{variant}-{i}:example.org"),
            )
        } else {
            (
                format!("room_member|@delta{variant}-{i}:example.org"),
                format!("$new{variant}-{i}:example.org"),
            )
        };
        let mut r = unreachable_resolver();
        root = hamt::insert(&root, STRUCTURAL_KEY, k, v, &mut r)
            .expect("insert should not collide")
            .0;
    }
    root
}

/// Times `reps` diffs from `a` to `b`, resolving lazy nodes from `store`.
/// Prints average nanoseconds per diff and the final diff's fetch count and
/// combined added/removed leaf count under `label`.
///
/// # Panics
/// Panics if `reps` is zero, a needed hash is missing from `store`, or the diff
/// exceeds the HAMT traversal depth limit.
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

/// Reports fully resident and RAM-resolved diff timings for an `n`-entry base
/// with `delta` mutations, varying the number of cached child layers.
///
/// # Panics
/// Panics if HAMT construction, mutation, or differencing fails.
fn bench(n: usize, delta: usize) {
    let entries = make_string_entries(n, 0x5EED_0000 + n as u64);
    let base = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
        .expect("build should not collide");
    let next = mutate(&base, &entries, delta, 0);
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

/// Disk-backed cold reads (Linux only: needs `O_DIRECT`).
///
/// Nodes live in 4 KiB-or-larger aligned slots at pseudo-random positions
/// inside a `HAMT_DELTA_SPAN_MIB`-sized file (default 1024), so reads pay
/// realistic seeks instead of landing in one short-stroked region. The file
/// goes in `HAMT_DELTA_DIR` (default `<manifest>/target`; it must be on a
/// filesystem that supports `O_DIRECT`, so not tmpfs) under a unique name
/// created with `create_new`, which refuses to follow a pre-existing path.
#[cfg(target_os = "linux")]
mod disk {
    use super::{cache_layers, hamt, mutate, tree_depth, Key, Node, Store, Value, STRUCTURAL_KEY};
    use crate::common::{make_string_entries, to_persisted, Xorshift128};
    use rezzy::hamt::codec::PersistedInternalNode;
    use rezzy::hamt::hash::StructuralHash;
    use std::alloc::{alloc, dealloc, Layout};
    use std::collections::{HashMap, HashSet};
    use std::fs::{File, OpenOptions};
    use std::io::{self, Write};
    use std::os::unix::fs::{FileExt, OpenOptionsExt};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// Independent samples per config, each diffing a different edit set so
    /// the touched nodes are not already in the drive's own cache.
    const SAMPLES: usize = 5;
    /// Direct-I/O alignments to try, smallest first.
    const ALIGNS: [usize; 4] = [4096, 8192, 16384, 65536];

    struct AlignedBuf(*mut u8, Layout);
    impl AlignedBuf {
        /// Allocates `len` zeroed bytes with alignment `align`; `len` must be nonzero.
        ///
        /// # Panics
        /// Panics if the allocation layout is invalid or allocation fails.
        fn new(len: usize, align: usize) -> Self {
            let layout = Layout::from_size_align(len, align).unwrap();
            // SAFETY: non-zero size; zeroed so reads never see uninit memory.
            let ptr = unsafe { alloc(layout) };
            assert!(!ptr.is_null());
            unsafe { ptr.write_bytes(0, len) };
            Self(ptr, layout)
        }
        /// Borrows the entire allocation as a mutable byte slice.
        fn as_mut(&mut self) -> &mut [u8] {
            // SAFETY: `ptr` is a live allocation of `layout.size()` bytes.
            unsafe { std::slice::from_raw_parts_mut(self.0, self.1.size()) }
        }
    }
    impl Drop for AlignedBuf {
        /// Releases the aligned allocation.
        fn drop(&mut self) {
            // SAFETY: allocated with this layout in `new`.
            unsafe { dealloc(self.0, self.1) };
        }
    }

    struct DiskStore {
        path: PathBuf,
        file: File,
        slot: usize,
        index: HashMap<StructuralHash, (u64, usize)>,
    }

    /// Returns `HAMT_DELTA_DIR`, or `<manifest>/target` when it is unset.
    /// Does not create the directory.
    fn scratch_dir() -> PathBuf {
        std::env::var_os("HAMT_DELTA_DIR").map_or_else(
            || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"),
            PathBuf::from,
        )
    }

    /// Returns the file span in bytes from `HAMT_DELTA_SPAN_MIB` (in MiB).
    /// An unset or unparseable value defaults to 1024 MiB.
    fn span_bytes() -> u64 {
        std::env::var("HAMT_DELTA_SPAN_MIB")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(1024)
            << 20
    }

    /// Opens an existing node file for reads with `O_DIRECT`.
    ///
    /// # Errors
    /// Propagates file-open errors, including unsupported direct I/O.
    fn open_direct(path: &PathBuf) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECT)
            .open(path)
    }

    /// Smallest alignment for which an `O_DIRECT` read of that size at offset 0
    /// into a buffer of that alignment succeeds.
    /// Tries only `ALIGNS` and returns `None` if every probe read fails.
    fn probe_align(file: &File) -> Option<usize> {
        ALIGNS.into_iter().find(|&a| {
            let mut buf = AlignedBuf::new(a, a);
            file.read_exact_at(buf.as_mut(), 0).is_ok()
        })
    }

    impl DiskStore {
        /// Persists `mem` in a unique file under the scratch directory, scattering
        /// nodes across the configured span in aligned slots for direct reads.
        /// Creates the directory as needed and writes the full span before nodes.
        ///
        /// # Errors
        /// Propagates directory, file creation, cloning, writing, syncing, and
        /// direct-open errors. Returns an error if all alignment probes fail or
        /// the configured span cannot hold the encoded nodes.
        ///
        /// # Panics
        /// Panics if a node cannot be encoded or an aligned buffer cannot be allocated.
        fn build(mem: &Store) -> io::Result<Self> {
            let dir = scratch_dir();
            std::fs::create_dir_all(&dir)?;
            let path = dir.join(format!(
                "hamt_delta_nodes-{}-{}.bin",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ));
            let span = span_bytes();
            // `create_new` fails if the path exists (including as a symlink).
            let mut w = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&path)?;
            // From here on `store`'s Drop removes exactly this file.
            let mut store = Self {
                path,
                file: w.try_clone()?,
                slot: 0,
                index: HashMap::new(),
            };
            // Fill the span so blocks are really allocated across it.
            let zeros = vec![0u8; 1 << 20];
            for _ in 0..(span >> 20) {
                w.write_all(&zeros)?;
            }
            w.sync_all()?;

            let direct = open_direct(&store.path)?;
            let align = probe_align(&direct).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Unsupported,
                    "O_DIRECT reads not supported here",
                )
            })?;
            let encoded: Vec<_> = mem
                .iter()
                .map(|(h, n)| (*h, to_persisted(n).encode_v1()))
                .collect();
            let max_len = encoded.iter().map(|(_, b)| b.len()).max().unwrap_or(0);
            let slot = max_len.div_ceil(align).max(1) * align;
            let slots = span / slot as u64;
            if (encoded.len() as u64) > slots {
                return Err(io::Error::other("span too small for node count"));
            }

            let mut rng = Xorshift128::new(0xD15C);
            let mut used = HashSet::new();
            for (hash, bytes) in &encoded {
                let pos = loop {
                    let c = rng.next_u64() % slots;
                    if used.insert(c) {
                        break c * slot as u64;
                    }
                };
                w.write_all_at(bytes, pos)?;
                store.index.insert(*hash, (pos, bytes.len()));
            }
            w.sync_all()?;
            drop(w);
            store.file = direct;
            store.slot = slot;
            Ok(store)
        }

        /// Reads and verifies the node at `hash`, returning it with lazy children.
        /// `buf` must have this store's slot size and alignment; its contents are overwritten.
        ///
        /// # Errors
        /// Returns `Err(())` for an unknown hash, a read or decode failure, or a
        /// failed structural-hash verification, discarding the underlying error.
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
        /// Attempts to remove this store's node file, ignoring removal errors.
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Reports direct-I/O diff timings for an `n`-entry base with `delta`
    /// mutations per sample, varying cached child layers. Prints the median,
    /// minimum, and maximum milliseconds across five edit sets; fetch and delta
    /// leaf counts come from the median sample.
    ///
    /// Store setup errors print a skipped result and return.
    ///
    /// # Panics
    /// Panics if HAMT construction or mutation fails, a buffer cannot be allocated,
    /// or a diff fails, including node read, decode, or verification failures.
    pub fn bench(n: usize, delta: usize) {
        let entries = make_string_entries(n, 0x5EED_0000 + n as u64);
        let base = hamt::build_hamt::<Key, Value, _>(STRUCTURAL_KEY, entries.iter().cloned())
            .expect("build");
        let nexts: Vec<Node> = (0..SAMPLES)
            .map(|v| mutate(&base, &entries, delta, v))
            .collect();
        let depth = nexts
            .iter()
            .map(tree_depth)
            .chain([tree_depth(&base)])
            .max()
            .unwrap_or(0);
        let mut mem = Store::new();
        super::store_all(&base, &mut mem);
        for next in &nexts {
            super::store_all(next, &mut mem);
        }
        let store = match DiskStore::build(&mem) {
            Ok(s) => s,
            Err(e) => {
                println!("hamt delta on disk (n={n}, edits={delta}): skipped ({e})");
                return;
            }
        };
        println!(
            "hamt delta on disk (n={n}, edits={delta}, depth={depth}, {} nodes, {} B slots, median of {SAMPLES}):",
            store.index.len(),
            store.slot
        );
        let mut buf = AlignedBuf::new(store.slot, store.slot);
        for layers in 0..depth {
            let a = cache_layers(&base, layers);
            let mut samples: Vec<(Duration, u64, usize)> = Vec::with_capacity(SAMPLES);
            for next in &nexts {
                let b = cache_layers(next, layers);
                let mut fetches = 0u64;
                let start = Instant::now();
                let mut r = |h: &StructuralHash| -> Result<Node, ()> {
                    fetches += 1;
                    store.fetch(&mut buf, h)
                };
                let (ad, rm) = hamt::delta::diff_hamt_nodes(&a, &b, &mut r).expect("diff");
                samples.push((start.elapsed(), fetches, ad.len() + rm.len()));
            }
            samples.sort_by_key(|s| s.0);
            let (med, fetches, delta_len) = samples[SAMPLES / 2];
            println!(
                "  disk, {layers} cached layers (n={n}, d={delta}): {:.3} ms/op ({fetches} fetches, {:.2} ms/fetch, {delta_len} delta leaves; min {:.3}, max {:.3} ms)",
                med.as_secs_f64() * 1e3,
                med.as_secs_f64() * 1e3 / fetches.max(1) as f64,
                samples[0].0.as_secs_f64() * 1e3,
                samples[SAMPLES - 1].0.as_secs_f64() * 1e3,
            );
        }
    }
}

/// Runs the HAMT delta benchmark matrix for resident trees and a RAM resolver,
/// plus direct disk reads on Linux. Prints results to standard output.
/// Disk setup errors skip the affected configuration; other platforms skip disk runs.
///
/// # Panics
/// Panics if HAMT construction, mutation, or differencing fails, including disk
/// fetch failures after successful setup, or if an aligned allocation fails.
pub fn run() {
    for &n in &[1024usize, 16384, 131_072] {
        for &delta in &[1usize, 10, 100] {
            bench(n, delta);
        }
    }
    #[cfg(target_os = "linux")]
    for &n in &[16384usize, 131_072] {
        for &delta in &[1usize, 10, 100] {
            disk::bench(n, delta);
        }
    }
    #[cfg(not(target_os = "linux"))]
    println!("hamt delta on disk: skipped (needs Linux O_DIRECT)");
}
