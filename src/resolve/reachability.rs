//! Pure reachability contract for room DAG accelerators.
//!
//! # Choosing an index
//!
//! [`ForwardReachabilityIndex`] stores a descendant closure. It is excellent
//! for repeated broad queries over a sealed DAG snapshot, but must not be used
//! as a live room index: appending an event changes the descendant closure of
//! every ancestor, so its maintenance cost is unbounded with room history.
//!
//! [`RangePrefilterReachability`] is the default snapshot accelerator. It
//! stores indexed adjacency, conservative descendant ranges, and linear
//! segments; ranges and segments only prune its exact BFS, never decide
//! reachability by themselves.
//!
//! For MSC4297, this module expects a graph snapshot that already contains the
//! direct auth edges needed to form reverse adjacency. It cannot discover a
//! persisted event's children from that event's `auth_events`; a storage-backed
//! caller needs a reverse-edge index, a chain cover, or a loaded query
//! envelope. Use [`RangePrefilterReachability::filter_reachable`] for a sparse
//! candidate set and [`RangePrefilterReachability::forward_reachable_ids`] when
//! every node in the snapshot is a candidate.
//!
//! This module intentionally stays free of storage, threading, and cache
//! policy. It defines only the query result type and the minimal trait that a
//! drop-in accelerator must satisfy.

use crate::basespec::rezzy_types::LeanEvent;
use crate::{DenseIndex, FastMap, HashMap};
use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "roaring")]
use roaring::RoaringBitmap;

/// Tri-state reachability answer.
///
/// `Unknown` is a valid, non-error result. Callers use it to fall back to the
/// always-correct slow path when the accelerator cannot prove `Yes` or `No`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reach {
    Yes,
    No,
    Unknown,
}

impl Reach {
    /// Returns `true` when the answer is definitive.
    #[inline]
    #[must_use]
    pub const fn is_definitive(self) -> bool {
        matches!(self, Self::Yes | Self::No)
    }

    /// Returns `true` when the accelerator proved reachability.
    #[inline]
    #[must_use]
    pub const fn is_yes(self) -> bool {
        matches!(self, Self::Yes)
    }

    /// Returns `true` when the accelerator proved non-reachability.
    #[inline]
    #[must_use]
    pub const fn is_no(self) -> bool {
        matches!(self, Self::No)
    }

    /// Returns `true` when the caller should consult the slow path.
    #[inline]
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// Minimal contract for a reachability accelerator.
///
/// Implementations may use live overlays, sealed segments, bridge sets, or any
/// other indexing strategy. The only requirement is that `Unknown` must be a
/// safe fallback, never a correctness failure.
pub trait Reachability {
    /// Event identifier type used by the accelerator.
    type Id: ?Sized;

    /// Returns whether `from` can reach `to`.
    ///
    /// The contract is intentionally asymmetric:
    /// - `Reach::Yes` and `Reach::No` are hard answers.
    /// - `Reach::Unknown` means "ask the slow path."
    fn reaches(&self, from: &Self::Id, to: &Self::Id) -> Reach;

    /// Batch filter for the common antichain-to-candidate case.
    ///
    /// The default implementation is an optimistic yes-only filter: it linearly
    /// scans the candidates and keeps only the indices for which at least one
    /// seed definitively proves `Reach::Yes`.
    ///
    /// Callers must treat omitted candidates, including `Reach::No` and
    /// `Reach::Unknown` results, as slow-path fallbacks and send them to the
    /// always-correct resolver.
    ///
    /// Override implementations must preserve that yes-only contract.
    #[must_use]
    fn filter_reachable<'a, S, C>(&self, seeds: S, candidates: C) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Self::Id>,
        C: IntoIterator<Item = &'a Self::Id>,
        Self::Id: 'a,
    {
        let seeds: Vec<&'a Self::Id> = seeds.into_iter().collect();
        candidates
            .into_iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                seeds
                    .iter()
                    .copied()
                    .any(|seed| self.reaches(seed, candidate).is_yes())
                    .then_some(idx)
            })
            .collect()
    }
}

/// Forward reachability accelerator over a topologically ordered DAG snapshot.
///
/// The index stores, for each node, the transitive closure of its descendants
/// as a compressed bitmap. This makes repeated "which candidates are
/// forward-reachable from these seeds?" queries fast: seed closures are `ORed`
/// once, then candidate membership is a bitmap lookup.
#[cfg(feature = "roaring")]
#[derive(Debug, Clone)]
pub struct ForwardReachabilityIndex<Id> {
    index: DenseIndex<Id>,
    descendant_bitmaps: Vec<RoaringBitmap>,
    cyclic_nodes: BTreeSet<u32>,
}

#[cfg(feature = "roaring")]
impl<Id> ForwardReachabilityIndex<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
{
    /// Builds the forward reachability index from a DAG snapshot.
    ///
    /// The input graph must be acyclic with edges expressed through
    /// `auth_events`.
    ///
    /// # Panics
    /// Panics if the input graph is internally inconsistent or contains a
    /// cycle that prevents the topological build from completing.
    #[must_use]
    pub fn build<C: Clone, S: core::hash::BuildHasher>(
        graph: &HashMap<Id, LeanEvent<Id, C>, S>,
    ) -> Self {
        let (topo, children, leftover_nodes) = collect_topology(graph);
        let index = DenseIndex::try_build(topo.iter().map(|&id| id.clone()))
            .expect("graph too large for roaring bitmap index");

        let mut children_by_index = vec![Vec::<u32>::new(); topo.len()];
        for (parent_id, child_ids) in children {
            let Some(parent_idx) = index.index_of(parent_id) else {
                continue;
            };
            let parent_slot = &mut children_by_index[parent_idx as usize];
            for child_id in child_ids {
                if let Some(child_idx) = index.index_of(child_id) {
                    parent_slot.push(child_idx);
                }
            }
        }

        let mut descendant_bitmaps = vec![RoaringBitmap::new(); topo.len()];
        for idx in (0..topo.len()).rev() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(u32::try_from(idx).expect("graph too large for roaring bitmap index"));
            for &child_idx in &children_by_index[idx] {
                bitmap |= &descendant_bitmaps[child_idx as usize];
            }
            descendant_bitmaps[idx] = bitmap;
        }

        let cyclic_nodes = leftover_nodes
            .iter()
            .filter_map(|id| index.index_of(*id))
            .collect();

        Self {
            index,
            descendant_bitmaps,
            cyclic_nodes,
        }
    }

    /// Returns the descendants of a seed set as candidate indices.
    ///
    /// Callers must interpret the returned indices relative to the candidate
    /// iteration order they provided.
    #[must_use]
    pub fn filter_reachable<'a, S, C>(&self, seeds: S, candidates: C) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Id>,
        C: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        let mut reachable = RoaringBitmap::new();
        for seed in seeds {
            let Some(idx) = self.index.index_of(seed) else {
                continue;
            };
            reachable.insert(idx);
            reachable |= &self.descendant_bitmaps[idx as usize];
        }
        candidates
            .into_iter()
            .enumerate()
            .filter_map(|(idx, candidate)| {
                self.index
                    .index_of(candidate)
                    .filter(|candidate_idx| reachable.contains(*candidate_idx))
                    .map(|_| idx)
            })
            .collect()
    }
}

/// Low-memory exact reachability accelerator over a topologically ordered DAG snapshot.
///
/// This stores adjacency plus a coarse descendant interval per node, avoiding the
/// quadratic closure footprint of [`ForwardReachabilityIndex`]. Queries stay exact
/// by pruning obviously impossible branches and falling back to bounded BFS over
/// the stored adjacency.
#[derive(Debug, Clone)]
struct Segment {
    tail: u32,
}

/// Coarse build-time summary used to decide whether segment jumps are worth it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentStats {
    node_count: usize,
    segment_count: usize,
    singleton_segment_count: usize,
    long_segment_node_count: usize,
    max_segment_length: usize,
}

impl SegmentStats {
    /// Returns `true` when segment jumps are likely to amortize their setup cost.
    #[must_use]
    pub const fn should_jump(self) -> bool {
        self.max_segment_length >= 4
            && self.long_segment_node_count.saturating_mul(2) >= self.node_count
    }
}

/// How the low-memory reachability accelerator traverses segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentTraversalMode {
    PlainRangePruned,
    SegmentJumps,
}

/// Per-query traversal choice for the low-memory reachability accelerator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraversalMode {
    PlainIndexedBfs,
    RangePruned,
    SegmentJumps,
}

/// Positions a single node occupies in the caller-supplied candidate list.
///
/// Candidate lists are almost always duplicate-free, so the common case
/// (zero or one occurrence) is stored inline and never heap-allocates; only
/// a node that appears more than once in the candidate list falls back to a
/// `Vec`.
#[derive(Debug, Clone, Default)]
enum CandidatePositions {
    #[default]
    None,
    One(usize),
    Many(Vec<usize>),
}

impl CandidatePositions {
    const fn is_empty(&self) -> bool {
        matches!(self, Self::None)
    }

    /// Push a new position.
    fn push(&mut self, position: usize) {
        *self = match core::mem::take(self) {
            Self::None => Self::One(position),
            Self::One(first) => Self::Many(vec![first, position]),
            Self::Many(mut positions) => {
                positions.push(position);
                Self::Many(positions)
            }
        };
    }

    /// Get an iterator over the positions.
    fn iter(&self) -> CandidatePositionsIter<'_> {
        match self {
            Self::None => CandidatePositionsIter::Empty,
            Self::One(position) => CandidatePositionsIter::One(Some(*position)),
            Self::Many(positions) => CandidatePositionsIter::Many(positions.iter()),
        }
    }
}

enum CandidatePositionsIter<'a> {
    Empty,
    One(Option<usize>),
    Many(core::slice::Iter<'a, usize>),
}

impl Iterator for CandidatePositionsIter<'_> {
    type Item = usize;

    /// Get the next position.
    fn next(&mut self) -> Option<usize> {
        match self {
            Self::Empty => None,
            Self::One(position) => position.take(),
            Self::Many(iter) => iter.next().copied(),
        }
    }
}

struct CandidateQuery {
    candidate_count: usize,
    known_candidate_position_count: usize,
    unique_candidate_count: usize,
    /// Indexed directly by node index; `CandidatePositions::None` means "not a candidate".
    candidate_positions: Vec<CandidatePositions>,
    min_candidate_index: Option<u32>,
    max_candidate_index: Option<u32>,
}

impl CandidateQuery {
    /// Get the span of positions.
    fn span(&self, node_count: usize) -> usize {
        self.min_candidate_index
            .zip(self.max_candidate_index)
            .map_or(node_count, |(min, max)| {
                let min = usize::try_from(min).expect("candidate index fits usize");
                let max = usize::try_from(max).expect("candidate index fits usize");
                max.saturating_sub(min).saturating_add(1)
            })
    }

    const fn unique_count(&self) -> usize {
        self.unique_candidate_count
    }

    /// Get the positions at a specific node index.
    fn positions_at(&self, node_idx: u32) -> CandidatePositionsIter<'_> {
        self.candidate_positions
            .get(node_idx as usize)
            .map_or(CandidatePositionsIter::Empty, CandidatePositions::iter)
    }

    /// Builds the sorted set of remaining candidate node indices.
    ///
    /// Only the `RangePruned` and `SegmentJumps` traversal modes need this;
    /// it is deliberately not computed up front so that `PlainIndexedBfs`
    /// queries never pay for it.
    fn remaining_candidate_set(&self) -> BTreeSet<u32> {
        self.candidate_positions
            .iter()
            .enumerate()
            .filter_map(|(idx, positions)| {
                if positions.is_empty() {
                    None
                } else {
                    Some(u32::try_from(idx).expect("node index fits u32"))
                }
            })
            .collect()
    }
}

/// Low-memory reachability accelerator with adaptive per-query traversal.
///
/// Each query picks one of [`TraversalMode::PlainIndexedBfs`],
/// [`TraversalMode::RangePruned`], or [`TraversalMode::SegmentJumps`] based
/// on how selective the candidate set is relative to the graph.
///
/// # Performance envelope: candidate set size relative to graph size
///
/// Every query pays an unconditional `O(|candidates|)` pass to hash each
/// candidate ID and populate a per-node scratch array, *before* a
/// traversal mode is even chosen. When `|C| ≪ |V|` that pass is cheap and
/// the chosen mode prunes aggressively (6x-94x over naive BFS on
/// interleaved/layered topologies in `benches/resolve.rs`). When `|C| ≈
/// |V|`, that upfront pass dominates and a naive BFS-then-filter baseline
/// can win by 2-3x, since it filters a set sized to the *reachable* nodes
/// rather than scratch space sized to the *whole graph*. This is
/// structural, not a bug, and no traversal-mode choice can avoid it since
/// mode selection happens after the pass runs.
///
/// Callers who want "every node reachable from these seeds" rather than
/// "which of these specific candidates are reachable" should use
/// [`RangePrefilterReachability::forward_reachable_ids`] instead of
/// [`RangePrefilterReachability::filter_reachable`] — it skips this pass
/// entirely and enumerates the reachable set directly from the BFS, with
/// cost proportional to the reachable set rather than the whole graph.
/// This matters in practice: the conflicted-subgraph forward pass
/// (`resolve::subgraph`) used to build a full-graph candidate list purely
/// to recover reachable ids, which is exactly the `|C| ≈ |V|` shape above;
/// it now uses `forward_reachable_ids` and pays none of this cost.
#[derive(Debug, Clone)]
pub struct RangePrefilterReachability<Id> {
    index: DenseIndex<Id>,
    children_by_index: Vec<Vec<u32>>,
    descendant_ranges: Vec<(u32, u32)>,
    segments: Vec<Segment>,
    node_segment: Vec<u32>,
    node_segment_offset: Vec<u32>,
    segment_stats: SegmentStats,
    segment_mode: SegmentTraversalMode,
    cyclic_nodes: BTreeSet<u32>,
}

fn collect_topology<Id, C, S>(
    graph: &HashMap<Id, LeanEvent<Id, C>, S>,
) -> (Vec<&Id>, FastMap<&Id, Vec<&Id>>, Vec<&Id>)
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
    C: Clone,
    S: core::hash::BuildHasher,
{
    let mut in_degree: FastMap<&Id, usize> = FastMap::default();
    let mut children: FastMap<&Id, Vec<&Id>> = FastMap::default();

    for (id, ev) in graph {
        in_degree.entry(id).or_insert(0);
        for auth_id in &ev.auth_events {
            if graph.contains_key(auth_id) {
                children.entry(auth_id).or_default().push(id);
                let degree = in_degree.entry(id).or_insert(0);
                *degree = degree.saturating_add(1);
            }
        }
    }

    let mut queue: Vec<&Id> = in_degree
        .iter()
        .filter_map(|(id, &deg)| (deg == 0).then_some(*id))
        .collect();
    queue.sort_unstable();

    let mut topo = Vec::with_capacity(graph.len());
    let mut head = 0_usize;
    while head < queue.len() {
        let id = queue[head];
        head = head.saturating_add(1);
        topo.push(id);
        if let Some(children) = children.get(id) {
            for child in children {
                let degree = in_degree.get_mut(child).unwrap();
                *degree = degree.saturating_sub(1);
                if *degree == 0 {
                    queue.push(child);
                }
            }
        }
    }

    let mut leftover_nodes: Vec<&Id> = in_degree
        .iter()
        .filter_map(|(id, &deg)| (deg != 0).then_some(*id))
        .collect();
    leftover_nodes.sort_unstable();
    topo.extend(leftover_nodes.iter().copied());

    (topo, children, leftover_nodes)
}

fn build_indexed_children<'a, Id: crate::basespec::rezzy_types::EventId + Ord>(
    topo_len: usize,
    children: FastMap<&'a Id, Vec<&'a Id>>,
    index: &DenseIndex<Id>,
) -> (Vec<Vec<u32>>, Vec<usize>) {
    let mut children_by_index = vec![Vec::<u32>::new(); topo_len];
    let mut in_degree_by_index = vec![0_usize; topo_len];
    for (parent_id, child_ids) in children {
        let Some(parent_idx) = index.index_of(parent_id) else {
            continue;
        };
        let parent_slot = &mut children_by_index[parent_idx as usize];
        for child_id in child_ids {
            if let Some(child_idx) = index.index_of(child_id) {
                parent_slot.push(child_idx);
                in_degree_by_index[child_idx as usize] =
                    in_degree_by_index[child_idx as usize].saturating_add(1);
            }
        }
    }
    (children_by_index, in_degree_by_index)
}

/// Build descendant ranges for reachability queries.
fn build_descendant_ranges(children_by_index: &[Vec<u32>]) -> Vec<(u32, u32)> {
    let mut descendant_ranges = vec![(0_u32, 0_u32); children_by_index.len()];
    for idx in (0..children_by_index.len()).rev() {
        let idx_u32 = u32::try_from(idx).expect("graph too large for index space");
        let mut min_idx = idx_u32;
        let mut max_idx = idx_u32;
        for &child_idx in &children_by_index[idx] {
            let (child_min, child_max) = descendant_ranges[child_idx as usize];
            min_idx = min_idx.min(child_min);
            max_idx = max_idx.max(child_max);
        }
        descendant_ranges[idx] = (min_idx, max_idx);
    }
    descendant_ranges
}

/// Build segments for segment jumps.
fn build_segments(
    children_by_index: &[Vec<u32>],
    in_degree_by_index: &[usize],
) -> (Vec<Segment>, Vec<u32>, Vec<u32>, SegmentStats) {
    let mut node_segment = vec![u32::MAX; children_by_index.len()];
    let mut node_segment_offset = vec![0_u32; children_by_index.len()];
    let mut segments = Vec::new();
    let mut singleton_segment_count = 0_usize;
    let mut long_segment_node_count = 0_usize;
    let mut max_segment_length = 0_usize;
    for idx in 0..children_by_index.len() {
        if node_segment[idx] != u32::MAX {
            continue;
        }

        let segment_id = u32::try_from(segments.len()).expect("graph too large for segment index");
        let mut current = idx;
        let mut offset = 0_u32;
        loop {
            node_segment[current] = segment_id;
            node_segment_offset[current] = offset;
            offset = offset.saturating_add(1);

            let children = &children_by_index[current];
            if in_degree_by_index[current] != 1 || children.len() != 1 {
                break;
            }

            let next = children[0] as usize;
            if in_degree_by_index[next] != 1 || node_segment[next] != u32::MAX {
                break;
            }
            current = next;
        }

        let segment_length = usize::try_from(offset).expect("segment length fits usize");
        if segment_length == 1 {
            singleton_segment_count = singleton_segment_count.saturating_add(1);
        }
        if segment_length >= 4 {
            long_segment_node_count = long_segment_node_count.saturating_add(segment_length);
        }
        max_segment_length = max_segment_length.max(segment_length);
        segments.push(Segment {
            tail: u32::try_from(current).expect("graph too large for segment tail"),
        });
    }

    let segment_stats = SegmentStats {
        node_count: children_by_index.len(),
        segment_count: segments.len(),
        singleton_segment_count,
        long_segment_node_count,
        max_segment_length,
    };

    (segments, node_segment, node_segment_offset, segment_stats)
}

impl<Id> RangePrefilterReachability<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
{
    /// Builds the low-memory reachability index from a DAG snapshot.
    ///
    /// The input graph must be acyclic with edges expressed through
    /// `auth_events`.
    ///
    /// # Panics
    /// Panics if the input graph is internally inconsistent or contains a
    /// cycle that prevents the topological build from completing.
    #[must_use]
    pub fn build<C: Clone, S: core::hash::BuildHasher>(
        graph: &HashMap<Id, LeanEvent<Id, C>, S>,
    ) -> Self {
        let (topo, children, leftover_nodes) = collect_topology(graph);
        let index = DenseIndex::try_build(topo.iter().map(|&id| id.clone()))
            .expect("graph too large for index space");
        let (children_by_index, in_degree_by_index) =
            build_indexed_children(topo.len(), children, &index);
        let descendant_ranges = build_descendant_ranges(&children_by_index);
        let (segments, node_segment, node_segment_offset, segment_stats) =
            build_segments(&children_by_index, &in_degree_by_index);
        let segment_mode = if segment_stats.should_jump() {
            SegmentTraversalMode::SegmentJumps
        } else {
            SegmentTraversalMode::PlainRangePruned
        };
        let cyclic_nodes = leftover_nodes
            .iter()
            .filter_map(|id| index.index_of(*id))
            .collect();

        Self {
            index,
            children_by_index,
            descendant_ranges,
            segments,
            node_segment,
            node_segment_offset,
            segment_stats,
            segment_mode,
            cyclic_nodes,
        }
    }

    /// Returns the build-time segment summary used by the adaptive traversal chooser.
    #[must_use]
    pub const fn segment_stats(&self) -> SegmentStats {
        self.segment_stats
    }

    /// Returns the traversal mode selected for this snapshot.
    #[must_use]
    pub const fn segment_mode(&self) -> SegmentTraversalMode {
        self.segment_mode
    }

    /// Select the best traversal mode for the candidates.
    fn select_traversal_mode(&self, candidates: &CandidateQuery) -> TraversalMode {
        if candidates.candidate_count == 0 || candidates.known_candidate_position_count == 0 {
            return TraversalMode::PlainIndexedBfs;
        }
        if !self.cyclic_nodes.is_empty() {
            return TraversalMode::PlainIndexedBfs;
        }

        let node_count = self.children_by_index.len().max(1);
        let span = candidates.span(node_count);
        let narrow_span = span.saturating_mul(4) <= node_count;
        let broad_span = span.saturating_mul(2) > node_count;
        let unique_candidate_count = candidates.unique_count();
        let selective = unique_candidate_count.saturating_mul(50) <= node_count;
        let jump_selective = unique_candidate_count.saturating_mul(20) <= node_count;

        if self.segment_mode == SegmentTraversalMode::SegmentJumps && jump_selective && narrow_span
        {
            TraversalMode::SegmentJumps
        } else if selective && narrow_span && !broad_span {
            TraversalMode::RangePruned
        } else {
            TraversalMode::PlainIndexedBfs
        }
    }

    fn collect_candidates<'a, C>(&self, candidates: C) -> CandidateQuery
    where
        C: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        let mut candidate_positions: Vec<CandidatePositions> =
            vec![CandidatePositions::None; self.children_by_index.len()];
        let mut candidate_count = 0_usize;
        let mut known_candidate_count = 0_usize;
        let mut unique_candidate_count = 0_usize;
        let mut min_candidate_index = None;
        let mut max_candidate_index = None;
        for (idx, candidate) in candidates.into_iter().enumerate() {
            candidate_count = idx.saturating_add(1);
            let Some(candidate_idx) = self.index.index_of(candidate) else {
                continue;
            };
            let positions = &mut candidate_positions[candidate_idx as usize];
            if positions.is_empty() {
                unique_candidate_count = unique_candidate_count.saturating_add(1);
            }
            positions.push(idx);
            known_candidate_count = known_candidate_count.saturating_add(1);
            min_candidate_index =
                Some(min_candidate_index.map_or(candidate_idx, |min: u32| min.min(candidate_idx)));
            max_candidate_index =
                Some(max_candidate_index.map_or(candidate_idx, |max: u32| max.max(candidate_idx)));
        }

        CandidateQuery {
            candidate_count,
            known_candidate_position_count: known_candidate_count,
            unique_candidate_count,
            candidate_positions,
            min_candidate_index,
            max_candidate_index,
        }
    }

    fn seed_queue<'seed, S>(&self, seeds: S, reachable: &mut [bool]) -> VecDeque<u32>
    where
        S: IntoIterator<Item = &'seed Id>,
        Id: 'seed,
    {
        let mut queue = VecDeque::new();
        for seed in seeds {
            let Some(idx) = self.index.index_of(seed) else {
                continue;
            };
            if !reachable[idx as usize] {
                reachable[idx as usize] = true;
                queue.push_back(idx);
            }
        }
        queue
    }

    fn filter_reachable_numeric_bfs_with_candidates<'a, S>(
        &self,
        seeds: S,
        candidates: &CandidateQuery,
    ) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        if candidates.candidate_count == 0 || candidates.known_candidate_position_count == 0 {
            return Vec::new();
        }

        let mut results = vec![false; candidates.candidate_count];
        let mut reachable = vec![false; self.children_by_index.len()];
        let mut queue = self.seed_queue(seeds, &mut reachable);
        let mut remaining_known_candidates = candidates.known_candidate_position_count;

        while let Some(curr) = queue.pop_front() {
            for position in candidates.positions_at(curr) {
                if results[position] {
                    continue;
                }
                results[position] = true;
                remaining_known_candidates = remaining_known_candidates.saturating_sub(1);
            }

            if remaining_known_candidates == 0 {
                break;
            }

            for &child in &self.children_by_index[curr as usize] {
                if reachable[child as usize] {
                    continue;
                }
                reachable[child as usize] = true;
                queue.push_back(child);
            }
        }

        results
            .iter()
            .enumerate()
            .filter_map(|(idx, found)| found.then_some(idx))
            .collect()
    }

    fn filter_reachable_range_pruned_with_candidates<'a, S>(
        &self,
        seeds: S,
        candidates: &CandidateQuery,
    ) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        if candidates.candidate_count == 0 || candidates.known_candidate_position_count == 0 {
            return Vec::new();
        }

        let mut results = vec![false; candidates.candidate_count];
        let mut reachable = vec![false; self.children_by_index.len()];
        let mut queue = self.seed_queue(seeds, &mut reachable);
        let mut remaining_known_candidates = candidates.known_candidate_position_count;
        let mut remaining_candidates = candidates.remaining_candidate_set();
        while let Some(curr) = queue.pop_front() {
            let mut has_position = false;
            for position in candidates.positions_at(curr) {
                has_position = true;
                if results[position] {
                    continue;
                }
                results[position] = true;
                remaining_known_candidates = remaining_known_candidates.saturating_sub(1);
            }
            if has_position {
                remaining_candidates.remove(&curr);
            }

            if remaining_known_candidates == 0 {
                break;
            }

            for &child in &self.children_by_index[curr as usize] {
                if reachable[child as usize] {
                    continue;
                }

                let (min_descendant, max_descendant) = self.descendant_ranges[child as usize];
                if remaining_candidates
                    .range(min_descendant..=max_descendant)
                    .next()
                    .is_none()
                {
                    continue;
                }

                reachable[child as usize] = true;
                queue.push_back(child);
            }
        }

        results
            .iter()
            .enumerate()
            .filter_map(|(idx, found)| found.then_some(idx))
            .collect()
    }

    fn filter_reachable_segment_jumps<'a, S>(
        &self,
        seeds: S,
        candidates: &CandidateQuery,
    ) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        if candidates.candidate_count == 0 || candidates.known_candidate_position_count == 0 {
            return Vec::new();
        }

        let mut reachable = vec![false; self.children_by_index.len()];
        let mut candidate_positions_by_segment: Vec<Vec<(u32, u32, usize)>> =
            vec![Vec::new(); self.segments.len()];
        for (candidate_idx, positions) in candidates.candidate_positions.iter().enumerate() {
            if positions.is_empty() {
                continue;
            }
            let candidate_idx = u32::try_from(candidate_idx).expect("node index fits u32");
            let segment_id = self.node_segment[candidate_idx as usize] as usize;
            let segment_offset = self.node_segment_offset[candidate_idx as usize];
            for position in positions.iter() {
                candidate_positions_by_segment[segment_id].push((
                    segment_offset,
                    candidate_idx,
                    position,
                ));
            }
        }

        for segment_candidates in &mut candidate_positions_by_segment {
            segment_candidates.sort_unstable_by_key(|(offset, _, _)| *offset);
        }

        let mut results = vec![false; candidates.candidate_count];
        let mut queue = self.seed_queue(seeds, &mut reachable);
        let mut remaining_known_candidates = candidates.known_candidate_position_count;
        let mut remaining_candidates = candidates.remaining_candidate_set();
        let mut segment_covered_from = vec![usize::MAX; self.segments.len()];
        let mut segment_expanded = vec![false; self.segments.len()];
        while let Some(curr) = queue.pop_front() {
            let segment_id = self.node_segment[curr as usize] as usize;
            let segment_start = usize::try_from(self.node_segment_offset[curr as usize])
                .expect("segment offset fits usize");
            let previous_start = segment_covered_from[segment_id];
            let effective_start = match previous_start {
                usize::MAX => segment_start,
                covered => covered.min(segment_start),
            };
            if previous_start != usize::MAX && effective_start >= previous_start {
                continue;
            }
            segment_covered_from[segment_id] = effective_start;

            let segment_candidates = &candidate_positions_by_segment[segment_id];
            if !segment_candidates.is_empty() {
                let first = segment_candidates.partition_point(|(offset, _, _)| {
                    usize::try_from(*offset).expect("segment offset fits usize") < effective_start
                });
                for &(_, candidate_idx, position) in &segment_candidates[first..] {
                    if results[position] {
                        continue;
                    }
                    results[position] = true;
                    remaining_known_candidates = remaining_known_candidates.saturating_sub(1);
                    remaining_candidates.remove(&candidate_idx);
                }
            }

            if remaining_known_candidates == 0 {
                break;
            }

            if segment_expanded[segment_id] {
                continue;
            }
            segment_expanded[segment_id] = true;

            let tail_idx = self.segments[segment_id].tail;
            for &child in &self.children_by_index[tail_idx as usize] {
                if reachable[child as usize] {
                    continue;
                }

                let (min_descendant, max_descendant) = self.descendant_ranges[child as usize];
                if remaining_candidates
                    .range(min_descendant..=max_descendant)
                    .next()
                    .is_none()
                {
                    continue;
                }

                reachable[child as usize] = true;
                queue.push_back(child);
            }
        }

        results
            .iter()
            .enumerate()
            .filter_map(|(idx, found)| found.then_some(idx))
            .collect()
    }

    /// Check if a node reaches another by index.
    fn reaches_index(&self, from_idx: u32, to_idx: u32) -> bool {
        if from_idx == to_idx {
            return true;
        }

        let (min_descendant, max_descendant) = self.descendant_ranges[from_idx as usize];
        if to_idx < min_descendant || to_idx > max_descendant {
            return false;
        }

        let mut visited = vec![false; self.children_by_index.len()];
        let mut queue = VecDeque::new();
        visited[from_idx as usize] = true;
        queue.push_back(from_idx);

        while let Some(curr) = queue.pop_front() {
            for &child in &self.children_by_index[curr as usize] {
                if child == to_idx {
                    return true;
                }
                if child > to_idx {
                    continue;
                }
                let (child_min, child_max) = self.descendant_ranges[child as usize];
                if to_idx < child_min || to_idx > child_max {
                    continue;
                }
                if !visited[child as usize] {
                    visited[child as usize] = true;
                    queue.push_back(child);
                }
            }
        }

        false
    }

    /// Returns every node forward-reachable from `seeds` (seeds included).
    ///
    /// Unlike [`RangePrefilterReachability::filter_reachable`], this does
    /// not test membership against a caller-supplied candidate list: it
    /// enumerates the full forward-reachable set directly from the BFS
    /// visitation. This skips the candidate hashing pass and
    /// `CandidateQuery` scratch space used by
    /// [`RangePrefilterReachability::filter_reachable`], which is the main
    /// win when the caller wants "all reachable ids" rather than "which of
    /// these specific candidates are reachable".
    pub fn forward_reachable_ids<'a, 'seed, S>(
        &'a self,
        seeds: S,
    ) -> impl Iterator<Item = &'a Id> + 'a
    where
        S: IntoIterator<Item = &'seed Id>,
        Id: 'seed,
    {
        let mut reachable = vec![false; self.children_by_index.len()];
        let mut queue = self.seed_queue(seeds, &mut reachable);
        let mut visited_indices = Vec::new();
        while let Some(curr) = queue.pop_front() {
            visited_indices.push(curr);
            for &child in &self.children_by_index[curr as usize] {
                if reachable[child as usize] {
                    continue;
                }
                reachable[child as usize] = true;
                queue.push_back(child);
            }
        }
        visited_indices
            .into_iter()
            .map(move |idx| &self.index.items()[idx as usize])
    }

    /// Returns the descendants of a seed set as candidate indices.
    ///
    /// This is exact but uses only adjacency plus lightweight descendant
    /// ranges, so it avoids storing the full transitive closure.
    ///
    /// # Panics
    /// Panics if the graph exceeds the topological index space used by the
    /// internal bounds checks.
    #[must_use]
    pub fn filter_reachable<'a, S, C>(&self, seeds: S, candidates: C) -> Vec<usize>
    where
        S: IntoIterator<Item = &'a Id>,
        C: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        self.filter_reachable_with_mode(seeds, candidates).0
    }

    /// Returns the reachable candidate positions and the traversal mode used.
    ///
    /// The chosen mode is a per-query adaptive decision:
    /// - `PlainIndexedBfs` for broad candidate sets
    /// - `RangePruned` for selective, non-jumpable queries
    /// - `SegmentJumps` for selective queries on compressible segment graphs
    #[must_use]
    pub fn filter_reachable_with_mode<'a, S, C>(
        &self,
        seeds: S,
        candidates: C,
    ) -> (Vec<usize>, TraversalMode)
    where
        S: IntoIterator<Item = &'a Id>,
        C: IntoIterator<Item = &'a Id>,
        Id: 'a,
    {
        let candidates = self.collect_candidates(candidates);
        let mode = self.select_traversal_mode(&candidates);
        let hits = match mode {
            TraversalMode::PlainIndexedBfs => {
                self.filter_reachable_numeric_bfs_with_candidates(seeds, &candidates)
            }
            TraversalMode::RangePruned => {
                self.filter_reachable_range_pruned_with_candidates(seeds, &candidates)
            }
            TraversalMode::SegmentJumps => self.filter_reachable_segment_jumps(seeds, &candidates),
        };
        (hits, mode)
    }
}

impl<Id> Reachability for RangePrefilterReachability<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
{
    type Id = Id;

    fn reaches(&self, from: &Self::Id, to: &Self::Id) -> Reach {
        let Some(from_idx) = self.index.index_of(from) else {
            return Reach::Unknown;
        };
        let Some(to_idx) = self.index.index_of(to) else {
            return Reach::Unknown;
        };
        if self.cyclic_nodes.contains(&from_idx) || self.cyclic_nodes.contains(&to_idx) {
            return Reach::Unknown;
        }
        if self.reaches_index(from_idx, to_idx) {
            Reach::Yes
        } else {
            Reach::No
        }
    }
}

#[cfg(feature = "roaring")]
impl<Id> Reachability for ForwardReachabilityIndex<Id>
where
    Id: crate::basespec::rezzy_types::EventId + Ord,
{
    type Id = Id;

    fn reaches(&self, from: &Self::Id, to: &Self::Id) -> Reach {
        let Some(from_idx) = self.index.index_of(from) else {
            return Reach::Unknown;
        };
        let Some(to_idx) = self.index.index_of(to) else {
            return Reach::Unknown;
        };
        if from_idx == to_idx {
            return Reach::Yes;
        }
        if self.cyclic_nodes.contains(&from_idx) || self.cyclic_nodes.contains(&to_idx) {
            return Reach::Unknown;
        }
        if self.descendant_bitmaps[from_idx as usize].contains(to_idx) {
            Reach::Yes
        } else {
            Reach::No
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::basespec::rezzy_types::LeanEvent;
    use crate::HashMap;
    use alloc::format;
    use alloc::string::String;
    use alloc::vec;

    struct Dummy;

    fn build_chain_graph(node_count: usize) -> HashMap<String, LeanEvent<String>> {
        let mut graph = HashMap::with_capacity(node_count);
        let mut previous = None;
        for idx in 0..node_count {
            let event_id = format!("chain-{idx:04}");
            let auth_events = previous.iter().cloned().collect();
            graph.insert(
                event_id.clone(),
                LeanEvent {
                    event_id: event_id.clone(),
                    auth_events,
                    ..Default::default()
                },
            );
            previous = Some(event_id);
        }
        graph
    }

    fn build_layered_graph(
        node_count: usize,
        layer_width: usize,
    ) -> HashMap<String, LeanEvent<String>> {
        let layer_count = node_count.div_ceil(layer_width);
        let mut graph = HashMap::with_capacity(node_count);
        let mut previous_layer: Vec<String> = Vec::new();
        for layer in 0..layer_count {
            let remaining = node_count.saturating_sub(graph.len());
            let current_width = remaining.min(layer_width);
            let mut current_layer = Vec::with_capacity(current_width);
            for pos in 0..current_width {
                let idx = graph.len();
                let event_id = format!("layer-{layer:04}-{pos:04}");
                let auth_events = if previous_layer.is_empty() {
                    Vec::new()
                } else {
                    let len = previous_layer.len();
                    let first_idx = pos.checked_rem(len).expect("previous_layer is non-empty");
                    let second_idx = pos
                        .checked_add(1)
                        .expect("pos + 1 fits in usize")
                        .checked_rem(len)
                        .expect("previous_layer is non-empty");
                    let first = previous_layer[first_idx].clone();
                    let second = previous_layer[second_idx].clone();
                    if first == second {
                        vec![first]
                    } else {
                        vec![first, second]
                    }
                };
                graph.insert(
                    event_id.clone(),
                    LeanEvent {
                        event_id: event_id.clone(),
                        auth_events,
                        ..Default::default()
                    },
                );
                current_layer.push(event_id);
                debug_assert!(idx < node_count);
            }
            previous_layer = current_layer;
        }
        graph
    }

    fn build_interleaved_chain_graph(
        node_count: usize,
        chain_count: usize,
    ) -> HashMap<String, LeanEvent<String>> {
        let mut graph = HashMap::with_capacity(node_count);
        for idx in 0..node_count {
            let event_id = format!("interleaved-{idx:04}");
            let auth_events = if idx < chain_count {
                Vec::new()
            } else {
                let parent_idx = idx
                    .checked_sub(chain_count)
                    .expect("idx >= chain_count in this branch");
                vec![format!("interleaved-{parent_idx:04}")]
            };
            graph.insert(
                event_id.clone(),
                LeanEvent {
                    event_id: event_id.clone(),
                    auth_events,
                    ..Default::default()
                },
            );
        }
        graph
    }

    fn naive_reachable_positions(
        index: &RangePrefilterReachability<String>,
        seeds: &[String],
        candidates: &[String],
    ) -> Vec<usize> {
        let mut reachable = vec![false; index.children_by_index.len()];
        let mut queue = index.seed_queue(seeds.iter(), &mut reachable);
        while let Some(curr) = queue.pop_front() {
            for &child in &index.children_by_index[curr as usize] {
                if reachable[child as usize] {
                    continue;
                }
                reachable[child as usize] = true;
                queue.push_back(child);
            }
        }

        candidates
            .iter()
            .enumerate()
            .filter_map(|(position, candidate)| {
                index
                    .index
                    .index_of(candidate)
                    .and_then(|idx| reachable[idx as usize].then_some(position))
            })
            .collect()
    }

    fn assert_forced_traversals_match_naive(
        graph: &HashMap<String, LeanEvent<String>>,
        seeds: &[String],
        candidates: &[String],
    ) {
        let index = RangePrefilterReachability::build(graph);
        let query = index.collect_candidates(candidates.iter());
        let plain = index.filter_reachable_numeric_bfs_with_candidates(seeds.iter(), &query);
        let range = index.filter_reachable_range_pruned_with_candidates(seeds.iter(), &query);
        let jumps = index.filter_reachable_segment_jumps(seeds.iter(), &query);
        let naive = naive_reachable_positions(&index, seeds, candidates);

        for result in [&plain, &range, &jumps] {
            assert_eq!(result, &naive);
            assert!(result.windows(2).all(|pair| pair[0] < pair[1]));
        }
    }

    impl Reachability for Dummy {
        type Id = u32;

        fn reaches(&self, from: &Self::Id, to: &Self::Id) -> Reach {
            if from == to {
                Reach::Yes
            } else {
                Reach::Unknown
            }
        }
    }

    #[test]
    fn reach_helpers_reflect_the_variant() {
        assert!(Reach::Yes.is_definitive());
        assert!(Reach::No.is_definitive());
        assert!(!Reach::Unknown.is_definitive());
        assert!(Reach::Yes.is_yes());
        assert!(Reach::No.is_no());
        assert!(Reach::Unknown.is_unknown());
    }

    #[test]
    fn trait_contract_allows_unknown_fallback() {
        let accel = Dummy;
        assert_eq!(accel.reaches(&7, &7), Reach::Yes);
        assert_eq!(accel.reaches(&7, &8), Reach::Unknown);
    }

    #[test]
    fn batch_filter_defaults_to_any_reachable_candidate() {
        let accel = Dummy;
        let seeds = [&1_u32, &3_u32];
        let candidates = [&2_u32, &3_u32, &4_u32];
        assert_eq!(accel.filter_reachable(seeds, candidates), vec![1]);
    }

    #[test]
    fn forward_reachability_index_builds_and_queries_descendants() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        let a = String::from("A");
        let b = String::from("B");
        let c = String::from("C");
        let missing = String::from("missing");
        graph.insert(
            a.clone(),
            LeanEvent {
                event_id: a.clone(),
                auth_events: vec![],
                ..Default::default()
            },
        );
        graph.insert(
            b.clone(),
            LeanEvent {
                event_id: b.clone(),
                auth_events: vec![a.clone()],
                ..Default::default()
            },
        );
        graph.insert(
            c.clone(),
            LeanEvent {
                event_id: c.clone(),
                auth_events: vec![b.clone()],
                ..Default::default()
            },
        );

        let index = ForwardReachabilityIndex::build(&graph);

        assert_eq!(index.reaches(&a, &c), Reach::Yes);
        assert_eq!(index.reaches(&c, &a), Reach::No);
        assert_eq!(index.reaches(&a, &a), Reach::Yes);
        assert_eq!(index.reaches(&a, &missing), Reach::Unknown);

        let seeds = [&a];
        let candidates = [&a, &b, &c];
        assert_eq!(index.filter_reachable(seeds, candidates), vec![0, 1, 2]);
    }

    #[test]
    fn range_prefilter_reachability_matches_exact_descendants() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        let a = String::from("A");
        let b = String::from("B");
        let c = String::from("C");
        let missing = String::from("missing");
        graph.insert(
            a.clone(),
            LeanEvent {
                event_id: a.clone(),
                auth_events: vec![],
                ..Default::default()
            },
        );
        graph.insert(
            b.clone(),
            LeanEvent {
                event_id: b.clone(),
                auth_events: vec![a.clone()],
                ..Default::default()
            },
        );
        graph.insert(
            c.clone(),
            LeanEvent {
                event_id: c.clone(),
                auth_events: vec![b.clone()],
                ..Default::default()
            },
        );

        let index = RangePrefilterReachability::build(&graph);

        assert_eq!(index.reaches(&a, &c), Reach::Yes);
        assert_eq!(index.reaches(&c, &a), Reach::No);
        assert_eq!(index.reaches(&a, &a), Reach::Yes);
        assert_eq!(index.reaches(&a, &missing), Reach::Unknown);

        let seeds = [&a];
        let candidates = [&a, &b, &c];
        assert_eq!(index.filter_reachable(seeds, candidates), vec![0, 1, 2]);
    }

    #[test]
    fn range_prefilter_preserves_unknown_candidate_positions() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        let a = String::from("A");
        let b = String::from("B");
        let missing = String::from("missing");
        graph.insert(
            a.clone(),
            LeanEvent {
                event_id: a.clone(),
                auth_events: vec![],
                ..Default::default()
            },
        );
        graph.insert(
            b.clone(),
            LeanEvent {
                event_id: b.clone(),
                auth_events: vec![a.clone()],
                ..Default::default()
            },
        );

        let index = RangePrefilterReachability::build(&graph);
        let seeds = [&a];
        let candidates = [&a, &missing, &b];
        assert_eq!(index.filter_reachable(seeds, candidates), vec![0, 2]);
    }

    #[test]
    fn range_prefilter_chooses_segment_jumps_for_chain_topology() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        let nodes = ["A", "B", "C", "D", "E"];
        for (idx, node) in nodes.iter().enumerate() {
            let auth_events = if idx == 0 {
                Vec::new()
            } else {
                vec![String::from(nodes[idx - 1])]
            };
            graph.insert(
                String::from(*node),
                LeanEvent {
                    event_id: String::from(*node),
                    auth_events,
                    ..Default::default()
                },
            );
        }

        let index = RangePrefilterReachability::build(&graph);
        assert_eq!(index.segment_mode(), SegmentTraversalMode::SegmentJumps);
        assert!(index.segment_stats().should_jump());
    }

    #[test]
    fn range_prefilter_disables_segment_jumps_for_branchy_topology() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        for node in ["A", "B", "C", "D"] {
            graph.insert(
                String::from(node),
                LeanEvent {
                    event_id: String::from(node),
                    auth_events: match node {
                        "B" | "C" => vec![String::from("A")],
                        "D" => vec![String::from("B"), String::from("C")],
                        _ => Vec::new(),
                    },
                    ..Default::default()
                },
            );
        }

        let index = RangePrefilterReachability::build(&graph);
        assert_eq!(index.segment_mode(), SegmentTraversalMode::PlainRangePruned);
        assert!(!index.segment_stats().should_jump());
    }

    #[test]
    fn range_prefilter_selects_plain_indexed_bfs_for_broad_queries() {
        let graph = build_chain_graph(100);
        let index = RangePrefilterReachability::build(&graph);
        let seeds = [String::from("chain-0000")];
        let candidates = (0..100)
            .map(|idx| format!("chain-{idx:04}"))
            .collect::<Vec<_>>();

        let (_, mode) = index.filter_reachable_with_mode(seeds.iter(), candidates.iter());
        assert_eq!(mode, TraversalMode::PlainIndexedBfs);
    }

    #[test]
    fn range_prefilter_selects_range_pruned_for_selective_layered_queries() {
        let graph = build_layered_graph(101, 10);
        let index = RangePrefilterReachability::build(&graph);
        let seeds = [String::from("layer-0000-0000")];
        let candidates = [
            String::from("layer-0001-0000"),
            String::from("layer-0001-0001"),
        ];

        let (_, mode) = index.filter_reachable_with_mode(seeds.iter(), candidates.iter());
        assert_eq!(mode, TraversalMode::RangePruned);
    }

    #[test]
    fn range_prefilter_selects_segment_jumps_for_selective_chain_queries() {
        let graph = build_chain_graph(100);
        let index = RangePrefilterReachability::build(&graph);
        assert_eq!(index.segment_mode(), SegmentTraversalMode::SegmentJumps);
        let seeds = [String::from("chain-0000")];
        let candidates = [String::from("chain-0048"), String::from("chain-0049")];

        let (_, mode) = index.filter_reachable_with_mode(seeds.iter(), candidates.iter());
        assert_eq!(mode, TraversalMode::SegmentJumps);
    }

    #[test]
    fn forced_traversals_match_naive_bfs_across_topologies() {
        let chain_candidates = vec![
            String::from("chain-0008"),
            String::from("missing-chain"),
            String::from("chain-0010"),
            String::from("chain-0016"),
            String::from("chain-0016"),
            String::from("chain-0032"),
            String::from("chain-0048"),
            String::from("chain-0063"),
        ];
        let chain_graph = build_chain_graph(64);
        let chain_seeds = vec![String::from("chain-0010"), String::from("chain-0030")];
        assert_forced_traversals_match_naive(&chain_graph, &chain_seeds, &chain_candidates);

        let layered_candidates = vec![
            String::from("missing-layer"),
            String::from("layer-0003-0001"),
            String::from("layer-0004-0001"),
            String::from("layer-0006-0002"),
            String::from("layer-0006-0002"),
            String::from("layer-0008-0003"),
            String::from("layer-0010-0000"),
        ];
        let layered_graph = build_layered_graph(96, 6);
        let layered_seeds = vec![
            String::from("layer-0003-0001"),
            String::from("layer-0003-0004"),
        ];
        assert_forced_traversals_match_naive(&layered_graph, &layered_seeds, &layered_candidates);

        let interleaved_candidates = vec![
            String::from("interleaved-0004"),
            String::from("interleaved-0008"),
            String::from("interleaved-0020"),
            String::from("interleaved-0020"),
            String::from("interleaved-0032"),
            String::from("missing-interleaved"),
            String::from("interleaved-0068"),
            String::from("interleaved-0092"),
        ];
        let interleaved_graph = build_interleaved_chain_graph(96, 4);
        let interleaved_seeds = vec![
            String::from("interleaved-0008"),
            String::from("interleaved-0020"),
        ];
        assert_forced_traversals_match_naive(
            &interleaved_graph,
            &interleaved_seeds,
            &interleaved_candidates,
        );
    }

    #[test]
    fn forward_reachability_ids_enumerate_every_reachable_node() {
        let graph = build_chain_graph(4);
        let index = RangePrefilterReachability::build(&graph);
        let seeds = [String::from("chain-0001")];

        let reachable: Vec<_> = index.forward_reachable_ids(seeds.iter()).cloned().collect();
        assert_eq!(
            reachable,
            vec![
                String::from("chain-0001"),
                String::from("chain-0002"),
                String::from("chain-0003"),
            ]
        );
    }

    #[test]
    fn cyclic_graphs_fall_back_to_unknown_reachability() {
        let mut graph: HashMap<String, LeanEvent<String>> = HashMap::new();
        for (id, auth_events) in [
            ("A", vec![String::from("B")]),
            ("B", vec![String::from("A")]),
            ("C", Vec::new()),
        ] {
            graph.insert(
                String::from(id),
                LeanEvent {
                    event_id: String::from(id),
                    auth_events,
                    ..Default::default()
                },
            );
        }

        let forward = ForwardReachabilityIndex::build(&graph);
        let range = RangePrefilterReachability::build(&graph);
        let a = String::from("A");
        let b = String::from("B");
        let c = String::from("C");

        assert_eq!(forward.reaches(&a, &b), Reach::Unknown);
        assert_eq!(range.reaches(&a, &b), Reach::Unknown);
        assert_eq!(forward.reaches(&c, &a), Reach::Unknown);
        assert_eq!(range.reaches(&c, &a), Reach::Unknown);

        let seeds = [&a];
        let candidates = [&a, &b, &c];
        assert_eq!(forward.filter_reachable(seeds, candidates), vec![0, 1]);
        assert_eq!(range.filter_reachable(seeds, candidates), vec![0, 1]);
        assert_eq!(
            range
                .forward_reachable_ids([&a].into_iter())
                .cloned()
                .collect::<Vec<_>>(),
            vec![String::from("A"), String::from("B")]
        );
    }
}
