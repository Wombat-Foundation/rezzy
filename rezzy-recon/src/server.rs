// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Responder-side MSC0501 reconciliation digest generation.

use alloc::{
    collections::{BTreeSet, VecDeque},
    string::ToString,
    vec::Vec,
};

use crate::EventId;

use super::{
    algebraic::SyndromeSketch,
    triage::{BucketRequest, NodeSummary},
    AlgebraicError, ElementHash, EventIdFormat, RoomAccumulator, RoomEventIdKind, H64_TRIE_WIDTH,
};

/// Read-only helper over a pre-sorted `h64` index.
///
/// This keeps bucket extraction cheap and explicit without forcing callers into
/// a heavier storage abstraction.
#[derive(Debug, Clone, Copy)]
pub struct H64Index<'a> {
    sorted_h64: &'a [u64],
}

impl<'a> H64Index<'a> {
    /// Creates a view over a pre-sorted `h64` slice.
    #[must_use]
    pub const fn new(sorted_h64: &'a [u64]) -> Self {
        Self { sorted_h64 }
    }

    pub(crate) fn bounds_unchecked(request: &BucketRequest) -> core::ops::Range<u128> {
        let depth = u32::from(request.depth);
        let shift = u32::from(H64_TRIE_WIDTH).saturating_sub(depth);

        // A u128 safely handles (1 << 64) - 1, which cleanly downcasts to u64::MAX
        let prefix_mask = u64::try_from((1_u128 << depth).saturating_sub(1)).unwrap_or(u64::MAX);
        let prefix = request.prefix & prefix_mask;

        let start = u128::from(prefix) << shift;

        // When depth reaches the internal trie width, the shift collapses to 0.
        let end = start.saturating_add(1_u128 << shift);

        start..end
    }

    fn bucket_range_unchecked(&self, request: &BucketRequest) -> core::ops::Range<usize> {
        if request.depth == 0 {
            return 0..self.sorted_h64.len();
        }

        let bounds = Self::bounds_unchecked(request);
        let start_idx = self
            .sorted_h64
            .partition_point(|&x| u128::from(x) < bounds.start);
        let end_idx = start_idx.saturating_add(
            self.sorted_h64[start_idx..].partition_point(|&x| u128::from(x) < bounds.end),
        );

        start_idx..end_idx
    }

    /// Returns the half-open slice range covered by one bucket request.
    ///
    /// # Errors
    /// Returns an error when the request is malformed.
    pub fn bucket_range(
        &self,
        request: &BucketRequest,
    ) -> Result<core::ops::Range<usize>, AlgebraicError> {
        crate::triage::validate_bucket_requests(core::slice::from_ref(request))?;
        Ok(self.bucket_range_unchecked(request))
    }

    /// Returns the `h64` slice covered by one bucket request.
    ///
    /// # Errors
    /// Returns an error when the request is malformed.
    pub fn bucket_slice(&self, request: &BucketRequest) -> Result<&'a [u64], AlgebraicError> {
        crate::triage::validate_bucket_requests(core::slice::from_ref(request))?;
        let range = self.bucket_range_unchecked(request);
        Ok(&self.sorted_h64[range])
    }

    fn bucket_slice_unchecked(&self, request: &BucketRequest) -> &'a [u64] {
        let range = self.bucket_range_unchecked(request);
        &self.sorted_h64[range]
    }
}

/// Reusable reconciliation view over one room's current frame and `h64` index.
///
/// This is a convenience layer for callers that repeatedly query the same room
/// state: it avoids threading the graph, anchors, and sorted index separately
/// through every call site.
#[derive(Debug, Clone, Copy)]
pub struct ReconciliationContext<'a, Id: EventId, G: ForwardGraph<Id>> {
    graph: &'a G,
    frame_anchors: &'a [Id],
    h64_index: H64Index<'a>,
}

impl<'a, Id: EventId, G: ForwardGraph<Id>> ReconciliationContext<'a, Id, G> {
    /// Creates a reusable context for one room/frame snapshot.
    ///
    /// # Errors
    /// Returns [`AlgebraicError::UnsupportedRoomVersion`] for a room whose
    /// event IDs are not reference hashes: an `event_ids` frame MUST NOT be
    /// constructed for it.
    pub const fn new(
        kind: RoomEventIdKind,
        graph: &'a G,
        frame_anchors: &'a [Id],
        sorted_h64: &'a [u64],
    ) -> Result<Self, AlgebraicError> {
        if let Err(error) = kind.require_event_ids_frame() {
            return Err(error);
        }
        Ok(Self {
            graph,
            frame_anchors,
            h64_index: H64Index::new(sorted_h64),
        })
    }

    /// Returns the negotiated frame digest for this room snapshot.
    ///
    /// # Errors
    /// Returns an error if any frame event IDs violate format rules or element
    /// hashing limits.
    pub fn frame_digest(&self) -> Result<RoomAccumulator, AlgebraicError> {
        compute_frame_digest(
            RoomEventIdKind::ReferenceHash,
            self.graph,
            self.frame_anchors,
        )
    }

    /// Returns the `h64` range covered by one bucket request.
    ///
    /// # Errors
    /// Returns an error when the request is malformed.
    pub fn bucket_range(
        &self,
        request: &BucketRequest,
    ) -> Result<core::ops::Range<usize>, AlgebraicError> {
        self.h64_index.bucket_range(request)
    }

    /// Returns the `h64` slice covered by one bucket request.
    ///
    /// # Errors
    /// Returns an error when the request is malformed.
    pub fn bucket_slice(&self, request: &BucketRequest) -> Result<&'a [u64], AlgebraicError> {
        self.h64_index.bucket_slice(request)
    }

    /// Constructs bucket sketches over the room's sorted `h64` index.
    ///
    /// # Errors
    /// Returns an error if any sketches exceed capacity limits or if requests are invalid.
    pub fn bucket_sketches(
        &self,
        requests: &[BucketRequest],
    ) -> Result<Vec<SyndromeSketch>, AlgebraicError> {
        build_bucket_sketches(self.h64_index.sorted_h64, requests)
    }
}

/// Abstraction for forward traversal through the room DAG.
///
/// Matrix homeservers typically traverse backwards via `prev_events`.
/// To support MSC0501 causal frame bounding, we must traverse *forwards*
/// to collect all topological descendants of the frame anchors.
pub trait ForwardGraph<Id: EventId> {
    /// Iterator over the children of an event ID.
    type ChildrenIter<'a>: Iterator<Item = &'a Id>
    where
        Self: 'a,
        Id: 'a;

    /// Returns the children of the given event ID.
    /// This represents the forward edges in the causal graph (where a child's
    /// `prev_events` contains `id`).
    fn children<'a>(&'a self, id: &Id) -> Self::ChildrenIter<'a>;

    /// Checks if a given event ID is known to the server.
    /// A known event can be either fully accepted, or rejected (a tombstone).
    /// MSC0501 strictly requires that rejected events are included.
    fn is_known(&self, id: &Id) -> bool;

    /// Returns the string representation of an event ID if available without allocation.
    /// Defaults to `None`, falling back to `Display::to_string`.
    fn event_id_str<'a>(&'a self, _id: &'a Id) -> Option<&'a str> {
        None
    }

    /// Returns the event ID format for a given known event, used to compute
    /// its algebraic digest.
    ///
    /// Implementations MUST return the correct format even for rejected
    /// events (tombstones). If a rejected event's format is misidentified,
    /// its hash will be incorrect and will silently desync the reconciliation set.
    fn event_format(&self, id: &Id) -> EventIdFormat;

    /// Returns the computed `ElementHash` for a given event ID.
    ///
    /// The default implementation resolves `event_id_str` (or `Display`) and `event_format`
    /// to derive `ElementHash::from_matrix_event_id`.
    /// Custom implementations using integer/interned IDs (e.g. `u64` short IDs) can override
    /// this method to compute `ElementHash` directly without string formatting or allocations.
    ///
    /// # Errors
    /// Returns an error if the event ID format is invalid or hashing fails.
    fn event_hash(&self, id: &Id) -> Result<ElementHash, AlgebraicError> {
        let format = self.event_format(id);
        self.event_id_str(id).map_or_else(
            || ElementHash::from_matrix_event_id(&id.to_string(), format),
            |s| ElementHash::from_matrix_event_id(s, format),
        )
    }
}

/// Computes the MSC0501 room digest over a negotiated frame.
///
/// The frame is mathematically bounded by the causal graph. The digested
/// population includes only the known events that **causally succeed** (are
/// topological descendants of) the anchor antichain. Events that causally
/// precede the anchor, such as pre-join history, are excluded.
///
/// # Errors
/// Returns [`AlgebraicError::UnsupportedRoomVersion`] for a room whose event
/// IDs are not reference hashes (checked once, before any work), or an error
/// if any frame event IDs violate format rules or element hashing limits.
pub fn compute_frame_digest<Id: EventId, G: ForwardGraph<Id>>(
    kind: RoomEventIdKind,
    graph: &G,
    frame_anchors: &[Id],
) -> Result<RoomAccumulator, AlgebraicError> {
    kind.require_event_ids_frame()?;
    let mut accumulator = RoomAccumulator::new();
    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();

    // Initialize traversal frontier from the frame anchor antichain
    for anchor in frame_anchors {
        if graph.is_known(anchor) {
            queue.push_back(anchor.clone());
            visited.insert(anchor.clone());
        }
    }

    // Breadth-first traversal down the causal graph
    while let Some(current) = queue.pop_front() {
        for child in graph.children(&current) {
            // Unconditionally mark visited to avoid re-traversing unknown forks
            if visited.insert(child.clone()) && graph.is_known(child) {
                let hash = graph.event_hash(child)?;
                accumulator.insert(hash)?;
                queue.push_back(child.clone());
            }
        }
    }

    Ok(accumulator)
}

/// Constructs bucket sketches for the provided MSC0501 triage requests.
///
/// This uses an $O(\log n)$ binary search on a pre-sorted array of 64-bit event IDs,
/// extracting and toggling only the slice of events requested in each bucket.
///
/// # Errors
/// Returns an error if any sketches exceed capacity limits or if requests are invalid.
///
pub fn build_bucket_sketches(
    sorted_h64: &[u64],
    requests: &[BucketRequest],
) -> Result<Vec<SyndromeSketch>, AlgebraicError> {
    crate::triage::validate_bucket_requests(requests)?;
    let index = H64Index::new(sorted_h64);

    let mut sketches = Vec::with_capacity(requests.len());

    for request in requests {
        let mut sketch = SyndromeSketch::new(request.capacity)?;
        // The pre-sorted index makes the bucket's contents a contiguous slice.
        for &h64 in index.bucket_slice_unchecked(request) {
            sketch.toggle(h64)?;
        }

        sketches.push(sketch);
    }

    Ok(sketches)
}

/// A population sorted by `(h64, h128)`, with the two columns kept aligned.
///
/// Building it from [`ElementHash`]es sorts once, so a node's elements are a
/// contiguous slice of both columns and the `h64 -> h128` map is multi-valued
/// by construction: [`candidates`](Self::candidates) returns every element
/// sharing an `h64`. There is no way to construct it with misaligned columns.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SortedPopulation {
    h64: Vec<u64>,
    h128: Vec<u128>,
}

impl SortedPopulation {
    /// Sorts `elements` by `(h64, h128)`.
    #[must_use]
    pub fn new(mut elements: Vec<ElementHash>) -> Self {
        elements.sort_unstable_by_key(|e| (e.h64, e.h128));
        Self {
            h64: elements.iter().map(|e| e.h64).collect(),
            h128: elements.iter().map(|e| e.h128).collect(),
        }
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.h64.len()
    }

    /// Whether the population is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.h64.is_empty()
    }

    /// The sorted `h64` column.
    #[must_use]
    pub fn h64s(&self) -> &[u64] {
        &self.h64
    }

    /// The `h128` column, aligned with [`h64s`](Self::h64s).
    #[must_use]
    pub fn h128s(&self) -> &[u128] {
        &self.h128
    }

    /// An [`H64Index`] over this population's `h64` column.
    #[must_use]
    pub fn index(&self) -> H64Index<'_> {
        H64Index::new(&self.h64)
    }

    /// The `h128` of every element whose `h64` is `root`, in order; empty when
    /// the root is absent.
    #[must_use]
    pub fn candidates(&self, root: u64) -> &[u128] {
        let start = self.h64.partition_point(|&x| x < root);
        let end = self.h64.partition_point(|&x| x <= root);
        &self.h128[start..end]
    }
}

/// Like [`build_bucket_sketches`], but also returns each node's
/// [`NodeSummary`] (count and `h128` XOR), computed over the same slice that
/// is toggled into the sketch.
///
/// # Errors
/// Returns an error if a sketch exceeds capacity limits or the requests are
/// invalid.
pub fn build_bucket_nodes(
    population: &SortedPopulation,
    requests: &[BucketRequest],
) -> Result<Vec<(SyndromeSketch, NodeSummary)>, AlgebraicError> {
    let (sorted_h64, sorted_h128) = (population.h64s(), population.h128s());
    crate::triage::validate_bucket_requests(requests)?;
    let index = population.index();
    let mut nodes = Vec::with_capacity(requests.len());
    for request in requests {
        let range = index.bucket_range_unchecked(request);
        let mut sketch = SyndromeSketch::new(request.capacity)?;
        for &h64 in &sorted_h64[range.clone()] {
            sketch.toggle(h64)?;
        }
        nodes.push((sketch, NodeSummary::from_h128s(&sorted_h128[range])?));
    }
    Ok(nodes)
}

// =========================================================================
// Sketch Builder and Budget Planner Logic
// =========================================================================

/// Work limits applied while building sketches for a request.
pub struct SketchPolicy {
    /// Maximum total elements to process across all returned sketches.
    pub max_aggregate_work: usize,
    /// The absolute ceiling where a single slice proves the difference is pathological.
    pub hard_fallback_threshold: usize,
}

/// Outcome of building sketches for a set of bucket requests.
pub enum SketchResult {
    /// A sketch for every request, in order.
    Success(Vec<(SyndromeSketch, BucketRequest)>),
    /// The difference is too large to sketch; fall back to range sync.
    FallbackToRangeSync,
}

/// A responder-side materializer that validates requested slices before paying the O(S) cost to build sketches.
pub struct SketchBuilder<'a> {
    index: &'a H64Index<'a>,
    policy: SketchPolicy,
}

impl<'a> SketchBuilder<'a> {
    #[must_use]
    /// Builds a sketch builder over `index` under `policy`.
    pub const fn new(index: &'a H64Index<'a>, policy: SketchPolicy) -> Self {
        Self { index, policy }
    }

    /// Processes incoming requests, rejecting oversized slices rather than
    /// splitting them server-side, while enforcing total work budgets.
    ///
    /// # Errors
    /// Returns an error if sketch creation fails algebraically.
    pub fn build(
        &self,
        initial_requests: &[BucketRequest],
    ) -> Result<SketchResult, AlgebraicError> {
        let mut total_work: usize = 0;

        crate::triage::validate_bucket_requests(initial_requests)?;
        for req in initial_requests {
            let range = self.index.bucket_range_unchecked(req);
            let slice_len = range.len();

            if slice_len > self.policy.hard_fallback_threshold {
                return Ok(SketchResult::FallbackToRangeSync);
            }

            total_work = total_work.saturating_add(slice_len);
            if total_work > self.policy.max_aggregate_work {
                return Ok(SketchResult::FallbackToRangeSync);
            }
        }

        let mut sketches = Vec::with_capacity(initial_requests.len());
        for req in initial_requests {
            let mut sketch = SyndromeSketch::new(req.capacity)?;
            for &h64 in self.index.bucket_slice_unchecked(req) {
                sketch.toggle(h64)?;
            }
            sketches.push((sketch, *req));
        }

        Ok(SketchResult::Success(sketches))
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::fmt;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct MockId(String);

    impl fmt::Display for MockId {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    struct MockGraph {
        forward_edges: BTreeMap<MockId, Vec<MockId>>,
        known_events: BTreeSet<MockId>,
    }

    impl MockGraph {
        fn new() -> Self {
            Self {
                forward_edges: BTreeMap::new(),
                known_events: BTreeSet::new(),
            }
        }

        fn add_edge(&mut self, parent: &str, child: &str) {
            self.forward_edges
                .entry(MockId(parent.to_string()))
                .or_default()
                .push(MockId(child.to_string()));
            self.known_events.insert(MockId(parent.to_string()));
            self.known_events.insert(MockId(child.to_string()));
        }
    }

    impl ForwardGraph<MockId> for MockGraph {
        type ChildrenIter<'a> = core::slice::Iter<'a, MockId>;

        fn children<'a>(&'a self, id: &MockId) -> Self::ChildrenIter<'a> {
            self.forward_edges
                .get(id)
                .map_or_else(|| [].iter(), |children| children.iter())
        }

        fn is_known(&self, id: &MockId) -> bool {
            self.known_events.contains(id)
        }

        fn event_format(&self, _id: &MockId) -> EventIdFormat {
            EventIdFormat::V4Plus
        }

        fn event_hash(&self, id: &MockId) -> Result<ElementHash, AlgebraicError> {
            Ok(ElementHash::from_opaque_bytes(id.0.as_bytes()))
        }
    }

    fn id(s: &str) -> MockId {
        MockId(s.to_string())
    }

    fn hash1() -> ElementHash {
        ElementHash::from_opaque_bytes(b"$1")
    }

    fn hash2() -> ElementHash {
        ElementHash::from_opaque_bytes(b"$2")
    }

    fn four_entry_index() -> [u64; 4] {
        [
            0x0000_0001_0000_0001,
            0x0000_0001_0000_0002,
            0x0000_0002_0000_0001,
            0x0000_0003_0000_0001,
        ]
    }

    fn sketch_builder<'a>(
        index: &'a H64Index<'a>,
        max_aggregate_work: usize,
        hard_fallback_threshold: usize,
    ) -> SketchBuilder<'a> {
        SketchBuilder::new(
            index,
            SketchPolicy {
                max_aggregate_work,
                hard_fallback_threshold,
            },
        )
    }

    fn single_bucket_roots(
        sorted_h64: &[u64],
        request: BucketRequest,
        capacity: usize,
    ) -> Vec<u64> {
        let requests = [request];
        let sketches = build_bucket_sketches(sorted_h64, &requests).unwrap();
        assert_eq!(sketches.len(), 1);
        sketches[0].clone().decode_elements(capacity).unwrap()
    }

    fn assert_fallback(builder: &SketchBuilder<'_>, requests: &[BucketRequest]) {
        let result = builder.build(requests).unwrap();
        assert!(matches!(result, SketchResult::FallbackToRangeSync));
    }

    #[test]
    fn test_event_id_str_some_branch() {
        // Exercises the `Some(...)` arm of the default `event_hash` impl directly,
        // without needing a full graph traversal.
        struct StringIdGraph;
        impl ForwardGraph<MockId> for StringIdGraph {
            type ChildrenIter<'a> = core::slice::Iter<'a, MockId>;

            fn children<'a>(&'a self, _id: &MockId) -> Self::ChildrenIter<'a> {
                [].iter()
            }

            fn is_known(&self, _id: &MockId) -> bool {
                true
            }

            fn event_id_str<'a>(&'a self, id: &'a MockId) -> Option<&'a str> {
                Some(&id.0)
            }

            fn event_format(&self, _id: &MockId) -> EventIdFormat {
                EventIdFormat::V4Plus
            }

            fn event_hash(&self, id: &MockId) -> Result<ElementHash, AlgebraicError> {
                Ok(ElementHash::from_opaque_bytes(id.0.as_bytes()))
            }
        }

        let event_id = id("$anchor");
        assert!(StringIdGraph.is_known(&event_id));
        assert_eq!(StringIdGraph.children(&event_id).next(), None);

        let hash = StringIdGraph.event_hash(&event_id).unwrap();
        assert_eq!(hash, ElementHash::from_opaque_bytes(b"$anchor"));
    }

    #[test]
    fn test_custom_event_hash_override() {
        struct CustomHashGraph(MockGraph);
        impl ForwardGraph<MockId> for CustomHashGraph {
            type ChildrenIter<'a> = core::slice::Iter<'a, MockId>;

            fn children<'a>(&'a self, id: &MockId) -> Self::ChildrenIter<'a> {
                self.0.children(id)
            }

            fn is_known(&self, id: &MockId) -> bool {
                self.0.is_known(id)
            }

            fn event_format(&self, id: &MockId) -> EventIdFormat {
                self.0.event_format(id)
            }

            fn event_hash(&self, id: &MockId) -> Result<ElementHash, AlgebraicError> {
                // Deliberately distinct from the default legacy hash of `id.0`
                // (which would hash "$child") so the assertion below can only
                // pass if traversal actually dispatches through this override.
                Ok(ElementHash::from_opaque_bytes(
                    alloc::format!("$custom-{}", id.0).as_bytes(),
                ))
            }
        }

        let mut base = MockGraph::new();
        base.add_edge("$anchor", "$child");
        let custom_graph = CustomHashGraph(base);

        assert_eq!(
            custom_graph.event_format(&id("$anchor")),
            EventIdFormat::V4Plus
        );

        let digest = compute_frame_digest(
            RoomEventIdKind::ReferenceHash,
            &custom_graph,
            &[id("$anchor")],
        )
        .unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(ElementHash::from_opaque_bytes(b"$custom-$child"))
            .unwrap();

        assert_eq!(digest.digest(), expected.digest());
        assert_eq!(digest.known_event_count(), 1);
    }

    #[test]
    fn tests_frame_bounds() {
        let mut graph = MockGraph::new();
        // pre-join history
        graph.add_edge("$genesis", "$prejoin1");
        graph.add_edge("$prejoin1", "$anchor");
        // in frame
        graph.add_edge("$anchor", "$child1");
        graph.add_edge("$anchor", "$child2");
        graph.add_edge("$child1", "$grandchild");
        graph.add_edge("$child2", "$grandchild");

        let digest =
            compute_frame_digest(RoomEventIdKind::ReferenceHash, &graph, &[id("$anchor")]).unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(ElementHash::from_opaque_bytes(b"$child1"))
            .unwrap();
        expected
            .insert(ElementHash::from_opaque_bytes(b"$child2"))
            .unwrap();
        expected
            .insert(ElementHash::from_opaque_bytes(b"$grandchild"))
            .unwrap();

        assert_eq!(digest.digest(), expected.digest());
        assert_eq!(digest.known_event_count(), 3);
    }

    #[test]
    fn tests_outlier_quarantine() {
        let mut graph = MockGraph::new();
        graph.add_edge("$anchor", "$child");

        // Disconnected outlier
        graph.known_events.insert(id("$outlier"));

        let digest =
            compute_frame_digest(RoomEventIdKind::ReferenceHash, &graph, &[id("$anchor")]).unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(ElementHash::from_opaque_bytes(b"$child"))
            .unwrap();

        assert_eq!(digest.digest(), expected.digest());
    }

    #[test]
    fn test_build_bucket_sketches_exact_match() {
        use crate::triage::BucketRequest;
        let h1 = hash1();

        let bucket_idx = h1.h64 >> 56;
        let roots = single_bucket_roots(&[h1.h64], BucketRequest::new(8, bucket_idx, 4), 4);

        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], h1.h64);
    }

    #[test]
    fn test_h64_index_bucket_slice() {
        use crate::triage::BucketRequest;

        let sorted_h64 = four_entry_index();
        let index = H64Index::new(&sorted_h64);
        let request = BucketRequest::new(32, 1, 4);

        let slice = index.bucket_slice(&request).unwrap();
        assert_eq!(slice, &[0x0000_0001_0000_0001, 0x0000_0001_0000_0002]);
    }

    /// Two events sharing an `h64` (a 64-bit collision) occupy adjacent slots
    /// in the sorted index. `bucket_slice` returns both -- the index is a
    /// multiset -- but toggling an element twice is the identity in
    /// characteristic two, so the pair contributes nothing to the sketch and
    /// can never be decoded as a root. Only the 128-bit residual can notice.
    #[test]
    fn duplicate_h64_is_returned_twice_but_cancels_in_the_sketch() {
        use crate::triage::BucketRequest;

        let shared = 0x0000_0001_0000_0002;
        let sorted_h64 = [0x0000_0001_0000_0001, shared, shared, 0x0000_0002_0000_0001];
        let request = BucketRequest::new(32, 1, 4);

        let slice = H64Index::new(&sorted_h64).bucket_slice(&request).unwrap();
        assert_eq!(slice, &[0x0000_0001_0000_0001, shared, shared]);

        let sketch = &build_bucket_sketches(&sorted_h64, &[request]).unwrap()[0];
        let mut singleton = SyndromeSketch::new(4).unwrap();
        singleton.toggle(0x0000_0001_0000_0001).unwrap();
        assert_eq!(sketch, &singleton, "the colliding pair must cancel out");
        assert_eq!(
            sketch.decode_elements(4).unwrap(),
            vec![0x0000_0001_0000_0001]
        );
    }

    #[test]
    fn duplicate_h64_alone_leaves_an_empty_sketch() {
        use crate::triage::BucketRequest;

        let sorted_h64 = [7, 7];
        let sketch =
            &build_bucket_sketches(&sorted_h64, &[BucketRequest::new(0, 0, 2)]).unwrap()[0];
        assert_eq!(sketch, &SyndromeSketch::new(2).unwrap());
        assert_eq!(sketch.decode_elements(2).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn test_h64_index_bucket_range() {
        use crate::triage::BucketRequest;

        let sorted_h64 = four_entry_index();
        let index = H64Index::new(&sorted_h64);
        let request = BucketRequest::new(32, 1, 4);

        let range = index.bucket_range(&request).unwrap();
        assert_eq!(range, 0..2);
    }

    #[test]
    fn test_reconciliation_context_delegates_room_lookups() {
        use crate::triage::BucketRequest;

        let mut graph = MockGraph::new();
        graph.add_edge("$anchor", "$child");
        graph.add_edge("$child", "$grandchild");

        let child = ElementHash::from_opaque_bytes(b"$child");
        let grandchild = ElementHash::from_opaque_bytes(b"$grandchild");
        let mut sorted_h64 = vec![grandchild.h64, child.h64];
        sorted_h64.sort_unstable();
        let anchors = [id("$anchor")];

        let context = ReconciliationContext::new(
            RoomEventIdKind::ReferenceHash,
            &graph,
            &anchors,
            &sorted_h64,
        )
        .unwrap();
        let digest = context.frame_digest().unwrap();

        let mut expected = RoomAccumulator::new();
        expected.insert(child).unwrap();
        expected.insert(grandchild).unwrap();
        assert_eq!(digest.digest(), expected.digest());
        assert_eq!(digest.known_event_count(), 2);

        let request = BucketRequest::new(0, 0, 4);
        let range = context.bucket_range(&request).unwrap();
        assert_eq!(range, 0..2);
        let slice = context.bucket_slice(&request).unwrap();
        assert_eq!(slice, sorted_h64.as_slice());
        let sketches = context.bucket_sketches(&[request]).unwrap();
        assert_eq!(sketches.len(), 1);
        let mut roots = sketches[0].clone().decode_elements(4).unwrap();
        roots.sort_unstable();
        let mut expected_roots = sorted_h64.clone();
        expected_roots.sort_unstable();
        assert_eq!(roots, expected_roots);
    }

    #[test]
    fn test_build_bucket_sketches_dynamic_summation() {
        use crate::triage::BucketRequest;
        let h1 = hash1();
        let h2 = hash2();

        // Depth 0 encompasses everything
        let requests = [BucketRequest::new(0, 0, 4)];

        let mut sorted_h64 = vec![h1.h64, h2.h64];
        sorted_h64.sort_unstable();
        let sketches = build_bucket_sketches(&sorted_h64, &requests).unwrap();

        assert_eq!(sketches.len(), 1);
        let mut roots = sketches[0].clone().decode_elements(4).unwrap();
        roots.sort_unstable();

        let mut expected = [h1.h64, h2.h64];
        expected.sort_unstable();

        assert_eq!(roots, expected);
    }

    #[test]
    fn test_build_bucket_sketches_deep_extraction() {
        use crate::triage::BucketRequest;
        let h1 = hash1();
        let h2 = hash2();

        let depth: u8 = 16;
        let shift = u32::from(H64_TRIE_WIDTH) - u32::from(depth);
        let prefix = h1.h64 >> shift;

        let requests = [BucketRequest::new(depth, prefix, 4)];

        // Deep extraction uses elements_provider
        let mut sorted_h64 = vec![h1.h64, h2.h64];
        sorted_h64.sort_unstable();
        let sketches = build_bucket_sketches(&sorted_h64, &requests).unwrap();

        assert_eq!(sketches.len(), 1);
        // Only elements that match the prefix should be present.
        let roots = sketches[0].clone().decode_elements(4).unwrap();
        assert!(roots.contains(&h1.h64));
    }

    #[test]
    fn test_build_bucket_sketches_invalid_indices() {
        use crate::triage::BucketRequest;
        let sorted_h64 = vec![];
        let requests = [BucketRequest::new(8, 256, 4)];
        assert_eq!(
            build_bucket_sketches(&sorted_h64, &requests),
            Err(AlgebraicError::InvalidBucketIndex)
        );

        let requests = [BucketRequest::new(7, 256, 4)];
        assert_eq!(
            build_bucket_sketches(&sorted_h64, &requests),
            Err(AlgebraicError::InvalidBucketIndex)
        );
    }

    #[test]
    fn test_build_bucket_sketches_depth_0_slow_path() {
        use crate::triage::BucketRequest;
        let h1 = hash1();

        let roots = single_bucket_roots(&[h1.h64], BucketRequest::new(0, 0, 10), 10);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], h1.h64);
    }

    #[test]
    fn test_sketch_builder_build_success_no_split() {
        use crate::triage::BucketRequest;
        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x2000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1000, 1000);
        let requests = [BucketRequest::new(0, 0, 10)];

        let result = builder.build(&requests).unwrap();
        if let SketchResult::Success(sketches) = result {
            assert_eq!(sketches.len(), 1);
            assert_eq!(sketches[0].1, requests[0]);
        } else {
            panic!("Expected Success");
        }
    }

    #[test]
    fn test_sketch_builder_build_materializes_large_slice_at_small_capacity() {
        use crate::triage::BucketRequest;
        let sorted_h64 = vec![0x0000_0000_0000_0001, 0x8000_0000_0000_0002];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1000, 1000);
        let requests = [BucketRequest::new(0, 0, 1)];

        let result = builder.build(&requests).unwrap();
        assert!(matches!(result, SketchResult::Success(sketches) if sketches.len() == 1));
    }

    #[test]
    fn test_sketch_builder_build_hard_fallback() {
        use crate::triage::BucketRequest;
        let sorted_h64 = vec![1, 2, 3];
        let index = H64Index::new(&sorted_h64);
        // 3 > 2, triggers hard fallback
        let builder = sketch_builder(&index, 1000, 2);
        assert_fallback(&builder, &[BucketRequest::new(0, 0, 1)]);
    }

    #[test]
    fn test_sketch_builder_build_budget_exhausted() {
        use crate::triage::BucketRequest;
        // Two elements, capacity 1, will split.
        // Splitting creates two slices of length 1.
        // Aggregate work will be 1 + 1 = 2.
        let sorted_h64 = vec![0x0000_0000_0000_0001, 0x8000_0000_0000_0002];
        let index = H64Index::new(&sorted_h64);
        // Budget of 1 will be exhausted since 2 work is needed
        let builder = sketch_builder(&index, 1, 1000);
        assert_fallback(&builder, &[BucketRequest::new(0, 0, 1)]);
    }

    #[test]
    fn test_sketch_builder_build_falls_back_on_aggregate_work_limit() {
        use crate::triage::BucketRequest;

        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x9000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1, 1000);
        assert_fallback(
            &builder,
            &[BucketRequest::new(1, 0, 1), BucketRequest::new(1, 1, 1)],
        );
    }

    #[test]
    fn test_sketch_builder_build_propagates_bucket_materialization_errors() {
        use crate::triage::BucketRequest;

        let sorted_h64 = vec![0, 0x1000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1000, 1000);
        let requests = [BucketRequest::new(0, 0, 2)];

        assert!(matches!(
            builder.build(&requests),
            Err(AlgebraicError::ZeroShortIdentifier)
        ));
    }

    #[test]
    fn test_sketch_builder_build_rejects_malformed_request_before_localization() {
        use crate::triage::BucketRequest;
        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x2000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1000, 1000);
        // Zero capacity is rejected by `validate_bucket_requests` before any
        // range localization is attempted.
        let requests = [BucketRequest::new(0, 0, 0)];

        assert!(matches!(
            builder.build(&requests),
            Err(AlgebraicError::InvalidSketchCapacity)
        ));
    }

    #[test]
    fn test_sketch_builder_rejects_depth_above_maximum() {
        let sorted_h64 = [1_u64];
        let index = H64Index::new(&sorted_h64);
        let builder = sketch_builder(&index, 1_000, 1_000);
        let requests = [BucketRequest::new(crate::MAX_DEPTH.saturating_add(1), 0, 1)];

        assert!(matches!(
            builder.build(&requests),
            Err(AlgebraicError::InvalidBucketIndex)
        ));
    }

    fn element(h128: u128, h64: u64) -> ElementHash {
        ElementHash { h128, h64 }
    }

    #[test]
    fn sorted_population_keeps_columns_aligned_and_ordered() {
        let population =
            SortedPopulation::new(vec![element(0xC, 30), element(0xA, 10), element(0xB, 20)]);
        assert_eq!(population.h64s(), &[10, 20, 30]);
        assert_eq!(population.h128s(), &[0xA, 0xB, 0xC]);
        assert_eq!(population.len(), 3);
        assert!(!population.is_empty());
    }

    #[test]
    fn sorted_population_candidates_are_multi_valued_and_deterministic() {
        let population = SortedPopulation::new(vec![
            element(0x9, 7),
            element(0x1, 7),
            element(0x5, 3),
            element(0x2, 9),
        ]);
        // Equal h64 values sort by h128, so the order is input-independent.
        assert_eq!(population.candidates(7), &[0x1, 0x9]);
        assert_eq!(population.candidates(3), &[0x5]);
        assert!(population.candidates(8).is_empty());
        assert!(population.candidates(u64::MAX).is_empty());
    }

    #[test]
    fn empty_sorted_population_has_no_candidates_and_empty_nodes() {
        let population = SortedPopulation::default();
        assert!(population.is_empty());
        assert!(population.candidates(1).is_empty());
        let nodes = build_bucket_nodes(&population, &[BucketRequest::new(0, 0, 4)]).unwrap();
        assert_eq!(nodes[0].1, NodeSummary::default());
    }

    #[test]
    fn bucket_nodes_summarize_exactly_the_slice_they_sketch() {
        let population = SortedPopulation::new(vec![
            element(0x1, 5),
            element(0x2, 6),
            element(0x4, (1_u64 << 63) | 5),
        ]);
        let nodes = build_bucket_nodes(
            &population,
            &[BucketRequest::new(1, 0, 4), BucketRequest::new(1, 1, 4)],
        )
        .unwrap();
        assert_eq!(
            nodes[0].1,
            NodeSummary {
                count: 2,
                digest: 0x3
            }
        );
        assert_eq!(
            nodes[1].1,
            NodeSummary {
                count: 1,
                digest: 0x4
            }
        );
        // The two children sum to the level-0 pair.
        let whole = build_bucket_nodes(&population, &[BucketRequest::new(0, 0, 4)]).unwrap();
        assert_eq!(
            whole[0].1,
            NodeSummary {
                count: 3,
                digest: 0x7
            }
        );
    }

    /// Room versions 1 and 2 have sender-chosen event IDs, so no `event_ids`
    /// frame may be built for them, and the rejection is explicit rather than
    /// a side effect of an ID that happens not to be valid base64.
    #[test]
    fn sender_chosen_rooms_cannot_construct_an_event_ids_frame() {
        let mut graph = MockGraph::new();
        graph.add_edge("$anchor", "$child");
        let anchors = [id("$anchor")];
        assert_eq!(
            compute_frame_digest(RoomEventIdKind::SenderChosen, &graph, &anchors),
            Err(AlgebraicError::UnsupportedRoomVersion)
        );
        let sorted = [1_u64];
        assert_eq!(
            ReconciliationContext::new(RoomEventIdKind::SenderChosen, &graph, &anchors, &sorted)
                .err(),
            Some(AlgebraicError::UnsupportedRoomVersion)
        );
    }
}
