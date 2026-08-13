// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

//! Responder-side MSC0501 reconciliation digest generation.

use alloc::{
    collections::{BTreeSet, VecDeque},
    string::ToString,
};

use crate::basespec::rezzy_types::EventId;

use alloc::vec::Vec;

use super::{
    algebraic::SyndromeSketch, triage::BucketRequest, AlgebraicError, ElementHash, EventIdFormat,
    RoomAccumulator,
};

/// Internal width for the H64 trie/index used to map requests to ranges.
///
/// The protocol request-depth cap is enforced separately at depth <= 32 by
/// `triage::validate_bucket_requests`.
use super::H64_TRIE_WIDTH;

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

    fn bounds_unchecked(request: &BucketRequest) -> core::ops::Range<u128> {
        let depth = u32::from(request.depth);
        let shift = u32::from(H64_TRIE_WIDTH).saturating_sub(depth);

        // A u128 safely handles (1 << 64) - 1, which cleanly downcasts to u64::MAX
        let prefix_mask = u64::try_from((1_u128 << depth).saturating_sub(1)).unwrap_or(u64::MAX);
        let prefix = u64::from(request.prefix) & prefix_mask;

        let start = u128::from(prefix) << shift;

        // When depth reaches the internal trie width, the shift collapses to 0.
        // Request validation still caps protocol depth at 32.
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
        crate::reconcile::triage::validate_bucket_requests(core::slice::from_ref(request))?;
        Ok(self.bucket_range_unchecked(request))
    }

    /// Returns the `h64` slice covered by one bucket request.
    ///
    /// # Errors
    /// Returns an error when the request is malformed.
    pub fn bucket_slice(&self, request: &BucketRequest) -> Result<&'a [u64], AlgebraicError> {
        crate::reconcile::triage::validate_bucket_requests(core::slice::from_ref(request))?;
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
    #[must_use]
    pub const fn new(graph: &'a G, frame_anchors: &'a [Id], sorted_h64: &'a [u64]) -> Self {
        Self {
            graph,
            frame_anchors,
            h64_index: H64Index::new(sorted_h64),
        }
    }

    /// Returns the negotiated frame digest for this room snapshot.
    ///
    /// # Errors
    /// Returns an error if any frame event IDs violate format rules or element
    /// hashing limits.
    pub fn frame_digest(&self) -> Result<RoomAccumulator, AlgebraicError> {
        compute_frame_digest(self.graph, self.frame_anchors)
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
        if let Some(s) = self.event_id_str(id) {
            ElementHash::from_matrix_event_id(s, format)
        } else {
            ElementHash::from_matrix_event_id(&id.to_string(), format)
        }
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
/// Returns an error if any frame event IDs violate format rules or element
/// hashing limits.
pub fn compute_frame_digest<Id: EventId, G: ForwardGraph<Id>>(
    graph: &G,
    frame_anchors: &[Id],
) -> Result<RoomAccumulator, AlgebraicError> {
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
/// # Panics
/// Panics if the calculated prefix falls out of the bounds of a `u32`.
pub fn build_bucket_sketches(
    sorted_h64: &[u64],
    requests: &[BucketRequest],
) -> Result<Vec<SyndromeSketch>, AlgebraicError> {
    crate::reconcile::triage::validate_bucket_requests(requests)?;
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

// =========================================================================
// Sketch Builder and Budget Planner Logic
// =========================================================================

pub struct SketchPolicy {
    /// Maximum total elements to process across all returned sketches.
    pub max_aggregate_work: usize,
    /// The absolute ceiling where a single slice proves the difference is pathological.
    pub hard_fallback_threshold: usize,
}

pub enum SketchResult {
    Success(Vec<SyndromeSketch>),
    FallbackToRangeSync,
}

/// A responder-side materializer that validates requested slices before paying the O(S) cost to build sketches.
pub struct SketchBuilder<'a> {
    index: &'a H64Index<'a>,
    policy: SketchPolicy,
}

impl<'a> SketchBuilder<'a> {
    #[must_use]
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

        crate::reconcile::triage::validate_bucket_requests(initial_requests)?;
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
            sketches.push(sketch);
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
            EventIdFormat::Legacy
        }
    }

    fn id(s: &str) -> MockId {
        MockId(s.to_string())
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
                EventIdFormat::Legacy
            }
        }

        let event_id = id("$anchor");
        assert!(StringIdGraph.is_known(&event_id));
        assert_eq!(StringIdGraph.children(&event_id).next(), None);

        let hash = StringIdGraph.event_hash(&event_id).unwrap();
        assert_eq!(
            hash,
            ElementHash::from_matrix_event_id("$anchor", EventIdFormat::Legacy).unwrap()
        );
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
                ElementHash::from_matrix_event_id(
                    &alloc::format!("$custom-{}", id.0),
                    EventIdFormat::Legacy,
                )
            }
        }

        let mut base = MockGraph::new();
        base.add_edge("$anchor", "$child");
        let custom_graph = CustomHashGraph(base);

        assert_eq!(
            custom_graph.event_format(&id("$anchor")),
            EventIdFormat::Legacy
        );

        let digest = compute_frame_digest(&custom_graph, &[id("$anchor")]).unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(
                ElementHash::from_matrix_event_id("$custom-$child", EventIdFormat::Legacy).unwrap(),
            )
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

        let digest = compute_frame_digest(&graph, &[id("$anchor")]).unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(ElementHash::from_matrix_event_id("$child1", EventIdFormat::Legacy).unwrap())
            .unwrap();
        expected
            .insert(ElementHash::from_matrix_event_id("$child2", EventIdFormat::Legacy).unwrap())
            .unwrap();
        expected
            .insert(
                ElementHash::from_matrix_event_id("$grandchild", EventIdFormat::Legacy).unwrap(),
            )
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

        let digest = compute_frame_digest(&graph, &[id("$anchor")]).unwrap();

        let mut expected = RoomAccumulator::new();
        expected
            .insert(ElementHash::from_matrix_event_id("$child", EventIdFormat::Legacy).unwrap())
            .unwrap();

        assert_eq!(digest.digest(), expected.digest());
    }

    #[test]
    fn test_build_bucket_sketches_exact_match() {
        use crate::reconcile::triage::BucketRequest;
        let h1 = ElementHash::from_matrix_event_id("$1", EventIdFormat::Legacy).unwrap();

        let bucket_idx = (h1.h64 >> 56) as u32;
        let requests = [BucketRequest {
            depth: 8,
            prefix: bucket_idx,
            capacity: 4,
        }];

        let sorted_h64 = vec![h1.h64];
        let sketches = build_bucket_sketches(&sorted_h64, &requests).unwrap();

        assert_eq!(sketches.len(), 1);
        let roots = sketches[0].clone().decode_elements(4).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], h1.h64);
    }

    #[test]
    fn test_h64_index_bucket_slice() {
        use crate::reconcile::triage::BucketRequest;

        let sorted_h64 = vec![
            0x0000_0001_0000_0001,
            0x0000_0001_0000_0002,
            0x0000_0002_0000_0001,
            0x0000_0003_0000_0001,
        ];
        let index = H64Index::new(&sorted_h64);
        let request = BucketRequest {
            depth: 32,
            prefix: 1,
            capacity: 4,
        };

        let slice = index.bucket_slice(&request).unwrap();
        assert_eq!(slice, &[0x0000_0001_0000_0001, 0x0000_0001_0000_0002]);
    }

    #[test]
    fn test_h64_index_bucket_range() {
        use crate::reconcile::triage::BucketRequest;

        let sorted_h64 = vec![
            0x0000_0001_0000_0001,
            0x0000_0001_0000_0002,
            0x0000_0002_0000_0001,
            0x0000_0003_0000_0001,
        ];
        let index = H64Index::new(&sorted_h64);
        let request = BucketRequest {
            depth: 32,
            prefix: 1,
            capacity: 4,
        };

        let range = index.bucket_range(&request).unwrap();
        assert_eq!(range, 0..2);
    }

    #[test]
    fn test_reconciliation_context_delegates_room_lookups() {
        use crate::reconcile::triage::BucketRequest;

        let mut graph = MockGraph::new();
        graph.add_edge("$anchor", "$child");
        graph.add_edge("$child", "$grandchild");

        let child = ElementHash::from_matrix_event_id("$child", EventIdFormat::Legacy).unwrap();
        let grandchild =
            ElementHash::from_matrix_event_id("$grandchild", EventIdFormat::Legacy).unwrap();
        let mut sorted_h64 = vec![grandchild.h64, child.h64];
        sorted_h64.sort_unstable();
        let anchors = [id("$anchor")];

        let context = ReconciliationContext::new(&graph, &anchors, &sorted_h64);
        let digest = context.frame_digest().unwrap();

        let mut expected = RoomAccumulator::new();
        expected.insert(child).unwrap();
        expected.insert(grandchild).unwrap();
        assert_eq!(digest.digest(), expected.digest());
        assert_eq!(digest.known_event_count(), 2);

        let request = BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 4,
        };
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
        use crate::reconcile::triage::BucketRequest;
        let h1 = ElementHash::from_matrix_event_id("$1", EventIdFormat::Legacy).unwrap();
        let h2 = ElementHash::from_matrix_event_id("$2", EventIdFormat::Legacy).unwrap();

        // Depth 0 encompasses everything
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 4,
        }];

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
        use crate::reconcile::triage::BucketRequest;
        let h1 = ElementHash::from_matrix_event_id("$1", EventIdFormat::Legacy).unwrap();
        let h2 = ElementHash::from_matrix_event_id("$2", EventIdFormat::Legacy).unwrap();

        let depth: u8 = 16;
        let shift = u32::from(H64_TRIE_WIDTH) - u32::from(depth);
        let prefix = u32::try_from(h1.h64 >> shift).unwrap();

        let requests = [BucketRequest {
            depth,
            prefix,
            capacity: 4,
        }];

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
        use crate::reconcile::triage::BucketRequest;
        let sorted_h64 = vec![];
        let requests = [BucketRequest {
            depth: 8,
            prefix: 256, // out of bounds for depth 8 (max prefix is 255)
            capacity: 4,
        }];
        assert_eq!(
            build_bucket_sketches(&sorted_h64, &requests),
            Err(AlgebraicError::InvalidBucketIndex)
        );

        let requests = [BucketRequest {
            depth: 7,
            prefix: 256, // out of bounds
            capacity: 4,
        }];
        assert_eq!(
            build_bucket_sketches(&sorted_h64, &requests),
            Err(AlgebraicError::InvalidBucketIndex)
        );
    }

    #[test]
    fn test_build_bucket_sketches_depth_0_slow_path() {
        use crate::reconcile::triage::BucketRequest;
        let h1 = ElementHash::from_matrix_event_id("$1", EventIdFormat::Legacy).unwrap();

        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 10, // > 8 forces the slow path
        }];

        let sorted_h64 = vec![h1.h64];
        let sketches = build_bucket_sketches(&sorted_h64, &requests).unwrap();

        assert_eq!(sketches.len(), 1);
        let roots = sketches[0].clone().decode_elements(10).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], h1.h64);
    }

    #[test]
    fn test_sketch_builder_build_success_no_split() {
        use crate::reconcile::triage::BucketRequest;
        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x2000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1000,
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 10,
        }];

        let result = builder.build(&requests).unwrap();
        if let SketchResult::Success(sketches) = result {
            assert_eq!(sketches.len(), 1);
        } else {
            panic!("Expected Success");
        }
    }

    #[test]
    fn test_sketch_builder_build_materializes_large_slice_at_small_capacity() {
        use crate::reconcile::triage::BucketRequest;
        let sorted_h64 = vec![0x0000_0000_0000_0001, 0x8000_0000_0000_0002];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1000,
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 1, // smaller than slice length (2)
        }];

        let result = builder.build(&requests).unwrap();
        assert!(matches!(result, SketchResult::Success(sketches) if sketches.len() == 1));
    }

    #[test]
    fn test_sketch_builder_build_hard_fallback() {
        use crate::reconcile::triage::BucketRequest;
        let sorted_h64 = vec![1, 2, 3];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1000,
            hard_fallback_threshold: 2, // 3 > 2, triggers hard fallback
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 1,
        }];

        let result = builder.build(&requests).unwrap();
        assert!(matches!(result, SketchResult::FallbackToRangeSync));
    }

    #[test]
    fn test_sketch_builder_build_budget_exhausted() {
        use crate::reconcile::triage::BucketRequest;
        // Two elements, capacity 1, will split.
        // Splitting creates two slices of length 1.
        // Aggregate work will be 1 + 1 = 2.
        let sorted_h64 = vec![0x0000_0000_0000_0001, 0x8000_0000_0000_0002];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1, // Budget of 1 will be exhausted since 2 work is needed
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 1,
        }];

        let result = builder.build(&requests).unwrap();
        assert!(matches!(result, SketchResult::FallbackToRangeSync));
    }

    #[test]
    fn test_sketch_builder_build_falls_back_on_aggregate_work_limit() {
        use crate::reconcile::triage::BucketRequest;

        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x9000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1,
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [
            BucketRequest {
                depth: 1,
                prefix: 0,
                capacity: 1,
            },
            BucketRequest {
                depth: 1,
                prefix: 1,
                capacity: 1,
            },
        ];

        let result = builder.build(&requests).unwrap();
        assert!(matches!(result, SketchResult::FallbackToRangeSync));
    }

    #[test]
    fn test_sketch_builder_build_propagates_bucket_materialization_errors() {
        use crate::reconcile::triage::BucketRequest;

        let sorted_h64 = vec![0, 0x1000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1000,
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 2,
        }];

        assert!(matches!(
            builder.build(&requests),
            Err(AlgebraicError::ZeroShortIdentifier)
        ));
    }

    #[test]
    fn test_sketch_builder_build_rejects_malformed_request_before_localization() {
        use crate::reconcile::triage::BucketRequest;
        let sorted_h64 = vec![0x1000_0000_0000_0000, 0x2000_0000_0000_0000];
        let index = H64Index::new(&sorted_h64);

        let policy = SketchPolicy {
            max_aggregate_work: 1000,
            hard_fallback_threshold: 1000,
        };

        let builder = SketchBuilder::new(&index, policy);
        // Zero capacity is rejected by `validate_bucket_requests` before any
        // range localization is attempted.
        let requests = [BucketRequest {
            depth: 0,
            prefix: 0,
            capacity: 0,
        }];

        assert!(matches!(
            builder.build(&requests),
            Err(AlgebraicError::InvalidSketchCapacity)
        ));
    }
}
