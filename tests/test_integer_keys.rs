//! Tests for integer-keyed (`LeanEvent<u32>`) support across rezzy's public API.
//!
//! These tests verify that `SubgraphResult`, `compute_v2_1_conflicted_subgraph`,
//! `compute_v2_1_conflicted_subgraph_bounded`, and `AuthGraph` all work with
//! non-String event IDs. Previously these were hardcoded to `String`.

use rezzy::auth::roaring::AuthGraph;
use rezzy::resolve::subgraph::{compute_v2_1_conflicted_subgraph, compute_v2_1_conflicted_subgraph_bounded};
use rezzy::{HashMap, LeanEvent};
use serde_json::json;

/// Helper: build a `LeanEvent<u32>` with integer event ID.
fn make_u32_event(
    id: u32,
    event_type: &str,
    auth_events: Vec<u32>,
) -> LeanEvent<u32> {
    LeanEvent {
        event_id: id,
        event_type: event_type.into(),
        state_key: Some(String::new()),
        sender: "@alice:example.com".into(),
        content: json!({}),
        auth_events,
        prev_events: vec![],
        depth: u64::from(id),
        ..Default::default()
    }
}

// ─── SubgraphResult with u32 keys ───────────────────────────────────────

#[test]
fn test_subgraph_u32_basic() {
    // Diamond auth DAG:
    //   1 (create, no auth)
    //   ├── 2 (power_levels, auth: [1])
    //   └── 3 (member, auth: [1])
    //   └── 4 (member, auth: [2, 3])  ← not in graph, just 2 and 3 are conflicted
    //
    // Conflicted set = {2, 3}. Both point back to 1.
    // Backwards from 2: {2, 1}. Backwards from 3: {3, 1}. Union: {1, 2, 3}.
    // Forwards from 2: {2}. Forwards from 3: {3}. But 1 has children 2 and 3,
    //   so forwards from 2 includes 2, forwards from 3 includes 3,
    //   and 1 is a parent of both → forwards from {2,3} includes {2,3,1} via children_map.
    // Actually: children_map[1] = [2, 3] (since 2 and 3 both have 1 in auth_events).
    // Forward BFS from {2, 3}: visit 2 → no children. visit 3 → no children.
    // So forwards = {2, 3}. Backwards = {1, 2, 3}. Intersection = {2, 3}.
    let mut graph: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    graph.insert(1, make_u32_event(1, "m.room.create", vec![]));
    graph.insert(2, make_u32_event(2, "m.room.power_levels", vec![1]));
    graph.insert(3, make_u32_event(3, "m.room.member", vec![1]));

    let conflicted_set: Vec<u32> = vec![2, 3];
    let result = compute_v2_1_conflicted_subgraph(&graph, &conflicted_set);

    assert!(
        result.contains_key(&2),
        "conflicted event 2 must be in subgraph"
    );
    assert!(
        result.contains_key(&3),
        "conflicted event 3 must be in subgraph"
    );
}

#[test]
fn test_subgraph_bounded_u32() {
    // Auth DAG:  1 ← 2 ← 3, and also 1 ← 4
    // Conflicted: {3, 4} (two fork tips sharing ancestor 1)
    // Full backwards: from 3 → {3,2,1}, from 4 → {4,1}. Union = {1,2,3,4}.
    // Full forwards: from 3 → {3}, from 4 → {4}. children_map[1]={2,4},
    //   children_map[2]={3}. So forward BFS from {3,4}: 3→nothing, 4→nothing.
    //   Forwards = {3, 4}.
    // Intersection = {3, 4}.
    //
    // With max_depth=1: backwards from 3 = {3, 2}, backwards from 4 = {4, 1}.
    //   Union = {2, 3, 4, 1}. Intersection with forwards {3, 4} = {3, 4}.
    let mut graph: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    graph.insert(1, make_u32_event(1, "m.room.create", vec![]));
    graph.insert(2, make_u32_event(2, "m.room.power_levels", vec![1]));
    graph.insert(3, make_u32_event(3, "m.room.member", vec![2]));
    graph.insert(4, make_u32_event(4, "m.room.member", vec![1]));

    let conflicted_set: Vec<u32> = vec![3, 4];

    // Unbounded
    let full = compute_v2_1_conflicted_subgraph_bounded(&graph, &conflicted_set, None);
    assert!(
        full.subgraph.contains_key(&3),
        "conflicted event 3 must be in unbounded subgraph"
    );
    assert!(
        full.subgraph.contains_key(&4),
        "conflicted event 4 must be in unbounded subgraph"
    );
    assert!(full.missing_auth_events.is_empty());

    // Bounded to depth 1 — should still include conflicted events
    let bounded = compute_v2_1_conflicted_subgraph_bounded(&graph, &conflicted_set, Some(1));
    assert!(
        bounded.subgraph.contains_key(&3),
        "conflicted event 3 must be in bounded result"
    );
    assert!(
        bounded.subgraph.contains_key(&4),
        "conflicted event 4 must be in bounded result"
    );
}

#[test]
fn test_subgraph_u32_missing_auth_events() {
    // Event 2 references auth event 99 which doesn't exist in the graph.
    let mut graph: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    graph.insert(1, make_u32_event(1, "m.room.create", vec![]));
    graph.insert(2, make_u32_event(2, "m.room.member", vec![1, 99]));

    let conflicted_set: Vec<u32> = vec![2];
    let result = compute_v2_1_conflicted_subgraph_bounded(&graph, &conflicted_set, None);

    assert!(
        result.missing_auth_events.contains(&99),
        "missing auth event 99 must be reported"
    );
}

#[test]
fn test_subgraph_u32_empty_conflicted_set() {
    let graph: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    let conflicted_set: Vec<u32> = vec![];
    let result = compute_v2_1_conflicted_subgraph(&graph, &conflicted_set);
    assert!(result.is_empty(), "empty conflicted set → empty subgraph");
}

// ─── AuthGraph with u32 keys ────────────────────────────────────────────

#[test]
fn test_auth_graph_u32_build() {
    // Same topology as the existing String test: A(1) ← B(2) ← C(3)
    let mut ctx: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    ctx.insert(1, make_u32_event(1, "m.room.create", vec![]));
    ctx.insert(2, make_u32_event(2, "m.room.member", vec![1]));
    ctx.insert(3, make_u32_event(3, "m.room.message", vec![2]));

    let graph = AuthGraph::build(&ctx);

    assert_eq!(graph.id_to_index.len(), 3);
    assert_eq!(graph.index_to_id.len(), 3);

    let idx_1 = graph.id_to_index[&1];
    let idx_2 = graph.id_to_index[&2];
    let idx_3 = graph.id_to_index[&3];

    // Topological order: 1 before 2 before 3
    assert!(idx_1 < idx_2);
    assert!(idx_2 < idx_3);

    // Auth bitmaps
    assert!(graph.auth_bitmaps[idx_1 as usize].is_empty(), "root has no auth ancestors");
    assert!(graph.auth_bitmaps[idx_2 as usize].contains(idx_1), "2 auths with 1");
    assert_eq!(graph.auth_bitmaps[idx_2 as usize].len(), 1);
    assert!(graph.auth_bitmaps[idx_3 as usize].contains(idx_2), "3 auths with 2");
    assert!(graph.auth_bitmaps[idx_3 as usize].contains(idx_1), "3 transitively auths with 1");
    assert_eq!(graph.auth_bitmaps[idx_3 as usize].len(), 2);
}

#[test]
fn test_auth_graph_u32_diamond() {
    //    1 (create)
    //   / \
    //  2   3  (both auth with 1)
    //   \ /
    //    4    (auths with 2 and 3)
    let mut ctx: HashMap<u32, LeanEvent<u32>> = HashMap::new();
    ctx.insert(1, make_u32_event(1, "m.room.create", vec![]));
    ctx.insert(2, make_u32_event(2, "m.room.member", vec![1]));
    ctx.insert(3, make_u32_event(3, "m.room.power_levels", vec![1]));
    ctx.insert(4, make_u32_event(4, "m.room.member", vec![2, 3]));

    let graph = AuthGraph::build(&ctx);

    let idx_1 = graph.id_to_index[&1];
    let idx_4 = graph.id_to_index[&4];

    // Event 4's auth chain should contain 1, 2, and 3 (all ancestors)
    let bitmap_4 = &graph.auth_bitmaps[idx_4 as usize];
    assert_eq!(bitmap_4.len(), 3, "4 should have 3 transitive auth ancestors");
    assert!(bitmap_4.contains(idx_1), "4 must transitively reach 1");
}
