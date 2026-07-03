mod utils;

use rezzy::{verify_pagination, LeanEvent, PaginationViolation, StateResVersion};
use std::collections::HashMap;

/// Negative test: `verify_pagination` must detect duplicate events
/// across pages. Forked DAG (A root, B/C fork, D continues B, E merges).
/// We manually place "C" on two different pages.
#[test]
fn test_verify_pagination_detects_duplicates() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":5,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":[]}
{"event_id":"E","type":"m.room.message","sender":"@x:x","depth":6,"prev_events":["C","D"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect();

    // Deliberately duplicate "C" on page 0 AND page 1
    let pages: Vec<Vec<String>> = vec![
        vec!["E".into(), "C".into()],
        vec!["C".into(), "B".into()], // "C" duplicated here
        vec!["A".into()],
    ];

    let violations = verify_pagination(&events_map, &pages);
    assert!(!violations.is_empty(), "must detect at least one violation");

    let has_dup = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::Duplicate {
                event_id,
                first_page: 0,
                second_page: 1,
            } if event_id == "C"
        )
    });
    assert!(
        has_dup,
        "must report C as duplicate on pages 0 and 1, got: {violations:?}"
    );
}

/// Negative test: `verify_pagination` must detect an ancestor appearing
/// on an earlier page than its descendant (violates backward-pagination
/// ordering where descendants come first).
///
/// DAG: A → B → C (linear chain, depths 1 → 2 → 3).
/// Broken pages: page 0 = [A], page 1 = [C, B].
#[test]
fn test_verify_pagination_detects_ancestor_before_descendant() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect();

    // Broken ordering: ancestor A on page 0 (earlier), descendants on page 1.
    let pages: Vec<Vec<String>> = vec![
        vec!["A".into()],             // page 0: ancestor (WRONG — too early)
        vec!["C".into(), "B".into()], // page 1: descendants
    ];

    let violations = verify_pagination(&events_map, &pages);
    assert!(
        !violations.is_empty(),
        "must detect ancestor-before-descendant violations"
    );

    // B's parent is A. A is on page 0, B is on page 1.
    // verify_pagination checks: for each event, each prev_event must be
    // on a page with index >= this event's page. A (page 0) < B (page 1) → violation.
    let has_ancestor_violation = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::AncestorAfterDescendant {
                ancestor,
                descendant,
                ancestor_page: 0,
                descendant_page: 1,
            } if ancestor == "A" && descendant == "B"
        )
    });
    assert!(
        has_ancestor_violation,
        "must report A (page 0) as ancestor appearing before descendant B (page 1), got: {violations:?}"
    );
}

// ─── Depth inflation regression tests (continuwuity P0.1) ────────────

/// Shared DAG for depth inflation tests. Branch B has `event.depth = 50`
/// (attacker-inflated), but topologically it's only depth 2.
///
/// ```text
///         A (event.depth=1, topo_depth=1)
///        / \
///       B   C   (B: event.depth=50 [INFLATED], topo_depth=2)
///        \ /    (C: event.depth=2  [honest],   topo_depth=2)
///         D     (event.depth=3, topo_depth=3)
/// ```
fn inflated_depth_dag() -> HashMap<String, LeanEvent> {
    utils::parse_jsonl_events(r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":50,"prev_events":["A"],"auth_events":[]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":[]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","C"],"auth_events":[]}
    "#).into_iter().map(|e| (e.event_id.clone(), e)).collect()
}

/// `compute_depths` and `compute_state_at` are siblings — both call
/// `topological_sort_short_ids` independently. This test proves BOTH
/// are immune to inflated `event.depth` values.
#[test]
fn test_topo_functions_ignore_federation_depth() {
    let events_map = inflated_depth_dag();

    // ── compute_depths: must derive from prev_events, not event.depth ──
    let depths = rezzy::compute_depths(&events_map);
    assert_eq!(depths["A"], 1, "root has topo_depth 1");
    assert_eq!(
        depths["B"], 2,
        "B must have topo_depth 2 despite event.depth=50"
    );
    assert_eq!(depths["C"], 2, "C has topo_depth 2");
    assert_eq!(
        depths["D"], 3,
        "D = max(B=2, C=2) + 1, NOT influenced by B's event.depth=50"
    );

    // ── compute_state_at: streaming pipeline uses same topo sort ──
    // If the topo sort were fooled by event.depth, it would process B
    // AFTER D (depth 50 > 3), producing wrong state at D.
    let state = rezzy::compute_state_at("D", &events_map, StateResVersion::V2)
        .expect("D must be reachable");
    // The create event from A must be in the resolved state at D
    assert_eq!(
        state.get(&("m.room.create".into(), String::new())),
        Some(&"A".into()),
        "state at D must include the create event from A"
    );
}

/// A paginator that naively orders by `event.depth` (federation-supplied)
/// instead of `compute_depths` produces broken backward pagination that
/// `verify_pagination` catches. This is the continuwuity P0.1 bug.
#[test]
fn test_inflated_depth_pagination_caught_by_verification() {
    let events_map = inflated_depth_dag();

    // Simulate the BROKEN paginator: sort by event.depth descending (naive).
    let mut naive_order: Vec<_> = events_map.values().collect();
    naive_order.sort_by_key(|b| std::cmp::Reverse(b.depth));
    let naive_ids: Vec<String> = naive_order.iter().map(|e| e.event_id.clone()).collect();

    // B (depth=50) sorts first, but D is B's child — B before D is wrong.
    assert_eq!(
        naive_ids[0], "B",
        "naive ordering puts B first due to inflated depth"
    );

    // verify_pagination checks ordering ACROSS pages (ancestor must not
    // appear on an earlier page than its descendant). One event per page
    // makes every position a page boundary.
    let pages: Vec<Vec<String>> = naive_ids.iter().map(|id| vec![id.clone()]).collect();
    let violations = verify_pagination(&events_map, &pages);
    assert!(
        !violations.is_empty(),
        "verify_pagination must catch the inflated-depth ordering"
    );

    // Specifically: B is an ancestor of D, but B appears before D in the page.
    // In backward pagination, descendants come first — so B (ancestor) before
    // D (descendant) is an AncestorAfterDescendant violation.
    let has_inflation_violation = violations.iter().any(|v| {
        matches!(
            v,
            PaginationViolation::AncestorAfterDescendant {
                ancestor, descendant, ..
            } if ancestor == "B" && descendant == "D"
        )
    });
    assert!(
        has_inflation_violation,
        "must catch B (inflated depth=50) before its descendant D, got: {violations:?}"
    );
}

/// `reverse_topological_order` must produce correct ordering regardless
/// of misleading `event.depth`. Positive counterpart to the test above.
#[test]
fn test_reverse_topo_order_correct_despite_inflated_depth() {
    let events_map = inflated_depth_dag();

    let order = rezzy::reverse_topological_order("D", &events_map, |a: &String, b: &String| {
        a.cmp(b).reverse()
    });

    assert_eq!(order.len(), 4, "all 4 events reachable from D");
    assert_eq!(order[0], "D", "D must be first (tip/newest)");
    assert_eq!(order[3], "A", "A must be last (root/oldest)");

    let pos = |id: &str| order.iter().position(|x| x == id).unwrap();
    assert!(pos("D") < pos("B"), "D before B");
    assert!(pos("D") < pos("C"), "D before C");
    assert!(pos("B") < pos("A"), "B before A");
    assert!(pos("C") < pos("A"), "C before A");

    // Verify the correct ordering passes verify_pagination
    let pages: Vec<Vec<String>> = order.chunks(2).map(<[String]>::to_vec).collect();
    let violations = verify_pagination(&events_map, &pages);
    assert!(
        violations.is_empty(),
        "rezzy's own reverse_topological_order must pass verification, got: {violations:?}"
    );
}

// ─── Auth gap detection tests ────────────────────────────────────────

/// `find_missing_auth_events` must detect auth chain gaps.
///
/// DAG: A (create) ← B (join, auth=[A]) ← C (message, auth=[A, B, MISSING])
/// Event "MISSING" is referenced by C's `auth_events` but absent from the map.
#[test]
fn test_find_missing_auth_events_detects_gap() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":["A","B","MISSING"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert_eq!(gaps.len(), 1, "only C has a missing auth event");
    assert_eq!(gaps[0].event_id, "C");
    assert_eq!(gaps[0].missing_auth_events, vec!["MISSING".to_string()]);
}

/// When all auth events are present, `find_missing_auth_events` returns empty.
#[test]
fn test_find_missing_auth_events_clean() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":["A","B"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert!(gaps.is_empty(), "all auth events present — no gaps");
}

/// The `exists` oracle suppresses false positives (auth event is in DB
/// but not loaded into the map).
#[test]
fn test_find_missing_auth_events_exists_oracle() {
    let events_map: HashMap<String, LeanEvent> = utils::parse_jsonl_events(
        r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":["A","IN_DB"]}
    "#,
    )
    .into_iter()
    .map(|e| (e.event_id.clone(), e))
    .collect();

    // Without oracle: IN_DB is missing
    let gaps = rezzy::find_missing_auth_events(&events_map, |_| false);
    assert_eq!(gaps.len(), 1);

    // With oracle: IN_DB exists externally
    let gaps = rezzy::find_missing_auth_events(&events_map, |id| id == "IN_DB");
    assert!(gaps.is_empty(), "oracle says IN_DB exists — no gap");
}

// ─── Topo positions tests ────────────────────────────────────────────

/// `compute_topo_positions` must produce a total order where every event
/// gets a unique position and parents always precede children.
///
/// Diamond DAG: A → B, A → C, B+C → D.
/// Tiebreak: lexicographic by `event_id` (B < C).
#[test]
fn test_compute_topo_positions_diamond() {
    let events_map = inflated_depth_dag(); // A, B(depth=50), C, D

    let sorted = rezzy::compute_topo_positions(&events_map, |a: &String, b: &String| a.cmp(b));

    assert_eq!(sorted.len(), 4, "all 4 events");

    let pos = |id: &str| sorted.iter().position(|x| x == id).unwrap();
    // Parents before children
    assert!(pos("A") < pos("B"), "A before B");
    assert!(pos("A") < pos("C"), "A before C");
    assert!(pos("B") < pos("D"), "B before D");
    assert!(pos("C") < pos("D"), "C before D");

    // B and C are at the same topo level — tiebreak is lexicographic, B < C
    assert!(pos("B") < pos("C"), "tiebreak: B < C lexicographically");

    // Every position is unique (total order)
    let actual: Vec<usize> = ["A", "B", "C", "D"].iter().map(|id| pos(id)).collect();
    let mut sorted_actual = actual.clone();
    sorted_actual.sort_unstable();
    sorted_actual.dedup();
    assert_eq!(
        sorted_actual.len(),
        4,
        "all positions must be unique: {actual:?}"
    );
}

/// Position-based ordering is immune to inflated `event.depth` values
/// (same property as `compute_depths`).
#[test]
fn test_compute_topo_positions_ignores_federation_depth() {
    let events_map = inflated_depth_dag(); // B has event.depth=50

    let sorted = rezzy::compute_topo_positions(&events_map, |a: &String, b: &String| a.cmp(b));

    // B must come AFTER A and BEFORE D, regardless of event.depth=50
    let pos = |id: &str| sorted.iter().position(|x| x == id).unwrap();
    assert!(pos("A") < pos("B"), "A before B despite B.depth=50");
    assert!(pos("B") < pos("D"), "B before D despite B.depth=50");
}
