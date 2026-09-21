// CLI-only: Multi-file event set merging.
use crate::error::{AppError, ErrorCode};
use std::collections::{HashMap, HashSet};
use std::string::String;
use std::vec::Vec;

/// Per-file reference index: own `event_ids` plus every id the file *mentions*.
struct FileRefs {
    /// Top-level `event_id` values owned by this file.
    event_ids: HashSet<String>,
    /// Ids referenced in `auth_events` arrays.
    auth_refs: HashSet<String>,
    /// Ids referenced in `prev_events` arrays.
    prev_refs: HashSet<String>,
    /// Ids referenced via `content.m.relates_to.event_id` / `relates_to`.
    relates_to: HashSet<String>,
    /// Ids targeted by `m.room.redaction` (the `redacts` field).
    redacts: HashSet<String>,
    /// `(type, state_key)` pairs from state events — implicit state chain,
    /// not an event-ID reference, tracked for diagnostics.
    state_keys: HashSet<(String, String)>,
}

impl FileRefs {
    fn with_capacity(n: usize) -> Self {
        Self {
            event_ids: HashSet::with_capacity(n),
            auth_refs: HashSet::with_capacity(n),
            prev_refs: HashSet::with_capacity(n),
            relates_to: HashSet::with_capacity(n),
            redacts: HashSet::with_capacity(n),
            state_keys: HashSet::with_capacity(n),
        }
    }

    /// The union of all event-ID sets — used for the connectivity check.
    fn all_ids(&self) -> HashSet<&String> {
        let mut out: HashSet<&String> = HashSet::new();
        out.extend(&self.event_ids);
        out.extend(&self.auth_refs);
        out.extend(&self.prev_refs);
        out.extend(&self.relates_to);
        out.extend(&self.redacts);
        out
    }
}

/// Perform a connectivity check across states.
fn perform_connectivity_check(per_file_refs: &[FileRefs]) -> Result<(), AppError> {
    let num_files = per_file_refs.len();
    if num_files < 2 {
        return Ok(());
    }

    // Treat files as nodes in a graph. An edge exists if an OWNED event ID
    // from one file appears in the OTHER file's owned OR referenced IDs.
    // This prevents shared absent references from establishing connectivity.
    let all_ids_sets: Vec<HashSet<&String>> = per_file_refs.iter().map(|r| r.all_ids()).collect();
    let owned_ids_sets: Vec<HashSet<&String>> = per_file_refs
        .iter()
        .map(|r| r.event_ids.iter().collect())
        .collect();

    let mut visited = vec![false; num_files];
    let mut queue = Vec::new();
    queue.push(0);
    visited[0] = true;

    while let Some(current) = queue.pop() {
        for next in 0..num_files {
            if !visited[next] {
                // Edge from current -> next: current's owned IDs in next's all IDs
                let current_owns_next_refs = owned_ids_sets[current]
                    .intersection(&all_ids_sets[next])
                    .next()
                    .is_some();
                // Edge from next -> current: next's owned IDs in current's all IDs
                let next_owns_current_refs = owned_ids_sets[next]
                    .intersection(&all_ids_sets[current])
                    .next()
                    .is_some();

                if current_owns_next_refs || next_owns_current_refs {
                    visited[next] = true;
                    queue.push(next);
                }
            }
        }
    }

    for (idx, &is_visited) in visited.iter().enumerate() {
        if !is_visited {
            bail_code!(
                ErrorCode::DisjointDags,
                "Disjoint DAGs: input file at index {idx} shares no history with the connected component. \
                 Cannot compute meaningful merge — all inputs must share history."
            );
        }
    }
    Ok(())
}

/// Report the highest shared depths.
fn report_highest_shared_depths(per_file_refs: &[FileRefs], merged: &[rz_core::JsonValue]) {
    let num_files = per_file_refs.len();
    let all_sets: Vec<HashSet<&String>> = per_file_refs.iter().map(|r| r.all_ids()).collect();
    let shared_all: HashSet<&String> = {
        let mut s: HashSet<&String> = HashSet::new();
        for i in 0..num_files {
            for j in (i.saturating_add(1))..num_files {
                s.extend(all_sets[i].intersection(&all_sets[j]));
            }
        }
        s
    };
    let depth_by_id: HashMap<&str, u64> = merged
        .iter()
        .filter_map(|v| {
            let eid = v.get("event_id")?.as_str()?;
            Some((eid, v.get("depth")?.as_u64().unwrap_or(0)))
        })
        .collect();
    let mut shared_depths: Vec<(&String, u64)> = shared_all
        .iter()
        .filter_map(|id| depth_by_id.get(id.as_str()).map(|&depth| (*id, depth)))
        .collect();
    shared_depths.sort_by_key(|b| std::cmp::Reverse(b.1));
    std::eprintln!(
        "[merge] highest shared depths: {:?}",
        &shared_depths[..shared_depths.len().min(5)]
    );
}

fn collect_refs(val: &rz_core::JsonValue, refs: &mut FileRefs, event_id: &str) {
    if let Some(auth) = val.get("auth_events").and_then(|a| a.as_array()) {
        for ae in auth {
            if let Some(aid) = ae.as_str() {
                refs.auth_refs.insert(aid.to_owned());
            }
        }
    }

    if let Some(prev) = val.get("prev_events").and_then(|p| p.as_array()) {
        for pe in prev {
            if let Some(pid) = pe.as_str() {
                refs.prev_refs.insert(pid.to_owned());
            }
        }
    }

    if let Some(content) = val.get("content") {
        if let Some(rel) = content.get("m.relates_to") {
            if let Some(rid) = rel.get("event_id").and_then(|v| v.as_str()) {
                refs.relates_to.insert(rid.to_owned());
            }
            if let Some(rid) = rel.get("relates_to").and_then(|v| v.as_str()) {
                refs.relates_to.insert(rid.to_owned());
            }
        }
    }

    if val.get("type").and_then(|t| t.as_str()) == Some("m.room.redaction") {
        if let Some(rid) = val.get("redacts").and_then(|v| v.as_str()) {
            refs.redacts.insert(rid.to_owned());
        }
        if let Some(rid) = val
            .get("content")
            .and_then(|c| c.get("redacts"))
            .and_then(|v| v.as_str())
        {
            refs.redacts.insert(rid.to_owned());
        }
    }

    if let Some(sk) = val.get("state_key").and_then(|s| s.as_str()) {
        if let Some(ty) = val.get("type").and_then(|t| t.as_str()) {
            refs.state_keys.insert((ty.to_owned(), sk.to_owned()));
        }
    }

    refs.event_ids.insert(event_id.to_owned());
}

/// Merge multiple event sets by `event_id` (first-seen wins, PDUs are immutable).
/// Returns the merged events.
///
/// # Errors
///
/// Returns an error if the files describe disjoint DAGs that share no history.
pub fn merge_event_sets(
    file_sets: &[(String, Vec<rz_core::JsonValue>)],
    debug: bool,
    quiet: bool,
) -> Result<Vec<rz_core::JsonValue>, AppError> {
    let num_files = file_sets.len();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut merged: Vec<rz_core::JsonValue> = Vec::new();
    let mut per_file_refs: Vec<FileRefs> = Vec::with_capacity(num_files);

    for (label, events) in file_sets {
        let mut refs = FileRefs::with_capacity(events.len());
        let mut added = 0usize;
        let mut dupes = 0usize;

        for val in events {
            let event_id = val
                .get("event_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();

            if event_id.is_empty() {
                continue;
            }

            collect_refs(val, &mut refs, &event_id);

            if seen_ids.insert(event_id) {
                merged.push(val.clone());
                added = added.saturating_add(1);
            } else {
                dupes = dupes.saturating_add(1);
            }
        }

        if !quiet {
            std::eprintln!(
                "[merge] {:<50} {:>6} {:>6} {:>6}  {:>5} {:>6} {:>7} {:>6} {:>5}",
                label,
                events.len(),
                added,
                dupes,
                refs.auth_refs.len(),
                refs.prev_refs.len(),
                refs.relates_to.len(),
                refs.redacts.len(),
                refs.state_keys.len(),
            );
        }
        per_file_refs.push(refs);
    }

    // Merge-base check: verify each file shares at least one event with another
    if num_files >= 2 {
        perform_connectivity_check(&per_file_refs)?;

        // Report total shared count (union of all pairwise intersections)
        let all_sets: Vec<HashSet<&String>> = per_file_refs.iter().map(|r| r.all_ids()).collect();
        let total_shared: usize = {
            let mut shared_ids: HashSet<&String> = HashSet::new();
            for i in 0..num_files {
                for j in (i.saturating_add(1))..num_files {
                    shared_ids.extend(all_sets[i].intersection(&all_sets[j]));
                }
            }
            shared_ids.len()
        };

        if !quiet {
            std::eprintln!(
                "[merge] merge-base: {total_shared} shared refs across {num_files} inputs"
            );
        }

        if debug {
            report_highest_shared_depths(&per_file_refs, &merged);
        }
    }

    if !quiet {
        std::eprintln!("[merge] total: {} unique events", merged.len());
    }

    Ok(merged)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use rz_core::json;

    fn ev(id: &str, depth: u64) -> rz_core::JsonValue {
        json!({
            "event_id": id,
            "type": "m.room.member",
            "state_key": format!("@user:{id}"),
            "origin_server_ts": 1000_u64.wrapping_add(depth),
            "depth": depth,
            "prev_events": [],
            "auth_events": []
        })
    }

    #[test]
    fn test_merge_dedup_by_event_id() {
        let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let b = vec![ev("$2", 2), ev("$3", 3), ev("$4", 4)];
        let result =
            merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();

        let ids: Vec<&str> = result
            .iter()
            .map(|v| v["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
    }

    #[test]
    fn test_merge_disjoint_fails() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$3", 3), ev("$4", 4)];
        let result = merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Disjoint DAGs"));
    }

    #[test]
    fn test_merge_pairwise_shared() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$2", 2), ev("$3", 3)];
        let c = vec![ev("$3", 3), ev("$4", 4)];
        let result = merge_event_sets(
            &[
                ("a.jsonl".into(), a),
                ("b.jsonl".into(), b),
                ("c.jsonl".into(), c),
            ],
            false,
            true,
        )
        .unwrap();

        let ids: Vec<&str> = result
            .iter()
            .map(|v| v["event_id"].as_str().unwrap())
            .collect();
        assert_eq!(ids, vec!["$1", "$2", "$3", "$4"]);
    }

    #[test]
    fn test_merge_single_file() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let result = merge_event_sets(&[("a.jsonl".into(), a)], false, true).unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_merge_complete_overlap() {
        let a = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let b = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3)];
        let result =
            merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_merge_subset() {
        let large = vec![ev("$1", 1), ev("$2", 2), ev("$3", 3), ev("$4", 4)];
        let small = vec![ev("$1", 1), ev("$2", 2)];
        let result = merge_event_sets(
            &[("large.jsonl".into(), large), ("small.jsonl".into(), small)],
            false,
            true,
        )
        .unwrap();
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn test_merge_debug_depths() {
        let a = vec![ev("$1", 10), ev("$2", 20)];
        let b = vec![ev("$2", 20), ev("$3", 30)];
        let result =
            merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], true, true).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_merge_single_event_per_file() {
        let a = vec![ev("$1", 1)];
        let b = vec![ev("$1", 1)];
        let result =
            merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_merge_two_single_events_disjoint() {
        let a = vec![ev("$1", 1)];
        let b = vec![ev("$2", 2)];
        let result = merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true);
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_two_events_one_shared() {
        let a = vec![ev("$1", 1), ev("$2", 2)];
        let b = vec![ev("$2", 2), ev("$3", 3)];
        let result =
            merge_event_sets(&[("a.jsonl".into(), a), ("b.jsonl".into(), b)], false, true).unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_shared_missing_reference_does_not_connect_files() {
        let mut a = ev("$a", 1);
        a["prev_events"] = json!(["$missing"]);
        let mut b = ev("$b", 1);
        b["prev_events"] = json!(["$missing"]);

        let result = merge_event_sets(
            &[("a.jsonl".into(), vec![a]), ("b.jsonl".into(), vec![b])],
            false,
            true,
        );

        assert_eq!(result.unwrap_err().code(), ErrorCode::DisjointDags);
    }

    #[test]
    fn test_merge_one_file_only() {
        let a = vec![ev("$1", 1)];
        let result = merge_event_sets(&[("a.jsonl".into(), a)], false, true).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_connectivity_via_auth_events() {
        // File a: only the create event (no auth/prev)
        let create = json!({
            "event_id": "$create",
            "type": "m.room.create",
            "state_key": "",
            "sender": "@alice:x",
            "origin_server_ts": 1000,
            "depth": 0,
            "content": {"room_version": "12"},
            "prev_events": [],
            "auth_events": []
        });
        // File b: a message that auth-references the create event
        let msg = json!({
            "event_id": "$msg",
            "type": "m.room.message",
            "sender": "@alice:x",
            "origin_server_ts": 2000,
            "depth": 1,
            "content": {"body": "hi"},
            "prev_events": [],
            "auth_events": ["$create"]
        });
        let result = merge_event_sets(
            &[
                ("create.jsonl".into(), vec![create]),
                ("msg.jsonl".into(), vec![msg]),
            ],
            false,
            true,
        );
        assert!(
            result.is_ok(),
            "auth_events reference should connect the files: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_connectivity_via_relates_to() {
        let a = vec![json!({
            "event_id": "$target",
            "type": "m.room.message",
            "sender": "@alice:x",
            "origin_server_ts": 1000,
            "depth": 1,
            "content": {"body": "original"},
            "prev_events": [],
            "auth_events": []
        })];
        let b = vec![json!({
            "event_id": "$reaction",
            "type": "m.reaction",
            "sender": "@bob:x",
            "origin_server_ts": 2000,
            "depth": 2,
            "content": {"m.relates_to": {"event_id": "$target", "rel_type": "m.annotation"}},
            "prev_events": [],
            "auth_events": []
        })];
        let result = merge_event_sets(
            &[("target.jsonl".into(), a), ("reaction.jsonl".into(), b)],
            false,
            true,
        );
        assert!(
            result.is_ok(),
            "m.relates_to should connect the files: {:?}",
            result.err()
        );
    }

    #[test]
    fn test_connectivity_via_redacts() {
        let a = vec![json!({
            "event_id": "$victim",
            "type": "m.room.message",
            "sender": "@alice:x",
            "origin_server_ts": 1000,
            "depth": 1,
            "content": {"body": "delete me"},
            "prev_events": [],
            "auth_events": []
        })];
        let b = vec![json!({
            "event_id": "$redaction",
            "type": "m.room.redaction",
            "sender": "@alice:x",
            "origin_server_ts": 2000,
            "depth": 2,
            "redacts": "$victim",
            "content": {"redacts": "$victim"},
            "prev_events": [],
            "auth_events": []
        })];
        let result = merge_event_sets(
            &[("victim.jsonl".into(), a), ("redaction.jsonl".into(), b)],
            false,
            true,
        );
        assert!(
            result.is_ok(),
            "m.room.redaction should connect the files: {:?}",
            result.err()
        );
    }
}
