// Copyright 2026 Shane Jaroch
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::network::fetch_room_state;
use crate::Args;
use rezzy::basespec::event_types::{
    EventType, FIELD_CONTENT, FIELD_EVENT_ID, FIELD_ROOM_VERSION, FIELD_STATE_KEY, FIELD_TYPE,
    FIELD_USERS, FIELD_USERS_DEFAULT, M_ROOM_CREATE, M_ROOM_JOIN_RULES, M_ROOM_MEMBER,
    M_ROOM_POWER_LEVELS,
};
use rezzy::{LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::PathBuf;
use std::time::Instant;

pub type SharedStateMap = std::sync::Arc<ResolvedState>;

/// Parse a room version string.
pub fn parse_room_version(ver: &str) -> anyhow::Result<StateResVersion> {
    StateResVersion::from_room_version(ver)
        .ok_or_else(|| anyhow::anyhow!("Unsupported room version: {ver}"))
}

/// Detect the room version from a state map.
pub fn detect_version(
    events: &[serde_json::Value],
    debug: bool,
) -> anyhow::Result<StateResVersion> {
    for ev in events {
        if ev.get(FIELD_TYPE).and_then(|t| t.as_str()) == Some(M_ROOM_CREATE) {
            if let Some(ver) = ev
                .get(FIELD_CONTENT)
                .and_then(|c| c.get(FIELD_ROOM_VERSION))
                .and_then(|v| v.as_str())
            {
                if debug {
                    eprintln!("[DEBUG] Found m.room.create with version: {ver}");
                }
                return parse_room_version(ver);
            }
        }
    }

    anyhow::bail!(
        "No m.room.create event found — cannot detect room version. \
         Use --state-res to specify the algorithm manually."
    )
}

/// Detect `prev_events` and `auth_events` references that point to events
/// absent from `events_map` and not known to the `exists` oracle.
///
/// This is the "warn surface" for DAG gaps. A reference to an unknown event is
/// *not* necessarily a resolution failure — a missing `prev_event` is a backward
/// extremity (incomplete timeline / backfill needed), while a missing
/// `auth_event` means the event's authorization cannot be verified (potentially
/// unsafe state). The two cases are reported separately so callers can treat
/// them differently.
///
/// `exists` is the seam where a caller can plug in a richer notion of "known":
/// e.g. a query against a homeserver's event store, a fetch attempt, or a
/// compact accumulator (Bloom filter / 128-bit digest) of the known event set.
/// A `|_| false` oracle means "known iff present in `events_map`".
///
/// Returns `(backward_extremities, missing_auth_events)`.
pub fn report_gaps<F>(
    events_map: &HashMap<String, LeanEvent>,
    exists: F,
) -> (
    Vec<rezzy::state::BackwardExtremity<String>>,
    Vec<rezzy::state::MissingAuthEvent<String>>,
)
where
    F: Fn(&String) -> bool,
{
    let backward = rezzy::find_backward_extremities(events_map, &exists);
    let missing_auth = rezzy::find_missing_auth_events(events_map, &exists);
    (backward, missing_auth)
}

/// Computes an FNV-1a hash of `StateEntries`.
pub fn compute_state_hash(state: &imbl::OrdMap<(EventType, String), String>) -> String {
    let mut hash: u64 = 14_695_981_039_346_656_037; // FNV offset basis
    for ((event_type, state_key), event_id) in state {
        for &byte in event_type.as_str().as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211); // FNV prime
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        for &byte in state_key.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash ^= 0x00;
        hash = hash.wrapping_mul(1_099_511_628_211);
        for &byte in event_id.as_bytes() {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(1_099_511_628_211);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(1_099_511_628_211);
    }
    format!("{hash:016x}")
}

/// Load a JSON file.
pub fn load_file(input_path: &PathBuf) -> anyhow::Result<Vec<serde_json::Value>> {
    let input_reader: Box<dyn Read> = if input_path.to_str() == Some("-") {
        Box::new(io::stdin())
    } else {
        Box::new(File::open(input_path)?)
    };

    let is_jsonl = input_path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));

    let mut reader = BufReader::new(input_reader);

    if is_jsonl {
        let mut values = Vec::new();
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let val: serde_json::Value = serde_json::from_str(&line)?;
            values.push(val);
        }
        if values.is_empty() {
            anyhow::bail!("No input data provided in JSONL file.");
        }
        Ok(values)
    } else {
        let mut input_data = Vec::new();
        loop {
            let mut line = String::new();
            let bytes_read = reader.read_line(&mut line)?;
            if bytes_read == 0 {
                break;
            }
            if line.trim().is_empty() {
                continue;
            }
            input_data.extend_from_slice(line.as_bytes());
        }
        if input_data.is_empty() {
            anyhow::bail!("No input data provided before empty line or EOF.");
        }
        let val: serde_json::Value = serde_json::from_slice(&input_data)?;
        match val {
            serde_json::Value::Array(arr) => Ok(arr),
            other => Ok(vec![other]),
        }
    }
}

/// Load or fetch the input value from args.
pub fn load_or_fetch_input_value(args: &Args) -> anyhow::Result<serde_json::Value> {
    if let Some(room_id) = &args.room {
        let homeserver = args
            .homeserver
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--homeserver is required when using --room"))?;

        let token = args.token.clone().or_else(|| {
            let env_key = format!(
                "MTOKEN_{}",
                homeserver
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .to_uppercase()
                    .replace(['.', '-'], "_")
            );
            std::env::var(&env_key).ok()
        });
        fetch_room_state(homeserver, room_id, token.as_deref())
    } else if !args.input.is_empty() {
        if args.input.len() == 1 {
            let input_path = &args.input[0];
            let is_jsonl = input_path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"));
            if is_jsonl {
                let events = load_file(input_path)?;
                Ok(serde_json::Value::Array(events))
            } else {
                let content = std::fs::read(input_path)?;
                let val: serde_json::Value = serde_json::from_slice(&content)?;
                Ok(val)
            }
        } else {
            let mut file_sets = Vec::with_capacity(args.input.len());
            for path in &args.input {
                let label = path.file_name().map_or_else(
                    || path.display().to_string(),
                    |n| n.to_string_lossy().to_string(),
                );
                let events = load_file(path)?;
                file_sets.push((label, events));
            }
            let merged = crate::jsonl_merge::merge_event_sets(&file_sets, args.debug, args.quiet)?;
            Ok(serde_json::Value::Array(merged))
        }
    } else {
        anyhow::bail!("Either --input or --room must be provided.");
    }
}

/// Parse input and extract the state heads.
pub fn parse_and_extract_heads(
    input_val: &serde_json::Value,
) -> anyhow::Result<(Vec<serde_json::Value>, Vec<String>)> {
    let (raw_events, heads) = if let Some(obj) = input_val.as_object() {
        if obj.contains_key("events") {
            let evs = obj
                .get("events")
                .unwrap()
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("'events' field must be a JSON array"))?
                .clone();
            let mut hds = Vec::new();
            if let Some(hds_arr) = obj.get("heads").and_then(|h| h.as_array()) {
                for v in hds_arr {
                    hds.push(
                        v.as_str()
                            .ok_or_else(|| anyhow::anyhow!("each 'head' must be a string"))?
                            .to_string(),
                    );
                }
            }
            (evs, hds)
        } else if obj.contains_key(FIELD_EVENT_ID) || obj.contains_key(FIELD_TYPE) {
            (vec![input_val.clone()], Vec::new())
        } else {
            anyhow::bail!(
                "Unrecognized JSON object structure. Top-level object must either contain 'events' or represent a single event with 'event_id' or 'type'."
            );
        }
    } else if let Some(arr) = input_val.as_array() {
        (arr.clone(), Vec::new())
    } else {
        anyhow::bail!("Unexpected JSON format: expected object or array");
    };
    Ok((raw_events, heads))
}

fn collect_reachable_events<'a>(
    start_id: &str,
    events_map: &'a HashMap<String, LeanEvent>,
) -> Vec<&'a LeanEvent> {
    let mut visited = std::collections::HashSet::new();
    let mut stack = vec![start_id.to_string()];
    let mut reachable = Vec::new();
    while let Some(ev_id) = stack.pop() {
        if visited.insert(ev_id.clone()) {
            if let Some(ev) = events_map.get(&ev_id) {
                reachable.push(ev);
                for pe in &ev.prev_events {
                    stack.push(pe.clone());
                }
            }
        }
    }
    reachable
}

fn build_state_map(
    sorted_events: Vec<&LeanEvent>,
    raw_map: &HashMap<String, serde_json::Value>,
) -> HashMap<(EventType, String), String> {
    let mut state_map = HashMap::new();
    for ev in sorted_events {
        if raw_map
            .get(&ev.event_id)
            .is_some_and(|r| r.get(FIELD_STATE_KEY).is_some())
        {
            let key = (
                EventType::from(ev.event_type.clone()),
                ev.state_key.clone().unwrap(),
            );
            state_map.insert(key, ev.event_id.clone());
        }
    }
    state_map
}

/// Compute state maps for the given events.
pub fn compute_state_maps(
    heads: &[String],
    events_map: &HashMap<String, LeanEvent>,
    raw_map: &HashMap<String, serde_json::Value>,
) -> Vec<HashMap<(EventType, String), String>> {
    if heads.len() <= 1 {
        let reachable_set: std::collections::HashSet<String> = if heads.len() == 1 {
            collect_reachable_events(&heads[0], events_map)
                .into_iter()
                .map(|ev| ev.event_id.clone())
                .collect()
        } else {
            events_map.keys().cloned().collect()
        };

        let mut sorted_events: Vec<&LeanEvent> = events_map
            .values()
            .filter(|ev| reachable_set.contains(&ev.event_id))
            .collect();
        sorted_events.sort_by(|a, b| a.cmp_by_depth(b));

        vec![build_state_map(sorted_events, raw_map)]
    } else {
        let mut maps = Vec::new();
        for head_id in heads {
            let mut reachable = collect_reachable_events(head_id, events_map);
            reachable.sort_by(|a, b| a.cmp_by_depth(b));
            maps.push(build_state_map(reachable, raw_map));
        }
        maps
    }
}

pub type ResolvedState = imbl::OrdMap<(EventType, String), String>;

/// Resolve parent states for a set of events.
pub fn resolve_parent_states(
    parent_states: &[SharedStateMap],
    events_map: &HashMap<String, LeanEvent>,
    version: StateResVersion,
) -> SharedStateMap {
    // Fast path: all parent states are identical (Arc::ptr_eq or value equality).
    // Common in linear DAGs where every parent shares the same resolved state.
    if parent_states.len() > 1 {
        let first = &parent_states[0];
        let all_identical = parent_states[1..]
            .iter()
            .all(|s| std::sync::Arc::ptr_eq(s, first) || s.as_ref() == first.as_ref());
        if all_identical {
            return first.clone();
        }
    }

    // Unwrap Arc<OrdMap> → &OrdMap for the library call
    let bare_maps: Vec<ResolvedState> = parent_states
        .iter()
        .map(|arc| arc.as_ref().clone())
        .collect();
    let resolved = rezzy::resolve_state_maps(&bare_maps, events_map, version);
    std::sync::Arc::new(resolved)
}

/// Partition and resolve state across components.
pub fn partition_and_resolve_state(
    heads: &[String],
    events_map: &HashMap<String, LeanEvent>,
    state_maps: &[HashMap<(EventType, String), String>],
    version: StateResVersion,
    auth_graph: &rezzy::auth::roaring::AuthGraph,
) -> (ResolvedState, std::time::Duration) {
    let start = Instant::now();
    let (unconflicted_state, conflicted_state_set) =
        rezzy::partition_state_maps(state_maps, state_maps.len());

    let mut auth_difference = std::collections::HashSet::new();
    if !heads.is_empty() {
        let mut union = roaring::RoaringBitmap::new();
        let mut intersection = roaring::RoaringBitmap::new();
        let mut first = true;

        for head_id in heads {
            if let Some(&idx) = auth_graph.id_to_index.get(head_id) {
                let chain_bitmap = &auth_graph.auth_bitmaps[idx as usize];
                if first {
                    union.clone_from(chain_bitmap);
                    intersection.clone_from(chain_bitmap);
                    first = false;
                } else {
                    union |= chain_bitmap;
                    intersection &= chain_bitmap;
                }
            }
        }

        let diff = <roaring::RoaringBitmap as std::ops::Sub<&roaring::RoaringBitmap>>::sub(
            union,
            &intersection,
        );
        for idx in diff {
            auth_difference.insert(auth_graph.index_to_id[idx as usize].clone());
        }
    }

    let mut conflicted_events = HashMap::new();
    for id in &conflicted_state_set {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    for id in &auth_difference {
        if let Some(ev) = events_map.get(id) {
            conflicted_events.insert(id.clone(), ev.clone());
        }
    }

    if version == StateResVersion::V2_1 || version == StateResVersion::V2_1_1 {
        let subgraph = rezzy::compute_v2_1_conflicted_subgraph(events_map, &conflicted_state_set);
        for (id, ev) in subgraph {
            conflicted_events.insert(id, ev);
        }
    }

    let mut pl_cache = HashMap::new();
    let final_state_map = rezzy::resolve_iterative_sort(
        unconflicted_state,
        conflicted_events,
        events_map,
        version,
        &mut pl_cache,
    );

    let duration = start.elapsed();
    (final_state_map, duration)
}

/// Apply global power levels to the state.
pub fn apply_global_power_levels(
    events_map: &mut HashMap<String, LeanEvent>,
    creator_user_id: &str,
    version: StateResVersion,
) {
    let mut power_events = HashMap::new();
    let power_event_types = [
        M_ROOM_CREATE,
        M_ROOM_POWER_LEVELS,
        M_ROOM_JOIN_RULES,
        M_ROOM_MEMBER,
    ];
    for ev in events_map.values() {
        if power_event_types.contains(&ev.event_type.as_str()) {
            let mut power_ev = ev.clone();
            if (!creator_user_id.is_empty() && ev.sender == creator_user_id)
                || ev.event_type == M_ROOM_CREATE
            {
                power_ev.power_level = 100;
            } else {
                power_ev.power_level = 0;
            }
            power_events.insert(ev.event_id.clone(), power_ev);
        }
    }

    let create_ev = events_map
        .values()
        .find(|ev| ev.event_type == M_ROOM_CREATE);
    let mut pl_cache = HashMap::new();
    let sorted_power_ids =
        rezzy::lean_kahn_sort(&power_events, events_map, create_ev, version, &mut pl_cache);
    let mut resolved_power_state = imbl::OrdMap::new();
    for id in sorted_power_ids {
        if let Some(ev) = power_events.get(&id) {
            resolved_power_state.insert((ev.event_type.clone(), ev.state_key.clone().unwrap()), id);
        }
    }

    let mut user_power_levels = HashMap::new();
    let mut default_power_level = 0;
    if let Some(id) = resolved_power_state.get(&(M_ROOM_POWER_LEVELS.to_string(), String::new())) {
        if let Some(ev) = events_map.get(id) {
            if let Some(users) = ev.content.get(FIELD_USERS).and_then(|u| u.as_object()) {
                for (user_id, pl) in users {
                    if let Some(pl_val) = pl.as_i64() {
                        user_power_levels.insert(user_id.clone(), pl_val);
                    }
                }
            }
            if let Some(pl_val) = ev
                .content
                .get(FIELD_USERS_DEFAULT)
                .and_then(serde_json::Value::as_i64)
            {
                default_power_level = pl_val;
            }
        }
    }

    for ev in events_map.values_mut() {
        ev.power_level = *user_power_levels
            .get(&ev.sender)
            .unwrap_or(&default_power_level);
    }
}

/// Convert epoch days to a YMD tuple.
pub fn epoch_days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days.wrapping_add(719_468);
    let era = (if z >= 0 { z } else { z.wrapping_sub(146_096) }).wrapping_div(146_097);
    let doe = u64::try_from(z.wrapping_sub(era.wrapping_mul(146_097))).unwrap();
    let yoe = (doe
        .wrapping_sub(doe.wrapping_div(1460))
        .wrapping_add(doe.wrapping_div(36524))
        .wrapping_sub(doe.wrapping_div(146_096)))
    .wrapping_div(365);
    let y = i64::try_from(yoe)
        .unwrap()
        .wrapping_add(era.wrapping_mul(400));
    let doy = doe.wrapping_sub(
        (365_u64)
            .wrapping_mul(yoe)
            .wrapping_add(yoe.wrapping_div(4))
            .wrapping_sub(yoe.wrapping_div(100)),
    );
    let mp = (5_u64.wrapping_mul(doy).wrapping_add(2)).wrapping_div(153);
    let d = u32::try_from(
        doy.wrapping_sub((153_u64.wrapping_mul(mp).wrapping_add(2)).wrapping_div(5))
            .wrapping_add(1),
    )
    .unwrap();
    let m = u32::try_from(if mp < 10 {
        mp.wrapping_add(3)
    } else {
        mp.wrapping_sub(9)
    })
    .unwrap();
    let y = if m <= 2 { y.wrapping_add(1) } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rezzy::LeanEvent;

    fn map_from_jsonl(jsonl: &str) -> HashMap<String, LeanEvent> {
        jsonl
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let e: LeanEvent = serde_json::from_str(l).unwrap_or_else(|err| {
                    panic!("failed to parse JSONL fixture line: {err}\nline: {l}")
                });
                (e.event_id.clone(), e)
            })
            .collect()
    }

    /// A gap in `auth_events` must be reported distinctly from a `prev_events`
    /// gap, and both must be absent when no oracle gap exists.
    #[test]
    fn test_report_gaps_distinguishes_prev_vs_auth() {
        let events = map_from_jsonl(
            r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","MISSING_PREV"],"auth_events":["A","B"]}
{"event_id":"D","type":"m.room.message","sender":"@x:x","depth":4,"prev_events":["C"],"auth_events":["A","MISSING_AUTH"]}
            "#,
        );

        let (backward, missing_auth) = report_gaps(&events, |_| false);

        assert_eq!(backward.len(), 1);
        assert_eq!(backward[0].event_id, "C");
        assert_eq!(backward[0].missing_prev_events, vec!["MISSING_PREV"]);

        assert_eq!(missing_auth.len(), 1);
        assert_eq!(missing_auth[0].event_id, "D");
        assert_eq!(missing_auth[0].missing_auth_events, vec!["MISSING_AUTH"]);
    }

    /// The `exists` oracle suppresses gaps for events the caller knows about
    /// outside the map (the seam for a fetch check / 128-bit accumulator).
    #[test]
    fn test_report_gaps_uses_exists_oracle() {
        let events = map_from_jsonl(
            r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.message","sender":"@x:x","depth":2,"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B","KNOWN_ELSEWHERE"],"auth_events":["A"]}
            "#,
        );

        // No oracle: the reference to KNOWN_ELSEWHERE is a backward extremity.
        let (backward, _) = report_gaps(&events, |_| false);
        assert_eq!(backward.len(), 1);

        // Oracle that knows KNOWN_ELSEWHERE: gap suppressed.
        let (backward, _) = report_gaps(&events, |id| id == "KNOWN_ELSEWHERE");
        assert!(backward.is_empty(), "oracle-known prev must not be a gap");
    }

    /// A fully-connected DAG reports no gaps.
    #[test]
    fn test_report_gaps_clean() {
        let events = map_from_jsonl(
            r#"
{"event_id":"A","type":"m.room.create","state_key":"","sender":"@x:x","depth":1,"content":{"room_version":"10","creator":"@x:x"},"prev_events":[],"auth_events":[]}
{"event_id":"B","type":"m.room.member","state_key":"@x:x","sender":"@x:x","depth":2,"content":{"membership":"join"},"prev_events":["A"],"auth_events":["A"]}
{"event_id":"C","type":"m.room.message","sender":"@x:x","depth":3,"prev_events":["B"],"auth_events":["A","B"]}
            "#,
        );
        let (backward, missing_auth) = report_gaps(&events, |_| false);
        assert!(backward.is_empty());
        assert!(missing_auth.is_empty());
    }
}
