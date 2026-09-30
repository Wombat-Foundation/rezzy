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

use crate::error::AppError;
use crate::provenance::{self, StreamOrderIndex};
use crate::timeline_order::{
    build_key, kahn_order_by, KeyValue, OrderKey, TimelineOrder, DEFAULT_TIE_BREAK,
    MISSING_STREAM_ORDER, SYNAPSE_TIE_BREAK,
};
use crate::utils::{epoch_days_to_ymd, resolve_parent_states, SharedStateMap};
use crate::{Args, OutputFormat};
use rezzy::auth::{apply_authorized_redactions, RedactionReport, RoomState};
use rezzy::basespec::event_types::EventType;
use rezzy::{resolved_state_entries, LeanEvent, StateResVersion};
use std::collections::HashMap;
use std::path::PathBuf;

pub struct FormattingContext<'a> {
    pub args: &'a Args,
    pub events_map: &'a HashMap<String, LeanEvent>,
    pub raw_map: &'a HashMap<String, rezzy::JsonValue>,
    pub heads: &'a [String],
    pub final_state_map: &'a imbl::OrdMap<(EventType, String), String>,
    pub resolved_state_list: &'a [String],
    pub auth_chain_ids: &'a [String],
    pub auth_graph: &'a rezzy::auth::roaring::AuthGraph,
    pub version: StateResVersion,
    pub room_version: Option<&'a str>,
    pub duration: std::time::Duration,
    pub event_count: usize,
    pub stream_order: Option<&'a StreamOrderIndex>,
}

use rezzy::hamt::{
    build_hamt, diff_hamt_nodes, persist_mutation, HamtNode, PersistedInternalNode, StructuralHash,
};

fn format_structural_hash(hash: &StructuralHash) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Output of a live event walk over the DAG.
pub struct HamtLiveWalkOutput {
    pub roots: Vec<rezzy::JsonValue>,
    pub nodes: Vec<rezzy::JsonValue>,
    pub checkpoints: Vec<rezzy::JsonValue>,
}

fn record_hamt_subtree_nodes(
    root: &std::sync::Arc<HamtNode<(EventType, String), String>>,
    seen: &mut std::collections::HashSet<StructuralHash>,
    nodes: &mut Vec<rezzy::JsonValue>,
) {
    let mut stack = vec![root.clone()];
    while let Some(node) = stack.pop() {
        if seen.insert(node.structural_hash) {
            let leaves = node
                .leaves
                .iter()
                .map(|((etype, skey), eid)| {
                    rezzy::json!({
                        "type": etype.as_str(),
                        "state_key": skey,
                        "event_id": eid,
                    })
                })
                .collect::<Vec<_>>();
            let children = node
                .children
                .iter()
                .map(|c| format_structural_hash(&c.structural_hash()))
                .collect::<Vec<_>>();
            nodes.push(rezzy::json!({
                "hash": format_structural_hash(&node.structural_hash),
                "datamap": node.datamap,
                "nodemap": node.nodemap,
                "leaves": leaves,
                "children": children,
            }));
            for child in &node.children {
                if let rezzy::hamt::NodeRef::Resolved(child_node) = child {
                    stack.push(child_node.clone());
                }
            }
        }
    }
}

fn hamt_to_state_map(
    root: &std::sync::Arc<HamtNode<(EventType, String), String>>,
) -> SharedStateMap {
    let mut map = imbl::OrdMap::new();
    let mut no_resolver = |_h: &StructuralHash| -> Result<
        std::sync::Arc<HamtNode<(EventType, String), String>>,
        std::convert::Infallible,
    > { unreachable!() };
    let _ = root.visit_entries(&mut no_resolver, &mut |key, event_id| {
        map.insert(key.clone(), event_id.clone());
        Ok::<(), std::convert::Infallible>(())
    });
    std::sync::Arc::new(map)
}

/// Run an incremental HAMT-backed live walk over DAG events.
#[allow(clippy::too_many_lines)]
#[must_use]
pub fn run_hamt_live_walk(ctx: &FormattingContext) -> HamtLiveWalkOutput {
    let debug = ctx.args.debug;
    let total = ctx.event_count;
    let progress_interval = if debug { 10_000 } else { 50_000 };
    if debug {
        eprintln!("[DEBUG] hamt walk: walking {total} events...");
    }
    let overall_start = std::time::Instant::now();

    let tie_break = if ctx.args.tie_break.is_empty() {
        DEFAULT_TIE_BREAK.as_slice()
    } else {
        ctx.args.tie_break.as_slice()
    };
    let raw_events: Vec<LeanEvent> = ctx.events_map.values().cloned().collect();
    let sorted_events = reorder_by_kahn(&raw_events, tie_break, ctx.stream_order);

    let structural_key: &[u8] = ctx
        .args
        .room
        .as_deref()
        .map(str::as_bytes)
        .or_else(|| {
            ctx.events_map
                .values()
                .find_map(|e| e.room_id.as_deref())
                .map(str::as_bytes)
        })
        .unwrap_or(b"");

    let empty_root = build_hamt::<(EventType, String), String, _>(structural_key, [])
        .expect("empty HAMT build must succeed");

    let mut roots_map: HashMap<String, std::sync::Arc<HamtNode<(EventType, String), String>>> =
        HashMap::new();

    let mut seen_node_hashes: std::collections::HashSet<StructuralHash> =
        std::collections::HashSet::new();
    let mut unique_nodes = Vec::new();
    let mut roots_json = Vec::new();
    let mut checkpoints = Vec::new();

    let mut fork_count: usize = 0;
    let mut fork_time = std::time::Duration::ZERO;
    let mut processed: usize = 0;

    let mut no_resolver =
        |_h: &StructuralHash| -> Result<
            std::sync::Arc<HamtNode<(EventType, String), String>>,
            std::convert::Infallible,
        > { unreachable!("in-memory HAMT nodes do not have unresolvable lazy references") };

    for ev in &sorted_events {
        processed = processed.saturating_add(1);
        if debug && processed.checked_rem(progress_interval) == Some(0) {
            eprintln!(
                "[DEBUG] hamt walk: {processed}/{total} events walked ({fork_count} forks resolved, {:.2?} spent in state-res) elapsed {:.2?}",
                fork_time,
                overall_start.elapsed()
            );
        }

        let base_root: std::sync::Arc<HamtNode<(EventType, String), String>>;
        let mut parent_root_hashes: Vec<String> = Vec::with_capacity(ev.prev_events.len());

        for prev_id in &ev.prev_events {
            if let Some(prev_root) = roots_map.get(prev_id) {
                parent_root_hashes.push(format_structural_hash(&prev_root.structural_hash));
            }
        }

        if ev.prev_events.is_empty() {
            base_root = empty_root.clone();
        } else if ev.prev_events.len() == 1 {
            let prev_id = &ev.prev_events[0];
            base_root = roots_map
                .get(prev_id)
                .cloned()
                .unwrap_or_else(|| empty_root.clone());
        } else {
            let mut parent_roots = Vec::new();
            for prev_id in &ev.prev_events {
                if let Some(prev_root) = roots_map.get(prev_id) {
                    parent_roots.push(prev_root.clone());
                }
            }

            if parent_roots.is_empty() {
                base_root = empty_root.clone();
            } else if parent_roots.len() == 1 {
                base_root = parent_roots[0].clone();
            } else {
                let all_identical = parent_roots
                    .windows(2)
                    .all(|w| w[0].structural_hash == w[1].structural_hash);
                if all_identical {
                    base_root = parent_roots[0].clone();
                } else {
                    let parent_states: Vec<SharedStateMap> =
                        parent_roots.iter().map(hamt_to_state_map).collect();
                    let t = std::time::Instant::now();
                    let resolved_state = resolve_parent_states(
                        &parent_states,
                        ctx.events_map,
                        ctx.version,
                        ctx.auth_graph,
                    );
                    let elapsed = t.elapsed();
                    fork_count = fork_count.saturating_add(1);
                    fork_time = fork_time.saturating_add(elapsed);
                    if debug && elapsed.as_millis() > 50 {
                        eprintln!(
                            "[DEBUG] hamt walk: slow fork resolve at {} ({} parents) took {elapsed:.2?}",
                            ev.event_id,
                            parent_states.len()
                        );
                    }

                    base_root = build_hamt(
                        structural_key,
                        resolved_state.iter().map(|(k, v)| (k.clone(), v.clone())),
                    )
                    .expect("build merged hamt");
                    record_hamt_subtree_nodes(&base_root, &mut seen_node_hashes, &mut unique_nodes);
                }
            }
        }

        let new_root;

        if let Some(state_key) = &ev.state_key {
            let key = (EventType::from(ev.event_type.clone()), state_key.clone());
            let (mutated_root, _displaced, created) = persist_mutation(
                &base_root,
                structural_key,
                key,
                Some(ev.event_id.clone()),
                &mut no_resolver,
            )
            .expect("persist mutation");

            new_root = mutated_root;

            for (node_hash, encoded_bytes) in created {
                if seen_node_hashes.insert(node_hash) {
                    if let Ok(decoded) =
                        PersistedInternalNode::<(EventType, String), String>::decode_v1_unverified(
                            &encoded_bytes,
                        )
                    {
                        let leaves = decoded
                            .leaves
                            .into_iter()
                            .map(|((etype, skey), eid)| {
                                rezzy::json!({
                                    "type": etype.as_str(),
                                    "state_key": skey,
                                    "event_id": eid,
                                })
                            })
                            .collect::<Vec<_>>();
                        let children = decoded
                            .child_hashes
                            .into_iter()
                            .map(|h| format_structural_hash(&h))
                            .collect::<Vec<_>>();
                        unique_nodes.push(rezzy::json!({
                            "hash": format_structural_hash(&node_hash),
                            "datamap": decoded.datamap,
                            "nodemap": decoded.nodemap,
                            "leaves": leaves,
                            "children": children,
                        }));
                    }
                }
            }
        } else {
            new_root = base_root.clone();
        }

        let new_root_hash_str = format_structural_hash(&new_root.structural_hash);
        roots_map.insert(ev.event_id.clone(), new_root.clone());

        roots_json.push(rezzy::json!({
            "event_id": &ev.event_id,
            "root_hash": &new_root_hash_str,
            "parent_root": parent_root_hashes.first().cloned(),
            "parent_roots": &parent_root_hashes,
        }));

        let mut deltas = Vec::new();
        if ev.prev_events.is_empty() {
            let _ = new_root.visit_entries(&mut no_resolver, &mut |key, event_id| {
                deltas.push(rezzy::json!({
                    "type": &key.0,
                    "state_key": &key.1,
                    "event_id": event_id,
                }));
                Ok::<(), std::convert::Infallible>(())
            });
        } else if let Ok((added, removed)) =
            diff_hamt_nodes(&base_root, &new_root, &mut no_resolver)
        {
            let added_keys: std::collections::HashSet<&(EventType, String)> =
                added.iter().map(|(k, _)| k).collect();
            for (key, event_id) in &added {
                deltas.push(rezzy::json!({
                    "type": key.0.as_str(),
                    "state_key": &key.1,
                    "event_id": event_id,
                }));
            }
            for (key, _) in &removed {
                if !added_keys.contains(key) {
                    deltas.push(rezzy::json!({
                        "type": key.0.as_str(),
                        "state_key": &key.1,
                        "event_id": rezzy::JsonValue::Null,
                    }));
                }
            }
        }

        checkpoints.push(rezzy::json!({
            "hash": &new_root_hash_str,
            "parent": parent_root_hashes.first().cloned(),
            "event_id": &ev.event_id,
            "deltas": deltas,
        }));
    }

    if debug {
        eprintln!(
            "[DEBUG] hamt walk: done. {processed} events walked, {fork_count} forks resolved via state-res ({:.2?} total), overall {:.2?}",
            fork_time,
            overall_start.elapsed()
        );
    }

    HamtLiveWalkOutput {
        roots: roots_json,
        nodes: unique_nodes,
        checkpoints,
    }
}

/// Format the output for HAMT roots and unique nodes.
#[must_use]
pub fn format_hamt_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    if ctx.event_count == 0 || ctx.events_map.is_empty() {
        return rezzy::json!({
            "roots": [],
            "nodes": []
        });
    }
    let walk = run_hamt_live_walk(ctx);
    rezzy::json!({
        "roots": walk.roots,
        "nodes": walk.nodes,
    })
}

/// Format the output for deltas.
#[must_use]
pub fn format_deltas_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    if ctx.event_count == 0 || ctx.events_map.is_empty() {
        return rezzy::json!([]);
    }
    let walk = run_hamt_live_walk(ctx);
    rezzy::json!(walk.checkpoints)
}

/// Compute the roots of the components.
#[must_use]
pub fn compute_component_roots(
    events_map: &HashMap<String, LeanEvent, impl std::hash::BuildHasher>,
    include_prev: bool,
    include_auth: bool,
) -> Vec<String> {
    let mut component_roots = Vec::new();
    if !events_map.is_empty() {
        let mut parent: Vec<usize> = (0..events_map.len()).collect();
        let index_to_ev: Vec<&LeanEvent> = events_map.values().collect();
        let id_to_index = rezzy::index_by_event_id(index_to_ev.iter().copied());
        let find_root = |mut node: usize, parent: &mut Vec<usize>| -> usize {
            while parent[node] != node {
                parent[node] = parent[parent[node]];
                node = parent[node];
            }
            node
        };
        let union_nodes = |u: usize, v: usize, parent: &mut Vec<usize>| {
            let root_u = find_root(u, parent);
            let root_v = find_root(v, parent);
            if root_u != root_v {
                parent[root_u] = root_v;
            }
        };

        for ev in events_map.values() {
            if let Some(&u) = id_to_index.get(ev.event_id.as_str()) {
                if include_prev {
                    for prev in &ev.prev_events {
                        if let Some(&v) = id_to_index.get(prev.as_str()) {
                            union_nodes(u, v, &mut parent);
                        }
                    }
                }
                if include_auth {
                    for auth in &ev.auth_events {
                        if let Some(&v) = id_to_index.get(auth.as_str()) {
                            union_nodes(u, v, &mut parent);
                        }
                    }
                }
            }
        }
        let mut comp_roots_map: HashMap<usize, &LeanEvent> = HashMap::new();
        for (i, &ev) in index_to_ev.iter().enumerate() {
            let u = find_root(i, &mut parent);
            comp_roots_map
                .entry(u)
                .and_modify(|e| {
                    if ev.depth < e.depth || (ev.depth == e.depth && ev.event_id < e.event_id) {
                        *e = ev;
                    }
                })
                .or_insert(ev);
        }
        component_roots = comp_roots_map
            .values()
            .map(|e| e.event_id.clone())
            .collect();
        component_roots.sort();
    }
    component_roots
}

/// Format the summary output.
pub fn format_summary_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    let mut state_entries: Vec<rezzy::JsonValue> = Vec::new();
    let mut members: HashMap<String, Vec<rezzy::JsonValue>> = HashMap::new();

    for ((typ, sk), eid) in ctx.final_state_map {
        let ev = ctx.events_map.get(eid);
        if typ.as_str() == "m.room.member" {
            let membership = ev
                .and_then(|e| e.content.get("membership"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            let displayname = ev
                .and_then(|e| e.content.get("displayname"))
                .and_then(|d| d.as_str())
                .unwrap_or("");
            members
                .entry(membership.to_string())
                .or_default()
                .push(rezzy::json!({
                    "user_id": sk,
                    "displayname": displayname,
                    "event_id": eid,
                    "depth": ev.map_or(0, |e| e.depth),
                }));
        } else {
            state_entries.push(rezzy::json!({
                "type": typ,
                "state_key": sk,
                "event_id": eid,
                "sender": ev.map_or("?", |e| e.sender.as_str()),
                "depth": ev.map_or(0, |e| e.depth),
            }));
        }
    }

    state_entries.sort_by(|a, b| {
        let ta = a["type"].as_str().unwrap_or("");
        let tb = b["type"].as_str().unwrap_or("");
        ta.cmp(tb).then_with(|| {
            let sa = a["state_key"].as_str().unwrap_or("");
            let sb = b["state_key"].as_str().unwrap_or("");
            sa.cmp(sb)
        })
    });

    for list in members.values_mut() {
        list.sort_by(|a, b| {
            let ua = a["user_id"].as_str().unwrap_or("");
            let ub = b["user_id"].as_str().unwrap_or("");
            ua.cmp(ub)
        });
    }

    let membership_order = ["join", "invite", "knock", "leave", "ban"];
    let mut membership_obj = rezzy::JsonObject::new();
    for status in &membership_order {
        if let Some(list) = members.get(*status) {
            membership_obj.insert(
                (*status).to_string(),
                rezzy::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }
    for (status, list) in &members {
        if !membership_order.contains(&status.as_str()) {
            membership_obj.insert(
                status.clone(),
                rezzy::json!({
                    "count": list.len(),
                    "users": list
                }),
            );
        }
    }

    let min_depth = ctx.events_map.values().map(|e| e.depth).min().unwrap_or(0);
    let max_depth = ctx.events_map.values().map(|e| e.depth).max().unwrap_or(0);
    let root_event_id = ctx
        .events_map
        .values()
        .min_by_key(|e| e.depth)
        .map_or("", |e| e.event_id.as_str());

    let component_roots_prev = compute_component_roots(ctx.events_map, true, false);
    let component_roots_auth = compute_component_roots(ctx.events_map, false, true);
    let component_roots_union = compute_component_roots(ctx.events_map, true, true);

    rezzy::json!({
        "status": "success",
        "version": ctx.version,
        "duration_ms": ctx.duration.as_millis(),
        "total_events": ctx.event_count,
        "resolved_state_size": state_entries.len().saturating_add(members.values().map(std::vec::Vec::len).sum::<usize>()),
        "auth_chain_size": ctx.auth_chain_ids.len(),
        "min_depth": min_depth,
        "max_depth": max_depth,
        "root_event_id": root_event_id,
        "n_components": component_roots_union.len(),
        "n_components_prev": component_roots_prev.len(),
        "n_components_auth": component_roots_auth.len(),
        "component_roots_prev": component_roots_prev,
        "heads": ctx.heads,
        "membership": membership_obj,
        "state": state_entries
    })
}

fn format_resolve_state_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    let resolved_state: Vec<rezzy::JsonValue> = resolved_state_entries(ctx.final_state_map)
        .into_iter()
        .map(|entry| {
            rezzy::json!({
                "type": entry.event_type,
                "state_key": entry.state_key,
                "event_id": entry.event_id,
            })
        })
        .collect();

    rezzy::json!({
        "status": "success",
        "format": "resolve_state",
        "resolved_state": resolved_state,
    })
}

/// Get a user's display name.
#[must_use]
pub fn get_user_displayname(
    user_id: &str,
    displaynames: &HashMap<String, String, impl std::hash::BuildHasher>,
) -> String {
    displaynames.get(user_id).cloned().unwrap_or_else(|| {
        user_id
            .split(':')
            .next()
            .unwrap_or(user_id)
            .trim_start_matches('@')
            .to_string()
    })
}

/// Format an event description.
#[must_use]
pub fn format_event_description(
    ev: &LeanEvent,
    sender: &str,
    displaynames: &HashMap<String, String, impl std::hash::BuildHasher>,
) -> Option<String> {
    match ev.event_type.as_str() {
        "m.room.create" => Some(format!("{sender} sent m.room.create state event")),
        "m.room.member" => {
            let membership = ev
                .content
                .get("membership")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let target =
                get_user_displayname(ev.state_key.as_deref().unwrap_or_default(), displaynames);
            let reason = ev
                .content
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match membership {
                "join" => Some(format!("joined the room — {target}")),
                "leave" if ev.state_key.as_ref() == Some(&ev.sender) => {
                    Some(format!("left the room — {target}"))
                }
                "leave" => Some(format!(
                    "{} kicked {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "ban" => Some(format!(
                    "{} banned {}{}",
                    sender,
                    target,
                    if reason.is_empty() {
                        String::new()
                    } else {
                        format!(" {reason}")
                    }
                )),
                "invite" => Some(format!("{sender} invited {target}")),
                "knock" => Some(format!("knocked — {target}")),
                _ => Some(format!(
                    "{sender} set {target}'s membership to {membership}"
                )),
            }
        }
        "m.room.message" => {
            let body = ev
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let msgtype = ev
                .content
                .get("msgtype")
                .and_then(|v| v.as_str())
                .unwrap_or("m.text");
            match msgtype {
                "m.text" | "m.notice" => Some(format!("{sender}: {body}")),
                "m.image" => Some(format!("{sender} sent an image")),
                "m.video" => Some(format!("{sender} sent a video")),
                "m.audio" => Some(format!("{sender} sent an audio file")),
                "m.file" => Some(format!("{sender} sent a file")),
                "m.emote" => Some(format!("* {sender} {body}")),
                _ => Some(format!("{sender} sent {msgtype}")),
            }
        }
        "m.room.name" => {
            let name = ev
                .content
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room name to \"{name}\""))
        }
        "m.room.topic" => {
            let topic = ev
                .content
                .get("topic")
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            Some(format!("{sender} changed room topic to \"{topic}\""))
        }
        "m.room.avatar" => Some(format!("{sender} changed room avatar")),
        "m.room.redaction" => Some(format!("{sender} redacted an event")),
        "m.reaction" => None,
        "m.sticker" => Some(format!("{sender} sent a sticker")),
        typ => Some(format!("{sender} sent {typ} state event")),
    }
}

/// Logs a redaction application report's outcomes to stderr under `--debug`.
fn log_redaction_report<Id: std::fmt::Display>(redaction_report: &RedactionReport<Id>) {
    for (rid, tid) in &redaction_report.applied {
        eprintln!("[INFO] redaction {rid} stripped {tid}");
    }
    for (rid, tid) in &redaction_report.skipped_unauthorized {
        eprintln!("[WARN] redaction {rid} rejected for {tid}: sender lacks authorization");
    }
    for (rid, tid) in &redaction_report.target_not_in_batch {
        eprintln!(
            "[WARN] redaction {rid} targets {tid}, absent from the input set; redaction deferred"
        );
    }
    for (rid, tid) in &redaction_report.failed_to_apply {
        eprintln!(
            "[WARN] redaction {rid} targets {tid}, present but failed to apply (e.g. already redacted by a cycle)"
        );
    }
}

/// Whether `args` selects an ordering that needs sidecar stream order.
#[must_use]
pub fn needs_stream_order(args: &Args) -> bool {
    matches!(args.format, OutputFormat::Timeline)
        && (args.timeline_order == TimelineOrder::Synapse
            || args
                .tie_break
                .iter()
                .copied()
                .any(OrderKey::needs_stream_order))
}

/// Load and validate the stream-order index for `--timeline-order synapse`.
///
/// An explicit `--metadata` path is fatal on error. Auto-discovered sibling
/// sidecars are best-effort: missing, mismatched, or conflicting entries are
/// counted and reported in one summary warning, and the caller falls back.
///
/// # Errors
/// Returns an error only when an explicit `--metadata` sidecar cannot be read.
pub fn load_stream_order(
    args: &Args,
    events_map: &HashMap<String, LeanEvent>,
    raw_map: &HashMap<String, rezzy::JsonValue>,
    room_version: Option<&str>,
) -> Result<Option<StreamOrderIndex>, AppError> {
    let explicit = args.metadata.clone();
    let paths: Vec<PathBuf> = match &explicit {
        Some(path) => vec![path.clone()],
        None => args
            .input
            .iter()
            .filter(|path| {
                path.extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            })
            .map(|path| provenance::sidecar_path(path))
            .filter(|path| path.is_file())
            .collect(),
    };
    if paths.is_empty() {
        warn_once(
            args.quiet,
            "no provenance sidecar found; stream ordering unavailable",
        );
        return Ok(None);
    }

    let expected_room_id = raw_map
        .values()
        .find_map(|value| value.get("room_id").and_then(rezzy::JsonValue::as_str));
    let mut index = StreamOrderIndex::default();
    let mut missing = 0_usize;
    let mut mismatched = 0_usize;
    let mut room_mismatch = 0_usize;
    for path in &paths {
        let sidecar = if explicit.is_some() {
            provenance::load_sidecar(path)?
        } else {
            match provenance::load_sidecar(path) {
                Ok(sidecar) => sidecar,
                Err(error) => {
                    warn_once(
                        args.quiet,
                        &format!("ignoring provenance sidecar {}: {error}", path.display()),
                    );
                    continue;
                }
            }
        };
        if room_version.is_some()
            && sidecar.room_version.is_some()
            && room_version != sidecar.room_version.as_deref()
        {
            room_mismatch = room_mismatch.saturating_add(1);
            continue;
        }
        if expected_room_id.is_some()
            && sidecar
                .room_id
                .as_deref()
                .is_some_and(|id| Some(id) != expected_room_id)
        {
            room_mismatch = room_mismatch.saturating_add(1);
            continue;
        }
        for (event_id, _event) in events_map {
            let Some(record) = sidecar.events.get(event_id) else {
                missing = missing.saturating_add(1);
                continue;
            };
            if let Some(raw) = raw_map.get(event_id) {
                if let Ok(serialized) = rezzy::json::write_string_value(raw) {
                    if provenance::sha256_id(serialized.as_bytes()) != record.payload_sha256 {
                        mismatched = mismatched.saturating_add(1);
                        continue;
                    }
                }
            }
            match record.stream_ordering {
                Some(value) => {
                    index.by_event.insert(event_id.clone(), value);
                }
                None => missing = missing.saturating_add(1),
            }
        }
    }
    if index.is_empty() {
        warn_once(
            args.quiet,
            "provenance sidecar had no usable stream_ordering",
        );
        return Ok(None);
    }
    if missing > 0 || mismatched > 0 || room_mismatch > 0 {
        warn_once(
            args.quiet,
            &format!(
                "stream_ordering incomplete ({missing} missing/conflicting, {mismatched} payload mismatch, {room_mismatch} room/version mismatch); those events sort after events with a known stream order"
            ),
        );
    }
    Ok(Some(index))
}

fn warn_once(quiet: bool, message: &str) {
    if !quiet {
        eprintln!("[WARN] {message}");
    }
}

/// Format the timeline output.
/// Render the timeline to a string, applying only authorized redactions.
fn render_timeline(ctx: &FormattingContext) -> String {
    let events = prepare_timeline_events(ctx);
    let sorted_events = match ctx.args.timeline_order {
        TimelineOrder::Causal => sort_timeline_causal(ctx.args, ctx.stream_order, &events),
        TimelineOrder::Synapse => sort_timeline_synapse(ctx.args, ctx.stream_order, &events),
    };
    render_timeline_events(ctx, &sorted_events)
}

/// Render the timestamp-primary human view (`-f timeline-chronological`).
fn render_timeline_chronological(ctx: &FormattingContext) -> String {
    let mut sorted_events = prepare_timeline_events(ctx);
    sort_timeline_chronological(&mut sorted_events);
    render_timeline_events(ctx, &sorted_events)
}

/// Collect events and apply only authorized redactions.
fn prepare_timeline_events(ctx: &FormattingContext) -> Vec<LeanEvent> {
    // Owned copy of the events so the authorized redaction pass can mutate the
    // in-set targets in place. The resolved room state below is what the
    // redaction pass needs to authorize each redaction.
    let mut sorted_events: Vec<LeanEvent> = ctx.events_map.values().cloned().collect();

    // Prefer the resolved `m.room.create` event's own `room_version` field
    // over `ctx.room_version` (a pre-resolution guess derived from the raw
    // input, before conflicts were settled). Fall back to `ctx.room_version`,
    // then "1", only when no create event made it into the resolved state.
    let create_room_version = ctx
        .final_state_map
        .get(&(EventType::from("m.room.create"), String::new()))
        .and_then(|eid| ctx.events_map.get(eid))
        .and_then(|ev| ev.content.get("room_version"))
        .and_then(|v| v.as_str());
    let room_version = create_room_version.or(ctx.room_version).unwrap_or("1");

    // Resolved room state (event type + state_key -> event), used to check the
    // `redact` power level and each redaction sender's own power level.
    // NOTE: This uses final resolved state, not per-redaction event-time state.
    // The spec requires per-redaction state, but reconstructing it requires
    // proper topological state resolution at each redaction's prev_events —
    // depth-based ordering is insufficient because depth is untrusted and does
    // not guarantee parent-before-child processing. A future fix should use
    // apply_authorized_redactions_with_state_at with proper state resolution.
    let mut room_state: RoomState<String, rezzy::JsonValue, String> = RoomState::new();
    for ((typ, sk), eid) in ctx.final_state_map {
        if let Some(ev) = ctx.events_map.get(eid) {
            room_state.insert((typ.as_str().to_string(), sk.clone()), ev.clone());
        }
    }

    // Apply redactions resolvable within the input set, but only when the
    // sender is authorized: the target's own sender, a sender holding the
    // `redact` power level, or (room v1/v2) a same-domain sender. An
    // unauthorized redaction leaves the target untouched. The returned report
    // drives the --debug diagnostics below.
    let redaction_report = if sorted_events.iter().any(LeanEvent::is_redaction) {
        apply_authorized_redactions(&mut sorted_events, &room_state, ctx.version, room_version)
    } else {
        RedactionReport::default()
    };

    if ctx.args.debug {
        log_redaction_report(&redaction_report);
    }

    sorted_events
}

/// Kahn causal order; the ready queue uses `--tie-break` (default
/// `origin_server_ts,matrix_depth,event_id`). Stream-order key components are
/// dropped with a warning when no sidecar supplied them.
#[must_use]
fn sort_timeline_causal(
    args: &Args,
    stream: Option<&StreamOrderIndex>,
    events: &[LeanEvent],
) -> Vec<LeanEvent> {
    let requested: Vec<OrderKey> = if args.tie_break.is_empty() {
        DEFAULT_TIE_BREAK.to_vec()
    } else {
        args.tie_break.clone()
    };
    let mut ready_keys: Vec<OrderKey> = Vec::with_capacity(requested.len());
    let mut dropped_stream = false;
    for key in requested {
        if key.needs_stream_order() && stream.is_none() {
            dropped_stream = true;
            continue;
        }
        ready_keys.push(key);
    }
    if ready_keys.is_empty() {
        ready_keys.push(OrderKey::EventId);
    }
    if dropped_stream {
        warn_once(
            args.quiet,
            "stream_ordering unavailable; dropping it from --tie-break",
        );
    }
    reorder_by_kahn(events, &ready_keys, stream)
}

/// Synapse-like causal order: `matrix_depth, stream_ordering, event_id`
/// (`SYNAPSE_TIE_BREAK`), still routed through Kahn so parents always precede
/// children even when the supplied `depth` is untrusted or inconsistent.
///
/// Events without a known stream order sort after those with one at the same
/// depth; the missing component is a sentinel, never a substituted timestamp.
#[must_use]
fn sort_timeline_synapse(
    args: &Args,
    stream: Option<&StreamOrderIndex>,
    events: &[LeanEvent],
) -> Vec<LeanEvent> {
    let fallbacks = events
        .iter()
        .filter(|event| {
            stream
                .and_then(|index| index.get(&event.event_id))
                .is_none()
        })
        .count();
    if fallbacks > 0 {
        warn_once(
            args.quiet,
            &format!(
                "{fallbacks} event(s) had no stream_ordering; sorted after those with one (matrix_depth, event_id)"
            ),
        );
    }
    reorder_by_kahn(events, &SYNAPSE_TIE_BREAK, stream)
}

/// Timestamp-primary human view: `origin_server_ts, matrix_depth, event_id`.
///
/// Deliberately *not* causal: use `-f timeline` for parent-before-child order.
fn sort_timeline_chronological(events: &mut [LeanEvent]) {
    events.sort_by(|a, b| {
        a.origin_server_ts
            .cmp(&b.origin_server_ts)
            .then(a.depth.cmp(&b.depth))
            .then(a.event_id.cmp(&b.event_id))
    });
}

/// Reorder `events` into a parent-before-child (Kahn) order, using `keys` for
/// the currently-ready frontier only. A requested stream component that is
/// unknown for an event becomes [`MISSING_STREAM_ORDER`] rather than a
/// timestamp.
#[must_use]
fn reorder_by_kahn(
    events: &[LeanEvent],
    keys: &[OrderKey],
    stream: Option<&StreamOrderIndex>,
) -> Vec<LeanEvent> {
    let ids: Vec<String> = events.iter().map(|event| event.event_id.clone()).collect();
    let parents: Vec<Vec<String>> = events
        .iter()
        .map(|event| event.prev_events.clone())
        .collect();
    let order_keys: Vec<Vec<KeyValue>> = events
        .iter()
        .map(|event| {
            let stream_value = stream
                .and_then(|index| index.get(&event.event_id))
                .unwrap_or(MISSING_STREAM_ORDER);
            build_key(
                keys,
                &event.event_id,
                event.depth,
                event.origin_server_ts,
                stream_value,
            )
        })
        .collect();
    kahn_order_by(&ids, &parents, &order_keys)
        .into_iter()
        .map(|index| events[index].clone())
        .collect()
}

fn render_timeline_events(ctx: &FormattingContext, sorted_events: &[LeanEvent]) -> String {
    let mut displaynames: HashMap<String, String> = HashMap::new();
    for ev in sorted_events {
        if ev.event_type == "m.room.member" {
            if let Some(dn) = ev.content.get("displayname").and_then(|v| v.as_str()) {
                if !dn.is_empty() {
                    displaynames.insert(ev.state_key.clone().unwrap_or_default(), dn.to_string());
                }
            }
        }
    }

    let mut output = String::new();
    let mut last_date = String::new();

    for ev in sorted_events {
        let sender = get_user_displayname(&ev.sender, &displaynames);
        let Some(desc) = format_event_description(ev, &sender, &displaynames) else {
            continue;
        };
        let desc = if ev.soft_fail {
            // Hide soft-failed and rejected events from the default timeline;
            // only surface them under --debug, flagged, as they're diagnostic.
            if !ctx.args.debug {
                continue;
            }
            format!("[SOFT-FAIL] {desc}")
        } else if ev.rejected {
            if !ctx.args.debug {
                continue;
            }
            format!("[REJECTED] {desc}")
        } else {
            desc
        };

        let ts_ms = ev.origin_server_ts;
        let ts_secs = i64::try_from(ts_ms / 1000).unwrap();
        let time_of_day =
            u64::try_from((ts_secs.wrapping_rem(86_400).wrapping_add(86_400)).wrapping_rem(86_400))
                .unwrap();
        let hours = time_of_day / 3_600;
        let minutes = (time_of_day % 3_600) / 60;
        let days = ts_secs.div_euclid(86_400);

        let (y, m, d) = epoch_days_to_ymd(days);
        let month_names = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let month_str = month_names
            .get(m.saturating_sub(1) as usize)
            .unwrap_or(&"???");
        let ampm = if hours < 12 { "AM" } else { "PM" };
        let h12 = if hours == 0 {
            12
        } else if hours > 12 {
            hours.wrapping_sub(12)
        } else {
            hours
        };
        let date = format!("{d} {month_str} {y} {h12:02}:{minutes:02} {ampm}");

        if date != last_date {
            if !last_date.is_empty() {
                output.push('\n');
            }
            last_date.clone_from(&date);
        }

        output.push_str(&desc);
        output.push('\n');
        output.push_str(&date);
        output.push('\n');
    }

    output
}

/// Format the timeline output, printing the rendered timeline to stderr.
#[must_use]
pub fn format_timeline_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    eprint!("{}", render_timeline(ctx));
    rezzy::json!({
        "status": "success",
        "format": "timeline",
        "order": format_name(ctx.args.timeline_order),
        "events": ctx.event_count
    })
}

#[must_use]
pub fn format_timeline_chronological_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    eprint!("{}", render_timeline_chronological(ctx));
    rezzy::json!({
        "status": "success",
        "format": "timeline-chronological",
        "events": ctx.event_count
    })
}

fn format_name(order: TimelineOrder) -> &'static str {
    match order {
        TimelineOrder::Causal => "causal",
        TimelineOrder::Synapse => "synapse",
    }
}

/// Format the main CLI output.
#[must_use]
pub fn format_cli_output(ctx: &FormattingContext) -> rezzy::JsonValue {
    match ctx.args.format {
        OutputFormat::Deltas => format_deltas_output(ctx),
        OutputFormat::Summary => format_summary_output(ctx),
        OutputFormat::ResolveState => format_resolve_state_output(ctx),
        OutputFormat::Timeline => format_timeline_output(ctx),
        OutputFormat::TimelineChronological => format_timeline_chronological_output(ctx),
        OutputFormat::Events => {
            let mut state_events: Vec<&rezzy::JsonValue> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            state_events.sort_by(|a, b| {
                let a_ev = a
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));
                let b_ev = b
                    .get("event_id")
                    .and_then(|id| id.as_str())
                    .and_then(|id| ctx.events_map.get(id));

                let a_depth = a_ev.map_or(0, |e| e.depth);
                let b_depth = b_ev.map_or(0, |e| e.depth);

                a_depth.cmp(&b_depth).then_with(|| {
                    let a_id = a_ev.map_or("", |e| e.event_id.as_str());
                    let b_id = b_ev.map_or("", |e| e.event_id.as_str());
                    a_id.cmp(b_id)
                })
            });
            rezzy::json!(state_events)
        }
        OutputFormat::Federation => {
            let state_events: Vec<&rezzy::JsonValue> = ctx
                .resolved_state_list
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();
            let auth_chain_events: Vec<&rezzy::JsonValue> = ctx
                .auth_chain_ids
                .iter()
                .filter_map(|id| ctx.raw_map.get(id))
                .collect();

            rezzy::json!({
                "origin": &ctx.args.origin,
                "state": state_events,
                "auth_chain": auth_chain_events
            })
        }
        OutputFormat::Hamt => format_hamt_output(ctx),
        OutputFormat::Default => rezzy::json!({
            "status": "success",
            "version": ctx.version,
            "duration_ms": ctx.duration.as_millis(),
            "resolved_state_size": ctx.resolved_state_list.len(),
            "auth_chain_size": ctx.auth_chain_ids.len(),
            "state_event_ids": ctx.resolved_state_list
        }),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn build_auth_graph(
        events_map: &HashMap<String, LeanEvent>,
    ) -> rezzy::auth::roaring::AuthGraph {
        rezzy::auth::roaring::AuthGraph::build(events_map)
    }

    fn test_args(format: OutputFormat) -> Args {
        Args {
            input: Vec::new(),
            room: None,
            homeserver: None,
            token: None,
            output: None,
            state_res: None,
            format,
            debug: false,
            quiet: false,
            check: false,
            origin: String::from("matrix.org"),
            timeline_order: TimelineOrder::default(),
            tie_break: Vec::new(),
            timeline_order_explicit: false,
            metadata: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn formatting_context<'a>(
        room_version: Option<&'a str>,
        duration: std::time::Duration,
        event_count: usize,
        args: &'a Args,
        events_map: &'a HashMap<String, LeanEvent>,
        raw_map: &'a HashMap<String, rezzy::JsonValue>,
        heads: &'a [String],
        final_state_map: &'a imbl::OrdMap<(EventType, String), String>,
        resolved_state_list: &'a [String],
        auth_chain_ids: &'a [String],
        auth_graph: &'a rezzy::auth::roaring::AuthGraph,
    ) -> FormattingContext<'a> {
        FormattingContext {
            args,
            events_map,
            raw_map,
            heads,
            final_state_map,
            resolved_state_list,
            auth_chain_ids,
            auth_graph,
            version: StateResVersion::V2,
            room_version,
            duration,
            event_count,
            stream_order: None,
        }
    }

    #[test]
    fn empty_context_supports_all_non_timeline_output_formats() {
        let events_map = HashMap::new();
        let raw_map = HashMap::new();
        let heads = Vec::new();
        let final_state_map = imbl::OrdMap::new();
        let resolved_state_list = Vec::new();
        let auth_chain_ids = Vec::new();
        let auth_graph = build_auth_graph(&events_map);

        let render = |format| {
            let args = test_args(format);
            let ctx = formatting_context(
                None,
                std::time::Duration::ZERO,
                0,
                &args,
                &events_map,
                &raw_map,
                &heads,
                &final_state_map,
                &resolved_state_list,
                &auth_chain_ids,
                &auth_graph,
            );
            format_cli_output(&ctx)
        };

        assert_eq!(render(OutputFormat::Events), rezzy::json!([]));
        assert_eq!(
            render(OutputFormat::Federation),
            rezzy::json!({"origin": "matrix.org", "state": [], "auth_chain": []})
        );
        assert_eq!(
            render(OutputFormat::Default)["status"].as_str(),
            Some("success")
        );
        assert_eq!(
            render(OutputFormat::Summary)["status"].as_str(),
            Some("success")
        );
        assert_eq!(render(OutputFormat::Deltas), rezzy::json!([]));
        assert_eq!(
            render(OutputFormat::Hamt),
            rezzy::json!({"roots": [], "nodes": []})
        );
        assert_eq!(
            render(OutputFormat::ResolveState)["resolved_state"],
            rezzy::json!([])
        );
    }

    #[test]
    fn resolve_state_output_exposes_the_resolved_state_entries() {
        let args = test_args(OutputFormat::ResolveState);

        let events_map = HashMap::new();
        let raw_map = HashMap::new();
        let heads = Vec::new();
        let mut final_state_map = imbl::OrdMap::new();
        final_state_map.insert(("m.room.create".into(), String::new()), "$create".into());
        final_state_map.insert(("m.room.member".into(), "@alice:x".into()), "$join".into());
        let resolved_state_list = vec!["$create".to_string(), "$join".to_string()];
        let auth_chain_ids = Vec::new();
        let auth_graph = build_auth_graph(&events_map);

        let ctx = formatting_context(
            Some("11"),
            std::time::Duration::from_millis(0),
            2,
            &args,
            &events_map,
            &raw_map,
            &heads,
            &final_state_map,
            &resolved_state_list,
            &auth_chain_ids,
            &auth_graph,
        );

        let output = format_cli_output(&ctx);
        assert_eq!(output["status"].as_str(), Some("success"));
        assert_eq!(output["format"].as_str(), Some("resolve_state"));
        assert_eq!(
            output["resolved_state"],
            rezzy::json!([
                {
                    "type": "m.room.create",
                    "state_key": "",
                    "event_id": "$create",
                },
                {
                    "type": "m.room.member",
                    "state_key": "@alice:x",
                    "event_id": "$join",
                }
            ])
        );
    }

    /// The CLI timeline applies a redaction only when it is authorized against
    /// the resolved room state: an unrelated sender with no `redact` power must
    /// not strip the target, while the target's own sender may.
    #[test]
    fn timeline_redaction_requires_authorization() {
        let render = |events: Vec<LeanEvent>| -> String {
            let mut events_map = HashMap::new();
            for ev in &events {
                events_map.insert(ev.event_id.clone(), ev.clone());
            }
            let args = test_args(OutputFormat::Timeline);
            let raw_map = HashMap::new();
            let heads = Vec::new();
            let mut final_state_map = imbl::OrdMap::new();
            final_state_map.insert(("m.room.power_levels".into(), String::new()), "$pl".into());
            let resolved_state_list: Vec<String> = Vec::new();
            let auth_chain_ids: Vec<String> = Vec::new();
            let auth_graph = build_auth_graph(&events_map);
            let ctx = formatting_context(
                Some("11"),
                std::time::Duration::from_millis(0),
                events.len(),
                &args,
                &events_map,
                &raw_map,
                &heads,
                &final_state_map,
                &resolved_state_list,
                &auth_chain_ids,
                &auth_graph,
            );
            render_timeline(&ctx)
        };

        let pl: LeanEvent = LeanEvent {
            event_id: "$pl".into(),
            event_type: "m.room.power_levels".into(),
            state_key: Some(String::new()),
            sender: "@admin:x".into(),
            content: rezzy::json!({
                "users": { "@admin:x": 100, "@bob:x": 0, "@mallory:x": 0 },
                "redact": 50
            }),
            ..Default::default()
        };
        let msg: LeanEvent = LeanEvent {
            event_id: "$msg".into(),
            event_type: "m.room.message".into(),
            sender: "@bob:x".into(),
            origin_server_ts: 10,
            content: rezzy::json!({ "body": "secret" }),
            ..Default::default()
        };
        let mallory_redact: LeanEvent = LeanEvent {
            event_id: "$r_mal".into(),
            event_type: "m.room.redaction".into(),
            sender: "@mallory:x".into(),
            origin_server_ts: 11,
            content: rezzy::json!({ "redacts": "$msg" }),
            ..Default::default()
        };
        let self_redact: LeanEvent = LeanEvent {
            event_id: "$r_self".into(),
            event_type: "m.room.redaction".into(),
            sender: "@bob:x".into(),
            origin_server_ts: 12,
            content: rezzy::json!({ "redacts": "$msg" }),
            ..Default::default()
        };

        // Unauthorized: mallory (PL 0 < redact 50, not the target's sender)
        // must NOT strip Bob's message.
        let out = render(vec![pl.clone(), msg.clone(), mallory_redact.clone()]);
        assert!(
            out.contains("secret"),
            "unauthorized redaction must not strip the target; got: {out:?}"
        );

        // Authorized: Bob redacts his own message -> content is stripped.
        let out = render(vec![pl.clone(), msg.clone(), self_redact.clone()]);
        assert!(
            !out.contains("secret"),
            "authorized self-redaction must strip the target content; got: {out:?}"
        );
    }

    fn timeline_event(id: &str, prev: &[&str], depth: u64, ts: u64) -> LeanEvent {
        LeanEvent {
            event_id: id.into(),
            prev_events: prev.iter().map(|parent| (*parent).to_string()).collect(),
            depth,
            origin_server_ts: ts,
            ..Default::default()
        }
    }

    fn order_of(events: &[LeanEvent]) -> Vec<&str> {
        events.iter().map(|event| event.event_id.as_str()).collect()
    }

    fn stream_index(entries: &[(&str, u64)]) -> StreamOrderIndex {
        let mut index = StreamOrderIndex::default();
        for (event_id, stream) in entries {
            index.by_event.insert((*event_id).to_string(), *stream);
        }
        index
    }

    #[test]
    fn causal_keeps_parent_before_child_despite_earlier_child_timestamp() {
        let parent = timeline_event("$parent", &[], 1, 200);
        let child = timeline_event("$child", &["$parent"], 2, 100);
        let args = test_args(OutputFormat::Timeline);
        let out = sort_timeline_causal(&args, None, &[child, parent]);
        assert_eq!(order_of(&out), vec!["$parent", "$child"]);
    }

    #[test]
    fn causal_orders_concurrent_frontier_by_timestamp() {
        let root = timeline_event("$root", &[], 0, 0);
        let x = timeline_event("$x", &["$root"], 1, 500);
        let y = timeline_event("$y", &["$root"], 1, 100);
        let args = test_args(OutputFormat::Timeline);
        let out = sort_timeline_causal(&args, None, &[x, y, root]);
        assert_eq!(order_of(&out), vec!["$root", "$y", "$x"]);
    }

    #[test]
    fn chronological_sorts_by_timestamp_not_by_dag() {
        let parent = timeline_event("$parent", &[], 1, 200);
        let child = timeline_event("$child", &["$parent"], 2, 100);
        let mut events = vec![parent, child];
        sort_timeline_chronological(&mut events);
        assert_eq!(order_of(&events), vec!["$child", "$parent"]);
    }

    #[test]
    fn synapse_orders_by_stream_within_depth() {
        let root = timeline_event("$root", &[], 0, 0);
        // y has the earlier timestamp but the later stream order: stream wins.
        let x = timeline_event("$x", &["$root"], 1, 500);
        let y = timeline_event("$y", &["$root"], 1, 100);
        let stream = stream_index(&[("$x", 1), ("$y", 2)]);
        let args = test_args(OutputFormat::Timeline);
        let out = sort_timeline_synapse(&args, Some(&stream), &[x, y, root]);
        assert_eq!(order_of(&out), vec!["$root", "$x", "$y"]);
    }

    #[test]
    fn synapse_stays_causal_even_with_inconsistent_depth() {
        // The child claims a lower depth than its parent; a global depth sort
        // would emit it first. Kahn must keep the parent first.
        let parent = timeline_event("$parent", &[], 5, 100);
        let child = timeline_event("$child", &["$parent"], 1, 200);
        let args = test_args(OutputFormat::Timeline);
        let out = sort_timeline_synapse(&args, None, &[child, parent]);
        assert_eq!(order_of(&out), vec!["$parent", "$child"]);
    }

    #[test]
    fn partial_stream_order_never_substitutes_timestamp() {
        let root = timeline_event("$root", &[], 0, 0);
        // x has a large timestamp but a known stream order; y has a tiny
        // timestamp and no stream order. A timestamp fallback would wrongly
        // sort y first; the missing-stream sentinel sorts it last.
        let x = timeline_event("$x", &["$root"], 1, 1_700_000_000_000);
        let y = timeline_event("$y", &["$root"], 1, 1);
        let stream = stream_index(&[("$x", 100)]);
        let args = Args {
            tie_break: vec![OrderKey::StreamOrdering],
            ..test_args(OutputFormat::Timeline)
        };
        let out = sort_timeline_causal(&args, Some(&stream), &[root, x, y]);
        assert_eq!(order_of(&out), vec!["$root", "$x", "$y"]);
    }

    #[test]
    fn test_hamt_live_walk_roots_and_nodes_output() {
        let ev1: LeanEvent = LeanEvent {
            event_id: "$create".into(),
            event_type: "m.room.create".into(),
            state_key: Some(String::new()),
            depth: 1,
            ..Default::default()
        };
        let ev2: LeanEvent = LeanEvent {
            event_id: "$join".into(),
            event_type: "m.room.member".into(),
            state_key: Some("@alice:x".into()),
            prev_events: vec!["$create".into()],
            depth: 2,
            ..Default::default()
        };
        let ev3: LeanEvent = LeanEvent {
            event_id: "$msg".into(),
            event_type: "m.room.message".into(),
            state_key: None,
            prev_events: vec!["$join".into()],
            depth: 3,
            ..Default::default()
        };

        let mut events_map: HashMap<String, LeanEvent> = HashMap::new();
        events_map.insert(ev1.event_id.clone(), ev1);
        events_map.insert(ev2.event_id.clone(), ev2);
        events_map.insert(ev3.event_id.clone(), ev3);

        let raw_map = HashMap::new();
        let heads = vec!["$msg".into()];
        let final_state_map = imbl::OrdMap::new();
        let resolved_state_list = Vec::new();
        let auth_chain_ids = Vec::new();
        let auth_graph = build_auth_graph(&events_map);

        let args = test_args(OutputFormat::Hamt);
        let ctx = formatting_context(
            None,
            std::time::Duration::ZERO,
            3,
            &args,
            &events_map,
            &raw_map,
            &heads,
            &final_state_map,
            &resolved_state_list,
            &auth_chain_ids,
            &auth_graph,
        );

        let hamt_output = format_cli_output(&ctx);
        let roots = hamt_output["roots"].as_array().expect("roots array");
        assert_eq!(roots.len(), 3);
        assert_eq!(roots[0]["event_id"], "$create");
        assert_eq!(roots[0]["parent_root"], rezzy::JsonValue::Null);
        assert_eq!(roots[1]["event_id"], "$join");
        assert_eq!(roots[1]["parent_root"], roots[0]["root_hash"]);
        assert_eq!(roots[2]["event_id"], "$msg");
        // Timeline message does not change state -> root_hash matches parent
        assert_eq!(roots[2]["root_hash"], roots[1]["root_hash"]);

        let nodes = hamt_output["nodes"].as_array().expect("nodes array");
        assert!(!nodes.is_empty());

        let deltas_args = test_args(OutputFormat::Deltas);
        let deltas_ctx = formatting_context(
            None,
            std::time::Duration::ZERO,
            3,
            &deltas_args,
            &events_map,
            &raw_map,
            &heads,
            &final_state_map,
            &resolved_state_list,
            &auth_chain_ids,
            &auth_graph,
        );
        let deltas_output = format_cli_output(&deltas_ctx);
        let checkpoints = deltas_output.as_array().expect("checkpoints array");
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0]["event_id"], "$create");
        assert_eq!(checkpoints[1]["event_id"], "$join");
        assert_eq!(checkpoints[2]["event_id"], "$msg");
        assert_eq!(checkpoints[2]["deltas"], rezzy::json!([]));
    }
}
